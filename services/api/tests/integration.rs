//! API integration tests against a real Postgres 16. Requires `DATABASE_URL`
//! (defaults to the local dev cluster). Applies the migrations idempotently, then
//! drives the router in-process via `tower::ServiceExt::oneshot`.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::Engine as _;
use sentinel_api::auth::{GoogleVerifier, MockGoogleVerifier};
use sentinel_api::config::{Config, JwtKeys};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

fn database_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://sentinel:sentinel@127.0.0.1:5433/sentinel".into())
}

/// Serialize migrations across the parallel test threads and run them only once —
/// concurrent DDL (DROP/CREATE trigger, the schema-guard DO block) otherwise races.
static MIGRATED: std::sync::OnceLock<tokio::sync::Mutex<bool>> = std::sync::OnceLock::new();

async fn ensure_migrated(pool: &PgPool) {
    let mutex = MIGRATED.get_or_init(|| tokio::sync::Mutex::new(false));
    let mut done = mutex.lock().await;
    if *done {
        return;
    }
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "sql").unwrap_or(false))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.chars().next().unwrap().is_ascii_digit())
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    for f in files {
        let sql = std::fs::read_to_string(&f).unwrap();
        sqlx::raw_sql(&sql).execute(pool).await.expect("migration");
    }
    *done = true;
}

async fn setup() -> (Router, PgPool) {
    setup_with(None).await
}

async fn setup_with(bootstrap_token: Option<&str>) -> (Router, PgPool) {
    setup_full(bootstrap_token, 0).await
}

async fn setup_full(bootstrap_token: Option<&str>, autoban_threshold: u32) -> (Router, PgPool) {
    let pool = sentinel_api::connect(&database_url())
        .await
        .expect("db connect");
    ensure_migrated(&pool).await;

    let config = Config {
        bind: "127.0.0.1:0".into(),
        database_url: database_url(),
        google_client_id: None,
        bootstrap_token: bootstrap_token.map(|s| s.to_string()),
        totp_enc_key: [7u8; 32],
        production: false,
        trust_forwarded_for: false,
        cors_allowed_origins: Vec::new(),
        autoban_threshold,
        autoban_window_secs: 300,
        autoban_minutes: 60,
    };
    let google: Arc<dyn GoogleVerifier> = Arc::new(MockGoogleVerifier);
    let app = sentinel_api::build_app(pool.clone(), JwtKeys::ephemeral(), config, google);
    (app, pool)
}

#[tokio::test]
async fn bootstrap_mints_a_working_approved_session() {
    let (app, _pool) = setup_with(Some("s3cr3t-bootstrap")).await;

    // Wrong token → 401.
    let (s, _v) = call(
        &app,
        post(
            "/v1/auth/bootstrap",
            None,
            json!({ "token": "nope", "device": { "name": "Desk", "platform": "linux" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Right token mints a session directly — no Google, no TOTP.
    let (s, v) = call(
        &app,
        post(
            "/v1/auth/bootstrap",
            None,
            json!({ "token": "s3cr3t-bootstrap", "device": { "name": "Desk", "platform": "linux" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "bootstrap: {v}");
    let access = v["access_token"].as_str().unwrap().to_string();

    // The device is already APPROVED: an authed sync call must not 403. A fresh account has no
    // vault yet → 204 (not 403), proving the bootstrap session works on the sync endpoints.
    let req = Request::builder()
        .method("GET")
        .uri("/v1/vault")
        .header("authorization", format!("Bearer {access}"))
        .body(Body::empty())
        .unwrap();
    let (s, _v) = call(&app, req).await;
    assert_ne!(s, StatusCode::FORBIDDEN, "device should be approved");
    assert!(
        s == StatusCode::NO_CONTENT || s == StatusCode::OK,
        "vault get: {s}"
    );
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let val = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, val)
}

fn post(uri: &str, token: Option<&str>, body: Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

/// A bodyless authenticated request (GET/DELETE) with a bearer token.
fn authed_req(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

/// Run the full onboarding flow and return an approved-device access token + refresh.
async fn onboard(app: &Router, sub: &str) -> (String, String) {
    onboard_with(app, sub, "Test Desktop", "linux").await
}

/// Onboard a device of a given name/platform on the account keyed by `sub`. A second call with the
/// same `sub` but a different platform enrolls another device on the *same* account (e.g. an iOS
/// companion alongside the desktop).
async fn onboard_with(app: &Router, sub: &str, name: &str, platform: &str) -> (String, String) {
    let (s, v) = call(
        app,
        post(
            "/v1/auth/google",
            None,
            json!({ "id_token": format!("fixture:{sub}:{sub}@example.com"),
                    "device": { "name": name, "platform": platform } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "google: {v}");
    let pending = v["pending_token"].as_str().unwrap().to_string();

    let (s, v) = call(app, post("/v1/auth/totp/enroll", Some(&pending), json!({}))).await;
    assert_eq!(s, StatusCode::OK, "enroll: {v}");
    let secret_b32 = v["secret_base32"].as_str().unwrap().to_string();
    let code = totp_now(&secret_b32);

    let (s, v) = call(
        app,
        post(
            "/v1/auth/totp/verify",
            Some(&pending),
            json!({ "code": code }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "verify: {v}");
    (
        v["access_token"].as_str().unwrap().to_string(),
        v["refresh_token"].as_str().unwrap().to_string(),
    )
}

fn totp_now(secret_b32: &str) -> String {
    let secret = base32_decode(secret_b32);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    sentinel_api::auth::totp_code(&secret, now)
}

fn base32_decode(s: &str) -> Vec<u8> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buf, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.chars() {
        let val = A.iter().position(|&x| x as char == c).unwrap() as u32;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

#[tokio::test]
async fn healthz_ok() {
    let (app, _) = setup().await;
    let (s, v) = call(
        &app,
        Request::builder()
            .uri("/healthz")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["status"], "ok");
}

#[tokio::test]
async fn onboarding_and_vault_version_flow() {
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (access, _refresh) = onboard(&app, &sub).await;

    // Empty vault → 204.
    let (s, _) = call(
        &app,
        Request::builder()
            .uri("/v1/vault")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let ct = base64::engine::general_purpose::STANDARD.encode(vec![9u8; 48]);

    // First PUT with If-Match: 0 → version 1.
    let (s, v) = call(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/v1/vault")
            .header("authorization", format!("Bearer {access}"))
            .header("content-type", "application/json")
            .header("If-Match", "0")
            .body(Body::from(json!({ "ciphertext_b64": ct }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["version"], 1);

    // Stale PUT with If-Match: 0 again → 409 with current version.
    let (s, v) = call(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/v1/vault")
            .header("authorization", format!("Bearer {access}"))
            .header("content-type", "application/json")
            .header("If-Match", "0")
            .body(Body::from(json!({ "ciphertext_b64": ct }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(v["current"], 1);

    // Correct PUT with If-Match: 1 → version 2.
    let (s, v) = call(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/v1/vault")
            .header("authorization", format!("Bearer {access}"))
            .header("content-type", "application/json")
            .header("If-Match", "1")
            .body(Body::from(json!({ "ciphertext_b64": ct }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["version"], 2);
}

#[tokio::test]
async fn wrapped_keys_round_trip() {
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (access, _) = onboard(&app, &sub).await;

    // A valid-shaped SNTL recovery blob (96 bytes: 8 header + 16 params + 24 + 48).
    let mut blob = vec![0u8; 96];
    blob[0..4].copy_from_slice(b"SNTL");
    blob[4] = 1;
    blob[5] = 3; // recovery
    blob[6] = 16; // params_len LE
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

    let (s, _) = call(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/v1/wrapped-keys/3")
            .header("authorization", format!("Bearer {access}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "blob_b64": blob_b64 }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    let (s, v) = call(
        &app,
        Request::builder()
            .uri("/v1/wrapped-keys/3")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let got = base64::engine::general_purpose::STANDARD
        .decode(v["blob_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(got, blob);
}

#[tokio::test]
async fn password_wrapped_key_escrow_round_trips() {
    // Wrapper D (master password, type 4) must be storable + fetchable so a second device can
    // "sign in + master password" and unwrap the vault key. The server never unwraps it.
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (access, _) = onboard(&app, &sub).await;

    // A canonical 96-byte SNTL Password blob (8 header + 16 params + 24 nonce + 48 ct).
    let mut blob = vec![0u8; 96];
    blob[0..4].copy_from_slice(b"SNTL");
    blob[4] = 1; // version
    blob[5] = 4; // wrapper_type = Password
    blob[6] = 16; // params_len LE (16-byte salt)
    let blob_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

    let (s, _) = call(
        &app,
        Request::builder()
            .method("PUT")
            .uri("/v1/wrapped-keys/4")
            .header("authorization", format!("Bearer {access}"))
            .header("content-type", "application/json")
            .body(Body::from(json!({ "blob_b64": blob_b64 }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "type-4 escrow must be accepted");

    let (s, v) = call(&app, authed_req("GET", "/v1/wrapped-keys/4", &access)).await;
    assert_eq!(s, StatusCode::OK);
    let got = base64::engine::general_purpose::STANDARD
        .decode(v["blob_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(got, blob);
}

#[tokio::test]
async fn refresh_reuse_revokes_chain() {
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (_access, refresh) = onboard(&app, &sub).await;

    // Rotate once — old token now revoked.
    let (s, v) = call(
        &app,
        post(
            "/v1/auth/refresh",
            None,
            json!({ "refresh_token": refresh }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let new_refresh = v["refresh_token"].as_str().unwrap().to_string();

    // Replaying the OLD token is reuse → 401, and it revokes the chain.
    let (s, _) = call(
        &app,
        post(
            "/v1/auth/refresh",
            None,
            json!({ "refresh_token": refresh }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // The rotated (new) token is now also dead because the chain was revoked.
    let (s, _) = call(
        &app,
        post(
            "/v1/auth/refresh",
            None,
            json!({ "refresh_token": new_refresh }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn schema_guard_finds_no_plaintext_columns() {
    let (_app, pool) = setup().await;
    let offending: Option<String> = sqlx::query_scalar(
        "SELECT string_agg(table_name || '.' || column_name, ', ')
         FROM information_schema.columns
         WHERE table_schema = 'public'
           AND column_name ~* '(password|secret|passphrase|private_key|plaintext)'
           AND column_name NOT LIKE '%\\_enc'
           AND data_type <> 'bytea'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(
        offending.is_none(),
        "plaintext-suspect columns exist: {offending:?}"
    );
}

#[tokio::test]
async fn unapproved_device_cannot_read_vault() {
    let (app, pool) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (access, _) = onboard(&app, &sub).await;

    // Forcibly revoke the device, then the access token must be forbidden on the vault.
    sqlx::query("UPDATE devices SET status = 'revoked' WHERE account_id = (SELECT id FROM accounts WHERE google_sub = $1)")
        .bind(&sub)
        .execute(&pool)
        .await
        .unwrap();

    let (s, _) = call(
        &app,
        Request::builder()
            .uri("/v1/vault")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

async fn devices(app: &Router, token: &str) -> Vec<Value> {
    let (_, v) = call(
        app,
        Request::builder()
            .uri("/v1/devices")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    v["devices"].as_array().cloned().unwrap_or_default()
}

#[tokio::test]
async fn unlock_relay_lifecycle_is_opaque() {
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    // Two devices on one account: the desktop and the phone.
    let (desktop, _) = onboard(&app, &sub).await;
    let (phone, _) = onboard(&app, &sub).await;

    // The phone device is the one that is not "current" from the desktop's view.
    let list = devices(&app, &desktop).await;
    let phone_id = list
        .iter()
        .find(|d| d["current"] == false)
        .and_then(|d| d["id"].as_str())
        .unwrap()
        .to_string();

    // Desktop creates an unlock request carrying an opaque E2E payload.
    let req_payload = base64::engine::general_purpose::STANDARD.encode(b"e2e-ciphertext-request");
    let (s, v) = call(
        &app,
        post(
            "/v1/unlock-requests",
            Some(&desktop),
            json!({ "phone_device_id": phone_id, "kind": "unlock", "request_payload_b64": req_payload }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let req_id = v["id"].as_str().unwrap().to_string();

    // Before the phone responds, the desktop sees it pending.
    let (s, v) = call(
        &app,
        Request::builder()
            .uri(format!("/v1/unlock-requests/{req_id}"))
            .header("authorization", format!("Bearer {desktop}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["state"], "pending");

    // The phone fetches the request over the same relay: it gets the opaque request payload it must
    // open, the kind, and its own device id as the designated approver.
    let (s, v) = call(
        &app,
        Request::builder()
            .uri(format!("/v1/unlock-requests/{req_id}"))
            .header("authorization", format!("Bearer {phone}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["request_payload_b64"], req_payload);
    assert_eq!(v["kind"], "unlock");
    assert_eq!(v["phone_device_id"], phone_id);

    // The phone approves with its opaque E2E response.
    let resp_payload = base64::engine::general_purpose::STANDARD.encode(b"e2e-ciphertext-share");
    let (s, _) = call(
        &app,
        post(
            &format!("/v1/unlock-requests/{req_id}/respond"),
            Some(&phone),
            json!({ "state": "approved", "response_payload_b64": resp_payload }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // The desktop now sees approved and gets the opaque response back verbatim.
    let (s, v) = call(
        &app,
        Request::builder()
            .uri(format!("/v1/unlock-requests/{req_id}"))
            .header("authorization", format!("Bearer {desktop}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["state"], "approved");
    assert_eq!(v["response_payload_b64"], resp_payload);
}

#[tokio::test]
async fn phone_pins_key_and_desktop_reads_it() {
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (desktop, _) = onboard(&app, &sub).await;
    let (phone, _) = onboard_with(&app, &sub, "iPhone", "ios").await;

    // A valid 65-byte SEC1 uncompressed point (0x04 tag). Its content is opaque to the server.
    let mut point = vec![0u8; 65];
    point[0] = 0x04;
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&point);

    // A malformed key (wrong length) is rejected before it ever hits the DB.
    let short = base64::engine::general_purpose::STANDARD.encode([0x04u8; 10]);
    let (s, _) = call(
        &app,
        post(
            "/v1/devices/pin",
            Some(&phone),
            json!({ "phone_pub_b64": short }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // A desktop (non-iOS) device cannot pin a phone key — only iOS companions may.
    let (s, _) = call(
        &app,
        post(
            "/v1/devices/pin",
            Some(&desktop),
            json!({ "phone_pub_b64": pub_b64 }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // The iOS device pins its own key → 204.
    let (s, _) = call(
        &app,
        post(
            "/v1/devices/pin",
            Some(&phone),
            json!({ "phone_pub_b64": pub_b64 }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // The desktop reads the account's devices and sees the phone's pinned key; its own row has none.
    let list = devices(&app, &desktop).await;
    let phone_row = list.iter().find(|d| d["platform"] == "ios").unwrap();
    assert_eq!(phone_row["phone_pub_b64"], pub_b64);
    let desktop_row = list.iter().find(|d| d["current"] == true).unwrap();
    assert!(desktop_row["phone_pub_b64"].is_null());
}

// --- file transfer --------------------------------------------------------

/// The device id the given token authenticates as (its own row is `current` in the device list).
async fn own_device_id(app: &Router, token: &str) -> String {
    devices(app, token)
        .await
        .iter()
        .find(|d| d["current"] == true)
        .and_then(|d| d["id"].as_str())
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn file_transfer_lifecycle_own_devices() {
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (sender, _) = onboard(&app, &sub).await;
    let (recipient, _) = onboard(&app, &sub).await;

    // Sender uploads an opaque blob for any of the account's devices to claim (broadcast).
    let blob = base64::engine::general_purpose::STANDARD.encode(b"opaque-file-ciphertext");
    let (s, v) = call(
        &app,
        post(
            "/v1/transfers",
            Some(&sender),
            json!({ "recipient_device_id": null, "size_bytes": 12, "ciphertext_b64": blob }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_string();

    // The recipient sees it as incoming and downloads the exact bytes back.
    let (s, v) = call(&app, authed_req("GET", "/v1/transfers", &recipient)).await;
    assert_eq!(s, StatusCode::OK);
    let inbox = v["transfers"].as_array().unwrap();
    assert!(
        inbox
            .iter()
            .any(|t| t["id"] == id.as_str() && t["outgoing"] == false),
        "recipient inbox: {v}"
    );
    let (s, v) = call(
        &app,
        authed_req("GET", &format!("/v1/transfers/{id}"), &recipient),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["ciphertext_b64"], blob);

    // The sender now sees it delivered on its outgoing side.
    let (_s, v) = call(&app, authed_req("GET", "/v1/transfers", &sender)).await;
    let mine = v["transfers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == id.as_str())
        .unwrap()
        .clone();
    assert_eq!(mine["state"], "delivered");
    assert_eq!(mine["outgoing"], true);

    // A different account can neither see nor download it.
    let other_sub = format!("user-{}", uuid::Uuid::new_v4());
    let (other, _) = onboard(&app, &other_sub).await;
    let (s, _) = call(
        &app,
        authed_req("GET", &format!("/v1/transfers/{id}"), &other),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The sender deletes it, and it's gone for everyone.
    let (s, _) = call(
        &app,
        authed_req("DELETE", &format!("/v1/transfers/{id}"), &sender),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        &app,
        authed_req("GET", &format!("/v1/transfers/{id}"), &recipient),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn file_transfer_targeting_and_validation() {
    let (app, _) = setup().await;
    let sub = format!("user-{}", uuid::Uuid::new_v4());
    let (sender, _) = onboard(&app, &sub).await;
    let (target, _) = onboard(&app, &sub).await;
    let (bystander, _) = onboard(&app, &sub).await;
    let target_id = own_device_id(&app, &target).await;

    let blob = base64::engine::general_purpose::STANDARD.encode(b"for-one-device-only");
    let (s, v) = call(
        &app,
        post(
            "/v1/transfers",
            Some(&sender),
            json!({ "recipient_device_id": target_id, "size_bytes": 5, "ciphertext_b64": blob }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_string();

    // The named target sees and can download it.
    let (s, _) = call(
        &app,
        authed_req("GET", &format!("/v1/transfers/{id}"), &target),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // A same-account device that is NOT the target neither lists nor may download it.
    let (_s, v) = call(&app, authed_req("GET", "/v1/transfers", &bystander)).await;
    assert!(
        !v["transfers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["id"] == id.as_str()),
        "bystander must not see a targeted transfer: {v}"
    );
    let (s, _) = call(
        &app,
        authed_req("GET", &format!("/v1/transfers/{id}"), &bystander),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Empty ciphertext is rejected.
    let (s, _) = call(
        &app,
        post(
            "/v1/transfers",
            Some(&sender),
            json!({ "recipient_device_id": null, "size_bytes": 0, "ciphertext_b64": "" }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // An unknown recipient device is rejected.
    let (s, _) = call(
        &app,
        post(
            "/v1/transfers",
            Some(&sender),
            json!({ "recipient_device_id": uuid::Uuid::new_v4(), "size_bytes": 5, "ciphertext_b64": blob }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

// --- attack monitor -------------------------------------------------------

#[tokio::test]
async fn security_events_recorded_and_listed() {
    let (app, _pool) = setup_with(Some("watch-bootstrap")).await;

    // A wrong bootstrap token must be recorded as a failure event…
    let (s, _v) = call(
        &app,
        post(
            "/v1/auth/bootstrap",
            None,
            json!({ "token": "wrong", "device": { "name": "D", "platform": "linux" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // …and a correct one signs in (recorded as login_ok).
    let (s, v) = call(
        &app,
        post(
            "/v1/auth/bootstrap",
            None,
            json!({ "token": "watch-bootstrap", "device": { "name": "D", "platform": "linux" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "bootstrap: {v}");
    let access = v["access_token"].as_str().unwrap().to_string();

    // The authed device can read the security event log.
    let (s, v) = call(
        &app,
        Request::builder()
            .uri("/v1/security-events")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "events: {v}");
    let kinds: Vec<&str> = v["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"login_fail_bootstrap"), "kinds: {kinds:?}");
    assert!(kinds.contains(&"login_ok"), "kinds: {kinds:?}");

    // The summary endpoint aggregates and reports auto-ban off by default.
    let (s, v) = call(
        &app,
        Request::builder()
            .uri("/v1/security-summary")
            .header("authorization", format!("Bearer {access}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "summary: {v}");
    assert_eq!(v["autobanEnabled"], false);
    assert!(v["last24h"]["login_fail_bootstrap"].as_i64().unwrap() >= 1);
}

#[tokio::test]
async fn manual_ban_endpoint_and_unban() {
    let (app, pool) = setup_with(Some("ban-bootstrap")).await;
    let (_s, v) = call(
        &app,
        post(
            "/v1/auth/bootstrap",
            None,
            json!({ "token": "ban-bootstrap", "device": { "name": "D", "platform": "linux" } }),
        ),
    )
    .await;
    let access = v["access_token"].as_str().unwrap().to_string();

    // Use a distinctive IP so parallel tests don't collide.
    let ip = "203.0.113.77";
    sentinel_api::security::unban(&pool, ip).await.unwrap(); // clean slate

    let (s, _v) = call(
        &app,
        post(
            "/v1/security-events/ban",
            Some(&access),
            json!({ "ip": ip, "minutes": 60 }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(sentinel_api::security::is_banned(&pool, ip).await);

    let (s, _v) = call(
        &app,
        post(
            "/v1/security-events/unban",
            Some(&access),
            json!({ "ip": ip }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(!sentinel_api::security::is_banned(&pool, ip).await);
}

#[tokio::test]
async fn permanent_and_expired_bans_behave() {
    let (_app, pool) = setup_with(None).await;
    let ip = "203.0.113.88";
    sentinel_api::security::unban(&pool, ip).await.unwrap();

    // Permanent (no minutes) → banned.
    sentinel_api::security::ban(&pool, ip, None).await.unwrap();
    assert!(sentinel_api::security::is_banned(&pool, ip).await);

    // An already-expired ban (0 minutes falls back to permanent per ban(), so set via SQL).
    sqlx::query("UPDATE banned_ips SET until = now() - interval '1 minute' WHERE ip = $1::inet")
        .bind(ip)
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        !sentinel_api::security::is_banned(&pool, ip).await,
        "expired ban must not block"
    );

    sentinel_api::security::unban(&pool, ip).await.unwrap();
}

/// Auto-ban only triggers once failures reach the threshold, and the owner-lockout guard keeps a
/// recently-successful IP from being banned. Driven directly (the in-process HTTP harness has no
/// peer IP, so `client_ip` is `"local"` and never auto-bans).
#[tokio::test]
async fn auto_ban_threshold_and_owner_guard() {
    use sentinel_api::security;
    let (_app, pool) = setup_full(None, 3).await;

    // An AppState mirroring `build_app`, but with auto-ban threshold 3 so we can exercise it.
    let config = Config {
        bind: "127.0.0.1:0".into(),
        database_url: database_url(),
        google_client_id: None,
        bootstrap_token: None,
        totp_enc_key: [7u8; 32],
        production: false,
        trust_forwarded_for: false,
        cors_allowed_origins: Vec::new(),
        autoban_threshold: 3,
        autoban_window_secs: 300,
        autoban_minutes: 60,
    };
    let google: Arc<dyn GoogleVerifier> = Arc::new(MockGoogleVerifier);
    let st = sentinel_api::state::AppState {
        pool: pool.clone(),
        keys: JwtKeys::ephemeral(),
        config,
        google,
        limiter: sentinel_api::ratelimit::RateLimiter::new(),
    };

    let ip = "203.0.113.99";
    security::unban(&pool, ip).await.unwrap(); // clean slate

    // Two failures is below the threshold ⇒ no ban.
    for _ in 0..2 {
        security::record(&pool, None, "totp_fail", ip, None).await;
    }
    security::maybe_autoban(&st, ip).await;
    assert!(!security::is_banned(&pool, ip).await, "below threshold");

    // The third failure reaches the threshold ⇒ auto-ban.
    security::record(&pool, None, "totp_fail", ip, None).await;
    security::maybe_autoban(&st, ip).await;
    assert!(security::is_banned(&pool, ip).await, "threshold reached");

    // Owner guard: a recent successful sign-in from the same IP prevents a ban even past threshold.
    security::unban(&pool, ip).await.unwrap();
    security::record(&pool, None, "login_ok", ip, None).await;
    for _ in 0..5 {
        security::record(&pool, None, "totp_fail", ip, None).await;
    }
    security::maybe_autoban(&st, ip).await;
    assert!(
        !security::is_banned(&pool, ip).await,
        "owner guard must protect a recently-successful IP"
    );

    security::unban(&pool, ip).await.unwrap();
}
