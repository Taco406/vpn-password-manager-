//! Account-unification tests: one personal server = ONE account, regardless of the order the
//! owner uses the built-in (bootstrap) login and Google sign-in. These are the regression tests
//! for the "0 passwords synced" bug, where the two auth paths silently created two accounts and
//! a second device joined the empty one.
//!
//! Runs in its own test binary because each test TRUNCATEs `accounts` to get a deterministic
//! account count — the main `integration.rs` suite runs many tests in parallel against the same
//! database, which would race with that. Cargo runs test binaries sequentially, and a static
//! mutex serializes the tests inside this one.

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

static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();

async fn migrate(pool: &PgPool) {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/migrations");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|e| e == "sql").unwrap_or(false))
        .collect();
    files.sort();
    for f in files {
        let sql = std::fs::read_to_string(&f).unwrap();
        sqlx::raw_sql(&sql).execute(pool).await.expect("migration");
    }
}

/// Fresh app + EMPTY accounts table (cascades to devices/vaults/wrapped keys/etc.).
async fn fresh() -> (Router, PgPool) {
    let pool = sentinel_api::connect(&database_url())
        .await
        .expect("db connect");
    migrate(&pool).await;
    sqlx::raw_sql("TRUNCATE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("truncate");
    let config = Config {
        bind: "127.0.0.1:0".into(),
        database_url: database_url(),
        google_client_id: None,
        bootstrap_token: Some("unify-bootstrap".into()),
        totp_enc_key: [7u8; 32],
        production: false,
        trust_forwarded_for: false,
        cors_allowed_origins: Vec::new(),
        autoban_threshold: 0,
        autoban_window_secs: 300,
        autoban_minutes: 60,
        update_flag_dir: None,
        tls_cert_pem: None,
    };
    let google: Arc<dyn GoogleVerifier> = Arc::new(MockGoogleVerifier);
    let app = sentinel_api::build_app(pool.clone(), JwtKeys::ephemeral(), config, google);
    (app, pool)
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

fn get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn bootstrap_signin(app: &Router) -> String {
    let (s, v) = call(
        app,
        post(
            "/v1/auth/bootstrap",
            None,
            json!({ "token": "unify-bootstrap", "device": { "name": "D", "platform": "linux" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "bootstrap: {v}");
    v["access_token"].as_str().unwrap().to_string()
}

/// Google onboarding (sign-in + TOTP enroll/verify) → approved-device access token.
async fn google_onboard(app: &Router, sub: &str) -> String {
    google_onboard_with_secret(app, sub).await.0
}

/// Same, but also hands back the raw TOTP secret so a test can mint later codes.
async fn google_onboard_with_secret(app: &Router, sub: &str) -> (String, Vec<u8>) {
    let (s, v) = call(
        app,
        post(
            "/v1/auth/google",
            None,
            json!({ "id_token": format!("fixture:{sub}:{sub}@example.com"),
                    "device": { "name": "G", "platform": "linux" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "google: {v}");
    let pending = v["pending_token"].as_str().unwrap().to_string();
    let (s, v) = call(app, post("/v1/auth/totp/enroll", Some(&pending), json!({}))).await;
    assert_eq!(s, StatusCode::OK, "enroll: {v}");
    let secret = base32_decode(v["secret_base32"].as_str().unwrap());
    let code =
        sentinel_api::auth::totp_code(&secret, time::OffsetDateTime::now_utc().unix_timestamp());
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
    (v["access_token"].as_str().unwrap().to_string(), secret)
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

async fn put_vault(app: &Router, token: &str, bytes: &[u8]) {
    let ct = base64::engine::general_purpose::STANDARD.encode(bytes);
    let (s, v) = call(
        app,
        Request::builder()
            .method("PUT")
            .uri("/v1/vault")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .header("If-Match", "0")
            .body(Body::from(json!({ "ciphertext_b64": ct }).to_string()))
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "put vault: {v}");
}

async fn account_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM accounts")
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn bootstrap_then_google_is_one_account() {
    let _g = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let (app, pool) = fresh().await;

    // Bootstrap first (the one-click deploy path) and push a vault.
    let boot = bootstrap_signin(&app).await;
    put_vault(&app, &boot, b"vault-ciphertext-from-bootstrap-device").await;

    // Google sign-in afterwards must RE-KEY the same account, not create a second one.
    let google = google_onboard(&app, "owner-sub-1").await;
    assert_eq!(account_count(&pool).await, 1, "must stay one account");

    let (s, v) = call(&app, get("/v1/vault", &google)).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "google must see the bootstrap vault: {v}"
    );
    assert_eq!(v["version"], 1);

    // And bootstrap still lands on the same (now Google-keyed) account.
    let boot2 = bootstrap_signin(&app).await;
    let (s, v) = call(&app, get("/v1/vault", &boot2)).await;
    assert_eq!(s, StatusCode::OK, "bootstrap must still see the vault: {v}");
    assert_eq!(account_count(&pool).await, 1);
}

#[tokio::test]
async fn google_then_bootstrap_adopts_the_single_account() {
    let _g = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let (app, pool) = fresh().await;

    // Owner signs in with Google first and pushes their vault.
    let google = google_onboard(&app, "owner-sub-2").await;
    put_vault(&app, &google, b"vault-ciphertext-from-google-device").await;

    // A joining device (join code / phone) signs in via bootstrap → must ADOPT that account.
    let boot = bootstrap_signin(&app).await;
    assert_eq!(
        account_count(&pool).await,
        1,
        "bootstrap must adopt, not fork"
    );
    let (s, v) = call(&app, get("/v1/vault", &boot)).await;
    assert_eq!(s, StatusCode::OK, "joined device must see the vault: {v}");
    assert_eq!(v["version"], 1);
}

#[tokio::test]
async fn multi_account_server_keeps_bootstrap_separate() {
    let _g = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let (app, pool) = fresh().await;

    // Two Google users → ambiguous ownership; bootstrap must NOT hijack either.
    let _a = google_onboard(&app, "family-a").await;
    let _b = google_onboard(&app, "family-b").await;
    let boot = bootstrap_signin(&app).await;
    assert_eq!(account_count(&pool).await, 3, "separate synthetic account");
    let (s, _v) = call(&app, get("/v1/vault", &boot)).await;
    assert_eq!(
        s,
        StatusCode::NO_CONTENT,
        "fresh synthetic account is empty"
    );
}

// --- master-password sign-in (THE login, v0.1.48) --------------------------
// The server never sees a password: clients send a 32-byte HKDF proof and the server stores its
// SHA-256. These tests exercise the wire contract; the KDF itself is covered by the core tests
// and the iOS golden vectors.

async fn enroll_password(app: &Router, token: &str, salt: &[u8; 16], verifier: &[u8; 32]) {
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let (s, v) = call(
        app,
        post(
            "/v1/auth/password/enroll",
            Some(token),
            json!({ "salt_b64": b64(salt), "verifier_b64": b64(verifier) }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "enroll password: {v}");
}

#[tokio::test]
async fn password_signin_full_cycle() {
    let _g = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let (app, pool) = fresh().await;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

    // Nothing enrolled yet → params 404 (client shows "enable it on your computer").
    let (s, _v) = call(
        &app,
        Request::builder()
            .uri("/v1/auth/password/params")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // The owner's first device (bootstrap here) turns password sign-in on.
    let boot = bootstrap_signin(&app).await;
    let salt = [0x5A; 16];
    let verifier = [0xC3; 32];
    enroll_password(&app, &boot, &salt, &verifier).await;

    // Params are public and echo the salt + production Argon2 cost.
    let (s, v) = call(
        &app,
        Request::builder()
            .uri("/v1/auth/password/params")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "params: {v}");
    assert_eq!(v["salt_b64"], b64(&salt));
    assert_eq!(v["m_kib"], 65536);
    assert_eq!(v["t"], 3);
    assert_eq!(v["p"], 4);

    // A brand-new device signs in with just the proof → approved session on the SAME account.
    let (s, v) = call(
        &app,
        post(
            "/v1/auth/password",
            None,
            json!({ "proof_b64": b64(&verifier),
                    "device": { "name": "Mac", "platform": "macos" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "password sign-in: {v}");
    let access = v["access_token"].as_str().unwrap().to_string();
    assert_eq!(account_count(&pool).await, 1, "no account fork");
    let (s, _v) = call(&app, get("/v1/devices", &access)).await;
    assert_eq!(s, StatusCode::OK, "session must be fully usable");

    // Wrong proof → 401 (and never a session).
    let (s, _v) = call(
        &app,
        post(
            "/v1/auth/password",
            None,
            json!({ "proof_b64": b64(&[0u8; 32]),
                    "device": { "name": "Evil", "platform": "linux" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Malformed enroll inputs are rejected.
    let (s, _v) = call(
        &app,
        post(
            "/v1/auth/password/enroll",
            Some(&boot),
            json!({ "salt_b64": b64(&[1u8; 8]), "verifier_b64": b64(&verifier) }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn password_signin_honors_the_totp_second_factor() {
    let _g = LOCK
        .get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await;
    let (app, _pool) = fresh().await;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);

    // Owner onboards via Google WITH the authenticator app, then enables password sign-in.
    let (owner, totp_secret) = google_onboard_with_secret(&app, "totp-owner").await;
    let salt = [0x11; 16];
    let verifier = [0x22; 32];
    enroll_password(&app, &owner, &salt, &verifier).await;

    // Correct password but no code → the sentinel error "totp_required".
    let (s, v) = call(
        &app,
        post(
            "/v1/auth/password",
            None,
            json!({ "proof_b64": b64(&verifier),
                    "device": { "name": "Mac", "platform": "macos" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    // Clients key off this exact string (in `detail`) to show the 6-digit field.
    assert_eq!(v["detail"], "totp_required");

    // With the current 6-digit code → session.
    let code = sentinel_api::auth::totp_code(
        &totp_secret,
        time::OffsetDateTime::now_utc().unix_timestamp(),
    );
    let (s, v) = call(
        &app,
        post(
            "/v1/auth/password",
            None,
            json!({ "proof_b64": b64(&verifier), "code": code,
                    "device": { "name": "Mac", "platform": "macos" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "password+totp sign-in: {v}");
    assert!(v["access_token"].as_str().is_some());

    // Wrong code → 401.
    let (s, _v) = call(
        &app,
        post(
            "/v1/auth/password",
            None,
            json!({ "proof_b64": b64(&verifier), "code": "000000",
                    "device": { "name": "Mac", "platform": "macos" } }),
        ),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}
