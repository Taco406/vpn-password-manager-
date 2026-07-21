//! HTTP routes. Handlers are thin; all crypto lives in `sentinel-core` or `auth`.

use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::security;
use crate::state::{AppState, Auth, PendingAuth};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use rand::RngCore;
use sentinel_core::crypto::{self, Key32, Nonce24};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;
use uuid::Uuid;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/google", post(auth_google))
        .route("/v1/auth/bootstrap", post(auth_bootstrap))
        .route("/v1/auth/totp/enroll", post(totp_enroll))
        .route("/v1/auth/totp/verify", post(totp_verify))
        .route("/v1/auth/refresh", post(auth_refresh))
        .route("/v1/auth/logout", post(auth_logout))
        .route("/v1/vault", get(vault_get).put(vault_put))
        .route(
            "/v1/wrapped-keys/{wrapper_type}",
            get(wrapped_get).put(wrapped_put).delete(wrapped_delete),
        )
        .route("/v1/devices", get(devices_list))
        .route("/v1/devices/{id}/approve", post(device_approve))
        .route("/v1/devices/{id}", axum::routing::delete(device_revoke))
        .route("/v1/unlock-requests", post(unlock_create))
        .route("/v1/unlock-requests/{id}", get(unlock_get))
        .route("/v1/unlock-requests/{id}/respond", post(unlock_respond))
        .route("/v1/push/register", post(push_register))
        .route("/v1/security-events", get(security_events_list))
        .route("/v1/security-summary", get(security_summary))
        .route("/v1/security-events/ban", post(security_ban))
        .route("/v1/security-events/unban", post(security_unban))
        .with_state(state)
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

async fn healthz(State(st): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    sqlx::query("SELECT 1").execute(&st.pool).await?;
    Ok(Json(json!({ "status": "ok" })))
}

// --- auth: google ---------------------------------------------------------

#[derive(Deserialize)]
struct GoogleReq {
    id_token: String,
    device: DeviceReq,
}
#[derive(Deserialize)]
struct DeviceReq {
    name: String,
    platform: String,
}

#[derive(Serialize)]
struct PendingResp {
    pending_token: String,
    totp_required: bool,
}

async fn auth_google(
    State(st): State<AppState>,
    headers: HeaderMap,
    peer: PeerAddr,
    Json(req): Json<GoogleReq>,
) -> ApiResult<Json<PendingResp>> {
    let ip = guard(&st, &headers, peer.0, "auth_google", 10, 60).await?;
    if req.device.name.len() > 64 || !valid_platform(&req.device.platform) {
        return Err(ApiError::BadRequest("invalid device".into()));
    }
    let claims = match st.google.verify(&req.id_token).await {
        Ok(c) => c,
        Err(e) => {
            security::record(&st.pool, None, "google_reject", &ip, None).await;
            security::maybe_autoban(&st, &ip).await;
            return Err(e);
        }
    };

    // Upsert account by google_sub.
    let account: Uuid = sqlx::query_scalar(
        "INSERT INTO accounts (google_sub, email) VALUES ($1, $2)
         ON CONFLICT (google_sub) DO UPDATE SET email = EXCLUDED.email
         RETURNING id",
    )
    .bind(&claims.sub)
    .bind(&claims.email)
    .fetch_one(&st.pool)
    .await?;

    // Register (or reuse) this device. New devices start pending.
    let device: Uuid = sqlx::query_scalar(
        "INSERT INTO devices (account_id, name, platform, status)
         VALUES ($1, $2, $3, 'pending') RETURNING id",
    )
    .bind(account)
    .bind(&req.device.name)
    .bind(&req.device.platform)
    .fetch_one(&st.pool)
    .await?;

    let totp_confirmed: Option<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT totp_confirmed_at FROM accounts WHERE id = $1")
            .bind(account)
            .fetch_one(&st.pool)
            .await?;

    let pending_token = auth::issue_pending(&st.keys, account, device, now())?;
    Ok(Json(PendingResp {
        pending_token,
        totp_required: totp_confirmed.is_none(),
    }))
}

fn valid_platform(p: &str) -> bool {
    matches!(p, "windows" | "macos" | "linux" | "ios")
}

// --- auth: bootstrap (personal, no Google) --------------------------------
// A one-click self-hosted deploy sets SENTINEL_BOOTSTRAP_TOKEN. A device presenting that shared
// secret is trusted as THE single personal account and is issued a real session directly — no
// Google OAuth client id required. Inert (401) unless the token is configured.

#[derive(Deserialize)]
struct BootstrapReq {
    token: String,
    device: DeviceReq,
}

async fn auth_bootstrap(
    State(st): State<AppState>,
    headers: HeaderMap,
    peer: PeerAddr,
    Json(req): Json<BootstrapReq>,
) -> ApiResult<Json<TokensResp>> {
    let ip = guard(&st, &headers, peer.0, "auth_bootstrap", 10, 60).await?;
    let expected = st
        .config
        .bootstrap_token
        .as_deref()
        .ok_or(ApiError::Unauthorized)?;
    if !auth::constant_time_eq(req.token.as_bytes(), expected.as_bytes()) {
        security::record(&st.pool, None, "login_fail_bootstrap", &ip, None).await;
        security::maybe_autoban(&st, &ip).await;
        return Err(ApiError::Unauthorized);
    }
    if req.device.name.len() > 64 || !valid_platform(&req.device.platform) {
        return Err(ApiError::BadRequest("invalid device".into()));
    }
    // The single personal account, keyed on a synthetic sub (never collides with a Google sub).
    let account: Uuid = sqlx::query_scalar(
        "INSERT INTO accounts (google_sub, email) VALUES ($1, $2)
         ON CONFLICT (google_sub) DO UPDATE SET email = EXCLUDED.email
         RETURNING id",
    )
    .bind("bootstrap:local")
    .bind("personal@sentinel.local")
    .fetch_one(&st.pool)
    .await?;
    // Bootstrap trust == device trust: register this device as already approved so the sync
    // endpoints (which require an approved device) work immediately, without a TOTP step.
    let device: Uuid = sqlx::query_scalar(
        "INSERT INTO devices (account_id, name, platform, status)
         VALUES ($1, $2, $3, 'approved') RETURNING id",
    )
    .bind(account)
    .bind(&req.device.name)
    .bind(&req.device.platform)
    .fetch_one(&st.pool)
    .await?;
    let tokens = mint_session(&st, account, device, None).await?;
    security::record(&st.pool, Some(account), "login_ok", &ip, Some("bootstrap")).await;
    Ok(Json(tokens))
}

// --- auth: totp -----------------------------------------------------------

fn totp_enc_key(st: &AppState) -> Key32 {
    Key32::from_bytes(st.config.totp_enc_key)
}

fn seal_secret(st: &AppState, secret: &[u8]) -> Vec<u8> {
    let (nonce, ct) = crypto::seal(&totp_enc_key(st), b"totp", secret);
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(nonce.as_bytes());
    out.extend_from_slice(&ct);
    out
}

fn open_secret(st: &AppState, blob: &[u8]) -> ApiResult<Vec<u8>> {
    if blob.len() < 24 {
        return Err(ApiError::Internal);
    }
    let mut nb = [0u8; 24];
    nb.copy_from_slice(&blob[..24]);
    let pt = crypto::open(
        &totp_enc_key(st),
        b"totp",
        &Nonce24::from_bytes(nb),
        &blob[24..],
    )
    .map_err(|_| ApiError::Internal)?;
    Ok(pt.as_slice().to_vec())
}

#[derive(Serialize)]
struct EnrollResp {
    otpauth_uri: String,
    secret_base32: String,
}

async fn totp_enroll(State(st): State<AppState>, p: PendingAuth) -> ApiResult<Json<EnrollResp>> {
    // Generate a 20-byte secret, store it encrypted (pre-confirmation).
    let mut secret = [0u8; 20];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let enc = seal_secret(&st, &secret);
    let email: String = sqlx::query_scalar("SELECT email FROM accounts WHERE id = $1")
        .bind(p.account)
        .fetch_one(&st.pool)
        .await?;
    sqlx::query("UPDATE accounts SET totp_secret_enc = $1 WHERE id = $2")
        .bind(&enc)
        .bind(p.account)
        .execute(&st.pool)
        .await?;
    let b32 = base32(&secret);
    Ok(Json(EnrollResp {
        otpauth_uri: auth::otpauth_uri(&secret, &email, "SENTINEL"),
        secret_base32: b32,
    }))
}

fn base32(data: &[u8]) -> String {
    // Mirror of auth::base32_encode for display; kept local to avoid exposing it.
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buf, mut bits, mut out) = (0u32, 0u32, String::new());
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((buf >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[derive(Deserialize)]
struct TotpVerifyReq {
    code: String,
}
#[derive(Serialize)]
struct TokensResp {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

async fn totp_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    peer: PeerAddr,
    p: PendingAuth,
    Json(req): Json<TotpVerifyReq>,
) -> ApiResult<Json<TokensResp>> {
    let ip = guard(
        &st,
        &headers,
        peer.0,
        &format!("totp:{}", p.account),
        10,
        60,
    )
    .await?;

    // Enforce lockout.
    let locked: Option<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT locked_until FROM totp_lockouts WHERE account_id = $1")
            .bind(p.account)
            .fetch_optional(&st.pool)
            .await?
            .flatten();
    if let Some(until) = locked {
        if until > time::OffsetDateTime::now_utc() {
            security::record(&st.pool, Some(p.account), "totp_lockout", &ip, None).await;
            return Err(ApiError::LockedOut);
        }
    }

    let enc: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT totp_secret_enc FROM accounts WHERE id = $1")
            .bind(p.account)
            .fetch_one(&st.pool)
            .await?;
    let enc = enc.ok_or(ApiError::BadRequest("totp not enrolled".into()))?;
    let secret = open_secret(&st, &enc)?;

    if !auth::totp_verify(&secret, &req.code, now()) {
        // Bump failure count; lock after 5.
        sqlx::query(
            "INSERT INTO totp_lockouts (account_id, failed_count, locked_until)
             VALUES ($1, 1, NULL)
             ON CONFLICT (account_id) DO UPDATE SET
                failed_count = totp_lockouts.failed_count + 1,
                locked_until = CASE WHEN totp_lockouts.failed_count + 1 >= 5
                    THEN now() + interval '15 minutes' ELSE NULL END",
        )
        .bind(p.account)
        .execute(&st.pool)
        .await?;
        security::record(&st.pool, Some(p.account), "totp_fail", &ip, None).await;
        security::maybe_autoban(&st, &ip).await;
        return Err(ApiError::Unauthorized);
    }

    // Success: confirm TOTP, approve the device, clear lockout, mint tokens.
    sqlx::query(
        "UPDATE accounts SET totp_confirmed_at = COALESCE(totp_confirmed_at, now()) WHERE id = $1",
    )
    .bind(p.account)
    .execute(&st.pool)
    .await?;
    sqlx::query("UPDATE devices SET status = 'approved' WHERE id = $1")
        .bind(p.device)
        .execute(&st.pool)
        .await?;
    sqlx::query("DELETE FROM totp_lockouts WHERE account_id = $1")
        .bind(p.account)
        .execute(&st.pool)
        .await?;

    let tokens = mint_session(&st, p.account, p.device, None).await?;
    security::record(&st.pool, Some(p.account), "login_ok", &ip, Some("totp")).await;
    Ok(Json(tokens))
}

async fn mint_session(
    st: &AppState,
    account: Uuid,
    device: Uuid,
    parent: Option<Uuid>,
) -> ApiResult<TokensResp> {
    let access = auth::issue_access(&st.keys, account, device, now())?;
    let refresh = auth::mint_refresh();
    let expires = time::OffsetDateTime::now_utc() + time::Duration::days(30);
    sqlx::query(
        "INSERT INTO refresh_tokens (account_id, device_id, token_hash, parent_id, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(account)
    .bind(device)
    .bind(&refresh.hash)
    .bind(parent)
    .bind(expires)
    .execute(&st.pool)
    .await?;
    Ok(TokensResp {
        access_token: access,
        refresh_token: refresh.token,
        expires_in: 600,
    })
}

// --- auth: refresh / logout ----------------------------------------------

#[derive(Deserialize)]
struct RefreshReq {
    refresh_token: String,
}

async fn auth_refresh(
    State(st): State<AppState>,
    headers: HeaderMap,
    peer: PeerAddr,
    Json(req): Json<RefreshReq>,
) -> ApiResult<Json<TokensResp>> {
    let ip = guard(&st, &headers, peer.0, "auth_refresh", 30, 60).await?;
    let hash = auth::hash_refresh(&req.refresh_token);
    let row: Option<(
        Uuid,
        Uuid,
        Uuid,
        Option<time::OffsetDateTime>,
        time::OffsetDateTime,
    )> = sqlx::query_as(
        "SELECT id, account_id, device_id, revoked_at, expires_at
             FROM refresh_tokens WHERE token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(&st.pool)
    .await?;
    let (id, account, device, revoked, expires) = row.ok_or(ApiError::Unauthorized)?;

    // Reuse detection: a revoked token being replayed means the chain is compromised.
    if revoked.is_some() {
        sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() WHERE account_id = $1 AND device_id = $2",
        )
        .bind(account)
        .bind(device)
        .execute(&st.pool)
        .await?;
        security::record(&st.pool, Some(account), "refresh_reuse", &ip, None).await;
        security::maybe_autoban(&st, &ip).await;
        return Err(ApiError::Unauthorized);
    }
    if expires < time::OffsetDateTime::now_utc() {
        return Err(ApiError::Unauthorized);
    }

    // Rotate: revoke this token, mint a child.
    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1")
        .bind(id)
        .execute(&st.pool)
        .await?;
    let tokens = mint_session(&st, account, device, Some(id)).await?;
    Ok(Json(tokens))
}

async fn auth_logout(State(st): State<AppState>, a: Auth) -> ApiResult<StatusCode> {
    sqlx::query("UPDATE refresh_tokens SET revoked_at = now() WHERE account_id = $1 AND device_id = $2 AND revoked_at IS NULL")
        .bind(a.account)
        .bind(a.device)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- vault ----------------------------------------------------------------

async fn require_approved_device(st: &AppState, device: Uuid) -> ApiResult<()> {
    let status: String = sqlx::query_scalar("SELECT status FROM devices WHERE id = $1")
        .bind(device)
        .fetch_optional(&st.pool)
        .await?
        .ok_or(ApiError::Unauthorized)?;
    if status != "approved" {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn vault_get(State(st): State<AppState>, a: Auth) -> ApiResult<axum::response::Response> {
    require_approved_device(&st, a.device).await?;
    let row: Option<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, ciphertext FROM vaults WHERE account_id = $1")
            .bind(a.account)
            .fetch_optional(&st.pool)
            .await?;
    use axum::response::IntoResponse;
    match row {
        None => Ok(StatusCode::NO_CONTENT.into_response()),
        Some((version, ct)) => Ok(Json(json!({
            "version": version,
            "ciphertext_b64": base64::engine::general_purpose::STANDARD.encode(ct),
        }))
        .into_response()),
    }
}

#[derive(Deserialize)]
struct VaultPutReq {
    ciphertext_b64: String,
}

async fn vault_put(
    State(st): State<AppState>,
    a: Auth,
    headers: HeaderMap,
    Json(req): Json<VaultPutReq>,
) -> ApiResult<Json<serde_json::Value>> {
    require_approved_device(&st, a.device).await?;
    let if_match: i64 = headers
        .get("If-Match")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim_matches('"').parse().ok())
        .ok_or(ApiError::BadRequest("If-Match header required".into()))?;
    let ct = base64::engine::general_purpose::STANDARD
        .decode(req.ciphertext_b64.as_bytes())
        .map_err(|_| ApiError::BadRequest("ciphertext_b64 not base64".into()))?;
    if ct.len() < 32 || ct.len() > 33_554_432 {
        return Err(ApiError::BadRequest("ciphertext size out of range".into()));
    }

    let current: Option<i64> =
        sqlx::query_scalar("SELECT version FROM vaults WHERE account_id = $1")
            .bind(a.account)
            .fetch_optional(&st.pool)
            .await?;

    match current {
        None => {
            if if_match != 0 {
                return Err(ApiError::VersionConflict { current: 0 });
            }
            sqlx::query(
                "INSERT INTO vaults (account_id, version, ciphertext, updated_by)
                 VALUES ($1, 1, $2, $3)",
            )
            .bind(a.account)
            .bind(&ct)
            .bind(a.device)
            .execute(&st.pool)
            .await?;
            Ok(Json(json!({ "version": 1 })))
        }
        Some(v) => {
            if if_match != v {
                return Err(ApiError::VersionConflict { current: v });
            }
            // The BEFORE UPDATE trigger backstops the +1 rule.
            sqlx::query(
                "UPDATE vaults SET version = version + 1, ciphertext = $1, updated_by = $2, updated_at = now()
                 WHERE account_id = $3",
            )
            .bind(&ct)
            .bind(a.device)
            .bind(a.account)
            .execute(&st.pool)
            .await?;
            Ok(Json(json!({ "version": v + 1 })))
        }
    }
}

// --- wrapped keys ---------------------------------------------------------

#[derive(Deserialize)]
struct WrappedPutReq {
    blob_b64: String,
    device_id: Option<Uuid>,
}

async fn wrapped_get(
    State(st): State<AppState>,
    a: Auth,
    Path(wt): Path<i16>,
) -> ApiResult<Json<serde_json::Value>> {
    require_approved_device(&st, a.device).await?;
    let blob: Vec<u8> = sqlx::query_scalar(
        "SELECT blob FROM wrapped_keys WHERE account_id = $1 AND wrapper_type = $2 LIMIT 1",
    )
    .bind(a.account)
    .bind(wt)
    .fetch_optional(&st.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    Ok(Json(json!({
        "wrapper_type": wt,
        "blob_b64": base64::engine::general_purpose::STANDARD.encode(blob),
    })))
}

async fn wrapped_put(
    State(st): State<AppState>,
    a: Auth,
    Path(wt): Path<i16>,
    Json(req): Json<WrappedPutReq>,
) -> ApiResult<StatusCode> {
    require_approved_device(&st, a.device).await?;
    if !(1..=3).contains(&wt) {
        return Err(ApiError::BadRequest("wrapper_type must be 1..3".into()));
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(req.blob_b64.as_bytes())
        .map_err(|_| ApiError::BadRequest("blob_b64 not base64".into()))?;
    // Validate the SNTL envelope shape (magic + length) without unwrapping.
    if blob.len() < 80 || blob.len() > 512 || &blob[0..4] != b"SNTL" {
        return Err(ApiError::BadRequest("invalid wrapped-key blob".into()));
    }
    sqlx::query(
        "INSERT INTO wrapped_keys (account_id, wrapper_type, device_id, blob)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (account_id, wrapper_type, device_key)
         DO UPDATE SET blob = EXCLUDED.blob, created_at = now()",
    )
    .bind(a.account)
    .bind(wt)
    .bind(req.device_id)
    .bind(&blob)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn wrapped_delete(
    State(st): State<AppState>,
    a: Auth,
    Path(wt): Path<i16>,
) -> ApiResult<StatusCode> {
    require_approved_device(&st, a.device).await?;
    sqlx::query("DELETE FROM wrapped_keys WHERE account_id = $1 AND wrapper_type = $2")
        .bind(a.account)
        .bind(wt)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- devices --------------------------------------------------------------

async fn devices_list(State(st): State<AppState>, a: Auth) -> ApiResult<Json<serde_json::Value>> {
    let rows: Vec<(Uuid, String, String, String, time::OffsetDateTime)> = sqlx::query_as(
        "SELECT id, name, platform, status, created_at FROM devices WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(a.account)
    .fetch_all(&st.pool)
    .await?;
    let devices: Vec<_> = rows
        .into_iter()
        .map(|(id, name, platform, status, created)| {
            json!({
                "id": id, "name": name, "platform": platform, "status": status,
                "created_at": created.unix_timestamp(), "current": id == a.device,
            })
        })
        .collect();
    Ok(Json(json!({ "devices": devices })))
}

async fn device_approve(
    State(st): State<AppState>,
    a: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    require_approved_device(&st, a.device).await?;
    let n = sqlx::query(
        "UPDATE devices SET status = 'approved', approved_by = $1 WHERE id = $2 AND account_id = $3",
    )
    .bind(a.device)
    .bind(id)
    .bind(a.account)
    .execute(&st.pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn device_revoke(
    State(st): State<AppState>,
    a: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<StatusCode> {
    require_approved_device(&st, a.device).await?;
    sqlx::query("UPDATE devices SET status = 'revoked' WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(a.account)
        .execute(&st.pool)
        .await?;
    sqlx::query(
        "UPDATE refresh_tokens SET revoked_at = now() WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .execute(&st.pool)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- unlock relay (E2E-opaque) --------------------------------------------

#[derive(Deserialize)]
struct UnlockCreateReq {
    phone_device_id: Uuid,
    kind: String,
    request_payload_b64: String,
}

async fn unlock_create(
    State(st): State<AppState>,
    a: Auth,
    headers: HeaderMap,
    peer: PeerAddr,
    Json(req): Json<UnlockCreateReq>,
) -> ApiResult<Json<serde_json::Value>> {
    require_approved_device(&st, a.device).await?;
    rate_limit(
        &st,
        &headers,
        peer.0,
        &format!("unlock:{}", a.account),
        5,
        60,
    )?;
    if req.kind != "unlock" && req.kind != "new_device" {
        return Err(ApiError::BadRequest("bad kind".into()));
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(req.request_payload_b64.as_bytes())
        .map_err(|_| ApiError::BadRequest("payload not base64".into()))?;
    if payload.len() > 4096 {
        return Err(ApiError::BadRequest("payload too large".into()));
    }
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO unlock_requests (account_id, desktop_device_id, phone_device_id, kind, request_payload)
         VALUES ($1, $2, $3, $4, $5) RETURNING id",
    )
    .bind(a.account)
    .bind(a.device)
    .bind(req.phone_device_id)
    .bind(&req.kind)
    .bind(&payload)
    .fetch_one(&st.pool)
    .await?;
    // A real deployment fires an APNs push here (trait Pusher, mock default).
    Ok(Json(json!({ "id": id })))
}

async fn unlock_get(
    State(st): State<AppState>,
    a: Auth,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<serde_json::Value>> {
    // Short long-poll: check a few times for a state transition before returning.
    for _ in 0..3 {
        let row: Option<(String, Option<Vec<u8>>, time::OffsetDateTime)> = sqlx::query_as(
            "SELECT state, response_payload, expires_at FROM unlock_requests
             WHERE id = $1 AND account_id = $2",
        )
        .bind(id)
        .bind(a.account)
        .fetch_optional(&st.pool)
        .await?;
        let (mut state, resp, expires) = row.ok_or(ApiError::NotFound)?;
        if state == "pending" && expires < time::OffsetDateTime::now_utc() {
            sqlx::query("UPDATE unlock_requests SET state = 'expired' WHERE id = $1")
                .bind(id)
                .execute(&st.pool)
                .await?;
            state = "expired".into();
        }
        if state != "pending" {
            return Ok(Json(json!({
                "state": state,
                "response_payload_b64": resp.map(|b| base64::engine::general_purpose::STANDARD.encode(b)),
            })));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Ok(Json(json!({ "state": "pending" })))
}

#[derive(Deserialize)]
struct UnlockRespondReq {
    state: String,
    response_payload_b64: Option<String>,
}

async fn unlock_respond(
    State(st): State<AppState>,
    a: Auth,
    Path(id): Path<Uuid>,
    Json(req): Json<UnlockRespondReq>,
) -> ApiResult<StatusCode> {
    require_approved_device(&st, a.device).await?;
    if req.state != "approved" && req.state != "denied" {
        return Err(ApiError::BadRequest("state must be approved|denied".into()));
    }
    let resp = match &req.response_payload_b64 {
        Some(b) => Some(
            base64::engine::general_purpose::STANDARD
                .decode(b.as_bytes())
                .map_err(|_| ApiError::BadRequest("payload not base64".into()))?,
        ),
        None => None,
    };
    if let Some(r) = &resp {
        if r.len() > 4096 {
            return Err(ApiError::BadRequest("payload too large".into()));
        }
    }
    // Only the designated phone device may respond, and only while pending.
    let n = sqlx::query(
        "UPDATE unlock_requests SET state = $1, response_payload = $2
         WHERE id = $3 AND account_id = $4 AND phone_device_id = $5 AND state = 'pending'",
    )
    .bind(&req.state)
    .bind(&resp)
    .bind(id)
    .bind(a.account)
    .bind(a.device)
    .execute(&st.pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(ApiError::Forbidden);
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct PushRegisterReq {
    token: String,
}

async fn push_register(
    State(st): State<AppState>,
    a: Auth,
    Json(req): Json<PushRegisterReq>,
) -> ApiResult<StatusCode> {
    if req.token.len() > 512 {
        return Err(ApiError::BadRequest("token too long".into()));
    }
    sqlx::query("UPDATE devices SET push_token = $1 WHERE id = $2 AND account_id = $3")
        .bind(&req.token)
        .bind(a.device)
        .bind(a.account)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// --- helpers --------------------------------------------------------------

// --- attack monitor (security events + IP bans) ---------------------------

#[derive(Deserialize)]
struct EventsQuery {
    /// Only events after this unix timestamp (default 0 = all recent).
    since: Option<i64>,
    limit: Option<i64>,
}

/// One row from `security_events` as read for the API: id, kind, ip (text), detail, created_at.
type EventRow = (
    Uuid,
    String,
    Option<String>,
    Option<String>,
    time::OffsetDateTime,
);

/// Recent security events, newest first. Authed (any signed-in device on the personal account).
async fn security_events_list(
    State(st): State<AppState>,
    _a: Auth,
    Query(q): Query<EventsQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let since = q.since.unwrap_or(0);
    let rows: Vec<EventRow> = sqlx::query_as(
        "SELECT id, kind, ip::text, detail, created_at FROM security_events
             WHERE created_at > to_timestamp($1) ORDER BY created_at DESC LIMIT $2",
    )
    .bind(since as f64)
    .bind(limit)
    .fetch_all(&st.pool)
    .await?;
    let events: Vec<_> = rows
        .into_iter()
        .map(|(id, kind, ip, detail, created)| {
            json!({
                "id": id, "kind": kind, "ip": ip, "detail": detail,
                "createdAt": created.unix_timestamp(),
            })
        })
        .collect();
    Ok(Json(json!({ "events": events })))
}

/// 24h counts per event kind + the number of currently-active IP bans (for the panel headline).
async fn security_summary(
    State(st): State<AppState>,
    _a: Auth,
) -> ApiResult<Json<serde_json::Value>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT kind, count(*) FROM security_events
         WHERE created_at > now() - interval '24 hours' GROUP BY kind",
    )
    .fetch_all(&st.pool)
    .await?;
    let mut counts = serde_json::Map::new();
    for (kind, n) in rows {
        counts.insert(kind, json!(n));
    }
    let banned: i64 =
        sqlx::query_scalar("SELECT count(*) FROM banned_ips WHERE until IS NULL OR until > now()")
            .fetch_one(&st.pool)
            .await?;
    let autoban = st.config.autoban_threshold > 0;
    Ok(Json(json!({
        "last24h": counts,
        "bannedActive": banned,
        "autobanEnabled": autoban,
    })))
}

#[derive(Deserialize)]
struct BanReq {
    ip: String,
    /// Ban duration in minutes; omit for a permanent ban.
    minutes: Option<i64>,
}

async fn security_ban(
    State(st): State<AppState>,
    _a: Auth,
    Json(req): Json<BanReq>,
) -> ApiResult<StatusCode> {
    security::ban(&st.pool, &req.ip, req.minutes).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct UnbanReq {
    ip: String,
}

async fn security_unban(
    State(st): State<AppState>,
    _a: Auth,
    Json(req): Json<UnbanReq>,
) -> ApiResult<StatusCode> {
    security::unban(&st.pool, &req.ip).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// The peer socket address from the TCP connection, if the server was started with connection
/// info (`into_make_service_with_connect_info`, i.e. production). `None` under the in-process
/// test harness (`oneshot`). Infallible so it never blocks a request.
pub struct PeerAddr(pub Option<SocketAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerAddr {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(PeerAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0),
        ))
    }
}

fn rate_limit(
    st: &AppState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    action: &str,
    max: usize,
    secs: u64,
) -> ApiResult<()> {
    let key = format!("{action}:{}", client_ip(st, headers, peer));
    if st.limiter.check(&key, max, Duration::from_secs(secs)) {
        Ok(())
    } else {
        Err(ApiError::RateLimited)
    }
}

/// Attack-monitor guard for an auth endpoint: reject banned IPs, enforce the rate limit, and
/// record the outcome. Returns the caller's IP so the handler can attribute later events to it.
/// Ban check first (a banned IP never even reaches the limiter or the password compare).
async fn guard(
    st: &AppState,
    headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    action: &str,
    max: usize,
    secs: u64,
) -> ApiResult<String> {
    let ip = client_ip(st, headers, peer);
    if security::is_banned(&st.pool, &ip).await {
        security::record(&st.pool, None, "banned_block", &ip, Some(action)).await;
        return Err(ApiError::Forbidden);
    }
    if st
        .limiter
        .check(&format!("{action}:{ip}"), max, Duration::from_secs(secs))
    {
        Ok(ip)
    } else {
        security::record(&st.pool, None, "rate_limited", &ip, Some(action)).await;
        security::maybe_autoban(st, &ip).await;
        Err(ApiError::RateLimited)
    }
}

/// The client's identity for rate limiting. By default this is the real peer IP (from the TCP
/// connection), which a client cannot spoof. Only when explicitly configured to run behind a
/// trusted proxy (`SENTINEL_TRUST_FORWARDED_FOR`) do we honor the first `X-Forwarded-For` hop.
fn client_ip(st: &AppState, headers: &HeaderMap, peer: Option<std::net::SocketAddr>) -> String {
    if st.config.trust_forwarded_for {
        if let Some(fwd) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            return fwd.to_string();
        }
    }
    peer.map(|p| p.ip().to_string())
        .unwrap_or_else(|| "local".to_string())
}
