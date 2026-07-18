//! HTTP routes. Handlers are thin; all crypto lives in `sentinel-core` or `auth`.

use crate::auth;
use crate::error::{ApiError, ApiResult};
use crate::state::{AppState, Auth, PendingAuth};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use rand::RngCore;
use sentinel_core::crypto::{self, Key32, Nonce24};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/google", post(auth_google))
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
    Json(req): Json<GoogleReq>,
) -> ApiResult<Json<PendingResp>> {
    rate_limit(&st, &headers, "auth_google", 10, 60)?;
    if req.device.name.len() > 64 || !valid_platform(&req.device.platform) {
        return Err(ApiError::BadRequest("invalid device".into()));
    }
    let claims = st.google.verify(&req.id_token).await?;

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
    p: PendingAuth,
    Json(req): Json<TotpVerifyReq>,
) -> ApiResult<Json<TokensResp>> {
    rate_limit(&st, &headers, &format!("totp:{}", p.account), 10, 60)?;

    // Enforce lockout.
    let locked: Option<time::OffsetDateTime> =
        sqlx::query_scalar("SELECT locked_until FROM totp_lockouts WHERE account_id = $1")
            .bind(p.account)
            .fetch_optional(&st.pool)
            .await?
            .flatten();
    if let Some(until) = locked {
        if until > time::OffsetDateTime::now_utc() {
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
    Json(req): Json<RefreshReq>,
) -> ApiResult<Json<TokensResp>> {
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

// --- helpers --------------------------------------------------------------

fn rate_limit(
    st: &AppState,
    headers: &HeaderMap,
    action: &str,
    max: usize,
    secs: u64,
) -> ApiResult<()> {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("local");
    let key = format!("{action}:{ip}");
    if st.limiter.check(&key, max, Duration::from_secs(secs)) {
        Ok(())
    } else {
        Err(ApiError::RateLimited)
    }
}
