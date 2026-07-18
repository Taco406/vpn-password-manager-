//! Shared application state and the JWT extractor.

use crate::auth::{verify_access, verify_pending, AccessClaims, GoogleVerifier};
use crate::config::{Config, JwtKeys};
use crate::error::ApiError;
use crate::ratelimit::RateLimiter;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub keys: JwtKeys,
    pub config: Config,
    pub google: Arc<dyn GoogleVerifier>,
    pub limiter: RateLimiter,
}

/// An authenticated caller (valid access JWT). Extractable in handlers.
pub struct Auth {
    pub account: Uuid,
    pub device: Uuid,
}

fn bearer(parts: &Parts) -> Result<&str, ApiError> {
    parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let claims: AccessClaims = verify_access(&state.keys, bearer(parts)?)?;
        Ok(Auth {
            account: claims.sub.parse().map_err(|_| ApiError::Unauthorized)?,
            device: claims.dev.parse().map_err(|_| ApiError::Unauthorized)?,
        })
    }
}

/// A caller holding a 5-minute pending token (post-Google, pre-TOTP-confirmation).
pub struct PendingAuth {
    pub account: Uuid,
    pub device: Uuid,
}

impl FromRequestParts<AppState> for PendingAuth {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let claims: AccessClaims = verify_pending(&state.keys, bearer(parts)?)?;
        Ok(PendingAuth {
            account: claims.sub.parse().map_err(|_| ApiError::Unauthorized)?,
            device: claims.dev.parse().map_err(|_| ApiError::Unauthorized)?,
        })
    }
}
