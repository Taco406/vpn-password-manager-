//! API error type with a safe, structured JSON body. Never leaks secret material or
//! internal detail (SECURITY.md T8) — DB errors are logged, not returned verbatim.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("version conflict")]
    VersionConflict { current: i64 },
    #[error("too many requests")]
    RateLimited,
    #[error("locked out")]
    LockedOut,
    #[error("internal error")]
    Internal,
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, serde_json::Value) {
        match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized", json!({})),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "forbidden", json!({})),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found", json!({})),
            ApiError::BadRequest(m) => (
                StatusCode::BAD_REQUEST,
                "bad_request",
                json!({ "detail": m }),
            ),
            ApiError::VersionConflict { current } => (
                StatusCode::CONFLICT,
                "version_conflict",
                json!({ "current": current }),
            ),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", json!({})),
            ApiError::LockedOut => (StatusCode::TOO_MANY_REQUESTS, "locked_out", json!({})),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal", json!({})),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, extra) = self.parts();
        let mut body = json!({ "error": code });
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                body[k] = v.clone();
            }
        }
        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        match e {
            sqlx::Error::RowNotFound => ApiError::NotFound,
            other => {
                tracing::error!(error = %other, "database error");
                ApiError::Internal
            }
        }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
