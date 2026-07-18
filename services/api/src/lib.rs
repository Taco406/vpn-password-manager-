//! sentinel-api — the optional zero-knowledge sync backend.
//!
//! Local-first (D16): the desktop app and vault work with none of this. The server
//! stores only opaque wrapped-key blobs and vault ciphertext plus account/2FA state,
//! and can never derive vault plaintext.

pub mod auth;
pub mod config;
pub mod error;
pub mod ratelimit;
pub mod routes;
pub mod state;

use config::{Config, JwtKeys};
use sqlx::postgres::PgPoolOptions;
use state::AppState;
use std::sync::Arc;

/// Build the Axum app with a given pool, keys, config, and Google verifier.
pub fn build_app(
    pool: sqlx::PgPool,
    keys: JwtKeys,
    config: Config,
    google: Arc<dyn auth::GoogleVerifier>,
) -> axum::Router {
    let state = AppState {
        pool,
        keys,
        config,
        google,
        limiter: ratelimit::RateLimiter::new(),
    };
    routes::router(state)
}

/// Connect to Postgres with a bounded pool.
pub async fn connect(database_url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .connect(database_url)
        .await
}
