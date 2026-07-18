//! sentinel-api server entry point.

use sentinel_api::auth::{GoogleIdTokenVerifier, GoogleVerifier, MockGoogleVerifier};
use sentinel_api::config::{Config, JwtKeys};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sentinel_api=info,tower_http=info".into()),
        )
        .init();

    let config = Config::from_env()?;
    let keys = match std::env::var("SENTINEL_JWT_ES256_PEM") {
        Ok(path_or_pem) if !path_or_pem.is_empty() => {
            let pem = std::fs::read_to_string(&path_or_pem).unwrap_or(path_or_pem);
            JwtKeys::from_private_pem(&pem)?
        }
        _ => {
            tracing::warn!("SENTINEL_JWT_ES256_PEM unset — using an ephemeral signing key");
            JwtKeys::ephemeral()
        }
    };

    let pool = sentinel_api::connect(&config.database_url).await?;

    // Use the real JWKS-backed verifier when a Google OAuth client id is configured;
    // fall back to the fixture-accepting mock otherwise (dev/test/CI without a client
    // id). The mock never activates once GOOGLE_OAUTH_CLIENT_ID is set.
    let google: Arc<dyn GoogleVerifier> = match config.google_client_id.clone() {
        Some(client_id) => {
            tracing::info!("google id_token verification: real (JWKS)");
            Arc::new(GoogleIdTokenVerifier::new(client_id))
        }
        None => {
            tracing::warn!(
                "GOOGLE_OAUTH_CLIENT_ID unset — using MockGoogleVerifier (dev/test only)"
            );
            Arc::new(MockGoogleVerifier)
        }
    };

    let bind = config.bind.clone();
    let app = sentinel_api::build_app(pool, keys, config, google);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(%bind, "sentinel-api listening");
    axum::serve(listener, app).await?;
    Ok(())
}
