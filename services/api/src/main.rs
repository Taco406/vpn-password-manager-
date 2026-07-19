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

    // In production (SENTINEL_ENV=production) the server must NOT silently fall back to
    // dev-only fixtures — a mock Google verifier accepts any identity, an ephemeral JWT key
    // changes every boot (invalidating tokens) and isn't a real trust root, and a generated
    // TOTP key would make enrolled 2FA undecryptable after a restart. Refuse to boot instead.
    let missing = config.check_production_secrets(
        env_set("SENTINEL_JWT_ES256_PEM"),
        env_set("SENTINEL_TOTP_ENC_KEY"),
    );
    if !missing.is_empty() {
        return Err(format!(
            "SENTINEL_ENV=production but required secrets are unset: {}. \
             Refusing to start with insecure dev fallbacks.",
            missing.join(", ")
        )
        .into());
    }

    let keys = match std::env::var("SENTINEL_JWT_ES256_PEM") {
        Ok(path_or_pem) if !path_or_pem.is_empty() => {
            let pem = std::fs::read_to_string(&path_or_pem).unwrap_or(path_or_pem);
            JwtKeys::from_private_pem(&pem)?
        }
        _ => {
            tracing::warn!("SENTINEL_JWT_ES256_PEM unset — using an ephemeral signing key (dev)");
            JwtKeys::ephemeral()
        }
    };

    let pool = sentinel_api::connect(&config.database_url).await?;

    // One-click deploys set SENTINEL_AUTO_MIGRATE=1 so the server applies the (idempotent)
    // migrations itself on first boot, avoiding a separate psql/migrate step. Read the SQL from a
    // directory (the Docker image ships them at /opt/sentinel/migrations) via sqlx's RUNTIME
    // Migrator — no compile-time `query!`/DATABASE_URL, keeping the D17 "no offline cache" rule.
    // CI keeps applying migrations via psql and never sets this flag, so its path is unchanged.
    if env_flag("SENTINEL_AUTO_MIGRATE") {
        let dir = std::env::var("SENTINEL_MIGRATIONS_DIR")
            .unwrap_or_else(|_| "/opt/sentinel/migrations".to_string());
        tracing::info!(dir, "SENTINEL_AUTO_MIGRATE set — applying migrations");
        sqlx::migrate::Migrator::new(std::path::Path::new(&dir))
            .await?
            .run(&pool)
            .await?;
    }

    // Use the real JWKS-backed verifier when a Google OAuth client id is configured;
    // fall back to the fixture-accepting mock otherwise (dev/test/CI without a client
    // id). The mock never activates once GOOGLE_OAUTH_CLIENT_ID is set, and production
    // refuses to boot without it (checked above).
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

    // `into_make_service_with_connect_info` exposes the peer address to handlers so the rate
    // limiter can key off the real client IP (not a spoofable header). `axum-server` (TLS) keeps
    // this working, so it's used on both paths.
    //
    // Serve HTTPS directly if a cert + key are provided (one-click deploys generate a self-signed
    // cert the desktop app pins); otherwise plain HTTP (behind a proxy that terminates TLS).
    match (
        read_pem_env("SENTINEL_TLS_CERT_PEM"),
        read_pem_env("SENTINEL_TLS_KEY_PEM"),
    ) {
        (Some(cert), Some(key)) => {
            let addr: std::net::SocketAddr = bind
                .parse()
                .map_err(|e| format!("SENTINEL_API_BIND is not a socket addr: {e}"))?;
            tracing::info!(%bind, "sentinel-api listening (HTTPS, self-signed OK)");
            let tls = axum_server::tls_rustls::RustlsConfig::from_pem(
                cert.into_bytes(),
                key.into_bytes(),
            )
            .await?;
            axum_server::bind_rustls(addr, tls)
                .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await?;
        }
        _ => {
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(%bind, "sentinel-api listening (HTTP)");
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}

/// True if an environment variable is set to a non-empty value.
fn env_set(name: &str) -> bool {
    std::env::var(name).map(|v| !v.is_empty()).unwrap_or(false)
}

/// True if an env var is set to `1`/`true`.
fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Read a PEM from an env var that is either a filesystem path or the inline PEM itself
/// (mirrors the `SENTINEL_JWT_ES256_PEM` convention). `None` if unset/empty.
fn read_pem_env(name: &str) -> Option<String> {
    let val = std::env::var(name).ok().filter(|v| !v.is_empty())?;
    Some(std::fs::read_to_string(&val).unwrap_or(val))
}
