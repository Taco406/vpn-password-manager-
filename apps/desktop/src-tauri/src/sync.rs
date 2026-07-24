//! Stage 3 (opt-in): Google sign-in + encrypted, multi-device vault sync.
//!
//! This is inert until the user configures a sync server URL + a Google client id (Settings
//! → Account & Sync) and signs in. With no configuration the app stays 100% local-only, so
//! this path can never disturb a working local vault.
//!
//! Zero-knowledge invariant: the server only ever receives *ciphertext*. The 256-bit vault
//! key never leaves the device except wrapped by the printed recovery kit (Wrapper C), which
//! is derived from a key the user alone holds. All crypto lives in `sentinel-core`; this
//! module is transport + OS glue:
//!   - a real system-browser opener and a real Google token exchanger for the PKCE flow,
//!   - a loopback listener that catches the OAuth redirect,
//!   - non-secret config (server URL, client id, email) in `sync-config.json`,
//!   - secret tokens (access / refresh / pending) in the OS keychain, mirroring `vpn.rs`,
//!   - a thin authed HTTP client that refreshes a rotating refresh token on 401.

use crate::state::AppState;
use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use sentinel_core::auth::{BrowserOpener, GoogleAuth, PkceParams, TokenExchanger, TokenSet};
use sentinel_core::crypto::Key32;
use sentinel_core::error::{CoreError, Result as CoreResult};
use sentinel_core::keyring::password::PasswordWrapper;
use sentinel_core::keyring::recovery::RecoveryWrapper;
use sentinel_core::keyring::{KeyWrapper, VaultKey, WrappedBlob, WrapperType};
use sentinel_core::recovery_kit::{self, pdf::render_kit_pdf, RecoveryKey};
use sentinel_core::vault::fileblob::{
    open_file, pack_bundle, seal_file, unpack_bundle, BundleEntry, FileMeta, BUNDLE_MIME,
};
use sentinel_core::vault::model::Item;
use sentinel_core::vault::{decode_sync_blob, encode_sync_blob, VaultSession};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager, State};

const KC_SERVICE: &str = "com.sentinel.desktop";
const KC_ACCESS: &str = "sync-access";
const KC_REFRESH: &str = "sync-refresh";
const KC_PENDING: &str = "sync-pending";
/// Google OAuth client SECRET. Google requires it in the code→token exchange for
/// "Desktop app" clients even with PKCE (it's non-confidential for installed apps,
/// but omitting it is a hard 400). Kept in the keychain alongside the other tokens.
const KC_GSECRET: &str = "sync-google-secret";
// Same service/account `state::load_or_create_key` uses, so a restore rebinds the local key.
const KC_VAULT_KEY: &str = "vault-key";

const GOOGLE_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

// ---------------------------------------------------------------------------
// tiny helpers
// ---------------------------------------------------------------------------

fn estr<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap_or_default()
}

/// Build the sync HTTP client. For a deployed server we PIN its self-signed cert (trust exactly
/// that cert) and resolve the fixed `sentinel-sync` hostname to the server's IP — so there's real
/// TLS with no public CA or domain. For a manually-configured (real-CA) server this is the plain
/// client. The Google token exchanger deliberately keeps the un-pinned `http_client()`.
fn sync_http_client(cfg: &SyncConfig) -> reqwest::Client {
    // A `connect_timeout` bounds the TCP/TLS connect so a dead/black-holing server (silent packet
    // drop, no RST) fast-fails each attempt instead of blocking the full 30s request timeout — which
    // otherwise turns a bounded "short retry" (reconnect/health probes) into minutes of hang.
    let mut b = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(6));
    if let (Some(pem), Some(ip)) = (cfg.pinned_cert_pem.as_ref(), cfg.server_ip.as_ref()) {
        if let Ok(cert) = reqwest::Certificate::from_pem(pem.as_bytes()) {
            b = b.add_root_certificate(cert);
        }
        if let Ok(addr) = format!("{ip}:443").parse::<std::net::SocketAddr>() {
            b = b.resolve(SYNC_HOST, addr);
        }
    }
    b.build().unwrap_or_default()
}

fn data_dir(state: &State<'_, AppState>) -> PathBuf {
    state.inner.lock().unwrap().data_dir.clone()
}

/// The vault key from the LIVE unlocked session (cloned out of RAM). Never falls back to
/// `load_or_create_key`, which would mint a spurious fresh key when a master password is set (the
/// plaintext keychain key is deleted then, so re-reading it creates a new, wrong one). Errors
/// cleanly if the vault is locked. Used by every path that must wrap/transfer the real vault key
/// (backup, sync, device pairing).
fn session_vault_key(state: &State<'_, AppState>) -> Result<VaultKey, String> {
    state
        .inner
        .lock()
        .unwrap()
        .session
        .vault_key()
        .cloned()
        .ok_or_else(|| "Unlock your vault first, then try again.".to_string())
}

/// RFC3339 for a unix timestamp (device list display).
fn iso(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

/// `YYYY-MM-DD` for the recovery-kit PDF provenance line.
fn today_iso() -> String {
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    time::OffsetDateTime::now_utc()
        .format(&fmt)
        .unwrap_or_default()
}

/// A human-facing device name (best effort, non-secret).
fn device_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "NorthKey desktop".to_string())
}

/// Decode the `email` claim from a Google id_token (a JWT) for display only. No signature
/// verification is done client-side — the server validates the token; this is cosmetic.
fn email_from_id_token(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("email").and_then(|e| e.as_str()).map(str::to_string)
}

// ---------------------------------------------------------------------------
// keychain-backed secret tokens
// ---------------------------------------------------------------------------

fn kc_get(account: &str) -> Option<String> {
    let entry = keyring::Entry::new(KC_SERVICE, account).ok()?;
    entry
        .get_password()
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn kc_set(account: &str, value: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KC_SERVICE, account).map_err(estr)?;
    if value.trim().is_empty() {
        let _ = entry.delete_credential();
        Ok(())
    } else {
        entry.set_password(value.trim()).map_err(estr)
    }
}

fn kc_del(account: &str) {
    if let Ok(entry) = keyring::Entry::new(KC_SERVICE, account) {
        let _ = entry.delete_credential();
    }
}

// ---------------------------------------------------------------------------
// non-secret config file (server URL + client id + email for display)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default, Clone)]
struct SyncConfig {
    #[serde(default)]
    server_url: Option<String>,
    #[serde(default)]
    google_client_id: Option<String>,
    #[serde(default)]
    email: Option<String>,
    /// For a deployed (self-signed) sync server: the exact cert PEM to pin (non-secret).
    #[serde(default)]
    pinned_cert_pem: Option<String>,
    /// The deployed server's IP, so the pinned client can resolve the fixed `sentinel-sync`
    /// hostname (whose cert SAN we control) to it without needing a domain.
    #[serde(default)]
    server_ip: Option<String>,
}

/// The fixed hostname baked into the deployed server's self-signed cert SAN. The desktop pins the
/// cert and resolves this name to the server's IP, so no domain / public CA is needed.
const SYNC_HOST: &str = "sentinel-sync";
/// Keychain account for the deployed server's bootstrap secret.
const KC_BOOTSTRAP: &str = "sync-bootstrap";
/// The prebuilt server image a deploy runs (published by CI to ghcr). Overridable for testing.
fn sync_image_ref() -> String {
    std::env::var("SENTINEL_SYNC_IMAGE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ghcr.io/taco406/sentinel-api:latest".to_string())
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("sync-config.json")
}

fn load_config(dir: &Path) -> SyncConfig {
    std::fs::read_to_string(config_path(dir))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_config(dir: &Path, cfg: &SyncConfig) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(estr)?;
    let text = serde_json::to_string_pretty(cfg).map_err(estr)?;
    std::fs::write(config_path(dir), text).map_err(estr)
}

// ---------------------------------------------------------------------------
// real BrowserOpener + TokenExchanger for the PKCE flow
// ---------------------------------------------------------------------------

/// Opens the system browser at `url`. Delegates to `vpn::open_url`, the one shared opener that
/// is known to survive an OAuth URL's query string on every platform (`explorer <url>` does NOT —
/// it silently opens a File Explorer window instead of the browser for any `?a=b&c=d` URL).
struct SystemBrowserOpener;

#[async_trait]
impl BrowserOpener for SystemBrowserOpener {
    async fn open(&self, url: &str) -> CoreResult<()> {
        crate::vpn::open_url(url.to_string()).map_err(|detail| CoreError::Provision {
            stage: "browser",
            detail,
        })
    }
}

/// Exchanges the authorization code for tokens at Google's token endpoint.
struct HttpTokenExchanger {
    http: reqwest::Client,
    client_id: String,
    /// Required by Google for Desktop-app clients (see `KC_GSECRET`).
    client_secret: Option<String>,
}

impl HttpTokenExchanger {
    fn new(client_id: String, client_secret: Option<String>) -> Self {
        HttpTokenExchanger {
            http: http_client(),
            client_id,
            client_secret,
        }
    }
}

#[async_trait]
impl TokenExchanger for HttpTokenExchanger {
    async fn exchange(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> CoreResult<TokenSet> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
        ];
        if let Some(secret) = self.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        let resp = self
            .http
            .post(GOOGLE_TOKEN_ENDPOINT)
            .form(&form)
            .send()
            .await
            .map_err(|e| CoreError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            let s = resp.status();
            // Surface Google's error body (e.g. `invalid_grant`, "client_secret is missing")
            // so a failure is diagnosable from the UI message alone.
            let body = resp.text().await.unwrap_or_default();
            let body = body.trim().chars().take(300).collect::<String>();
            return Err(CoreError::Provision {
                stage: "token",
                detail: format!("google token endpoint returned HTTP {s}: {body}"),
            });
        }
        #[derive(Deserialize)]
        struct T {
            id_token: String,
            access_token: String,
            refresh_token: Option<String>,
            #[serde(default)]
            expires_in: u64,
        }
        let t: T = resp
            .json()
            .await
            .map_err(|e| CoreError::Network(e.to_string()))?;
        Ok(TokenSet {
            id_token: t.id_token,
            access_token: t.access_token,
            refresh_token: t.refresh_token,
            expires_in: t.expires_in,
        })
    }
}

// ---------------------------------------------------------------------------
// loopback listener for the OAuth redirect
// ---------------------------------------------------------------------------

const CALLBACK_OK_HTML: &str = "<!doctype html><html><head><meta charset=utf-8><title>NorthKey</title>\
<style>body{font-family:system-ui,sans-serif;background:#0a0f14;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}\
.c{text-align:center}h1{color:#22d3ee;font-weight:600}</style></head>\
<body><div class=c><h1>Signed in</h1><p>You can close this tab and return to NorthKey.</p></div></body></html>";

const CALLBACK_ERR_HTML: &str = "<!doctype html><html><head><meta charset=utf-8><title>NorthKey</title>\
<style>body{font-family:system-ui,sans-serif;background:#0a0f14;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}\
.c{text-align:center}h1{color:#f87171;font-weight:600}</style></head>\
<body><div class=c><h1>Sign-in failed</h1><p>You can close this tab and try again in NorthKey.</p></div></body></html>";

/// Run the full PKCE loop: bind an ephemeral loopback port, open the browser, wait for the
/// single `/callback` GET, then exchange the code for tokens. ~2-minute overall timeout.
async fn run_pkce_flow(client_id: &str, client_secret: Option<String>) -> Result<TokenSet, String> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind loopback: {e}"))?;
    let port = listener.local_addr().map_err(estr)?.port();
    let params = PkceParams::generate(port);

    let auth = GoogleAuth::new(
        client_id.to_string(),
        Arc::new(SystemBrowserOpener),
        Arc::new(HttpTokenExchanger::new(
            client_id.to_string(),
            client_secret,
        )),
    );
    auth.start(&params).await.map_err(estr)?;

    let accept = tokio::task::spawn_blocking(move || accept_callback(listener));
    let joined = tokio::time::timeout(Duration::from_secs(120), accept)
        .await
        .map_err(|_| "sign-in timed out (no browser callback within 2 minutes)".to_string())?;
    let (code, returned_state) =
        joined.map_err(|e| format!("callback listener crashed: {e}"))??;

    auth.complete(&params, &returned_state, &code)
        .await
        .map_err(estr)
}

/// Block (in a spawn_blocking thread) until one connection arrives or ~2 min elapse.
fn accept_callback(listener: std::net::TcpListener) -> Result<(String, String), String> {
    listener.set_nonblocking(true).map_err(estr)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(115);
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("timed out waiting for the browser callback".into());
        }
        match listener.accept() {
            Ok((stream, _)) => return handle_callback(stream),
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("accept: {e}")),
        }
    }
}

/// Parse `code`/`state` from the redirect GET, reply with a small close-me page.
fn handle_callback(mut stream: std::net::TcpStream) -> Result<(String, String), String> {
    use std::io::{Read, Write};
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut buf = [0u8; 8192];
    let n = stream
        .read(&mut buf)
        .map_err(|e| format!("read callback: {e}"))?;
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    let target = first.split_whitespace().nth(1).unwrap_or("");
    let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");

    let (mut code, mut state, mut oauth_err) = (None, None, None);
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "code" => code = Some(percent_decode(v)),
            "state" => state = Some(percent_decode(v)),
            "error" => oauth_err = Some(percent_decode(v)),
            _ => {}
        }
    }

    let body = if code.is_some() && oauth_err.is_none() {
        CALLBACK_OK_HTML
    } else {
        CALLBACK_ERR_HTML
    };
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();

    if let Some(e) = oauth_err {
        return Err(format!("Google denied sign-in: {e}"));
    }
    let code = code.ok_or("callback did not include an authorization code")?;
    let state = state.ok_or("callback did not include a state value")?;
    Ok((code, state))
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// authenticated HTTP client (Bearer access + rotating refresh on 401)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ServerTokens {
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    expires_in: u64,
}

enum PutResult {
    Ok(i64),
    Conflict(i64),
}

struct Api {
    http: reqwest::Client,
    base: String,
}

impl Api {
    /// Refresh the access token using the (rotating) refresh token, storing both anew.
    async fn refresh(&self) -> Result<(), String> {
        let rt = kc_get(KC_REFRESH).ok_or("your session expired — sign in again")?;
        let resp = self
            .http
            .post(format!("{}/auth/refresh", self.base))
            .json(&json!({ "refresh_token": rt }))
            .send()
            .await
            .map_err(estr)?;
        if !resp.status().is_success() {
            return Err(format!("token refresh failed: HTTP {}", resp.status()));
        }
        let t: ServerTokens = resp.json().await.map_err(estr)?;
        kc_set(KC_ACCESS, &t.access_token)?;
        kc_set(KC_REFRESH, &t.refresh_token)?;
        Ok(())
    }

    /// Send an authed request; on 401 refresh once and retry.
    async fn authed(
        &self,
        method: reqwest::Method,
        path: &str,
        headers: &[(&'static str, String)],
        json_body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, String> {
        let url = format!("{}{}", self.base, path);
        let build = |access: &str| {
            let mut rb = self.http.request(method.clone(), &url).bearer_auth(access);
            for (k, v) in headers {
                rb = rb.header(*k, v);
            }
            if let Some(b) = &json_body {
                rb = rb.json(b);
            }
            rb
        };

        let access = kc_get(KC_ACCESS).ok_or("not signed in")?;
        let resp = build(&access).send().await.map_err(estr)?;
        if resp.status().as_u16() == 401 {
            self.refresh().await?;
            let access2 = kc_get(KC_ACCESS).ok_or("not signed in after refresh")?;
            return build(&access2).send().await.map_err(estr);
        }
        Ok(resp)
    }

    /// Send a request authed with the short-lived pending token (TOTP enroll/verify).
    async fn pending_post(
        &self,
        path: &str,
        json_body: Option<serde_json::Value>,
    ) -> Result<reqwest::Response, String> {
        let pending = kc_get(KC_PENDING).ok_or("no sign-in is in progress")?;
        let mut rb = self
            .http
            .post(format!("{}{}", self.base, path))
            .bearer_auth(pending);
        if let Some(b) = json_body {
            rb = rb.json(&b);
        }
        rb.send().await.map_err(estr)
    }

    /// GET /vault → None on 204, else (version, ciphertext bytes).
    async fn get_vault(&self) -> Result<Option<(i64, Vec<u8>)>, String> {
        let resp = self
            .authed(reqwest::Method::GET, "/vault", &[], None)
            .await?;
        match resp.status().as_u16() {
            204 => Ok(None),
            200 => {
                #[derive(Deserialize)]
                struct V {
                    version: i64,
                    ciphertext_b64: String,
                }
                let v: V = resp.json().await.map_err(estr)?;
                let ct = STANDARD.decode(v.ciphertext_b64.trim()).map_err(estr)?;
                Ok(Some((v.version, ct)))
            }
            s => Err(format!("GET /vault: HTTP {s}")),
        }
    }

    /// PUT /vault with an If-Match precondition. Distinguishes 409 conflicts.
    async fn put_vault(&self, if_match: i64, ciphertext: &[u8]) -> Result<PutResult, String> {
        let body = json!({ "ciphertext_b64": STANDARD.encode(ciphertext) });
        let headers = [("If-Match", format!("\"{if_match}\""))];
        let resp = self
            .authed(reqwest::Method::PUT, "/vault", &headers, Some(body))
            .await?;
        match resp.status().as_u16() {
            200 => {
                #[derive(Deserialize)]
                struct V {
                    version: i64,
                }
                let v: V = resp.json().await.map_err(estr)?;
                Ok(PutResult::Ok(v.version))
            }
            409 => {
                #[derive(Deserialize)]
                struct C {
                    #[serde(default)]
                    current: i64,
                }
                let c: C = resp.json().await.unwrap_or(C { current: if_match });
                Ok(PutResult::Conflict(c.current))
            }
            s => Err(format!("PUT /vault: HTTP {s}")),
        }
    }

    async fn put_wrapped_key(&self, wt: u8, blob: &[u8]) -> Result<(), String> {
        let path = format!("/wrapped-keys/{wt}");
        let body =
            json!({ "blob_b64": STANDARD.encode(blob), "device_id": serde_json::Value::Null });
        let resp = self
            .authed(reqwest::Method::PUT, &path, &[], Some(body))
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("PUT {path}: HTTP {}", resp.status()))
        }
    }

    async fn get_wrapped_key(&self, wt: u8) -> Result<Vec<u8>, String> {
        let path = format!("/wrapped-keys/{wt}");
        let resp = self.authed(reqwest::Method::GET, &path, &[], None).await?;
        if !resp.status().is_success() {
            return Err(format!("GET {path}: HTTP {}", resp.status()));
        }
        #[derive(Deserialize)]
        struct W {
            blob_b64: String,
        }
        let w: W = resp.json().await.map_err(estr)?;
        STANDARD.decode(w.blob_b64.trim()).map_err(estr)
    }

    /// POST /transfers — upload an opaque `SFIL` blob for a device (or all devices when None), with
    /// its retention (delete-on-download / permanent / N-day TTL).
    async fn create_transfer(
        &self,
        recipient_device_id: Option<String>,
        size_bytes: i64,
        ciphertext: &[u8],
        retention: &Retention,
    ) -> Result<String, String> {
        let body = json!({
            "recipient_device_id": recipient_device_id,
            "size_bytes": size_bytes,
            "ciphertext_b64": STANDARD.encode(ciphertext),
            "delete_on_download": retention.delete_on_download,
            "permanent": retention.permanent,
            "ttl_days": retention.ttl_days,
        });
        let resp = self
            .authed(reqwest::Method::POST, "/transfers", &[], Some(body))
            .await?;
        if !resp.status().is_success() {
            let s = resp.status();
            let t = resp.text().await.unwrap_or_default();
            return Err(format!(
                "POST /transfers: HTTP {s} {}",
                t.trim().chars().take(200).collect::<String>()
            ));
        }
        #[derive(Deserialize)]
        struct R {
            id: String,
        }
        let r: R = resp.json().await.map_err(estr)?;
        Ok(r.id)
    }

    /// GET /transfers — the pending transfers this device can see (incoming + its own outgoing).
    async fn list_transfers(&self) -> Result<Vec<TransferRow>, String> {
        let resp = self
            .authed(reqwest::Method::GET, "/transfers", &[], None)
            .await?;
        if !resp.status().is_success() {
            return Err(format!("GET /transfers: HTTP {}", resp.status()));
        }
        #[derive(Deserialize)]
        struct L {
            #[serde(default)]
            transfers: Vec<TransferRow>,
        }
        let l: L = resp.json().await.map_err(estr)?;
        Ok(l.transfers)
    }

    /// GET /transfers/{id} — download one blob's ciphertext (marks it delivered server-side).
    async fn download_transfer(&self, id: &str) -> Result<Vec<u8>, String> {
        let path = format!("/transfers/{id}");
        let resp = self.authed(reqwest::Method::GET, &path, &[], None).await?;
        if !resp.status().is_success() {
            return Err(format!("GET {path}: HTTP {}", resp.status()));
        }
        #[derive(Deserialize)]
        struct D {
            ciphertext_b64: String,
        }
        let d: D = resp.json().await.map_err(estr)?;
        STANDARD.decode(d.ciphertext_b64.trim()).map_err(estr)
    }

    async fn delete_transfer(&self, id: &str) -> Result<(), String> {
        let path = format!("/transfers/{id}");
        let resp = self
            .authed(reqwest::Method::DELETE, &path, &[], None)
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("DELETE {path}: HTTP {}", resp.status()))
        }
    }
}

/// One row of the transfer list. This type does double duty: it is *deserialized* from the sync
/// server's response (whose JSON fields are frozen snake_case — `sender_device_id`, `size_bytes`, …)
/// and *serialized* back out to the desktop frontend (which expects camelCase). `rename_all` gives
/// the frontend its camelCase, and each multi-word field carries a snake_case `alias` so the read
/// side still matches the server. Without the aliases, multi-word fields silently defaulted (every
/// row showed "0 B" with no sender/timestamp — a real bug pre-v0.1.56). Single-word fields (`id`,
/// `state`, `permanent`, `outgoing`) need no alias since their camelCase equals their snake_case.
#[derive(Deserialize, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TransferRow {
    pub id: String,
    #[serde(default, alias = "sender_device_id")]
    pub sender_device_id: String,
    #[serde(default, alias = "recipient_device_id")]
    pub recipient_device_id: Option<String>,
    #[serde(default, alias = "size_bytes")]
    pub size_bytes: i64,
    #[serde(default)]
    pub state: String,
    #[serde(default, alias = "created_at")]
    pub created_at: i64,
    #[serde(default, alias = "expires_at")]
    pub expires_at: i64,
    #[serde(default, alias = "delete_on_download")]
    pub delete_on_download: bool,
    #[serde(default)]
    pub permanent: bool,
    #[serde(default)]
    pub outgoing: bool,
}

/// How long a transfer lives on the relay, chosen per upload.
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Retention {
    /// Delete the moment a device downloads it.
    #[serde(default)]
    pub delete_on_download: bool,
    /// Keep forever (no auto-expiry) — the "file it permanently" option.
    #[serde(default)]
    pub permanent: bool,
    /// Days until auto-expiry when not permanent (server clamps 1..=365; None = 1 day default).
    #[serde(default)]
    pub ttl_days: Option<i64>,
}

/// Build an `Api` from the configured server URL (base `<serverUrl>/v1`), pinning the deployed
/// server's self-signed cert when present.
fn api_for(state: &State<'_, AppState>) -> Result<Api, String> {
    let cfg = load_config(&data_dir(state));
    let server = cfg
        .server_url
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or("no sync server configured")?;
    Ok(Api {
        http: sync_http_client(&cfg),
        base: format!("{}/v1", server.trim_end_matches('/')),
    })
}

/// Snapshot the local vault and push it, merging + retrying once on a version conflict.
/// Never holds the state mutex across an await.
async fn push_document(
    api: &Api,
    vk: &VaultKey,
    state: &State<'_, AppState>,
    mut current: i64,
) -> Result<i64, String> {
    for _ in 0..2 {
        let doc = {
            let g = state.inner.lock().unwrap();
            g.vault.to_document().map_err(estr)?
        };
        let blob = encode_sync_blob(vk, &doc, (current + 1) as u64).map_err(estr)?;
        match api.put_vault(current, &blob).await? {
            PutResult::Ok(v) => return Ok(v),
            PutResult::Conflict(server_current) => match api.get_vault().await? {
                Some((v, ct)) => {
                    let remote = decode_sync_blob(vk, &ct, v as u64).map_err(estr)?;
                    {
                        let g = state.inner.lock().unwrap();
                        g.vault.merge(&remote).map_err(estr)?;
                    }
                    current = v;
                }
                None => current = server_current,
            },
        }
    }
    Err("sync failed: version conflict persisted after retry".into())
}

// ---------------------------------------------------------------------------
// command output shapes
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncStatusOut {
    server_url: Option<String>,
    google_client_id: Option<String>,
    /// Whether a Google client SECRET is saved (never the value itself). The UI uses this to
    /// prompt for the secret before a Google sign-in can succeed (Google requires it).
    google_secret_set: bool,
    signed_in: bool,
    email: Option<String>,
    /// The deployed server's public address (what another device types to sign in).
    server_ip: Option<String>,
    /// Human-comparable identity code of the pinned server cert — a device signing in for the
    /// first time shows the same code, and matching means no man-in-the-middle.
    cert_fingerprint: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SigninOut {
    email: String,
    totp_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollOut {
    otpauth_uri: String,
    secret: String,
    /// The otpauth URI rendered as an SVG QR code, so the UI can show a scannable code
    /// (empty string if rendering failed — the typed secret is always present as fallback).
    qr_svg: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupOut {
    recovery_code: String,
    pdf_base64: String,
    version: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncNowOut {
    pushed: bool,
    pulled: bool,
    version: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreOut {
    restored: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceOut {
    id: String,
    name: String,
    platform: String,
    status: String,
    created_at: String,
    current: bool,
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn sync_status(state: State<AppState>) -> SyncStatusOut {
    let cfg = load_config(&data_dir(&state));
    SyncStatusOut {
        server_url: cfg.server_url,
        google_client_id: cfg.google_client_id,
        google_secret_set: kc_get(KC_GSECRET).is_some(),
        signed_in: kc_get(KC_ACCESS).is_some(),
        email: cfg.email,
        server_ip: cfg.server_ip,
        cert_fingerprint: cfg.pinned_cert_pem.as_deref().and_then(cert_fingerprint),
    }
}

/// Save (or clear, with an empty string) the Google OAuth client secret. Kept separate from
/// `sync_set_config` so re-saving the non-secret config can never silently wipe the secret.
#[tauri::command]
pub fn sync_set_google_secret(secret: String) -> Result<(), String> {
    kc_set(KC_GSECRET, &secret)
}

#[tauri::command]
pub fn sync_set_config(
    state: State<AppState>,
    server_url: Option<String>,
    google_client_id: Option<String>,
) -> Result<(), String> {
    let dir = data_dir(&state);
    let mut cfg = load_config(&dir);
    cfg.server_url = server_url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    cfg.google_client_id = google_client_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    save_config(&dir, &cfg)
}

#[tauri::command]
pub async fn auth_google_signin(
    _app: AppHandle,
    state: State<'_, AppState>,
) -> Result<SigninOut, String> {
    let dir = data_dir(&state);
    let cfg = load_config(&dir);
    let server = cfg
        .server_url
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or("set the sync server URL first")?;
    let client_id = cfg
        .google_client_id
        .clone()
        .filter(|s| !s.trim().is_empty())
        .ok_or("set the Google client id first")?;

    let tokens = run_pkce_flow(&client_id, kc_get(KC_GSECRET)).await?;
    let email = email_from_id_token(&tokens.id_token).unwrap_or_default();

    // Use the PINNED client so this reaches a one-click self-signed server (trust its exact
    // cert + resolve the fixed `sentinel-sync` host). A plain client would fail TLS there —
    // which is why Google sign-in never worked against a one-click deploy before.
    let client = sync_http_client(&cfg);
    let resp = client
        .post(format!("{}/v1/auth/google", server.trim_end_matches('/')))
        .json(&json!({
            "id_token": tokens.id_token,
            "device": { "name": device_name(), "platform": platform_str() },
        }))
        .send()
        .await
        .map_err(estr)?;
    if !resp.status().is_success() {
        return Err(format!(
            "sign-in rejected by server: HTTP {}",
            resp.status()
        ));
    }
    #[derive(Deserialize)]
    struct GoogleResp {
        pending_token: String,
        #[serde(default)]
        totp_required: bool,
    }
    let gr: GoogleResp = resp.json().await.map_err(estr)?;
    kc_set(KC_PENDING, &gr.pending_token)?;

    // Persist email for status display (survives restart).
    let mut cfg2 = load_config(&dir);
    cfg2.email = if email.is_empty() {
        None
    } else {
        Some(email.clone())
    };
    let _ = save_config(&dir, &cfg2);

    Ok(SigninOut {
        email,
        totp_required: gr.totp_required,
    })
}

#[tauri::command]
pub async fn auth_totp_enroll(state: State<'_, AppState>) -> Result<EnrollOut, String> {
    let api = api_for(&state)?;
    let resp = api.pending_post("/auth/totp/enroll", None).await?;
    if !resp.status().is_success() {
        return Err(format!("TOTP enrollment failed: HTTP {}", resp.status()));
    }
    #[derive(Deserialize)]
    struct E {
        otpauth_uri: String,
        secret_base32: String,
    }
    let e: E = resp.json().await.map_err(estr)?;
    let qr_svg = crate::applock::qr_svg(&e.otpauth_uri).unwrap_or_default();
    Ok(EnrollOut {
        otpauth_uri: e.otpauth_uri,
        secret: e.secret_base32,
        qr_svg,
    })
}

#[tauri::command]
pub async fn auth_totp_verify(state: State<'_, AppState>, code: String) -> Result<(), String> {
    let api = api_for(&state)?;
    let resp = api
        .pending_post("/auth/totp/verify", Some(json!({ "code": code.trim() })))
        .await?;
    if !resp.status().is_success() {
        return Err(format!("code rejected: HTTP {}", resp.status()));
    }
    let t: ServerTokens = resp.json().await.map_err(estr)?;
    kc_set(KC_ACCESS, &t.access_token)?;
    kc_set(KC_REFRESH, &t.refresh_token)?;
    kc_del(KC_PENDING);
    // Signed in — make sure the server actually holds this device's vault.
    let _ = try_push_vault(&state).await;
    Ok(())
}

#[tauri::command]
pub async fn auth_logout(state: State<'_, AppState>) -> Result<(), String> {
    // Best-effort server-side logout; local tokens are cleared regardless.
    if let Ok(api) = api_for(&state) {
        if let Some(access) = kc_get(KC_ACCESS) {
            let _ = api
                .http
                .post(format!("{}/auth/logout", api.base))
                .bearer_auth(access)
                .send()
                .await;
        }
    }
    kc_del(KC_ACCESS);
    kc_del(KC_REFRESH);
    kc_del(KC_PENDING);
    let dir = data_dir(&state);
    let mut cfg = load_config(&dir);
    cfg.email = None;
    let _ = save_config(&dir, &cfg);
    Ok(())
}

#[tauri::command]
pub async fn sync_backup(state: State<'_, AppState>) -> Result<BackupOut, String> {
    let vk = session_vault_key(&state)?;

    // Wrap the vault key with a fresh recovery key (Wrapper C) and store it server-side.
    let rk = RecoveryKey::random();
    let wrapper = RecoveryWrapper::new(rk.clone());
    let blob = wrapper.wrap(&vk).await.map_err(estr)?;

    let api = api_for(&state)?;
    api.put_wrapped_key(WrapperType::Recovery.code(), &blob.bytes)
        .await?;

    // Push the current vault as one sealed sync blob.
    let current = api.get_vault().await?.map(|(v, _)| v).unwrap_or(0);
    let version = push_document(&api, &vk, &state, current).await?;

    let code = recovery_kit::encode(&rk);
    let email = load_config(&data_dir(&state)).email.unwrap_or_default();
    let pdf = render_kit_pdf(&code, &email, &today_iso());

    Ok(BackupOut {
        recovery_code: code,
        pdf_base64: STANDARD.encode(&pdf),
        version,
    })
}

/// Best-effort: push the local vault to the server if this device is signed in and unlocked.
/// Called after every successful sign-in so the server is never silently empty — otherwise a
/// joining device pulls "0 items" even though everything else worked.
async fn try_push_vault(state: &State<'_, AppState>) -> Option<i64> {
    let vk = session_vault_key(state).ok()?;
    let api = api_for(state).ok()?;
    let current = api.get_vault().await.ok()?.map(|(v, _)| v).unwrap_or(0);
    push_document(&api, &vk, state, current).await.ok()
}

/// The core pull → merge → apply-settings → push cycle, shared by the `sync_now` command and
/// the background poller. Emits `sync:applied` afterward so screens that depend on synced tokens
/// (Servers, VPN) refresh themselves instead of waiting for their own interval.
async fn sync_once(state: &State<'_, AppState>, app: &AppHandle) -> Result<SyncNowOut, String> {
    let vk = session_vault_key(state)?;
    let api = api_for(state)?;

    let mut pulled = false;
    let mut current = 0i64;
    if let Some((v, ct)) = api.get_vault().await? {
        let remote = decode_sync_blob(&vk, &ct, v as u64).map_err(estr)?;
        {
            let g = state.inner.lock().unwrap();
            g.vault.merge(&remote).map_err(estr)?;
        }
        pulled = true;
        current = v;
    }

    // Apply synced device settings (or seed them from this device) before pushing.
    let _ = sync_device_settings(state);

    let version = push_document(&api, &vk, state, current).await?;
    let _ = app.emit(
        "sync:applied",
        json!({ "version": version, "pulled": pulled }),
    );
    Ok(SyncNowOut {
        pushed: true,
        pulled,
        version,
    })
}

#[tauri::command]
pub async fn sync_now(app: AppHandle, state: State<'_, AppState>) -> Result<SyncNowOut, String> {
    sync_once(&state, &app).await
}

// ---------------------------------------------------------------------------
// File transfer ("send to my devices") — encrypted, zero-knowledge relay.
//
// The file is sealed locally into an opaque `SFIL` blob (filename + bytes both inside the
// ciphertext) under the vault key, uploaded to the sync server's short-lived relay, and opened
// only on a receiving device that holds the same vault key. The server sees ciphertext + a size.
// ---------------------------------------------------------------------------

/// The server caps a single transfer's ciphertext at 25 MiB; guard client-side so the user gets a
/// friendly message instead of an opaque HTTP 400. Keep in lockstep with `TRANSFER_MAX_CIPHERTEXT`
/// in `services/api/src/routes.rs` (additive wire policy: never raise past the server's ceiling).
const TRANSFER_MAX_BLOB_BYTES: usize = 25 * 1024 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferSendOut {
    pub id: String,
    pub filename: String,
    /// Sealed blob size (what the server stores + counts against quota).
    pub blob_bytes: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferDownloadOut {
    pub filename: String,
    pub size_bytes: i64,
    pub mime: String,
    /// The decrypted file bytes, base64. The UI saves them via a browser download (no filesystem
    /// path crosses the bridge, so nothing can be written outside the user's chosen location). Empty
    /// string when this is a bundle (the files live in `bundle` instead).
    pub data_b64: String,
    /// v0.1.58: when the transfer is a multi-file bundle, its individual files (name + base64). The
    /// UI saves each one. `None` for an ordinary single-file transfer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<Vec<BundleFile>>,
}

/// One file inside a downloaded bundle.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleFile {
    pub name: String,
    pub size_bytes: i64,
    pub data_b64: String,
}

/// One file to include in an outgoing bundle (from the UI's multi-file picker / drag-drop).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundleInput {
    pub name: String,
    pub data_b64: String,
}

/// Reduce any path/name to its bare file-name component, defending against a malicious/garbled
/// sealed `filename` (e.g. `../../etc/foo`) that could otherwise mislead the receiver's save.
fn safe_basename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .trim();
    if base.is_empty() || base == "." || base == ".." {
        "download.bin".to_string()
    } else {
        base.to_string()
    }
}

/// Best-effort MIME from the file extension (advisory only — the receiver saves by name). The blob
/// carries this sealed so the phone/desktop can preview sensibly; unknowns fall back to octet-stream.
fn guess_mime(filename: &str) -> String {
    let ext = Path::new(filename)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let m = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "heic" => "image/heic",
        "pdf" => "application/pdf",
        "txt" | "log" | "md" => "text/plain",
        "json" => "application/json",
        "csv" => "text/csv",
        "zip" => "application/zip",
        "mp4" | "m4v" => "video/mp4",
        "mov" => "video/quicktime",
        "mp3" => "audio/mpeg",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    };
    m.to_string()
}

/// Seal a file (`filename` + base64 `data_b64` from the UI's file picker) and upload it for one
/// device (or all this account's devices when `recipient_device_id` is `None`). The bytes ride the
/// bridge as base64 — no filesystem path crosses in, so the app only ever reads what the user picked.
#[tauri::command]
pub async fn transfer_send(
    state: State<'_, AppState>,
    recipient_device_id: Option<String>,
    filename: String,
    data_b64: String,
    retention: Option<Retention>,
) -> Result<TransferSendOut, String> {
    let vk = session_vault_key(&state)?;
    let api = api_for(&state)?;

    let bytes = STANDARD.decode(data_b64.trim()).map_err(estr)?;
    if bytes.is_empty() {
        return Err("that file is empty".into());
    }
    let plaintext_size = bytes.len() as i64;
    let filename = safe_basename(&filename);
    let meta = FileMeta {
        filename: filename.clone(),
        mime: guess_mime(&filename),
    };
    let blob = seal_file(&vk, &meta, &bytes).map_err(estr)?;
    if blob.len() > TRANSFER_MAX_BLOB_BYTES {
        return Err(format!(
            "file too large to send ({:.1} MiB sealed; 25 MiB max)",
            blob.len() as f64 / (1024.0 * 1024.0)
        ));
    }
    let recipient = recipient_device_id.filter(|s| !s.trim().is_empty());
    let id = api
        .create_transfer(
            recipient,
            plaintext_size,
            &blob,
            &retention.unwrap_or_default(),
        )
        .await?;
    Ok(TransferSendOut {
        id,
        filename,
        blob_bytes: blob.len() as i64,
    })
}

/// Sanitise a bundle entry's relative path: keep sub-folders (so a folder's shape survives) but
/// neutralise absolute paths and `..` traversal, and never yield an empty name.
fn safe_bundle_name(name: &str) -> String {
    let parts: Vec<&str> = name
        .split(['/', '\\'])
        .filter(|s| !s.is_empty() && *s != "." && *s != "..")
        .collect();
    let joined = parts.join("/");
    if joined.is_empty() {
        "file".to_string()
    } else {
        joined
    }
}

/// v0.1.58: seal SEVERAL files (a multi-select or a dragged folder) into ONE bundle transfer — a
/// NKAR archive sealed as a single SFIL blob (mime = bundle). The recipient unpacks it back into the
/// individual files. Files are already zstd-compressed by the seal, so bundling — not re-compressing
/// — is the space win. The bytes ride the bridge as base64, same as `transfer_send`.
#[tauri::command]
pub async fn transfer_send_bundle(
    state: State<'_, AppState>,
    recipient_device_id: Option<String>,
    files: Vec<BundleInput>,
    retention: Option<Retention>,
) -> Result<TransferSendOut, String> {
    if files.is_empty() {
        return Err("no files selected".into());
    }
    let vk = session_vault_key(&state)?;
    let api = api_for(&state)?;

    let mut entries = Vec::with_capacity(files.len());
    let mut total_plaintext = 0i64;
    for f in &files {
        let bytes = STANDARD.decode(f.data_b64.trim()).map_err(estr)?;
        total_plaintext += bytes.len() as i64;
        entries.push(BundleEntry {
            name: safe_bundle_name(&f.name),
            data: bytes,
        });
    }
    if total_plaintext == 0 {
        return Err("those files are all empty".into());
    }

    let count = entries.len();
    let payload = pack_bundle(&entries);
    let display_name = format!("{count} files");
    let meta = FileMeta {
        filename: format!("{display_name}.nkbundle"),
        mime: BUNDLE_MIME.to_string(),
    };
    let blob = seal_file(&vk, &meta, &payload).map_err(estr)?;
    if blob.len() > TRANSFER_MAX_BLOB_BYTES {
        return Err(format!(
            "those files are too large together ({:.1} MiB sealed; 25 MiB max) — send fewer at once",
            blob.len() as f64 / (1024.0 * 1024.0)
        ));
    }
    let recipient = recipient_device_id.filter(|s| !s.trim().is_empty());
    let id = api
        .create_transfer(
            recipient,
            total_plaintext,
            &blob,
            &retention.unwrap_or_default(),
        )
        .await?;
    Ok(TransferSendOut {
        id,
        filename: display_name,
        blob_bytes: blob.len() as i64,
    })
}

/// The transfers this device can see: everything it sent (outgoing) plus anything addressed to it
/// or to "all my devices" (incoming). Filenames stay sealed — the row shows only size/state/age.
#[tauri::command]
pub async fn transfer_list(state: State<'_, AppState>) -> Result<Vec<TransferRow>, String> {
    let api = api_for(&state)?;
    api.list_transfers().await
}

/// Download + decrypt one transfer, returning its sealed filename and bytes (base64) for the UI to
/// save via a browser download. Does NOT delete the transfer — the recipient keeps it until they
/// choose to (the server TTL reaps it after 24h regardless).
#[tauri::command]
pub async fn transfer_download(
    state: State<'_, AppState>,
    id: String,
) -> Result<TransferDownloadOut, String> {
    let vk = session_vault_key(&state)?;
    let api = api_for(&state)?;

    let ct = api.download_transfer(&id).await?;
    let (meta, data) = open_file(&vk, &ct).map_err(estr)?;

    // v0.1.58: a bundle's plaintext is a NKAR archive of several files — unpack it so the UI can
    // save each one. A single-file transfer (the common case, and everything sent before v0.1.58)
    // returns its bytes in `data_b64` exactly as before.
    if meta.mime == BUNDLE_MIME {
        let entries = unpack_bundle(&data).map_err(estr)?;
        let files: Vec<BundleFile> = entries
            .into_iter()
            .map(|e| BundleFile {
                name: e.name,
                size_bytes: e.data.len() as i64,
                data_b64: STANDARD.encode(&e.data),
            })
            .collect();
        let total: i64 = files.iter().map(|f| f.size_bytes).sum();
        return Ok(TransferDownloadOut {
            filename: safe_basename(&meta.filename),
            size_bytes: total,
            mime: meta.mime,
            data_b64: String::new(),
            bundle: Some(files),
        });
    }

    Ok(TransferDownloadOut {
        filename: safe_basename(&meta.filename),
        size_bytes: data.len() as i64,
        mime: meta.mime,
        data_b64: STANDARD.encode(&data),
        bundle: None,
    })
}

/// Remove a transfer from the relay (either side may delete). Frees the account's quota.
#[tauri::command]
pub async fn transfer_delete(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let api = api_for(&state)?;
    api.delete_transfer(&id).await
}

/// How often the background auto-sync polls (seconds). Self-gating: a tick does nothing unless
/// the device is signed in and unlocked.
const SYNC_POLL_SECS: u64 = 90;

/// Background auto-sync loop: every ~90s, if signed in + unlocked, run the full sync cycle. This
/// makes "Sync now" a rarely-needed manual refresh and — crucially — makes a freshly-signed-in
/// device pull its synced provider tokens and populate the Servers/VPN screens on its own.
pub fn spawn_sync_poller(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(SYNC_POLL_SECS)).await;
            let state = app.state::<AppState>();
            // Gate: signed in (has an access token) and vault unlocked. Cheap checks first.
            if kc_get(KC_ACCESS).is_none() || session_vault_key(&state).is_err() {
                continue;
            }
            if let Err(e) = sync_once(&state, &app).await {
                crate::applog::info("sync.poller", &format!("auto-sync skipped: {e}"));
            }
        }
    });
}

#[tauri::command]
pub async fn sync_restore(
    state: State<'_, AppState>,
    recovery_code: String,
) -> Result<RestoreOut, String> {
    // Only ever restore onto an empty device — never clobber an existing local vault.
    {
        let g = state.inner.lock().unwrap();
        if !g.vault.list_envelopes().map_err(estr)?.is_empty() {
            return Err("this device already has a vault".into());
        }
    }

    let api = api_for(&state)?;
    let blob = WrappedBlob {
        wrapper: WrapperType::Recovery,
        bytes: api.get_wrapped_key(WrapperType::Recovery.code()).await?,
    };
    let rk = recovery_kit::decode(recovery_code.trim()).map_err(estr)?;
    let vk = RecoveryWrapper::new(rk).unwrap(&blob).await.map_err(estr)?;

    // Re-assert the vault is empty AND adopt the shared key in ONE locked section: an item saved
    // during the network fetch/unwrap above would have been sealed under the old local key, and
    // swapping keys now would orphan it (and propagate it on the next sync). Refuse instead.
    {
        let mut g = state.inner.lock().unwrap();
        if !g.vault.list_envelopes().map_err(estr)?.is_empty() {
            return Err("this device already has a vault".into());
        }
        g.session = VaultSession::unlocked(vk.clone());
    }
    // Persist the shared key to the keychain (survives restart).
    kc_set(KC_VAULT_KEY, &STANDARD.encode(vk.key().as_bytes()))?;

    let mut restored = 0i64;
    if let Some((v, ct)) = api.get_vault().await? {
        let doc = decode_sync_blob(&vk, &ct, v as u64).map_err(estr)?;
        let report = {
            let g = state.inner.lock().unwrap();
            g.vault.merge(&doc).map_err(estr)?
        };
        restored = report.added as i64;
    }
    let _ = sync_device_settings(&state);

    Ok(RestoreOut { restored })
}

/// Escrow the local master-password-wrapped vault key on the sync server (Wrapper D / type 4) and
/// push the current vault, so another device can unlock with the SAME master password — no device
/// code, no recovery code. Requires a master password set locally and the vault unlocked.
#[tauri::command]
pub async fn sync_enable_password_unlock(
    state: State<'_, AppState>,
    password: Option<String>,
) -> Result<i64, String> {
    let dir = data_dir(&state);
    let blob = std::fs::read(crate::state::wrap_path(&dir))
        .map_err(|_| "Set a master password first, then enable password unlock.".to_string())?;
    // Must be a Password (type 4) SNTL envelope — the same blob the local unlock uses.
    if blob.len() < 8 || &blob[0..4] != b"SNTL" || blob[5] != WrapperType::Password.code() {
        return Err("the local master-password wrapper is missing or malformed".into());
    }
    let vk = session_vault_key(&state)?;
    let api = api_for(&state)?;
    api.put_wrapped_key(WrapperType::Password.code(), &blob)
        .await?;
    // With the password in hand we can also enroll master-password SIGN-IN (the login verifier),
    // so a new device needs only address + password. Verify it's really the right password first
    // (it must unwrap the local blob) — enrolling a typo would lock sign-in behind gibberish.
    if let Some(pw) = password.as_deref().filter(|p| !p.is_empty()) {
        let check = WrappedBlob {
            wrapper: WrapperType::Password,
            bytes: blob.clone(),
        };
        PasswordWrapper::new(pw)
            .unwrap(&check)
            .await
            .map_err(|_| "that's not this vault's master password".to_string())?;
        enroll_login_verifier(&api, pw, &blob).await?;
    }
    // Make sure the server actually holds the vault, so another device pulls real data (not "0").
    let current = api.get_vault().await?.map(|(v, _)| v).unwrap_or(0);
    push_document(&api, &vk, &state, current).await
}

/// Unlock this (fresh) device from the sync server with the account master password: download the
/// escrowed Wrapper-D blob, unwrap it, adopt the shared key, and pull the vault. The device must be
/// signed in (Google/bootstrap) and have no local vault yet.
#[tauri::command]
pub async fn sync_unlock_with_password(
    state: State<'_, AppState>,
    password: String,
) -> Result<RestoreOut, String> {
    // Only ever unlock onto an empty device — never clobber an existing local vault.
    {
        let g = state.inner.lock().unwrap();
        if !g.vault.list_envelopes().map_err(estr)?.is_empty() {
            return Err("this device already has a vault".into());
        }
    }

    let api = api_for(&state)?;
    let blob = WrappedBlob {
        wrapper: WrapperType::Password,
        bytes: api.get_wrapped_key(WrapperType::Password.code()).await?,
    };
    let vk = PasswordWrapper::new(&password)
        .unwrap(&blob)
        .await
        .map_err(|_| "wrong master password".to_string())?;

    // Re-assert empty AND adopt the shared key in one locked section (mirrors sync_restore).
    {
        let mut g = state.inner.lock().unwrap();
        if !g.vault.list_envelopes().map_err(estr)?.is_empty() {
            return Err("this device already has a vault".into());
        }
        g.session = VaultSession::unlocked(vk.clone());
    }
    // v0.1.57: this device just proved the master password, so make it require the password on every
    // launch too (mirror sync_password_signin) rather than persisting a plaintext key.
    make_password_protected(&data_dir(&state), &blob.bytes, &vk);

    let mut restored = 0i64;
    if let Some((v, ct)) = api.get_vault().await? {
        let doc = decode_sync_blob(&vk, &ct, v as u64).map_err(estr)?;
        let report = {
            let g = state.inner.lock().unwrap();
            g.vault.merge(&doc).map_err(estr)?
        };
        restored = report.added as i64;
    }
    // We hold the password and a session: make sure master-password SIGN-IN (not just unlock)
    // is enrolled, so the next device needs nothing but address + password. Best-effort — an
    // old server without the endpoint changes nothing.
    let _ = enroll_login_verifier(&api, &password, &blob.bytes).await;
    let _ = sync_device_settings(&state);
    Ok(RestoreOut { restored })
}

// ---------------------------------------------------------------------------
// THE login (v0.1.48): server address + master password (+ 6-digit code)
// ---------------------------------------------------------------------------

/// `1.2.3.4`, `https://1.2.3.4`, `sync.example.com` → (`https://host`, `host`).
fn normalize_addr(address: &str) -> Result<(String, String), String> {
    let a = address.trim().trim_end_matches('/');
    if a.is_empty() {
        return Err("enter your server's address (the IP from the computer that set it up)".into());
    }
    let host = a
        .strip_prefix("https://")
        .or_else(|| a.strip_prefix("http://"))
        .unwrap_or(a)
        .split('/')
        .next()
        .unwrap_or(a)
        .to_string();
    Ok((format!("https://{host}"), host))
}

/// Short human-comparable fingerprint of a PEM cert: SHA-256 of the DER, first 8 bytes as
/// `AB12-CD34-EF56-7890`. Matches what another signed-in device displays.
fn cert_fingerprint(pem: &str) -> Option<String> {
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----") && !l.trim().is_empty())
        .collect();
    let der = STANDARD.decode(body).ok()?;
    let hash = <sha2::Sha256 as sha2::Digest>::digest(&der);
    let hex: Vec<String> = hash[..8].iter().map(|b| format!("{b:02X}")).collect();
    Some(format!(
        "{}{}-{}{}-{}{}-{}{}",
        hex[0], hex[1], hex[2], hex[3], hex[4], hex[5], hex[6], hex[7]
    ))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOut {
    pub cert_pem: Option<String>,
    pub fingerprint: Option<String>,
    pub server_version: Option<String>,
    /// False until a signed-in device has turned on master-password sign-in (or the server
    /// predates the endpoint — the UI copy covers both).
    pub password_signin_ready: bool,
}

/// First contact with a server by bare address: fetch its identity (version + the cert to pin)
/// over a deliberately-unverified TLS connection. Trust-on-first-use — nothing sensitive is sent
/// on this connection, and the UI shows the fingerprint to compare against another device before
/// the sign-in proceeds over the PINNED connection.
#[tauri::command]
pub async fn sync_probe_server(address: String) -> Result<ProbeOut, String> {
    let (base, _host) = normalize_addr(&address)?;
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(6))
        .build()
        .map_err(estr)?;
    let meta: serde_json::Value = http
        .get(format!("{base}/v1/meta"))
        .send()
        .await
        .map_err(|e| format!("couldn't reach {base}: {e}"))?
        .error_for_status()
        .map_err(|_| {
            "that server didn't identify itself — it may be too old (update or redeploy it), or the address is wrong"
                .to_string()
        })?
        .json()
        .await
        .map_err(estr)?;
    let cert_pem = meta["cert_pem"].as_str().map(str::to_string);
    let fingerprint = cert_pem.as_deref().and_then(cert_fingerprint);
    let ready = http
        .get(format!("{base}/v1/auth/password/params"))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false);
    Ok(ProbeOut {
        cert_pem,
        fingerprint,
        server_version: meta["version"].as_str().map(str::to_string),
        password_signin_ready: ready,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordSigninOut {
    /// True = the account has 2-step sign-in; re-submit with the 6-digit code.
    pub totp_required: bool,
    pub restored: i64,
}

/// v0.1.57 — make a freshly-adopted device require the master password on every launch when the
/// account has one. `escrow` is the server's Password-wrapped key: if it's a valid `SNTL` Password
/// wrapper we write it as this device's local wrapper (so the next boot boots LOCKED and demands the
/// password) and drop the plaintext keychain key. If the account has NO master password (the escrow
/// isn't a Password wrapper) — or writing the wrapper fails — we keep the plaintext key so the device
/// stays usable (unlocked-by-default). Best-effort and infallible: a device is NEVER left with
/// neither a wrapper nor a key, which would brick it on the next launch.
fn make_password_protected(dir: &std::path::Path, escrow: &[u8], vk: &VaultKey) {
    if crate::state::password_protected(dir) {
        return; // already requires the password on this device — leave its wrapper alone
    }
    let is_password_wrap =
        escrow.len() >= 8 && &escrow[0..4] == b"SNTL" && escrow[5] == WrapperType::Password.code();
    if is_password_wrap && std::fs::write(crate::state::wrap_path(dir), escrow).is_ok() {
        let _ = crate::state::delete_key(); // password is now the only way in
    } else {
        let _ = kc_set(KC_VAULT_KEY, &STANDARD.encode(vk.key().as_bytes()));
    }
}

/// The one login: point this device at a server (pinning the probed cert), prove the master
/// password, and pull the vault. Everything a new computer needs.
#[tauri::command]
pub async fn sync_password_signin(
    state: State<'_, AppState>,
    address: String,
    cert_pem: Option<String>,
    password: String,
    code: Option<String>,
) -> Result<PasswordSigninOut, String> {
    let (plain_base, host) = normalize_addr(&address)?;
    let dir = data_dir(&state);

    // Point the config at the server the same way deploy/join do, so every later call (sync,
    // devices, updates) uses the pinned client unchanged.
    let mut cfg = load_config(&dir);
    match cert_pem.as_deref().filter(|p| !p.trim().is_empty()) {
        Some(pem) => {
            cfg.server_url = Some(format!("https://{SYNC_HOST}"));
            cfg.server_ip = Some(host.clone());
            cfg.pinned_cert_pem = Some(pem.to_string());
        }
        None => {
            // Real-CA server (custom domain): plain TLS, no pin.
            cfg.server_url = Some(plain_base.clone());
            cfg.server_ip = None;
            cfg.pinned_cert_pem = None;
        }
    }
    save_config(&dir, &cfg)?;
    let http = sync_http_client(&cfg);
    let base = format!(
        "{}/v1",
        cfg.server_url.clone().unwrap().trim_end_matches('/')
    );

    // KDF parameters (the salt) — public, but only present once sign-in is enabled.
    let resp = http
        .get(format!("{base}/auth/password/params"))
        .send()
        .await
        .map_err(|e| format!("couldn't reach the server: {e}"))?;
    if resp.status().as_u16() == 404 {
        return Err(
            "Master-password sign-in isn't turned on for this server yet. On a computer that already has your vault: unlock it once (or use Account & Sync → Turn on master-password sign-in), then try again. If the server is old, click Update server first."
                .into(),
        );
    }
    if !resp.status().is_success() {
        return Err(format!("server error: HTTP {}", resp.status()));
    }
    #[derive(Deserialize)]
    struct Params {
        salt_b64: String,
    }
    let p: Params = resp.json().await.map_err(estr)?;
    let salt_vec = STANDARD.decode(p.salt_b64.trim()).map_err(estr)?;
    let salt: [u8; 16] = salt_vec
        .try_into()
        .map_err(|_| "server sent a malformed salt".to_string())?;

    // Argon2 is deliberately slow — off the async runtime.
    let pw = password.clone();
    let proof = tokio::task::spawn_blocking(move || PasswordWrapper::new(&pw).login_proof(&salt))
        .await
        .map_err(estr)?;

    let mut body = json!({
        "proof_b64": STANDARD.encode(proof.as_bytes()),
        "device": { "name": device_name(), "platform": platform_str() },
    });
    if let Some(c) = code.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
        body["code"] = json!(c);
    }
    let resp = http
        .post(format!("{base}/auth/password"))
        .json(&body)
        .send()
        .await
        .map_err(estr)?;
    if resp.status().as_u16() == 400 {
        let v: serde_json::Value = resp.json().await.unwrap_or_default();
        if v["detail"] == "totp_required" {
            return Ok(PasswordSigninOut {
                totp_required: true,
                restored: 0,
            });
        }
        return Err(format!(
            "sign-in rejected: {}",
            v["detail"].as_str().unwrap_or("bad request")
        ));
    }
    if resp.status().as_u16() == 401 {
        return Err(if code.is_some() {
            "wrong master password or 6-digit code".into()
        } else {
            "wrong master password".into()
        });
    }
    if !resp.status().is_success() {
        return Err(format!("sign-in failed: HTTP {}", resp.status()));
    }
    let t: ServerTokens = resp.json().await.map_err(estr)?;
    kc_set(KC_ACCESS, &t.access_token)?;
    kc_set(KC_REFRESH, &t.refresh_token)?;

    // Signed in — now do exactly what "Unlock this device with your master password" does:
    // download the escrowed key, unwrap, adopt (only onto an empty vault), and pull.
    let api = api_for(&state)?;
    let blob = WrappedBlob {
        wrapper: WrapperType::Password,
        bytes: api.get_wrapped_key(WrapperType::Password.code()).await?,
    };
    let vk = PasswordWrapper::new(&password)
        .unwrap(&blob)
        .await
        .map_err(|_| {
            "signed in, but the escrowed key didn't unwrap — was the master password changed on another device?"
                .to_string()
        })?;

    let already_has_vault = {
        let mut g = state.inner.lock().unwrap();
        let empty = g.vault.list_envelopes().map_err(estr)?.is_empty();
        if empty {
            g.session = VaultSession::unlocked(vk.clone());
        }
        !empty
    };
    let mut restored = 0i64;
    if !already_has_vault {
        // The account is password-protected (that's the only way this sign-in path succeeds), so
        // make THIS new device require the master password on every launch too — otherwise it would
        // boot UNLOCKED with the whole vault sitting open. The escrow we just unwrapped IS a valid
        // local wrapper. This run stays unlocked via the in-memory session set above; the next
        // launch boots locked and demands the password.
        make_password_protected(&dir, &blob.bytes, &vk);
        if let Some((v, ct)) = api.get_vault().await? {
            let doc = decode_sync_blob(&vk, &ct, v as u64).map_err(estr)?;
            let report = {
                let g = state.inner.lock().unwrap();
                g.vault.merge(&doc).map_err(estr)?
            };
            restored = report.added as i64;
        }
    }
    let _ = sync_device_settings(&state);
    Ok(PasswordSigninOut {
        totp_required: false,
        restored,
    })
}

// ---------------------------------------------------------------------------
// Settings sync (v0.1.49): device configuration rides the encrypted vault
// ---------------------------------------------------------------------------
// A hidden system item inside the vault carries the API credentials a device needs to be fully
// capable (Linode token, Google sign-in client). It syncs, merges (fixed id + last-writer-wins),
// and is end-to-end encrypted exactly like every password — the server can't read the tokens.
// Every list UI filters SYSTEM_TAG so the item never appears next to real logins.

/// Fixed id of the hidden settings item (fixed so concurrent devices merge, never duplicate).
const SETTINGS_ITEM_ID: &str = "a11d0e5e-771e-4b8a-9f30-0c0ffee5e771";
/// Tag marking system items — `vault_list` (desktop) and the phone's list filter it out.
pub const SYSTEM_TAG: &str = "northkey:system";

const SET_LINODE: &str = "linode_token";
const SET_GCLIENT: &str = "google_client_id";
const SET_GSECRET: &str = "google_client_secret";
const SET_HETZNER: &str = "hetzner_token";
const SET_NETDATA: &str = "netdata_config";
// v0.1.57 — the rest of a device's configuration, so a new device rehydrates fully on first login.
// All additive (the phone + old desktops ignore fields they don't know). SET_NDAUTH and SET_AOVPN
// carry secrets (a Netdata login header, the always-on node's client key) but ride the same
// end-to-end-encrypted item — the server still only ever sees ciphertext.
const SET_PREFS: &str = "app_prefs";
const SET_WATCHDOG: &str = "watchdog_cfg";
const SET_NDAUTH: &str = "netdata_auth";
const SET_AOVPN: &str = "always_on_vpn";

fn settings_item_id() -> uuid::Uuid {
    uuid::Uuid::parse_str(SETTINGS_ITEM_ID).expect("const uuid")
}

/// Current local values (empty string = unset), in stable field order.
fn local_settings(state: &State<'_, AppState>) -> Vec<(&'static str, String)> {
    let dir = data_dir(state);
    let cfg = load_config(&dir);
    vec![
        (SET_LINODE, crate::vpn::get_token().unwrap_or_default()),
        (SET_GCLIENT, cfg.google_client_id.unwrap_or_default()),
        (SET_GSECRET, kc_get(KC_GSECRET).unwrap_or_default()),
        (
            SET_HETZNER,
            crate::servers::hetzner_get_token().unwrap_or_default(),
        ),
        (SET_NETDATA, crate::servers::netdata_config_json(&dir)),
        (SET_PREFS, crate::commands::prefs_sync_export(&dir)),
        (SET_WATCHDOG, crate::servers::watchdog_config_json(&dir)),
        (SET_NDAUTH, crate::servers::netdata_auth_json(&dir)),
        (SET_AOVPN, crate::vpn::persistent_sync_export(&dir)),
    ]
}

/// Apply the synced settings item to this device (pull direction), or seed the item from local
/// settings when the vault has none yet (so the device that already had the tokens shares them).
/// Runs after every pull/merge; best-effort — a failure never breaks the sync that invoked it.
/// Returns true when it changed the LOCAL VAULT (caller's push then carries the seed).
pub(crate) fn sync_device_settings(state: &State<'_, AppState>) -> bool {
    let id = settings_item_id();
    let item: Option<Item> = {
        let g = state.inner.lock().unwrap();
        match g.vault.get(id) {
            Ok(Some(env)) => g.session.open(&env).ok(),
            _ => None,
        }
    };
    match item {
        Some(item) => {
            // Vault → device. The vault copy is authoritative: local edits go through
            // `settings_sync_write`, which updates the item first.
            for f in &item.custom_fields {
                let v = f.value.trim();
                if v.is_empty() {
                    continue;
                }
                match f.name.as_str() {
                    SET_LINODE => {
                        if crate::vpn::get_token().as_deref() != Some(v) {
                            let _ = crate::vpn::set_token(v);
                        }
                    }
                    SET_GCLIENT => {
                        let dir = data_dir(state);
                        let mut cfg = load_config(&dir);
                        if cfg.google_client_id.as_deref() != Some(v) {
                            cfg.google_client_id = Some(v.to_string());
                            let _ = save_config(&dir, &cfg);
                        }
                    }
                    SET_GSECRET => {
                        if kc_get(KC_GSECRET).as_deref() != Some(v) {
                            let _ = kc_set(KC_GSECRET, v);
                        }
                    }
                    SET_HETZNER => {
                        if crate::servers::hetzner_get_token().as_deref() != Some(v) {
                            let _ = crate::servers::hetzner_set_token(v);
                        }
                    }
                    SET_NETDATA => {
                        crate::servers::apply_netdata_config_json(&data_dir(state), v);
                    }
                    SET_PREFS => {
                        crate::commands::apply_prefs_sync(&data_dir(state), v);
                    }
                    SET_WATCHDOG => {
                        crate::servers::apply_watchdog_config_json(&data_dir(state), v);
                    }
                    SET_NDAUTH => {
                        crate::servers::apply_netdata_auth_json(v);
                    }
                    SET_AOVPN => {
                        crate::vpn::persistent_sync_import(&data_dir(state), v);
                    }
                    _ => {}
                }
            }

            // Self-heal (device → vault). The apply loop above NEVER fills a field the synced item
            // is missing — so a token added on this device after the settings item was first created
            // (the classic case: a Hetzner token on a settings item that predates it) would never
            // reach the other devices, which is exactly why the phone showed Linode but not Hetzner.
            // After applying, `local_settings` is the union of the synced values and this device's
            // own; if that union carries anything the item lacks, rewrite the item so it propagates.
            // The apply loop already made local match every non-empty synced value, so this only
            // ever fills blanks (or a widened Netdata map) — it never clobbers an authoritative value.
            let locals = local_settings(state);
            let synced_of = |name: &str| -> String {
                item.custom_fields
                    .iter()
                    .find(|f| f.name == name)
                    .map(|f| f.value.trim().to_string())
                    .unwrap_or_default()
            };
            let needs_heal = locals
                .iter()
                .any(|(name, val)| !val.trim().is_empty() && val.trim() != synced_of(name));
            if needs_heal {
                return write_settings_item(state, locals).is_ok();
            }
            false
        }
        None => {
            // Device → vault (first seed). Only when something is actually set locally.
            let locals = local_settings(state);
            if locals.iter().all(|(_, v)| v.is_empty()) {
                return false;
            }
            write_settings_item(state, locals).is_ok()
        }
    }
}

/// Build/replace the settings item from the given values and store it in the local vault.
fn write_settings_item(
    state: &State<'_, AppState>,
    values: Vec<(&'static str, String)>,
) -> Result<(), String> {
    let now = chrono_now();
    let g = state.inner.lock().unwrap();
    let created_at = g
        .vault
        .get(settings_item_id())
        .ok()
        .flatten()
        .and_then(|env| g.session.open(&env).ok())
        .map(|i| i.created_at)
        .unwrap_or(now);
    let item = Item {
        id: settings_item_id(),
        item_type: sentinel_core::vault::model::ItemType::Note,
        title: "NorthKey device settings".into(),
        tags: vec![SYSTEM_TAG.into()],
        urls: vec![],
        notes: Some("Synced app configuration — managed automatically, hidden from lists.".into()),
        custom_fields: values
            .into_iter()
            .map(|(name, value)| sentinel_core::vault::model::CustomField {
                name: name.into(),
                value,
                secret: true,
            })
            .collect(),
        login: None,
        card: None,
        identity: None,
        passkey: None,
        created_at,
        updated_at: now,
        password_changed_at: None,
    };
    let env = g.session.seal(&item).map_err(estr)?;
    g.vault.upsert(&env).map_err(estr)
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Called by the frontend after any synced setting changes locally (Linode token, Google
/// client): refresh the vault item and push quietly so other devices pick it up.
#[tauri::command]
pub async fn settings_sync_write(state: State<'_, AppState>) -> Result<(), String> {
    let locals = local_settings(&state);
    let had_item = {
        let g = state.inner.lock().unwrap();
        matches!(g.vault.get(settings_item_id()), Ok(Some(_)))
    };
    if !had_item && locals.iter().all(|(_, v)| v.is_empty()) {
        return Ok(()); // nothing to share yet
    }
    write_settings_item(&state, locals)?;
    // Quiet best-effort push (same posture as try_push_vault after sign-in).
    if let (Ok(vk), Ok(api)) = (session_vault_key(&state), api_for(&state)) {
        let current = api.get_vault().await?.map(|(v, _)| v).unwrap_or(0);
        let _ = push_document(&api, &vk, &state, current).await;
    }
    Ok(())
}

/// A non-secret view of the shared-settings item for the "Shared settings" status panel: which
/// provider settings are present in the synced vault item and when it was last written. Only
/// booleans + a timestamp cross the bridge — never a token, id, or secret value.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsSyncStatus {
    /// A synced settings item exists in the local vault.
    pub present: bool,
    /// When the item was last written (unix seconds), 0 if none.
    pub updated_at: i64,
    pub linode: bool,
    pub google: bool,
    pub hetzner: bool,
    pub netdata: bool,
}

#[tauri::command]
pub async fn settings_sync_status(
    state: State<'_, AppState>,
) -> Result<SettingsSyncStatus, String> {
    let id = settings_item_id();
    let item: Option<Item> = {
        let g = state.inner.lock().unwrap();
        match g.vault.get(id) {
            Ok(Some(env)) => g.session.open(&env).ok(),
            _ => None,
        }
    };
    let Some(item) = item else {
        return Ok(SettingsSyncStatus {
            present: false,
            updated_at: 0,
            linode: false,
            google: false,
            hetzner: false,
            netdata: false,
        });
    };
    let set = |name: &str| {
        item.custom_fields
            .iter()
            .any(|f| f.name == name && !f.value.trim().is_empty())
    };
    Ok(SettingsSyncStatus {
        present: true,
        updated_at: item.updated_at,
        linode: set(SET_LINODE),
        google: set(SET_GCLIENT),
        hetzner: set(SET_HETZNER),
        netdata: set(SET_NETDATA),
    })
}

/// Enroll (or refresh) the master-password sign-in verifier from a type-4 SNTL blob + the
/// password. The salt is read from the blob so ONE Argon2 derivation on any client serves both
/// login and unwrap. Best-effort against old servers (404 = endpoint not there yet).
async fn enroll_login_verifier(api: &Api, password: &str, blob_bytes: &[u8]) -> Result<(), String> {
    if blob_bytes.len() < 24 {
        return Err("malformed wrapped-key blob".into());
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&blob_bytes[8..24]);
    let pw = password.to_string();
    let proof = tokio::task::spawn_blocking(move || PasswordWrapper::new(&pw).login_proof(&salt))
        .await
        .map_err(estr)?;
    let body = json!({
        "salt_b64": STANDARD.encode(salt),
        "verifier_b64": STANDARD.encode(proof.as_bytes()),
    });
    let resp = api
        .authed(
            reqwest::Method::POST,
            "/auth/password/enroll",
            &[],
            Some(body),
        )
        .await?;
    if resp.status().as_u16() == 404 {
        return Err("this server predates master-password sign-in — update it".into());
    }
    if !resp.status().is_success() {
        return Err(format!("enroll verifier: HTTP {}", resp.status()));
    }
    Ok(())
}

#[tauri::command]
pub async fn sync_devices(state: State<'_, AppState>) -> Result<Vec<DeviceOut>, String> {
    let api = api_for(&state)?;
    let resp = api
        .authed(reqwest::Method::GET, "/devices", &[], None)
        .await?;
    if !resp.status().is_success() {
        return Err(format!("list devices: HTTP {}", resp.status()));
    }
    #[derive(Deserialize)]
    struct D {
        id: String,
        name: String,
        platform: String,
        status: String,
        #[serde(default)]
        created_at: i64,
        #[serde(default)]
        current: bool,
    }
    #[derive(Deserialize)]
    struct Resp {
        devices: Vec<D>,
    }
    let r: Resp = resp.json().await.map_err(estr)?;
    Ok(r.devices
        .into_iter()
        .map(|d| DeviceOut {
            id: d.id,
            name: d.name,
            platform: d.platform,
            status: d.status,
            created_at: iso(d.created_at),
            current: d.current,
        })
        .collect())
}

#[tauri::command]
pub async fn sync_device_revoke(state: State<'_, AppState>, id: String) -> Result<(), String> {
    let api = api_for(&state)?;
    let resp = api
        .authed(
            reqwest::Method::DELETE,
            &format!("/devices/{id}"),
            &[],
            None,
        )
        .await?;
    if !resp.status().is_success() {
        return Err(format!("revoke device: HTTP {}", resp.status()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Attack monitor — read the sync server's security event log and manage IP bans.
// The server records auth outcomes (failed sign-ins, refresh-token replays, rate-limit
// trips) and — when enabled — auto-bans abusive IPs. These commands surface that on the
// Devices screen and drive the manual Block/Unblock control.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityEventOut {
    id: String,
    kind: String,
    ip: Option<String>,
    detail: Option<String>,
    created_at: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySummaryOut {
    last24h: std::collections::HashMap<String, i64>,
    banned_active: i64,
    autoban_enabled: bool,
}

#[tauri::command]
pub async fn sync_security_events(
    state: State<'_, AppState>,
    since: Option<i64>,
) -> Result<Vec<SecurityEventOut>, String> {
    let api = api_for(&state)?;
    let path = match since {
        Some(s) => format!("/security-events?since={s}"),
        None => "/security-events".to_string(),
    };
    let resp = api.authed(reqwest::Method::GET, &path, &[], None).await?;
    if !resp.status().is_success() {
        return Err(format!("security events: HTTP {}", resp.status()));
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct E {
        id: String,
        kind: String,
        #[serde(default)]
        ip: Option<String>,
        #[serde(default)]
        detail: Option<String>,
        #[serde(default)]
        created_at: i64,
    }
    #[derive(Deserialize)]
    struct Resp {
        events: Vec<E>,
    }
    let r: Resp = resp.json().await.map_err(estr)?;
    Ok(r.events
        .into_iter()
        .map(|e| SecurityEventOut {
            id: e.id,
            kind: e.kind,
            ip: e.ip,
            detail: e.detail,
            created_at: iso(e.created_at),
        })
        .collect())
}

#[tauri::command]
pub async fn sync_security_summary(
    state: State<'_, AppState>,
) -> Result<SecuritySummaryOut, String> {
    let api = api_for(&state)?;
    let resp = api
        .authed(reqwest::Method::GET, "/security-summary", &[], None)
        .await?;
    if !resp.status().is_success() {
        return Err(format!("security summary: HTTP {}", resp.status()));
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Resp {
        #[serde(default)]
        last24h: std::collections::HashMap<String, i64>,
        #[serde(default)]
        banned_active: i64,
        #[serde(default)]
        autoban_enabled: bool,
    }
    let r: Resp = resp.json().await.map_err(estr)?;
    Ok(SecuritySummaryOut {
        last24h: r.last24h,
        banned_active: r.banned_active,
        autoban_enabled: r.autoban_enabled,
    })
}

#[tauri::command]
pub async fn sync_ban_ip(
    state: State<'_, AppState>,
    ip: String,
    minutes: Option<i64>,
) -> Result<(), String> {
    let api = api_for(&state)?;
    let body = json!({ "ip": ip, "minutes": minutes });
    let resp = api
        .authed(
            reqwest::Method::POST,
            "/security-events/ban",
            &[],
            Some(body),
        )
        .await?;
    if !resp.status().is_success() {
        return Err(format!("block IP: HTTP {}", resp.status()));
    }
    Ok(())
}

#[tauri::command]
pub async fn sync_unban_ip(state: State<'_, AppState>, ip: String) -> Result<(), String> {
    let api = api_for(&state)?;
    let body = json!({ "ip": ip });
    let resp = api
        .authed(
            reqwest::Method::POST,
            "/security-events/unban",
            &[],
            Some(body),
        )
        .await?;
    if !resp.status().is_success() {
        return Err(format!("unblock IP: HTTP {}", resp.status()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// "Deploy my sync server" — one-click durable Linode running the prebuilt image over
// self-signed HTTPS, authed by a generated bootstrap token. No Google client id, no domain.
// ---------------------------------------------------------------------------

use sentinel_core::cloud::{CloudProvider, InstanceSpec, LinodeClient, SYNC_TAG};
use sentinel_core::provision::{render_sync_base64, SyncServerParams};

/// Tracks the durable sync-server node so status/destroy work across restarts. Secrets that
/// matter (the bootstrap token) live in the keychain; the pinned cert lives in `SyncConfig`.
#[derive(Serialize, Deserialize, Default, Clone)]
struct SyncServerRecord {
    instance_id: String,
    ipv4: String,
    instance_type: String,
    region: String,
    created_at: i64,
}

fn server_record_path(dir: &Path) -> PathBuf {
    dir.join("sync-server.json")
}
fn load_server_record(dir: &Path) -> Option<SyncServerRecord> {
    std::fs::read_to_string(server_record_path(dir))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
}
fn save_server_record(dir: &Path, rec: &SyncServerRecord) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(estr)?;
    std::fs::write(
        server_record_path(dir),
        serde_json::to_string_pretty(rec).map_err(estr)?,
    )
    .map_err(estr)
}
fn delete_server_record(dir: &Path) {
    let _ = std::fs::remove_file(server_record_path(dir));
}

fn now_unix() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// A random lowercase-hex string of `bytes` bytes.
fn rand_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn emit_deploy(app: &AppHandle, stage: &str, detail: &str) {
    let _ = app.emit("sync:deploy", json!({ "stage": stage, "detail": detail }));
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncServerStatusOut {
    deployed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    hourly_usd: f64,
    monthly_usd: f64,
}

/// Current deployed-sync-server status (from the local record + a live Linode `get`).
#[tauri::command]
pub async fn sync_server_status(state: State<'_, AppState>) -> Result<SyncServerStatusOut, String> {
    let dir = data_dir(&state);
    let Some(rec) = load_server_record(&dir) else {
        return Ok(SyncServerStatusOut {
            deployed: false,
            ipv4: None,
            state: None,
            hourly_usd: 0.0,
            monthly_usd: 0.0,
        });
    };
    let token = crate::vpn::get_token().ok_or("no Linode token configured")?;
    let cloud = LinodeClient::new(token);
    let hourly = cloud.price_per_hour(&rec.instance_type);
    let live = cloud.get(&rec.instance_id).await.ok();
    Ok(SyncServerStatusOut {
        deployed: true,
        ipv4: Some(rec.ipv4.clone()),
        state: live.map(|i| format!("{:?}", i.state).to_lowercase()),
        hourly_usd: hourly,
        monthly_usd: hourly * 24.0 * 30.0,
    })
}

/// Provision a durable Linode running the sync server, wire the app to it, and sign in via the
/// generated bootstrap token. Long-running (a fresh box installs Docker + pulls the image); emits
/// `sync:deploy` progress events.
#[tauri::command]
pub async fn sync_deploy(
    app: AppHandle,
    state: State<'_, AppState>,
    region: String,
    instance_type: Option<String>,
    google_client_id: Option<String>,
    google_client_secret: Option<String>,
) -> Result<(), String> {
    let dir = data_dir(&state);
    if load_server_record(&dir).is_some() {
        return Err("a sync server is already deployed — destroy it first".into());
    }
    let token = crate::vpn::get_token()
        .ok_or("set a Linode API token first (Settings → Real VPN) — the deploy reuses it")?;
    let itype = instance_type.unwrap_or_else(|| "g6-nanode-1".to_string());
    // When set, the server validates real Google id_tokens and this device signs in with
    // Google (+ TOTP) instead of the bootstrap token. Empty ⇒ the personal bootstrap flow.
    let google_client_id = google_client_id
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    // The client SECRET stays on this device (keychain) — only the desktop's code→token
    // exchange needs it; the server validates id_tokens with just the client id.
    if google_client_id.is_some() {
        if let Some(secret) = google_client_secret
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
        {
            kc_set(KC_GSECRET, &secret)?;
        }
    }

    // 1) Generate everything client-side so we know the secrets + the exact cert to pin.
    emit_deploy(&app, "creating", "generating keys…");
    let bootstrap_token = rand_hex(32);
    let db_password = rand_hex(16);
    // The TOTP encryption key is a REQUIRED production secret — base64 of 32 random bytes. Without
    // it the server refuses to boot under SENTINEL_ENV=production and crash-loops (so /healthz never
    // answers and the deploy can never sign in). Generated on-device like the other secrets.
    let totp_enc_key = {
        use rand::RngCore as _;
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        STANDARD.encode(b)
    };
    let certified = rcgen::generate_simple_self_signed(vec![SYNC_HOST.to_string()])
        .map_err(|e| format!("generate cert: {e}"))?;
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();

    let user_data = render_sync_base64(&SyncServerParams {
        image_ref: sync_image_ref(),
        bootstrap_token: bootstrap_token.clone(),
        db_password,
        tls_cert_b64: STANDARD.encode(cert_pem.as_bytes()),
        tls_key_b64: STANDARD.encode(key_pem.as_bytes()),
        totp_enc_key,
        google_client_id: google_client_id.clone().unwrap_or_default(),
    })
    .map_err(estr)?;

    // 2) Create the durable (sentinel-sync-tagged) node.
    emit_deploy(&app, "creating", "creating the Linode…");
    let cloud = LinodeClient::new(token);
    let spec = InstanceSpec {
        region: region.clone(),
        instance_type: itype.clone(),
        user_data,
        label: "sentinel-sync".into(),
        tags: vec![SYNC_TAG.to_string()],
    };
    let inst = cloud.create(&spec).await.map_err(estr)?;

    // 3) Resolve the IP (assigned at create; poll a few times if not yet present).
    let mut ipv4 = inst.ipv4.clone();
    for _ in 0..20 {
        if ipv4.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
            break;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        if let Ok(cur) = cloud.get(&inst.id).await {
            ipv4 = cur.ipv4.clone();
        }
    }
    let ipv4 = match ipv4.filter(|s| !s.is_empty()) {
        Some(ip) => ip,
        None => {
            let _ = cloud.delete(&inst.id).await; // don't leave a billing box on failure
            return Err("the server never reported an IP; it was destroyed".into());
        }
    };

    // 4) Persist the record + wire the app to the pinned server BEFORE the health wait, so a
    //    crash mid-wait still lets the user see/destroy the node.
    save_server_record(
        &dir,
        &SyncServerRecord {
            instance_id: inst.id.clone(),
            ipv4: ipv4.clone(),
            instance_type: itype,
            region,
            created_at: now_unix(),
        },
    )?;
    {
        let mut cfg = load_config(&dir);
        cfg.server_url = Some(format!("https://{SYNC_HOST}"));
        cfg.pinned_cert_pem = Some(cert_pem);
        cfg.server_ip = Some(ipv4.clone());
        // Store the Google client id (if any) so the pinned "Sign in with Google" flow can run
        // its PKCE against this exact server without the user re-typing it.
        cfg.google_client_id = google_client_id.clone();
        save_config(&dir, &cfg)?;
    }
    kc_set(KC_BOOTSTRAP, &bootstrap_token)?;

    // 5) Wait for the server to finish installing (Docker + image pull + Postgres + migrate can
    //    take a few minutes) by polling /healthz over the pinned HTTPS.
    emit_deploy(
        &app,
        "provisioning",
        "installing the server (this can take a few minutes)…",
    );
    let client = sync_http_client(&load_config(&dir));
    let health_url = format!("https://{SYNC_HOST}/healthz");
    let mut healthy = false;
    for _ in 0..80 {
        // ~80 × 5s ≈ 6.5 min
        if let Ok(resp) = client.get(&health_url).send().await {
            if resp.status().is_success() {
                healthy = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    if !healthy {
        return Err(
            "the server didn't answer its health check in time. A first boot installs Docker and \
             pulls the image, which can occasionally run long — the node is saved, so give it a \
             minute and press Reconnect to finish signing in without redeploying."
                .into(),
        );
    }

    // 6) Sign in. A Google-enabled server can't be signed into from here — that needs the
    //    interactive browser PKCE + TOTP flow — so we stop at "ready" and the UI drives
    //    "Sign in with Google". A bootstrap-only (personal) server signs this device in now.
    if google_client_id.is_some() {
        emit_deploy(
            &app,
            "ready",
            "server ready — sign in with Google to finish",
        );
    } else {
        emit_deploy(&app, "connecting", "signing in…");
        bootstrap_signin(&dir).await?;
        // Upload the vault right away so a second device joining this server never pulls
        // an empty one (the old behavior silently left the server without a vault).
        if try_push_vault(&state).await.is_some() {
            emit_deploy(&app, "ready", "sync server ready — vault uploaded");
        } else {
            emit_deploy(&app, "ready", "sync server ready");
        }
    }
    Ok(())
}

/// Exchange the stored bootstrap token for an access/refresh session (mirrors the Google path's
/// token handling, but with no TOTP step).
async fn bootstrap_signin(dir: &Path) -> Result<(), String> {
    let token = kc_get(KC_BOOTSTRAP).ok_or("no bootstrap token — redeploy the sync server")?;
    let cfg = load_config(dir);
    let base = cfg
        .server_url
        .clone()
        .ok_or("no sync server configured")?
        .trim_end_matches('/')
        .to_string();
    let client = sync_http_client(&cfg);
    let resp = client
        .post(format!("{base}/v1/auth/bootstrap"))
        .json(&json!({
            "token": token,
            "device": { "name": device_name(), "platform": platform_str() },
        }))
        .send()
        .await
        .map_err(estr)?;
    if !resp.status().is_success() {
        return Err(format!("bootstrap sign-in failed: HTTP {}", resp.status()));
    }
    let t: ServerTokens = resp.json().await.map_err(estr)?;
    kc_set(KC_ACCESS, &t.access_token)?;
    kc_set(KC_REFRESH, &t.refresh_token)?;
    Ok(())
}

fn platform_str() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// Destroy the deployed sync server (stops billing) and clear all local sync state.
#[tauri::command]
pub async fn sync_server_destroy(state: State<'_, AppState>) -> Result<(), String> {
    let dir = data_dir(&state);
    if let Some(rec) = load_server_record(&dir) {
        if let Some(token) = crate::vpn::get_token() {
            let cloud = LinodeClient::new(token);
            let _ = cloud.delete(&rec.instance_id).await;
        }
    }
    delete_server_record(&dir);
    // Clear the pinned-server config + all session state.
    let mut cfg = load_config(&dir);
    cfg.server_url = None;
    cfg.pinned_cert_pem = None;
    cfg.server_ip = None;
    cfg.email = None;
    save_config(&dir, &cfg)?;
    kc_del(KC_BOOTSTRAP);
    kc_del(KC_ACCESS);
    kc_del(KC_REFRESH);
    kc_del(KC_PENDING);
    kc_del(KC_GSECRET);
    Ok(())
}

// ---------------------------------------------------------------------------
// Reconnect + device pairing.
//
// `sync_deploy` saves the server record + pinned config + bootstrap token BEFORE the health
// wait and the initial sign-in, so a deploy whose sign-in step timed out (first boot installs
// Docker + pulls the image + migrates, which can exceed the wait) leaves a "server up but this
// device not signed in" state with no way to finish. `sync_reconnect` re-runs just the client
// sign-in against the already-configured server — no destroy/redeploy, no lost billing.
//
// Device pairing lets a SECOND machine join a one-click server without any manual URL/cert/token
// entry: device #1 mints a one-shot "join code" carrying the server IP, the pinned cert, the
// (reusable, same-account) bootstrap token, and the vault key; device #2 pastes it to configure
// the pinned client, sign in as another device on the same account, adopt the shared vault key,
// and pull the vault. The code is a full-access secret (like the recovery kit) — shown once.
// ---------------------------------------------------------------------------

/// Prefix identifying a NorthKey device-join code (version 1).
const JOIN_PREFIX: &str = "SNTL1.";

/// The payload packed into a device-join code. base64url(JSON) of this, behind `JOIN_PREFIX`.
#[derive(Serialize, Deserialize)]
struct JoinBundle {
    /// Format version (1).
    v: u8,
    /// The deployed server's IPv4 (the pinned client resolves `sentinel-sync` to it).
    ip: String,
    /// The server's self-signed cert PEM to pin.
    cert: String,
    /// The reusable bootstrap token — every bootstrap device maps to the one shared account.
    token: String,
    /// base64 (std) of the 32-byte vault key device #2 needs to decrypt the synced vault.
    vkey: String,
    /// Unix timestamp the code was minted (for staleness display only).
    ts: i64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncReconnectOut {
    signed_in: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairCodeOut {
    code: String,
    created_at: String,
    /// SVG of the phone-onboarding QR: `{v:2, ip, cert, enroll, ts}` — server address, TLS pin,
    /// and a one-time enrollment code. No key material (the vault needs the master password).
    /// `None` when the server predates `/v1/enroll-codes` (text code still works).
    qr_svg: Option<String>,
    qr_expires_at: Option<i64>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairCompleteOut {
    restored: i64,
    server_ip: String,
}

/// Ask the sync server to update itself to the latest published image. The server's host does the
/// pull+recreate (a systemd path unit watching a flag file); expect ~30s of downtime. Servers
/// deployed before the updater existed return a clear "redeploy once" error.
#[tauri::command]
pub async fn sync_server_update(state: State<'_, AppState>) -> Result<(), String> {
    let api = api_for(&state)?;
    let resp = api
        .authed(reqwest::Method::POST, "/admin/update", &[], Some(json!({})))
        .await?;
    if resp.status().is_success() {
        Ok(())
    } else if resp.status().as_u16() == 400 {
        Err(
            "This server was deployed before in-place updates existed. Destroy + redeploy it once \
             (your vault re-uploads automatically after sign-in) — every server after that updates \
             itself."
                .into(),
        )
    } else {
        Err(format!("update request failed: HTTP {}", resp.status()))
    }
}

/// Finish (or repair) sign-in to an already-configured one-click server. Idempotent: if this
/// device is already signed in it returns success without contacting the server.
#[tauri::command]
pub async fn sync_reconnect(state: State<'_, AppState>) -> Result<SyncReconnectOut, String> {
    let dir = data_dir(&state);
    let cfg = load_config(&dir);
    if cfg.server_url.as_deref().unwrap_or("").is_empty()
        || cfg.pinned_cert_pem.is_none()
        || cfg.server_ip.is_none()
    {
        return Err(
            "No one-click sync server is set up on this device yet — deploy one first, \
             or join an existing server with a device code."
                .into(),
        );
    }
    if kc_get(KC_BOOTSTRAP).is_none() {
        return Err(
            "This device has no saved server login — destroy the server and redeploy, \
             or re-join it with a device code."
                .into(),
        );
    }
    // Already signed in — nothing to do.
    if kc_get(KC_ACCESS).is_some() {
        return Ok(SyncReconnectOut { signed_in: true });
    }
    // Probe health over the pinned client (user-initiated retry → short budget).
    let client = sync_http_client(&cfg);
    let health_url = format!("https://{SYNC_HOST}/healthz");
    let mut healthy = false;
    for _ in 0..10 {
        if let Ok(resp) = client.get(&health_url).send().await {
            if resp.status().is_success() {
                healthy = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    if !healthy {
        return Err(
            "Your sync server is running but its app hasn't answered yet. If you just \
             deployed it, give it another minute (first boot installs everything) and try again. \
             If this keeps happening, Destroy it and redeploy."
                .into(),
        );
    }
    bootstrap_signin(&dir).await?;
    // Signed in — make sure the server actually holds this device's vault.
    let _ = try_push_vault(&state).await;
    Ok(SyncReconnectOut { signed_in: true })
}

/// Mint a one-shot device-join code for another machine to join THIS device's sync server.
/// Requires a configured one-click server (pinned cert + IP + bootstrap token) on this device.
/// Pushes the vault FIRST, so the joining device always has something real to pull.
#[tauri::command]
pub async fn sync_pair_begin(state: State<'_, AppState>) -> Result<PairCodeOut, String> {
    let dir = data_dir(&state);
    let cfg = load_config(&dir);
    let ip = cfg.server_ip.clone().filter(|s| !s.is_empty()).ok_or(
        "This device isn't connected to a one-click sync server, so there's nothing to pair to.",
    )?;
    let cert = cfg
        .pinned_cert_pem
        .clone()
        .filter(|s| !s.is_empty())
        .ok_or(
            "Missing the server certificate — reconnect this device to the sync server first.",
        )?;
    let token = kc_get(KC_BOOTSTRAP)
        .ok_or("Missing this device's server login — reconnect to the sync server first.")?;
    // The vault key device #2 needs to decrypt the shared, end-to-end-encrypted vault. Taken from
    // the live session (never load_or_create_key, which would mint a WRONG key under a master
    // password) — so a locked vault gives a clean "unlock first" error, not a bad pairing code.
    let vk = session_vault_key(&state)?;
    // Upload this device's vault before handing out the code — a code minted against an empty
    // server is exactly the "joined and pulled 0 items" trap.
    {
        let api = api_for(&state)?;
        let current = api.get_vault().await?.map(|(v, _)| v).unwrap_or(0);
        push_document(&api, &vk, &state, current).await.map_err(|e| {
            format!("Couldn't upload your vault first ({e}). Use Reconnect / sign in on this device, then try again.")
        })?;
    }
    let vkey = STANDARD.encode(vk.key().as_bytes());
    let ts = now_unix();

    // Phone-onboarding QR: mint a one-time enrollment code and render {v:2, ip, cert, enroll, ts}
    // as a QR the iPhone scans instead of hand-typing a URL + token. Best-effort — a server that
    // predates /v1/enroll-codes just gets no QR (the desktop text code below still works).
    let (qr_svg, qr_expires_at) = {
        let api = api_for(&state)?;
        match api
            .authed(reqwest::Method::POST, "/enroll-codes", &[], Some(json!({})))
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                #[derive(Deserialize)]
                struct Minted {
                    code: String,
                    expires_at: i64,
                }
                match resp.json::<Minted>().await {
                    Ok(m) => {
                        let payload = serde_json::to_string(&json!({
                            "v": 2,
                            "ip": &ip,
                            "cert": &cert,
                            "enroll": m.code,
                            "ts": ts,
                        }))
                        .map_err(estr)?;
                        (crate::applock::qr_svg(&payload).ok(), Some(m.expires_at))
                    }
                    Err(_) => (None, None),
                }
            }
            _ => (None, None),
        }
    };

    let bundle = JoinBundle {
        v: 1,
        ip,
        cert,
        token,
        vkey,
        ts,
    };
    let json = serde_json::to_vec(&bundle).map_err(estr)?;
    let code = format!("{JOIN_PREFIX}{}", URL_SAFE_NO_PAD.encode(json));
    Ok(PairCodeOut {
        code,
        created_at: iso(ts),
        qr_svg,
        qr_expires_at,
    })
}

/// Join the sync server described by a device-join code from another machine. Only runs on a
/// fresh install with an empty local vault (so it can never overwrite existing items).
#[tauri::command]
pub async fn sync_pair_complete(
    state: State<'_, AppState>,
    code: String,
) -> Result<PairCompleteOut, String> {
    // Parse + validate the code first — no state changes on malformed/typo'd input.
    let body = code.trim().strip_prefix(JOIN_PREFIX).ok_or(
        "That doesn't look like a NorthKey device code. Copy the whole code from the other device.",
    )?;
    let json = URL_SAFE_NO_PAD.decode(body.as_bytes()).map_err(|_| {
        "The device code is malformed or was cut off. Copy the whole thing and try again."
            .to_string()
    })?;
    let bundle: JoinBundle = serde_json::from_slice(&json).map_err(|_| {
        "The device code is malformed. Copy the whole thing and try again.".to_string()
    })?;
    if bundle.v != 1 {
        return Err(
            "This device code is from a newer version of NorthKey. Update this app and try again."
                .into(),
        );
    }
    let key_bytes = STANDARD
        .decode(bundle.vkey.as_bytes())
        .map_err(|_| "The device code carried an invalid vault key.".to_string())?;
    let arr: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "The device code carried an invalid vault key.".to_string())?;
    let vk = VaultKey::from_key(Key32::from_bytes(arr));

    // Refuse a non-empty vault AND adopt the shared key in ONE locked section, so that between the
    // emptiness check and the key swap no concurrent vault_save can seal an item under this device's
    // about-to-be-replaced local key — which would orphan it (a mismatched-key envelope that then
    // propagates to every device on the next sync). The lock is held only for these in-memory ops.
    {
        let mut g = state.inner.lock().unwrap();
        if !g.vault.list_envelopes().map_err(estr)?.is_empty() {
            return Err(
                "This device already has a vault. Device pairing only works on a fresh \
                 install with an empty vault, so it can't overwrite what's already here."
                    .into(),
            );
        }
        g.session = VaultSession::unlocked(vk.clone());
    }
    // Persist the shared key to the keychain BEFORE sign-in, so an interruption can never leave a
    // signed-in device operating on a stale local key (which could later push an empty/mis-keyed
    // vault over the shared one). If sign-in below fails, the device is recoverable via Reconnect.
    kc_set(KC_VAULT_KEY, &STANDARD.encode(vk.key().as_bytes()))?;

    // Wire the pinned server config (server_url is the fixed hostname the pinned client resolves),
    // store the bootstrap token, then sign in as another device on the same account.
    let dir = data_dir(&state);
    {
        let mut cfg = load_config(&dir);
        cfg.server_url = Some(format!("https://{SYNC_HOST}"));
        cfg.pinned_cert_pem = Some(bundle.cert);
        cfg.server_ip = Some(bundle.ip.clone());
        save_config(&dir, &cfg)?;
    }
    kc_set(KC_BOOTSTRAP, &bundle.token)?;
    bootstrap_signin(&dir).await?;

    // Pull the shared vault down.
    let api = api_for(&state)?;
    let mut restored = 0i64;
    if let Some((v, ct)) = api.get_vault().await? {
        let doc = decode_sync_blob(&vk, &ct, v as u64).map_err(estr)?;
        let report = {
            let g = state.inner.lock().unwrap();
            g.vault.merge(&doc).map_err(estr)?
        };
        restored = report.added as i64;
    }
    // v0.1.57: if the account has a master password, make this QR-joined device require it on every
    // launch too (now that we're signed in, fetch the escrow). No master password ⇒ the plaintext
    // key stored above stays and the device remains unlocked-by-default, exactly as before.
    if let Ok(escrow) = api.get_wrapped_key(WrapperType::Password.code()).await {
        make_password_protected(&dir, &escrow, &vk);
    }
    let _ = sync_device_settings(&state);
    Ok(PairCompleteOut {
        restored,
        server_ip: bundle.ip,
    })
}

/// Forget the sync server this device is pointed at: clear the pinned config + bootstrap token +
/// session tokens, WITHOUT touching the local vault or its key or any deployed Linode. The escape
/// hatch for a device that joined (or half-joined) a server that's since gone away or was wrong —
/// afterward the device is plain local-only and can deploy or join fresh. NOT for the owner of a
/// deployed server (they use Destroy, which also deletes the Linode).
#[tauri::command]
pub fn sync_forget(state: State<AppState>) -> Result<(), String> {
    let dir = data_dir(&state);
    let mut cfg = load_config(&dir);
    cfg.server_url = None;
    cfg.pinned_cert_pem = None;
    cfg.server_ip = None;
    cfg.google_client_id = None;
    cfg.email = None;
    save_config(&dir, &cfg)?;
    kc_del(KC_BOOTSTRAP);
    kc_del(KC_ACCESS);
    kc_del(KC_REFRESH);
    kc_del(KC_PENDING);
    kc_del(KC_GSECRET);
    Ok(())
}
