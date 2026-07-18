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

use crate::state::{load_or_create_key, AppState};
use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use sentinel_core::auth::{BrowserOpener, GoogleAuth, PkceParams, TokenExchanger, TokenSet};
use sentinel_core::error::{CoreError, Result as CoreResult};
use sentinel_core::keyring::recovery::RecoveryWrapper;
use sentinel_core::keyring::{KeyWrapper, VaultKey, WrappedBlob, WrapperType};
use sentinel_core::recovery_kit::{self, pdf::render_kit_pdf, RecoveryKey};
use sentinel_core::vault::{decode_sync_blob, encode_sync_blob, VaultSession};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, State};

const KC_SERVICE: &str = "com.sentinel.desktop";
const KC_ACCESS: &str = "sync-access";
const KC_REFRESH: &str = "sync-refresh";
const KC_PENDING: &str = "sync-pending";
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

fn data_dir(state: &State<'_, AppState>) -> PathBuf {
    state.inner.lock().unwrap().data_dir.clone()
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
        .unwrap_or_else(|| "SENTINEL desktop".to_string())
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

/// Opens the system browser at `url`. We avoid `cmd /C start` (which mis-parses the `&`
/// in an OAuth URL); on Windows the URL is handed straight to the default handler.
struct SystemBrowserOpener;

#[async_trait]
impl BrowserOpener for SystemBrowserOpener {
    async fn open(&self, url: &str) -> CoreResult<()> {
        let url = url.to_string();
        let status = if cfg!(target_os = "windows") {
            // `explorer <url>` opens the default browser and treats the whole argument as a
            // single URL, side-stepping cmd.exe metacharacter parsing of `&`.
            tokio::process::Command::new("explorer")
                .arg(&url)
                .status()
                .await
        } else if cfg!(target_os = "macos") {
            tokio::process::Command::new("open")
                .arg(&url)
                .status()
                .await
        } else {
            tokio::process::Command::new("xdg-open")
                .arg(&url)
                .status()
                .await
        };
        match status {
            // `explorer` returns a non-zero exit code even on success, so on Windows we treat
            // a successful spawn as good enough; elsewhere require a clean exit.
            Ok(s) if s.success() || cfg!(target_os = "windows") => Ok(()),
            Ok(s) => Err(CoreError::Provision {
                stage: "browser",
                detail: format!("browser opener exited with {s}"),
            }),
            Err(e) => Err(CoreError::Provision {
                stage: "browser",
                detail: format!("could not launch browser: {e}"),
            }),
        }
    }
}

/// Exchanges the authorization code for tokens at Google's token endpoint.
struct HttpTokenExchanger {
    http: reqwest::Client,
    client_id: String,
}

impl HttpTokenExchanger {
    fn new(client_id: String) -> Self {
        HttpTokenExchanger {
            http: http_client(),
            client_id,
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
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("code_verifier", verifier),
            ("client_id", self.client_id.as_str()),
            ("redirect_uri", redirect_uri),
        ];
        let resp = self
            .http
            .post(GOOGLE_TOKEN_ENDPOINT)
            .form(&form)
            .send()
            .await
            .map_err(|e| CoreError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            let s = resp.status();
            return Err(CoreError::Provision {
                stage: "token",
                detail: format!("google token endpoint returned HTTP {s}"),
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

const CALLBACK_OK_HTML: &str = "<!doctype html><html><head><meta charset=utf-8><title>SENTINEL</title>\
<style>body{font-family:system-ui,sans-serif;background:#0a0f14;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}\
.c{text-align:center}h1{color:#22d3ee;font-weight:600}</style></head>\
<body><div class=c><h1>Signed in</h1><p>You can close this tab and return to SENTINEL.</p></div></body></html>";

const CALLBACK_ERR_HTML: &str = "<!doctype html><html><head><meta charset=utf-8><title>SENTINEL</title>\
<style>body{font-family:system-ui,sans-serif;background:#0a0f14;color:#e6edf3;display:grid;place-items:center;height:100vh;margin:0}\
.c{text-align:center}h1{color:#f87171;font-weight:600}</style></head>\
<body><div class=c><h1>Sign-in failed</h1><p>You can close this tab and try again in SENTINEL.</p></div></body></html>";

/// Run the full PKCE loop: bind an ephemeral loopback port, open the browser, wait for the
/// single `/callback` GET, then exchange the code for tokens. ~2-minute overall timeout.
async fn run_pkce_flow(client_id: &str) -> Result<TokenSet, String> {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind loopback: {e}"))?;
    let port = listener.local_addr().map_err(estr)?.port();
    let params = PkceParams::generate(port);

    let auth = GoogleAuth::new(
        client_id.to_string(),
        Arc::new(SystemBrowserOpener),
        Arc::new(HttpTokenExchanger::new(client_id.to_string())),
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
    fn new(base: String) -> Self {
        Api {
            http: http_client(),
            base,
        }
    }

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

    async fn put_wrapped_key(&self, blob: &[u8]) -> Result<(), String> {
        let body =
            json!({ "blob_b64": STANDARD.encode(blob), "device_id": serde_json::Value::Null });
        let resp = self
            .authed(reqwest::Method::PUT, "/wrapped-keys/3", &[], Some(body))
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("PUT /wrapped-keys/3: HTTP {}", resp.status()))
        }
    }

    async fn get_wrapped_key(&self) -> Result<Vec<u8>, String> {
        let resp = self
            .authed(reqwest::Method::GET, "/wrapped-keys/3", &[], None)
            .await?;
        if !resp.status().is_success() {
            return Err(format!("GET /wrapped-keys/3: HTTP {}", resp.status()));
        }
        #[derive(Deserialize)]
        struct W {
            blob_b64: String,
        }
        let w: W = resp.json().await.map_err(estr)?;
        STANDARD.decode(w.blob_b64.trim()).map_err(estr)
    }
}

/// Build an `Api` from the configured server URL (base `<serverUrl>/v1`).
fn api_for(state: &State<'_, AppState>) -> Result<Api, String> {
    let cfg = load_config(&data_dir(state));
    let server = cfg
        .server_url
        .filter(|s| !s.trim().is_empty())
        .ok_or("no sync server configured")?;
    Ok(Api::new(format!("{}/v1", server.trim_end_matches('/'))))
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
    signed_in: bool,
    email: Option<String>,
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
        signed_in: kc_get(KC_ACCESS).is_some(),
        email: cfg.email,
    }
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

    let tokens = run_pkce_flow(&client_id).await?;
    let email = email_from_id_token(&tokens.id_token).unwrap_or_default();

    let api = Api::new(format!("{}/v1", server.trim_end_matches('/')));
    let resp = api
        .http
        .post(format!("{}/auth/google", api.base))
        .json(&json!({
            "id_token": tokens.id_token,
            "device": { "name": device_name(), "platform": "windows" },
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
    Ok(EnrollOut {
        otpauth_uri: e.otpauth_uri,
        secret: e.secret_base32,
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
    let vk = load_or_create_key()?;

    // Wrap the vault key with a fresh recovery key (Wrapper C) and store it server-side.
    let rk = RecoveryKey::random();
    let wrapper = RecoveryWrapper::new(rk.clone());
    let blob = wrapper.wrap(&vk).await.map_err(estr)?;

    let api = api_for(&state)?;
    api.put_wrapped_key(&blob.bytes).await?;

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

#[tauri::command]
pub async fn sync_now(state: State<'_, AppState>) -> Result<SyncNowOut, String> {
    let vk = load_or_create_key()?;
    let api = api_for(&state)?;

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

    let version = push_document(&api, &vk, &state, current).await?;
    Ok(SyncNowOut {
        pushed: true,
        pulled,
        version,
    })
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
        bytes: api.get_wrapped_key().await?,
    };
    let rk = recovery_kit::decode(recovery_code.trim()).map_err(estr)?;
    let vk = RecoveryWrapper::new(rk).unwrap(&blob).await.map_err(estr)?;

    // Rebind this device's local vault key to the shared key, in the keychain and in RAM.
    kc_set(KC_VAULT_KEY, &STANDARD.encode(vk.key().as_bytes()))?;
    {
        let mut g = state.inner.lock().unwrap();
        g.session = VaultSession::unlocked(vk.clone());
    }

    let mut restored = 0i64;
    if let Some((v, ct)) = api.get_vault().await? {
        let doc = decode_sync_blob(&vk, &ct, v as u64).map_err(estr)?;
        let report = {
            let g = state.inner.lock().unwrap();
            g.vault.merge(&doc).map_err(estr)?
        };
        restored = report.added as i64;
    }

    Ok(RestoreOut { restored })
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
