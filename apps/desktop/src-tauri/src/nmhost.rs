//! Browser-autofill native-messaging host, served by the desktop binary *itself*.
//!
//! When Chrome/Edge launch a native-messaging host they exec the configured binary and
//! pass the requesting extension origin as `argv[1]`. We detect that (see [`is_host_mode`])
//! at the very top of `main` and, instead of building the Tauri UI, run a small stdio loop
//! ([`run`]) that speaks the same u32-LE-length-prefixed JSON framing as `crates/nm-host`.
//! No separate host binary ships: the app is its own host.
//!
//! Trust boundary (unchanged from the rest of SENTINEL): the page origin is validated
//! against each item's saved URL match *before* any field is released, and if the vault
//! can't be opened every credential request answers `LOCKED` with no data. The generator
//! is the only request that works without an open vault (it touches no secrets).
//!
//! This module also hosts the opt-in enable/disable Tauri commands ([`autofill_install`],
//! [`autofill_uninstall`], [`autofill_status`]) that register this binary as the OS
//! native-messaging host for the pinned, stable extension id.

use sentinel_core::generator::{self, PasswordSpec};
use sentinel_core::nm::{
    decode_frame, encode_frame, FrameError, NmEnvelope, NmError, NmErrorCode, NmType,
    VaultFieldsGetRequest, VaultSearchRequest, VaultSearchResultItem,
};
use sentinel_core::totp::TotpSecret;
use sentinel_core::vault::model::{Item, ItemType, UrlMatch, UrlMode};
use sentinel_core::vault::{origin_matches, LocalVault, VaultSession};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// The stable unpacked-extension id, derived from the RSA public key pinned in
/// `apps/extension/manifest.json` (`"key"`). Chrome derives the same id from that key,
/// so the host manifest below can allow-list exactly this extension.
pub const EXTENSION_ID: &str = "pbcngnmfielibgghcofedjmojogohcdf";

/// The Chrome Web Store assigns its own id on publish (independent of the pinned `key`), so a
/// store-installed extension has a *different* origin than the unpacked one. Once the store
/// listing is live, put its id here and the host will allow both. `None` until then.
/// See `docs/chrome-web-store.md`.
pub const STORE_EXTENSION_ID: Option<&str> = None;

/// Every extension id the native-messaging host will talk to (unpacked-dev + store, if set).
fn allowed_ids() -> Vec<&'static str> {
    let mut ids = vec![EXTENSION_ID];
    if let Some(store) = STORE_EXTENSION_ID {
        ids.push(store);
    }
    ids
}

/// Native-messaging host name — matches `NM_HOST_NAME` in `packages/shared` and the
/// filename Chrome/Edge look up.
const HOST_NAME: &str = "com.sentinel.host";

/// Host-manifest template shipped with the extension; rendered at install time with this
/// binary's path and [`EXTENSION_ID`]. Embedded so an installed app needs no repo files.
const HOST_MANIFEST_TMPL: &str =
    include_str!("../../../extension/host/com.sentinel.host.json.tmpl");

// ---------------------------------------------------------------------------
// host-mode detection + run loop
// ---------------------------------------------------------------------------

/// True when this process was launched as a native-messaging host: Chrome/Edge pass the
/// requesting extension origin (`chrome-extension://…`) as an argument; `--nm-host` is an
/// explicit override for manual testing. False for an ordinary double-click launch.
pub fn is_host_mode() -> bool {
    detect(std::env::args().skip(1))
}

fn detect(args: impl Iterator<Item = String>) -> bool {
    args.into_iter()
        .any(|a| a.starts_with("chrome-extension://") || a == "--nm-host")
}

/// Run the native-messaging host loop to completion (returns when the browser closes the
/// port). Never panics and never writes anything but framed replies to stdout.
pub fn run() {
    let host = open_vault();
    let stdin = io::stdin();
    let stdout = io::stdout();
    let _ = serve(host.as_ref(), &mut stdin.lock(), &mut stdout.lock());
}

/// The unlocked vault, if it can be opened. `None` ⇒ answer every credential request
/// `LOCKED`.
struct Host {
    session: VaultSession,
    vault: LocalVault,
}

/// `<app_data_dir>` resolved without a Tauri handle. Mirrors Tauri's `app_data_dir()` for
/// the `com.sentinel.desktop` bundle id on every platform (Windows `%APPDATA%\Roaming`,
/// macOS `~/Library/Application Support`, Linux `~/.local/share`).
fn data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("com.sentinel.desktop")
}

/// Open the same persistent vault the desktop app uses, unlocked with the keychain key.
/// Any failure (no keychain, no vault, bad key) yields `None` → served as locked.
fn open_vault() -> Option<Host> {
    let vault_path = data_dir().join("vault.db");
    let vault = LocalVault::open(vault_path.to_str()?).ok()?;
    let key = crate::state::load_or_create_key().ok()?;
    Some(Host {
        session: VaultSession::unlocked(key),
        vault,
    })
}

/// Buffer stdin, decode as many complete frames as arrive, answer each, and flush. Copied
/// in structure from `crates/nm-host/src/main.rs` so framing behaviour stays identical.
fn serve<R: Read, W: Write>(host: Option<&Host>, input: &mut R, output: &mut W) -> io::Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        loop {
            match decode_frame(&buf) {
                Ok((env, consumed)) => {
                    let reply = handle(host, &env);
                    output.write_all(&encode_frame(&reply))?;
                    output.flush()?;
                    buf.drain(..consumed);
                }
                Err(FrameError::Incomplete) => break,
                Err(FrameError::TooLarge(_)) | Err(FrameError::Malformed) => return Ok(()),
            }
        }
        let n = input.read(&mut chunk)?;
        if n == 0 {
            return Ok(()); // EOF: the browser closed the port.
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Route one request to its handler.
fn handle(host: Option<&Host>, env: &NmEnvelope) -> NmEnvelope {
    match env.kind {
        NmType::Hello => hello(host, &env.id),
        NmType::VaultSearch => search(host, env),
        NmType::VaultFieldsGet => fields(host, env),
        NmType::VaultTotpGet => totp(host, env),
        NmType::VaultGenerate => generate(&env.id),
        NmType::VaultSaveCandidate => save_candidate(host, env),
        _ => error(
            &env.id,
            env.kind,
            NmErrorCode::BadRequest,
            "unsupported request",
        ),
    }
}

// ---------------------------------------------------------------------------
// request handlers
// ---------------------------------------------------------------------------

const CAPS: &[&str] = &[
    "vault.search",
    "vault.fields.get",
    "vault.totp.get",
    "vault.generate",
    "vault.save_candidate",
];

fn hello(host: Option<&Host>, id: &str) -> NmEnvelope {
    ok(
        id,
        NmType::Hello,
        serde_json::json!({
            "caps": CAPS,
            "appVersion": env!("CARGO_PKG_VERSION"),
            "locked": host.is_none(),
        }),
    )
}

fn search(host: Option<&Host>, env: &NmEnvelope) -> NmEnvelope {
    let host = match host {
        Some(h) => h,
        None => return NmEnvelope::locked(&env.id),
    };
    let req: VaultSearchRequest = match parse(env) {
        Ok(r) => r,
        Err(e) => return e,
    };

    // Origin-match first (authoritative T4 gate), then rank most-recent-first (rank_matches
    // semantics), then apply the free-text query as a display filter.
    let mut matched: Vec<Item> = load_items(host)
        .into_iter()
        .filter(|it| origin_matches(&it.urls, &req.origin))
        .collect();
    matched.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    let q = req.query.trim().to_lowercase();
    let items: Vec<VaultSearchResultItem> = matched
        .iter()
        .filter(|it| {
            q.is_empty()
                || it.title.to_lowercase().contains(&q)
                || it.username().is_some_and(|u| u.to_lowercase().contains(&q))
        })
        .enumerate()
        .map(|(rank, it)| VaultSearchResultItem {
            id: it.id.to_string(),
            title: it.title.clone(),
            username: it.username().map(str::to_string),
            favicon_domain: it.urls.first().map(|u| host_of(&u.url)),
            match_quality: match_quality(it, &req.origin, rank),
        })
        .collect();

    ok(
        &env.id,
        NmType::VaultSearch,
        serde_json::json!({ "items": items }),
    )
}

fn fields(host: Option<&Host>, env: &NmEnvelope) -> NmEnvelope {
    let host = match host {
        Some(h) => h,
        None => return NmEnvelope::locked(&env.id),
    };
    let req: VaultFieldsGetRequest = match parse(env) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let item = match lookup(host, &req.id) {
        Ok(it) => it,
        Err(e) => return error(&env.id, env.kind, e.0, e.1),
    };
    // Re-check the requesting origin BEFORE releasing any field (never leak cross-origin).
    if !origin_matches(&item.urls, &req.origin) {
        return error(
            &env.id,
            env.kind,
            NmErrorCode::BadOrigin,
            "origin does not match this item",
        );
    }

    let mut out = serde_json::Map::new();
    for field in &req.fields {
        match field.as_str() {
            "username" => {
                if let Some(u) = item.username() {
                    out.insert("username".into(), u.into());
                }
            }
            "password" => {
                if let Some(p) = item.password() {
                    out.insert("password".into(), p.into());
                }
            }
            "totp" => {
                if let Some(code) = totp_code(&item) {
                    out.insert("totp".into(), code.into());
                }
            }
            _ => {}
        }
    }
    ok(
        &env.id,
        NmType::VaultFieldsGet,
        serde_json::json!({ "fields": out }),
    )
}

#[derive(Deserialize)]
struct TotpGetRequest {
    id: String,
    #[serde(default)]
    origin: String,
}

fn totp(host: Option<&Host>, env: &NmEnvelope) -> NmEnvelope {
    let host = match host {
        Some(h) => h,
        None => return NmEnvelope::locked(&env.id),
    };
    let req: TotpGetRequest = match parse(env) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let item = match lookup(host, &req.id) {
        Ok(it) => it,
        Err(e) => return error(&env.id, env.kind, e.0, e.1),
    };
    // Same origin gate as fields — a TOTP is a credential too.
    if !origin_matches(&item.urls, &req.origin) {
        return error(
            &env.id,
            env.kind,
            NmErrorCode::BadOrigin,
            "origin does not match this item",
        );
    }
    match totp_code(&item) {
        Some(code) => ok(
            &env.id,
            NmType::VaultTotpGet,
            serde_json::json!({ "code": code }),
        ),
        None => error(&env.id, env.kind, NmErrorCode::NotFound, "item has no TOTP"),
    }
}

fn generate(id: &str) -> NmEnvelope {
    match generator::password(&PasswordSpec::default()) {
        Ok(password) => ok(
            id,
            NmType::VaultGenerate,
            serde_json::json!({ "password": password }),
        ),
        Err(_) => error(
            id,
            NmType::VaultGenerate,
            NmErrorCode::Internal,
            "generate failed",
        ),
    }
}

#[derive(Deserialize)]
struct SaveCandidateRequest {
    origin: String,
    #[serde(default)]
    username: String,
    password: String,
    #[serde(default)]
    title: String,
}

/// Persist a credential the extension captured on a form submit. Finds an existing login for
/// this origin with the same username (→ update its password) or creates a new one; the new/
/// updated item's saved URL is exactly the requesting origin so future autofill matches it.
/// Only ever writes while unlocked; a locked vault answers `LOCKED` and stores nothing.
fn save_candidate(host: Option<&Host>, env: &NmEnvelope) -> NmEnvelope {
    let host = match host {
        Some(h) => h,
        None => return NmEnvelope::locked(&env.id),
    };
    let req: SaveCandidateRequest = match parse(env) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if req.password.is_empty() {
        return error(
            &env.id,
            env.kind,
            NmErrorCode::BadRequest,
            "no password to save",
        );
    }

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    // Match an existing login for this origin with the same username (empty matches empty).
    let existing = load_items(host).into_iter().find(|it| {
        it.item_type == ItemType::Login
            && origin_matches(&it.urls, &req.origin)
            && it.username().unwrap_or("") == req.username
    });

    let (item, action) = match existing {
        Some(mut it) => {
            if it.password() == Some(req.password.as_str()) {
                // Nothing changed — report success without a redundant write (no save nag).
                return ok(
                    &env.id,
                    NmType::VaultSaveCandidate,
                    serde_json::json!({ "saved": true, "action": "unchanged", "id": it.id.to_string() }),
                );
            }
            let login = it.login.get_or_insert_with(Default::default);
            login.password = Some(req.password.clone());
            it.updated_at = now;
            it.password_changed_at = Some(now);
            (it, "updated")
        }
        None => {
            let title = if req.title.trim().is_empty() {
                host_of(&req.origin)
            } else {
                req.title.clone()
            };
            let mut it = Item::new_login(title, now);
            it.urls = vec![UrlMatch {
                url: req.origin.clone(),
                mode: UrlMode::Domain,
            }];
            let login = it.login.get_or_insert_with(Default::default);
            if !req.username.is_empty() {
                login.username = Some(req.username.clone());
            }
            login.password = Some(req.password.clone());
            (it, "created")
        }
    };

    let sealed = match host.session.seal(&item) {
        Ok(s) => s,
        Err(_) => return error(&env.id, env.kind, NmErrorCode::Internal, "seal failed"),
    };
    if host.vault.upsert(&sealed).is_err() {
        return error(
            &env.id,
            env.kind,
            NmErrorCode::Internal,
            "vault write failed",
        );
    }
    ok(
        &env.id,
        NmType::VaultSaveCandidate,
        serde_json::json!({ "saved": true, "action": action, "id": item.id.to_string() }),
    )
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn load_items(host: &Host) -> Vec<Item> {
    host.vault
        .list_envelopes()
        .unwrap_or_default()
        .iter()
        .filter_map(|e| host.session.open(e).ok())
        .collect()
}

/// Load a single item by id, mapping the not-found / bad-id cases to error codes.
fn lookup(host: &Host, id: &str) -> Result<Item, (NmErrorCode, &'static str)> {
    let uid = uuid::Uuid::parse_str(id).map_err(|_| (NmErrorCode::BadRequest, "bad item id"))?;
    let env = host
        .vault
        .get(uid)
        .map_err(|_| (NmErrorCode::Internal, "vault read failed"))?
        .ok_or((NmErrorCode::NotFound, "no such item"))?;
    host.session
        .open(&env)
        .map_err(|_| (NmErrorCode::Internal, "decrypt failed"))
}

fn totp_code(item: &Item) -> Option<String> {
    let uri = item.login.as_ref().and_then(|l| l.totp.clone())?;
    let secret = TotpSecret::parse(&uri).ok()?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    Some(secret.code_at(now))
}

/// Best-effort host extraction ("https://a.example.com/x" -> "a.example.com").
fn host_of(url: &str) -> String {
    let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    after
        .split('/')
        .next()
        .unwrap_or(after)
        .to_ascii_lowercase()
}

/// A 0..1 quality signal: an exact-host saved URL ranks above a registrable-domain match,
/// with a small decay by rank so the most-recent match sorts first.
fn match_quality(item: &Item, origin: &str, rank: usize) -> f64 {
    let page_host = host_of(origin);
    let exact = item
        .urls
        .iter()
        .any(|u| host_of(&u.url) == page_host && !page_host.is_empty());
    let base = if exact { 1.0 } else { 0.75 };
    (base - (rank as f64) * 0.02).max(0.1)
}

fn parse<T: DeserializeOwned>(env: &NmEnvelope) -> Result<T, NmEnvelope> {
    serde_json::from_value(env.payload.clone().unwrap_or(serde_json::Value::Null)).map_err(|_| {
        error(
            &env.id,
            env.kind,
            NmErrorCode::BadRequest,
            "bad request payload",
        )
    })
}

fn ok(id: &str, kind: NmType, payload: serde_json::Value) -> NmEnvelope {
    NmEnvelope {
        id: id.to_string(),
        kind,
        ok: Some(true),
        payload: Some(payload),
        err: None,
    }
}

fn error(id: &str, kind: NmType, code: NmErrorCode, message: &str) -> NmEnvelope {
    NmEnvelope {
        id: id.to_string(),
        kind,
        ok: Some(false),
        payload: None,
        err: Some(NmError {
            code,
            message: message.into(),
        }),
    }
}

// ---------------------------------------------------------------------------
// opt-in enable / disable (Tauri commands)
// ---------------------------------------------------------------------------

/// Render the host manifest with this binary's path (JSON-escaped) and the allowed origins.
fn render_manifest() -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|e| format!("current exe: {e}"))?;
    // The path lands inside a JSON string literal: escape backslashes (Windows) and quotes.
    let escaped = exe
        .to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let origins = allowed_ids()
        .iter()
        .map(|id| format!("\"chrome-extension://{id}/\""))
        .collect::<Vec<_>>()
        .join(", ");
    Ok(HOST_MANIFEST_TMPL
        .replace("__SENTINEL_NM_HOST_PATH__", &escaped)
        .replace("__SENTINEL_ALLOWED_ORIGINS__", &format!("[{origins}]")))
}

/// Copy a directory tree recursively (`std` has no built-in for this).
fn copy_dir_all(src: &Path, dst: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Copy the bundled browser extension out of the app's read-only resources into a stable,
/// user-writable folder (`<app_data_dir>/extension`) and return that path, so the user can
/// point Chrome/Edge "Load unpacked" at it. The extension is bundled into the installer via
/// `bundle.resources` in tauri.conf.json; in a dev build it may be absent (returns an error).
#[tauri::command]
pub fn autofill_prepare(app: tauri::AppHandle) -> Result<String, String> {
    use tauri::Manager;
    let base = app
        .path()
        .resource_dir()
        .map_err(|e| format!("resource dir: {e}"))?;
    // Be tolerant of how Tauri lays out mapped resources across versions/platforms.
    let candidates = [
        base.join("extension"),
        base.join("resources").join("extension"),
    ];
    let src = candidates
        .iter()
        .find(|p| p.join("manifest.json").exists())
        .ok_or_else(|| {
            "bundled extension not found (only available in an installed build)".to_string()
        })?;
    let dest = data_dir().join("extension");
    let _ = std::fs::remove_dir_all(&dest);
    copy_dir_all(src, &dest).map_err(|e| format!("copy extension: {e}"))?;
    Ok(dest.to_string_lossy().to_string())
}

/// Reveal a folder in the OS file manager (so the user can drag it into "Load unpacked").
#[tauri::command]
pub fn open_folder(path: String) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let (cmd, args): (&str, Vec<&str>) = ("explorer", vec![path.as_str()]);
    #[cfg(target_os = "macos")]
    let (cmd, args): (&str, Vec<&str>) = ("open", vec![path.as_str()]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let (cmd, args): (&str, Vec<&str>) = ("xdg-open", vec![path.as_str()]);
    std::process::Command::new(cmd)
        .args(&args)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("open folder: {e}"))
}

/// Register this binary as the `com.sentinel.host` native-messaging host for Chrome/Edge.
#[tauri::command]
pub fn autofill_install() -> Result<(), String> {
    let manifest = render_manifest()?;
    let dir = data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create data dir: {e}"))?;
    let stable = dir.join(format!("{HOST_NAME}.json"));
    std::fs::write(&stable, &manifest).map_err(|e| format!("write host manifest: {e}"))?;
    register(&stable, &manifest)
}

/// Remove the native-messaging host registration.
#[tauri::command]
pub fn autofill_uninstall() -> Result<(), String> {
    unregister()?;
    let _ = std::fs::remove_file(data_dir().join(format!("{HOST_NAME}.json")));
    Ok(())
}

#[derive(serde::Serialize)]
pub struct AutofillStatus {
    pub installed: bool,
}

/// Whether the native-messaging host is currently registered.
#[tauri::command]
pub fn autofill_status() -> AutofillStatus {
    AutofillStatus {
        installed: is_installed(),
    }
}

// --- Windows: HKCU registry under Chrome + Edge -----------------------------

#[cfg(target_os = "windows")]
fn registry_keys() -> [&'static str; 2] {
    [
        "Software\\Google\\Chrome\\NativeMessagingHosts\\com.sentinel.host",
        "Software\\Microsoft\\Edge\\NativeMessagingHosts\\com.sentinel.host",
    ]
}

#[cfg(target_os = "windows")]
fn register(stable: &Path, _manifest: &str) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path_str = stable.to_string_lossy().to_string();
    for base in registry_keys() {
        let (key, _) = hkcu
            .create_subkey(base)
            .map_err(|e| format!("create {base}: {e}"))?;
        key.set_value("", &path_str)
            .map_err(|e| format!("set {base}: {e}"))?;
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn unregister() -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    for base in registry_keys() {
        match hkcu.delete_subkey_all(base) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("delete {base}: {e}")),
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn is_installed() -> bool {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    registry_keys().iter().any(|base| {
        hkcu.open_subkey(base)
            .and_then(|k| k.get_value::<String, _>(""))
            .map(|v| !v.is_empty())
            .unwrap_or(false)
    })
}

// --- macOS + Linux: a JSON file in each browser's NativeMessagingHosts dir --

#[cfg(target_os = "macos")]
fn browser_host_dirs() -> Vec<PathBuf> {
    // dirs::config_dir() on macOS is ~/Library/Application Support.
    let base = dirs::config_dir().unwrap_or_else(std::env::temp_dir);
    vec![
        base.join("Google/Chrome/NativeMessagingHosts"),
        base.join("Microsoft Edge/NativeMessagingHosts"),
        base.join("Chromium/NativeMessagingHosts"),
    ]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn browser_host_dirs() -> Vec<PathBuf> {
    // dirs::config_dir() on Linux is ~/.config.
    let base = dirs::config_dir().unwrap_or_else(std::env::temp_dir);
    vec![
        base.join("google-chrome/NativeMessagingHosts"),
        base.join("chromium/NativeMessagingHosts"),
        base.join("microsoft-edge/NativeMessagingHosts"),
    ]
}

#[cfg(not(target_os = "windows"))]
fn register(_stable: &Path, manifest: &str) -> Result<(), String> {
    for dir in browser_host_dirs() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        std::fs::write(dir.join(format!("{HOST_NAME}.json")), manifest)
            .map_err(|e| format!("write {}: {e}", dir.display()))?;
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn unregister() -> Result<(), String> {
    for dir in browser_host_dirs() {
        let _ = std::fs::remove_file(dir.join(format!("{HOST_NAME}.json")));
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn is_installed() -> bool {
    browser_host_dirs()
        .iter()
        .any(|dir| dir.join(format!("{HOST_NAME}.json")).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iter(args: &[&str]) -> std::vec::IntoIter<String> {
        args.iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn detects_browser_launch() {
        assert!(detect(iter(&[
            "chrome-extension://pbcngnmfielibgghcofedjmojogohcdf/"
        ])));
        assert!(detect(iter(&["--nm-host"])));
    }

    #[test]
    fn normal_launch_is_not_host_mode() {
        assert!(!detect(iter(&[])));
        assert!(!detect(iter(&["--flag", "value"])));
    }

    #[test]
    fn hello_reports_locked_without_vault() {
        let env = NmEnvelope {
            id: "1".into(),
            kind: NmType::Hello,
            ok: None,
            payload: None,
            err: None,
        };
        let reply = handle(None, &env);
        assert_eq!(reply.kind, NmType::Hello);
        assert_eq!(reply.payload.unwrap()["locked"], serde_json::json!(true));
    }

    #[test]
    fn credential_requests_are_locked_without_vault() {
        for kind in [
            NmType::VaultSearch,
            NmType::VaultFieldsGet,
            NmType::VaultTotpGet,
        ] {
            let env = NmEnvelope {
                id: "2".into(),
                kind,
                ok: None,
                payload: None,
                err: None,
            };
            let reply = handle(None, &env);
            assert_eq!(reply.err.unwrap().code, NmErrorCode::Locked);
            assert!(reply.payload.is_none(), "no credential data while locked");
        }
    }

    #[test]
    fn generate_works_without_vault() {
        let env = NmEnvelope {
            id: "3".into(),
            kind: NmType::VaultGenerate,
            ok: None,
            payload: None,
            err: None,
        };
        let reply = handle(None, &env);
        assert_eq!(reply.ok, Some(true));
        assert!(!reply.payload.unwrap()["password"]
            .as_str()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn extension_id_is_valid_chrome_id() {
        assert_eq!(EXTENSION_ID.len(), 32);
        assert!(EXTENSION_ID.bytes().all(|b| (b'a'..=b'p').contains(&b)));
    }

    fn test_host() -> Host {
        use sentinel_core::keyring::VaultKey;
        Host {
            session: VaultSession::unlocked(VaultKey::generate()),
            vault: LocalVault::open(":memory:").unwrap(),
        }
    }

    fn save_env(origin: &str, username: &str, password: &str) -> NmEnvelope {
        NmEnvelope {
            id: "s".into(),
            kind: NmType::VaultSaveCandidate,
            ok: None,
            payload: Some(serde_json::json!({
                "origin": origin, "username": username, "password": password, "title": ""
            })),
            err: None,
        }
    }

    #[test]
    fn save_candidate_is_locked_without_vault() {
        let reply = handle(None, &save_env("https://example.com", "me", "p1"));
        assert_eq!(reply.err.unwrap().code, NmErrorCode::Locked);
    }

    #[test]
    fn save_candidate_creates_then_updates_then_reports_unchanged() {
        let host = test_host();

        // 1) First save creates the login and makes it autofill-matchable.
        let r = handle(Some(&host), &save_env("https://example.com", "me", "p1"));
        assert_eq!(r.ok, Some(true));
        assert_eq!(r.payload.as_ref().unwrap()["action"], "created");
        assert_eq!(host.vault.count().unwrap(), 1);

        // The created item is returned by a search for that origin.
        let search_env = NmEnvelope {
            id: "q".into(),
            kind: NmType::VaultSearch,
            ok: None,
            payload: Some(serde_json::json!({ "query": "", "origin": "https://example.com" })),
            err: None,
        };
        let s = handle(Some(&host), &search_env);
        assert_eq!(s.payload.unwrap()["items"].as_array().unwrap().len(), 1);

        // 2) Same origin+username, new password → update (not a second item).
        let r = handle(Some(&host), &save_env("https://example.com", "me", "p2"));
        assert_eq!(r.payload.as_ref().unwrap()["action"], "updated");
        assert_eq!(host.vault.count().unwrap(), 1);

        // 3) Identical again → unchanged, still one item, no error.
        let r = handle(Some(&host), &save_env("https://example.com", "me", "p2"));
        assert_eq!(r.payload.as_ref().unwrap()["action"], "unchanged");
        assert_eq!(host.vault.count().unwrap(), 1);
    }

    #[test]
    fn save_candidate_rejects_empty_password() {
        let host = test_host();
        let reply = handle(Some(&host), &save_env("https://example.com", "me", ""));
        assert_eq!(reply.err.unwrap().code, NmErrorCode::BadRequest);
    }

    #[test]
    fn manifest_renders_with_id_and_no_placeholders() {
        let m = render_manifest().unwrap();
        assert!(m.contains(EXTENSION_ID));
        assert!(!m.contains("__SENTINEL_"));
        // Still valid JSON after substitution.
        serde_json::from_str::<serde_json::Value>(&m).unwrap();
    }
}
