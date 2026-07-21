//! Optional app-lock: a real master password (opt-in) plus an optional authenticator-app
//! (TOTP) second factor. The app is **unlocked by default** — these only engage once the user
//! turns them on (e.g. around VPN setup).
//!
//! Crypto model: the vault key stays the same random 256-bit key; setting a password just
//! wraps it under an Argon2id-derived KEK (`WrappedBlob`, `WrapperType::Password`) stored at
//! `<data_dir>/vault-key.wrap`, and DELETES the plaintext keychain copy so the password is a
//! genuine factor. Removing the password re-stores the key in the keychain. Nothing in the
//! vault is ever re-encrypted — only *how the key is obtained* changes.
//!
//! The TOTP secret lives in the OS-login-guarded keychain because it must be read *before* the
//! vault key at unlock; it's a convenience/defense-in-depth second factor, not the crypto root.

use crate::state::{self, AppState};
use sentinel_core::crypto::{argon2id_kek, Argon2Profile};
use sentinel_core::keyring::{VaultKey, WrappedBlob, WrapperType};
use sentinel_core::totp::{self, TotpSecret};
use sentinel_core::vault::VaultSession;
use serde::Serialize;
use tauri::State;

type R<T> = Result<T, String>;

fn now() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
}

fn data_dir(state: &State<AppState>) -> std::path::PathBuf {
    state.inner.lock().unwrap().data_dir.clone()
}

/// Persist a boolean flag into settings.json (same shape as `hello_set`).
fn set_settings_flag(dir: &std::path::Path, key: &str, val: bool) -> R<()> {
    let path = dir.join("settings.json");
    let mut cur = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if !cur.is_object() {
        cur = serde_json::json!({});
    }
    if let Some(obj) = cur.as_object_mut() {
        obj.insert(key.into(), serde_json::Value::Bool(val));
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&cur).unwrap_or_default(),
    )
    .map_err(|e| format!("write settings: {e}"))
}

/// If an authenticator-app code is required, verify the supplied `code`.
fn check_totp(dir: &std::path::Path, code: &Option<String>) -> R<()> {
    if !state::totp_enabled(dir) {
        return Ok(());
    }
    let secret =
        state::totp_secret_load()?.ok_or("authenticator is enabled but no secret is stored")?;
    let code = code
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or("enter the 6-digit code from your authenticator app")?;
    let t = TotpSecret::parse(&secret).map_err(|e| format!("totp: {e}"))?;
    if t.verify_at(code, now()) {
        Ok(())
    } else {
        Err("that authenticator code didn't match".into())
    }
}

/// Derive the KEK for `password` using the salt embedded in `blob`, and open it → vault key.
fn open_with_password(blob: &WrappedBlob, password: &str) -> R<VaultKey> {
    let salt = blob.params().map_err(|e| format!("wrap: {e}"))?;
    let salt16: [u8; 16] = salt
        .as_slice()
        .try_into()
        .map_err(|_| "corrupt password wrapper (bad salt)".to_string())?;
    let kek = argon2id_kek(password.as_bytes(), &salt16, Argon2Profile::Production);
    blob.open(&kek).map_err(|_| "wrong password".to_string())
}

fn read_wrap(dir: &std::path::Path) -> R<WrappedBlob> {
    let bytes = std::fs::read(state::wrap_path(dir))
        .map_err(|_| "no master password is set".to_string())?;
    Ok(WrappedBlob {
        wrapper: WrapperType::Password,
        bytes,
    })
}

fn seal_new(dir: &std::path::Path, password: &str, vk: &VaultKey) -> R<()> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let kek = argon2id_kek(password.as_bytes(), &salt, Argon2Profile::Production);
    let blob = WrappedBlob::seal(WrapperType::Password, &kek, &salt, vk);
    std::fs::write(state::wrap_path(dir), &blob.bytes).map_err(|e| format!("write wrapper: {e}"))
}

fn set_session(state: &State<AppState>, vk: VaultKey) {
    state.inner.lock().unwrap().session = VaultSession::unlocked(vk);
}

// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthStatus {
    pub locked: bool,
    pub password_protected: bool,
    pub totp_enabled: bool,
    pub require_hello: bool,
}

/// Current app-lock state, for deciding whether to show the Unlock screen and which fields.
#[tauri::command]
pub fn auth_status(state: State<AppState>) -> AuthStatus {
    let (locked, dir) = {
        let inner = state.inner.lock().unwrap();
        (inner.session.is_locked(), inner.data_dir.clone())
    };
    AuthStatus {
        locked,
        password_protected: state::password_protected(&dir),
        totp_enabled: state::totp_enabled(&dir),
        require_hello: state::require_hello(&dir),
    }
}

/// Set a master password: wrap the current vault key under an Argon2 KEK and drop the plaintext
/// keychain copy so the password becomes a real factor. The vault stays unlocked.
#[tauri::command]
pub fn auth_set_password(state: State<AppState>, password: String) -> R<()> {
    if password.trim().len() < 4 {
        return Err("choose a password of at least 4 characters".into());
    }
    let dir = data_dir(&state);
    if state::password_protected(&dir) {
        return Err("a master password is already set — use Change password".into());
    }
    // The current key is still in the keychain (we're not yet protected).
    let vk = state::load_or_create_key()?;
    seal_new(&dir, &password, &vk)?;
    state::delete_key()?; // password is now the only way in
    set_session(&state, vk);
    Ok(())
}

/// Unlock the vault with the master password (and authenticator code, if enabled).
#[tauri::command]
pub fn auth_unlock_password(
    state: State<AppState>,
    password: String,
    code: Option<String>,
) -> R<()> {
    let dir = data_dir(&state);
    let blob = read_wrap(&dir)?;
    let vk = open_with_password(&blob, &password)?;
    check_totp(&dir, &code)?;
    set_session(&state, vk);
    Ok(())
}

/// Change the master password (re-wrap the same vault key under a new KEK).
#[tauri::command]
pub fn auth_change_password(
    state: State<AppState>,
    old_password: String,
    new_password: String,
    code: Option<String>,
) -> R<()> {
    if new_password.trim().len() < 4 {
        return Err("choose a new password of at least 4 characters".into());
    }
    let dir = data_dir(&state);
    let blob = read_wrap(&dir)?;
    let vk = open_with_password(&blob, &old_password)?;
    check_totp(&dir, &code)?;
    seal_new(&dir, &new_password, &vk)?;
    set_session(&state, vk);
    Ok(())
}

/// Remove the master password: verify it, re-store the key in the keychain, delete the wrapper
/// (back to unlocked-by-default). Requires the authenticator code too, if enabled.
#[tauri::command]
pub fn auth_remove_password(
    state: State<AppState>,
    password: String,
    code: Option<String>,
) -> R<()> {
    let dir = data_dir(&state);
    let blob = read_wrap(&dir)?;
    let vk = open_with_password(&blob, &password)?;
    check_totp(&dir, &code)?;
    state::store_key(&vk)?;
    std::fs::remove_file(state::wrap_path(&dir)).map_err(|e| format!("remove wrapper: {e}"))?;
    set_session(&state, vk);
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpEnroll {
    pub otpauth_uri: String,
    pub secret: String,
    pub qr_svg: String,
}

/// Begin authenticator-app enrollment: generate a secret, store it, and return the otpauth URI,
/// the typed secret, and a scannable QR (SVG). Not enforced until `applock_totp_confirm`.
#[tauri::command]
pub fn applock_totp_enroll(state: State<AppState>) -> R<TotpEnroll> {
    let _ = data_dir(&state); // ensure state is live
    let secret = totp::generate_base32_secret();
    state::totp_secret_store(&secret)?;
    let uri = totp::otpauth_uri(&secret, "vault", "NorthKey");
    let qr_svg = qr_svg(&uri)?;
    Ok(TotpEnroll {
        otpauth_uri: uri,
        secret,
        qr_svg,
    })
}

/// Confirm enrollment by verifying a code from the authenticator app, then require it at unlock.
#[tauri::command]
pub fn applock_totp_confirm(state: State<AppState>, code: String) -> R<()> {
    let dir = data_dir(&state);
    let secret = state::totp_secret_load()?.ok_or("start enrollment first")?;
    let t = TotpSecret::parse(&secret).map_err(|e| format!("totp: {e}"))?;
    if !t.verify_at(code.trim(), now()) {
        return Err("that code didn't match — check your authenticator app".into());
    }
    set_settings_flag(&dir, "applockTotpEnabled", true)
}

/// Turn off the authenticator-app requirement (verify a current code first).
#[tauri::command]
pub fn applock_totp_disable(state: State<AppState>, code: String) -> R<()> {
    let dir = data_dir(&state);
    if let Some(secret) = state::totp_secret_load()? {
        let t = TotpSecret::parse(&secret).map_err(|e| format!("totp: {e}"))?;
        if !t.verify_at(code.trim(), now()) {
            return Err("that code didn't match".into());
        }
    }
    set_settings_flag(&dir, "applockTotpEnabled", false)?;
    state::totp_secret_delete()
}

/// Render an otpauth URI as an SVG QR string (also used by the sync sign-in's TOTP enrollment).
pub(crate) fn qr_svg(uri: &str) -> R<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(uri.as_bytes()).map_err(|e| format!("qr: {e}"))?;
    Ok(code
        .render::<svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build())
}
