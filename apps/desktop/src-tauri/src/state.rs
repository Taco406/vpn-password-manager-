//! Desktop app state: the on-disk vault, the unlocked session, and the OS-keychain-backed
//! vault key. All the actual crypto/vault logic lives in `sentinel-core`; this crate is glue.
//!
//! Persistence model (the piece sentinel-core deliberately leaves to the app layer):
//!   - The vault *ciphertext* is a SQLite file (`vault.db`) in the OS app-data dir.
//!   - The 256-bit *vault key* lives ONLY in the OS keychain (Windows Credential Manager /
//!     macOS Keychain / Secret Service). It is never written next to the vault, so a stolen
//!     `vault.db` on its own is opaque ciphertext.
//!
//! On launch we read (or, on first run, create + store) the key and open the session
//! unlocked — the security boundary is the OS login that guards the keychain.

use base64::Engine;
use sentinel_core::crypto::Key32;
use sentinel_core::keyring::VaultKey;
use sentinel_core::vault::{LocalVault, VaultSession};
use std::path::PathBuf;
use std::sync::Mutex;

const KEYCHAIN_SERVICE: &str = "com.sentinel.desktop";
const KEYCHAIN_ACCOUNT: &str = "vault-key";
/// Keychain account holding the base32 authenticator-app (TOTP) secret, when enrolled.
const KEYCHAIN_TOTP: &str = "applock-totp";

/// Shared, thread-safe app state.
pub struct AppState {
    pub inner: Mutex<Inner>,
}

pub struct Inner {
    pub session: VaultSession,
    pub vault: LocalVault,
    pub data_dir: PathBuf,
    /// The live VPN session, if connected (real ephemeral-node mode). None = disconnected.
    pub vpn: Option<crate::vpn::VpnActive>,
}

impl AppState {
    /// Build the real, persistent state: open `vault.db` in `data_dir` and unlock with the
    /// keychain-held vault key (created + stored on first run).
    pub fn new_persistent(data_dir: PathBuf) -> Result<Self, String> {
        std::fs::create_dir_all(&data_dir).map_err(|e| format!("create data dir: {e}"))?;
        let vault_path = data_dir.join("vault.db");
        let path_str = vault_path
            .to_str()
            .ok_or_else(|| "vault path is not valid UTF-8".to_string())?;
        let vault = LocalVault::open(path_str).map_err(|e| format!("open vault: {e}"))?;
        // Boot unlocked by default (personal-use tool). Start LOCKED only if the user has opted
        // into a protection method — a master password, an authenticator-app code, or Windows
        // Hello — so nothing is revealed until they pass it.
        //
        // Important: when a master password is set, the plaintext keychain key was DELETED (the
        // password is the only way in), so we must NOT call `load_or_create_key` here — it would
        // mint a fresh, wrong key. In that case we boot locked with no key and unlock via password.
        let protected =
            password_protected(&data_dir) || require_hello(&data_dir) || totp_enabled(&data_dir);
        let session = if protected {
            VaultSession::locked()
        } else {
            VaultSession::unlocked(load_or_create_key()?)
        };
        Ok(AppState {
            inner: Mutex::new(Inner {
                session,
                vault,
                data_dir,
                vpn: None,
            }),
        })
    }

    /// In-memory, empty fallback used only if the persistent path can't be initialised
    /// (e.g. no keychain available). Nothing is saved; the app still runs.
    pub fn new_memory_fallback() -> Self {
        let vault = LocalVault::open(":memory:").expect("open in-memory vault");
        AppState {
            inner: Mutex::new(Inner {
                session: VaultSession::unlocked(VaultKey::generate()),
                vault,
                data_dir: std::env::temp_dir(),
                vpn: None,
            }),
        }
    }
}

/// Whether the "require Windows Hello to unlock" setting is on (read from settings.json).
pub fn require_hello(data_dir: &std::path::Path) -> bool {
    settings_bool(data_dir, "requireHello")
}

/// Whether an authenticator-app (TOTP) unlock code is required (read from settings.json).
pub fn totp_enabled(data_dir: &std::path::Path) -> bool {
    settings_bool(data_dir, "applockTotpEnabled")
}

fn settings_bool(data_dir: &std::path::Path, key: &str) -> bool {
    std::fs::read_to_string(data_dir.join("settings.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v.get(key).and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

/// Path of the optional master-password wrapped-key blob.
pub fn wrap_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("vault-key.wrap")
}

/// Whether a master password is set (the wrapped-key blob exists on disk). When true, the
/// plaintext keychain key has been removed and the vault only opens via the password.
pub fn password_protected(data_dir: &std::path::Path) -> bool {
    wrap_path(data_dir).exists()
}

/// Store the vault key in the OS keychain (used when removing a master password, to return to
/// the keychain-backed "unlocked by default" model).
pub fn store_key(vk: &VaultKey) -> Result<(), String> {
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|e| e.to_string())?;
    let b64 = base64::engine::general_purpose::STANDARD.encode(vk.key().as_bytes());
    entry
        .set_password(&b64)
        .map_err(|e| format!("store vault key: {e}"))
}

/// Remove the plaintext vault key from the OS keychain (used when a master password is set, so
/// the password becomes the only way in). A missing entry is not an error.
pub fn delete_key() -> Result<(), String> {
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("delete vault key: {e}")),
    }
}

/// Store the base32 authenticator-app secret in the OS keychain.
pub fn totp_secret_store(secret: &str) -> Result<(), String> {
    keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TOTP)
        .map_err(|e| e.to_string())?
        .set_password(secret)
        .map_err(|e| format!("store totp secret: {e}"))
}

/// Load the base32 authenticator-app secret, or `None` if none is enrolled.
pub fn totp_secret_load() -> Result<Option<String>, String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TOTP).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(s) => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("keychain: {e}")),
    }
}

/// Remove the enrolled authenticator-app secret. A missing entry is not an error.
pub fn totp_secret_delete() -> Result<(), String> {
    let entry = keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TOTP).map_err(|e| e.to_string())?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("delete totp secret: {e}")),
    }
}

/// Read the vault key from the keychain WITHOUT creating one if it's absent (unlike
/// `load_or_create_key`). Used on unlock paths that must never mint a spurious key.
pub fn load_key_strict() -> Result<VaultKey, String> {
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|e| e.to_string())?;
    let b64 = entry.get_password().map_err(|e| format!("keychain: {e}"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|e| format!("decode stored key: {e}"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "stored vault key is not 32 bytes".to_string())?;
    Ok(VaultKey::from_key(Key32::from_bytes(arr)))
}

/// Read the 256-bit vault key from the OS keychain, generating and storing it on first run.
/// The key is base64 of the raw 32 bytes.
pub fn load_or_create_key() -> Result<VaultKey, String> {
    let entry =
        keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(b64) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| format!("decode stored key: {e}"))?;
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "stored vault key is not 32 bytes".to_string())?;
            Ok(VaultKey::from_key(Key32::from_bytes(arr)))
        }
        Err(keyring::Error::NoEntry) => {
            let vk = VaultKey::generate();
            let b64 = base64::engine::general_purpose::STANDARD.encode(vk.key().as_bytes());
            entry
                .set_password(&b64)
                .map_err(|e| format!("store vault key: {e}"))?;
            Ok(vk)
        }
        Err(e) => Err(format!("keychain: {e}")),
    }
}
