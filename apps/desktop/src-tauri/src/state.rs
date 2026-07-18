//! Desktop app state: the on-disk vault, the unlocked session, and the OS-keychain-backed
//! vault key. All the actual crypto/vault logic lives in `sentinel-core`; this crate is glue.
//!
//! Persistence model (the piece sentinel-core deliberately leaves to the app layer):
//!   - The vault *ciphertext* is a SQLite file (`vault.db`) in the OS app-data dir.
//!   - The 256-bit *vault key* lives ONLY in the OS keychain (Windows Credential Manager /
//!     macOS Keychain / Secret Service). It is never written next to the vault, so a stolen
//!     `vault.db` on its own is opaque ciphertext.
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
        let vault_key = load_or_create_key()?;
        Ok(AppState {
            inner: Mutex::new(Inner {
                session: VaultSession::unlocked(vault_key),
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
