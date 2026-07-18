//! Desktop app state: the unlocked vault session, the local store, mock wrappers, and
//! VPN dependencies. All the actual logic lives in `sentinel-core`; this crate is glue.

use sentinel_core::cloud::MockCloud;
use sentinel_core::keyring::mock::MockBiometricWrapper;
use sentinel_core::keyring::VaultKey;
use sentinel_core::vault::{seal_item, LocalVault, VaultSession};
use sentinel_core::vpn::{ConnectDeps, MockPubkeyFetcher};
use sentinel_core::wg::MockWgController;
use std::sync::{Arc, Mutex};

/// Shared, thread-safe app state.
pub struct AppState {
    pub inner: Mutex<Inner>,
}

pub struct Inner {
    pub session: VaultSession,
    pub vault: LocalVault,
    pub platform: MockBiometricWrapper,
}

impl AppState {
    /// Build an in-memory, seeded state for the demo/dev shell. A real build wires the
    /// OS keychain, the platform biometric, and the on-disk vault here instead.
    pub fn new_demo() -> Self {
        let vault = LocalVault::open(":memory:").expect("open in-memory vault");
        let vault_key = VaultKey::generate();
        for item in sentinel_core::seed::demo_items() {
            if let Ok(env) = seal_item(&vault_key, &item) {
                let _ = vault.upsert(&env);
            }
        }
        AppState {
            inner: Mutex::new(Inner {
                session: VaultSession::unlocked(vault_key),
                vault,
                platform: MockBiometricWrapper::always_approved(),
            }),
        }
    }
}

/// VPN dependencies for the demo shell (all mocks — no real cloud/WG here).
pub fn vpn_deps() -> ConnectDeps {
    ConnectDeps {
        cloud: Arc::new(MockCloud::new(2)),
        wg: Arc::new(MockWgController::default()),
        fetcher: Arc::new(MockPubkeyFetcher { fail: false }),
        max_boot_polls: 10,
    }
}
