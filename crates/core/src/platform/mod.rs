//! OS integration traits (kill switch, network info, secret storage). Each has a real
//! implementation (cfg-gated to its OS, documented) and a mock for tests/the demo.
//! Nothing here holds real secrets in plaintext.

pub mod killswitch;
pub mod netinfo;
pub mod secrets;

pub use killswitch::{KillSwitch, MockKillSwitch};
pub use netinfo::{MockNetInfo, NetInfo};
pub use secrets::{MemorySecretStore, SecretStore};
