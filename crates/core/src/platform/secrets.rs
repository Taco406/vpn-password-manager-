//! Secret storage abstraction. The real implementation is the OS keychain (via the
//! Tauri secure-storage plugin / the `keyring` crate); this in-memory mock is for
//! tests only and never persists to disk (SECURITY.md T1: no secrets in the bundle or
//! in plaintext files).

use crate::error::Result;
use std::collections::HashMap;
use std::sync::Mutex;

pub trait SecretStore: Send + Sync {
    fn get(&self, name: &str) -> Result<Option<String>>;
    fn set(&self, name: &str, value: &str) -> Result<()>;
    fn delete(&self, name: &str) -> Result<()>;
}

/// In-memory secret store for tests. Values live only in RAM.
#[derive(Default)]
pub struct MemorySecretStore {
    inner: Mutex<HashMap<String, String>>,
}

impl SecretStore for MemorySecretStore {
    fn get(&self, name: &str) -> Result<Option<String>> {
        Ok(self.inner.lock().unwrap().get(name).cloned())
    }
    fn set(&self, name: &str, value: &str) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .insert(name.to_string(), value.to_string());
        Ok(())
    }
    fn delete(&self, name: &str) -> Result<()> {
        self.inner.lock().unwrap().remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_delete() {
        let s = MemorySecretStore::default();
        assert!(s.get("linode_token").unwrap().is_none());
        s.set("linode_token", "secret").unwrap();
        assert_eq!(s.get("linode_token").unwrap().as_deref(), Some("secret"));
        s.delete("linode_token").unwrap();
        assert!(s.get("linode_token").unwrap().is_none());
    }
}
