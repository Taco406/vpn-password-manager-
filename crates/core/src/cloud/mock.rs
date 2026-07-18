//! Deterministic mock cloud provider. Models a boot delay (in poll counts, not wall
//! time, so tests never sleep) and is seeded with one pre-existing orphan so the
//! launch sweep has something to clean up.

use super::provider::{
    CloudProvider, Instance, InstanceSpec, InstanceState, Region, EPHEMERAL_TAG,
};
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

struct MockInstance {
    inst: Instance,
    /// `get` polls remaining before the instance flips Booting → Running.
    boot_polls_left: u32,
}

#[derive(Clone)]
pub struct MockCloud {
    instances: Arc<Mutex<HashMap<String, MockInstance>>>,
    next_id: Arc<AtomicU64>,
    boot_polls: u32,
    /// Force `create` to fail (to exercise the FSM's failure/cleanup path).
    fail_create: Arc<Mutex<bool>>,
}

impl Default for MockCloud {
    fn default() -> Self {
        Self::new(1)
    }
}

impl MockCloud {
    /// `boot_polls` = how many `get()` calls return Booting before Running.
    pub fn new(boot_polls: u32) -> Self {
        let cloud = MockCloud {
            instances: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(AtomicU64::new(1000)),
            boot_polls,
            fail_create: Arc::new(Mutex::new(false)),
        };
        // Seed one orphan from a "previous crashed session" for the sweep to reap.
        cloud.instances.lock().unwrap().insert(
            "orphan-666".into(),
            MockInstance {
                inst: Instance {
                    id: "orphan-666".into(),
                    region: "us-east".into(),
                    instance_type: "g6-nanode-1".into(),
                    state: InstanceState::Running,
                    ipv4: Some("203.0.113.66".into()),
                    tags: vec![EPHEMERAL_TAG.into()],
                },
                boot_polls_left: 0,
            },
        );
        cloud
    }

    pub fn set_fail_create(&self, fail: bool) {
        *self.fail_create.lock().unwrap() = fail;
    }

    pub fn count(&self) -> usize {
        self.instances.lock().unwrap().len()
    }
}

#[async_trait]
impl CloudProvider for MockCloud {
    async fn create(&self, spec: &InstanceSpec) -> Result<Instance> {
        if *self.fail_create.lock().unwrap() {
            return Err(CoreError::Provision {
                stage: "create",
                detail: "mock create failure".into(),
            });
        }
        let n = self.next_id.fetch_add(1, Ordering::SeqCst);
        let id = format!("inst-{n}");
        let octet = (n % 250) + 1;
        let inst = Instance {
            id: id.clone(),
            region: spec.region.clone(),
            instance_type: spec.instance_type.clone(),
            state: InstanceState::Booting,
            ipv4: Some(format!("203.0.113.{octet}")),
            tags: vec![EPHEMERAL_TAG.into()],
        };
        self.instances.lock().unwrap().insert(
            id.clone(),
            MockInstance {
                inst: inst.clone(),
                boot_polls_left: self.boot_polls,
            },
        );
        Ok(inst)
    }

    async fn get(&self, id: &str) -> Result<Instance> {
        let mut map = self.instances.lock().unwrap();
        let mi = map
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(format!("instance {id}")))?;
        if mi.boot_polls_left > 0 {
            mi.boot_polls_left -= 1;
            if mi.boot_polls_left == 0 {
                mi.inst.state = InstanceState::Running;
            }
        }
        Ok(mi.inst.clone())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.instances.lock().unwrap().remove(id);
        Ok(())
    }

    async fn list_ephemeral(&self) -> Result<Vec<Instance>> {
        Ok(self
            .instances
            .lock()
            .unwrap()
            .values()
            .filter(|mi| mi.inst.tags.iter().any(|t| t == EPHEMERAL_TAG))
            .map(|mi| mi.inst.clone())
            .collect())
    }

    async fn regions(&self) -> Result<Vec<Region>> {
        Ok(vec![
            Region {
                id: "us-east".into(),
                label: "Newark, NJ".into(),
                country: "US".into(),
            },
            Region {
                id: "eu-central".into(),
                label: "Frankfurt".into(),
                country: "DE".into(),
            },
            Region {
                id: "ap-northeast".into(),
                label: "Tokyo".into(),
                country: "JP".into(),
            },
        ])
    }

    fn price_per_hour(&self, instance_type: &str) -> f64 {
        match instance_type {
            "g6-nanode-1" => 0.0075,
            "g6-standard-2" => 0.036,
            "g6-standard-4" => 0.072,
            "g6-dedicated-4" => 0.108,
            _ => 0.0075,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> InstanceSpec {
        InstanceSpec {
            region: "us-east".into(),
            instance_type: "g6-nanode-1".into(),
            user_data: String::new(),
            label: "sentinel-test".into(),
        }
    }

    #[tokio::test]
    async fn boots_then_runs() {
        let cloud = MockCloud::new(2);
        let inst = cloud.create(&spec()).await.unwrap();
        assert_eq!(inst.state, InstanceState::Booting);
        assert_eq!(
            cloud.get(&inst.id).await.unwrap().state,
            InstanceState::Booting
        );
        assert_eq!(
            cloud.get(&inst.id).await.unwrap().state,
            InstanceState::Running
        );
    }

    #[tokio::test]
    async fn seeded_orphan_is_listed_and_deletable() {
        let cloud = MockCloud::new(0);
        let orphans = cloud.list_ephemeral().await.unwrap();
        assert!(orphans.iter().any(|i| i.id == "orphan-666"));
        cloud.delete("orphan-666").await.unwrap();
        assert!(cloud.get("orphan-666").await.is_err());
    }

    #[tokio::test]
    async fn create_failure_is_surfaced() {
        let cloud = MockCloud::new(0);
        cloud.set_fail_create(true);
        assert!(cloud.create(&spec()).await.is_err());
    }
}
