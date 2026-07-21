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
        // Honor the spec's tags (else ephemeral), matching the real client, so tests can prove a
        // durable-tagged node is excluded from the ephemeral-only sweep.
        let tags = if spec.tags.is_empty() {
            vec![EPHEMERAL_TAG.into()]
        } else {
            spec.tags.clone()
        };
        let inst = Instance {
            id: id.clone(),
            region: spec.region.clone(),
            instance_type: spec.instance_type.clone(),
            state: InstanceState::Booting,
            ipv4: Some(format!("203.0.113.{octet}")),
            tags,
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

    async fn shutdown(&self, id: &str) -> Result<()> {
        let mut map = self.instances.lock().unwrap();
        let mi = map
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(format!("instance {id}")))?;
        mi.inst.state = InstanceState::Stopped;
        mi.boot_polls_left = 0;
        Ok(())
    }

    async fn boot(&self, id: &str) -> Result<()> {
        let mut map = self.instances.lock().unwrap();
        let mi = map
            .get_mut(id)
            .ok_or_else(|| CoreError::NotFound(format!("instance {id}")))?;
        mi.inst.state = InstanceState::Booting;
        mi.boot_polls_left = self.boot_polls;
        if self.boot_polls == 0 {
            mi.inst.state = InstanceState::Running;
        }
        Ok(())
    }

    async fn reboot(&self, id: &str) -> Result<()> {
        self.boot(id).await
    }
}

// ---------------------------------------------------------------------------
// Deterministic full-account server manager (the Servers screen, demo/tests).
// ---------------------------------------------------------------------------

use super::manager::{
    MetricPoint, PowerAction, Provider, ServerEvent, ServerInfo, ServerManager, ServerMetrics,
    Snapshot,
};

/// A fixed 3-server fleet with sine-wave metrics. States are mutable so power actions
/// can be exercised in tests; Stage 3 snapshots/protection are held in-memory too.
#[derive(Clone)]
pub struct MockServerManager {
    states: Arc<Mutex<HashMap<String, InstanceState>>>,
    snapshots: Arc<Mutex<HashMap<String, Vec<Snapshot>>>>,
    protection: Arc<Mutex<HashMap<String, bool>>>,
    provider: Provider,
}

impl Default for MockServerManager {
    fn default() -> Self {
        Self::new(Provider::Hetzner)
    }
}

impl MockServerManager {
    pub fn new(provider: Provider) -> Self {
        let mut states = HashMap::new();
        states.insert("m-1".to_string(), InstanceState::Running);
        states.insert("m-2".to_string(), InstanceState::Running);
        states.insert("m-3".to_string(), InstanceState::Stopped);
        MockServerManager {
            states: Arc::new(Mutex::new(states)),
            snapshots: Arc::new(Mutex::new(HashMap::new())),
            protection: Arc::new(Mutex::new(HashMap::new())),
            provider,
        }
    }
}

#[async_trait]
impl ServerManager for MockServerManager {
    async fn list_all(&self) -> Result<Vec<ServerInfo>> {
        let states = self.states.lock().unwrap();
        let mut ids: Vec<&String> = states.keys().collect();
        ids.sort();
        Ok(ids
            .into_iter()
            .map(|id| ServerInfo {
                provider: self.provider,
                id: id.clone(),
                label: format!("mock-{id}"),
                region: "fsn1".into(),
                instance_type: "cx22".into(),
                state: states[id],
                ipv4: Some("203.0.113.9".into()),
                ipv6: None,
                tags: vec![],
                created_at: Some(1_700_000_000),
                vcpus: 2,
                memory_mb: 4096,
                disk_gb: 40,
                hourly: 0.008,
                monthly: 4.99,
                currency: "EUR",
            })
            .collect())
    }

    async fn metrics(&self, _id: &str, window_secs: u32) -> Result<ServerMetrics> {
        // 90 sine-wave points across the window, anchored to a fixed epoch (deterministic).
        let end: i64 = 1_700_000_000;
        let step = (window_secs.max(90) / 90) as i64;
        let mk = |amp: f64, base: f64| -> Vec<MetricPoint> {
            (0..90)
                .map(|i| MetricPoint {
                    ts: end - (89 - i) * step,
                    value: base + amp * ((i as f64) / 7.0).sin().abs(),
                })
                .collect()
        };
        Ok(ServerMetrics {
            cpu_pct: mk(35.0, 5.0),
            net_in_bps: mk(400_000.0, 20_000.0),
            net_out_bps: mk(150_000.0, 10_000.0),
            disk_io: mk(30.0, 2.0),
        })
    }

    async fn power(&self, id: &str, action: PowerAction) -> Result<()> {
        let mut states = self.states.lock().unwrap();
        let st = states
            .get_mut(id)
            .ok_or(CoreError::Network("no such server".into()))?;
        *st = match action {
            PowerAction::Boot | PowerAction::Reboot => InstanceState::Running,
            PowerAction::Shutdown => InstanceState::Stopped,
        };
        Ok(())
    }

    async fn snapshot(&self, id: &str, label: &str) -> Result<()> {
        let mut snaps = self.snapshots.lock().unwrap();
        let list = snaps.entry(id.to_string()).or_default();
        let next = 900 + list.len() as u64;
        // Newest first, matching the live parsers.
        list.insert(
            0,
            Snapshot {
                id: next.to_string(),
                label: label.to_string(),
                created_at: Some(1_700_000_000 + next as i64),
                size_gb: Some(2.5),
                status: "available".into(),
            },
        );
        Ok(())
    }

    async fn list_snapshots(&self, id: &str) -> Result<Vec<Snapshot>> {
        Ok(self
            .snapshots
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    async fn set_rdns(&self, _id: &str, _ip: &str, _ptr: &str) -> Result<()> {
        Ok(())
    }

    async fn set_protection(&self, id: &str, on: bool) -> Result<()> {
        self.protection.lock().unwrap().insert(id.to_string(), on);
        Ok(())
    }

    async fn recent_events(&self, _id: &str) -> Result<Vec<ServerEvent>> {
        Ok(vec![
            ServerEvent {
                action: "reboot".into(),
                status: "success".into(),
                created_at: Some(1_700_000_000),
                progress: Some(100.0),
            },
            ServerEvent {
                action: "create_image".into(),
                status: "success".into(),
                created_at: Some(1_699_990_000),
                progress: Some(100.0),
            },
        ])
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
            tags: vec![],
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

    #[tokio::test]
    async fn shutdown_boot_reboot_transitions() {
        let cloud = MockCloud::new(0);
        let inst = cloud.create(&spec()).await.unwrap();
        // running → stopped (still exists / still "billing")
        cloud.shutdown(&inst.id).await.unwrap();
        assert_eq!(
            cloud.get(&inst.id).await.unwrap().state,
            InstanceState::Stopped
        );
        assert!(cloud
            .list_ephemeral()
            .await
            .unwrap()
            .iter()
            .any(|i| i.id == inst.id));
        // stopped → running
        cloud.boot(&inst.id).await.unwrap();
        assert_eq!(
            cloud.get(&inst.id).await.unwrap().state,
            InstanceState::Running
        );
        // reboot keeps it running
        cloud.reboot(&inst.id).await.unwrap();
        assert_eq!(
            cloud.get(&inst.id).await.unwrap().state,
            InstanceState::Running
        );
        // power ops on a missing node error
        assert!(cloud.shutdown("nope").await.is_err());
    }

    #[tokio::test]
    async fn mock_server_manager_lists_and_powers() {
        let m = MockServerManager::default();
        let fleet = m.list_all().await.unwrap();
        assert_eq!(fleet.len(), 3);
        assert_eq!(fleet[2].state, InstanceState::Stopped);
        m.power("m-3", PowerAction::Boot).await.unwrap();
        assert_eq!(m.list_all().await.unwrap()[2].state, InstanceState::Running);
        let metrics = m.metrics("m-1", 3600).await.unwrap();
        assert_eq!(metrics.cpu_pct.len(), 90);
        assert!(m.power("nope", PowerAction::Reboot).await.is_err());
    }

    #[tokio::test]
    async fn mock_server_manager_stage3_roundtrips() {
        let m = MockServerManager::default();
        // Snapshots: empty, then two — newest first.
        assert!(m.list_snapshots("m-1").await.unwrap().is_empty());
        m.snapshot("m-1", "first").await.unwrap();
        m.snapshot("m-1", "second").await.unwrap();
        let snaps = m.list_snapshots("m-1").await.unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].label, "second"); // newest first
                                              // rDNS + protection succeed; events come back non-empty.
        m.set_rdns("m-1", "203.0.113.9", "host.example.com")
            .await
            .unwrap();
        m.set_protection("m-1", true).await.unwrap();
        assert_eq!(m.recent_events("m-1").await.unwrap().len(), 2);
    }
}
