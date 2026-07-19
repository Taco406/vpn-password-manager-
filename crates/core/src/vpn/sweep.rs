//! Orphan sweep: on every app launch (and periodically while running), destroy any
//! instance tagged ephemeral that a crash left behind (D10).

use crate::cloud::CloudProvider;
use crate::error::Result;
use std::collections::HashSet;

/// Destroy all ephemeral instances the provider knows about. Returns the ids reaped.
/// `keep` lets an active session exclude its own instance from the sweep.
pub async fn orphan_sweep(cloud: &dyn CloudProvider, keep: Option<&str>) -> Result<Vec<String>> {
    let set: HashSet<String> = keep.map(|k| k.to_string()).into_iter().collect();
    orphan_sweep_keeping(cloud, &set).await
}

/// Destroy every ephemeral instance whose id is NOT in `keep`. This is the money-critical
/// invariant behind node-keeping: nodes the user deliberately kept (registry) plus the current
/// active node are excluded; everything else (crash orphans) is reaped. Returns the ids reaped.
pub async fn orphan_sweep_keeping(
    cloud: &dyn CloudProvider,
    keep: &HashSet<String>,
) -> Result<Vec<String>> {
    let mut reaped = Vec::new();
    for inst in cloud.list_ephemeral().await? {
        if keep.contains(&inst.id) {
            continue;
        }
        if cloud.delete(&inst.id).await.is_ok() {
            reaped.push(inst.id);
        }
    }
    Ok(reaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::MockCloud;

    #[tokio::test]
    async fn reaps_seeded_orphan_on_launch() {
        let cloud = MockCloud::new(0);
        let reaped = orphan_sweep(&cloud, None).await.unwrap();
        assert!(reaped.contains(&"orphan-666".to_string()));
        // Nothing ephemeral left.
        assert!(cloud.list_ephemeral().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn keeps_active_instance() {
        let cloud = MockCloud::new(0);
        let spec = crate::cloud::InstanceSpec {
            region: "us-east".into(),
            instance_type: "g6-nanode-1".into(),
            user_data: String::new(),
            label: "active".into(),
        };
        let active = cloud.create(&spec).await.unwrap();
        let reaped = orphan_sweep(&cloud, Some(&active.id)).await.unwrap();
        assert!(reaped.contains(&"orphan-666".to_string()));
        assert!(!reaped.contains(&active.id));
        // The active instance survives.
        assert!(cloud.get(&active.id).await.is_ok());
    }

    #[tokio::test]
    async fn keeps_a_set_of_nodes() {
        let cloud = MockCloud::new(0);
        let spec = crate::cloud::InstanceSpec {
            region: "us-east".into(),
            instance_type: "g6-nanode-1".into(),
            user_data: String::new(),
            label: "kept".into(),
        };
        let a = cloud.create(&spec).await.unwrap();
        let b = cloud.create(&spec).await.unwrap();
        let keep: HashSet<String> = [a.id.clone(), b.id.clone()].into_iter().collect();
        let reaped = orphan_sweep_keeping(&cloud, &keep).await.unwrap();
        // Only the crash orphan is reaped; both kept nodes survive.
        assert_eq!(reaped, vec!["orphan-666".to_string()]);
        assert!(cloud.get(&a.id).await.is_ok());
        assert!(cloud.get(&b.id).await.is_ok());
    }
}
