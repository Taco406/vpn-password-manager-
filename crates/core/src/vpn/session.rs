//! The connect state machine. Target: ≤120s click-to-tunnel on a warm region. The
//! load-bearing safety property (D10): **every** failure edge destroys the instance,
//! so a crash or error mid-connect never leaves a billing box. A property test
//! exercises failure at each stage and asserts the instance is deleted.

use crate::cloud::{CloudProvider, Instance, InstanceSpec, InstanceState};
use crate::error::{CoreError, Result};
use crate::provision::{self, CloudInitParams};
use crate::wg::{full_tunnel, render_client_conf, ClientConf, WgController, WgKeypair};
use async_trait::async_trait;
use rand::RngCore;
use std::sync::Arc;

/// Observable connect state, surfaced to the UI as it advances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectState {
    Idle,
    CreatingInstance,
    Booting,
    ExchangingKeys,
    StartingTunnel,
    Connected {
        instance_id: String,
        egress_ip: Option<String>,
    },
    Disconnecting,
    Destroying,
    Failed {
        stage: &'static str,
        reason: String,
    },
}

/// Retrieves the fresh server's authenticated WireGuard public key.
#[async_trait]
pub trait ServerPubkeyFetcher: Send + Sync {
    async fn fetch(&self, ip: &str, token: &str, hmac_key_hex: &str) -> Result<String>;
}

/// Dependencies for a connect attempt (all mockable).
#[derive(Clone)]
pub struct ConnectDeps {
    pub cloud: Arc<dyn CloudProvider>,
    pub wg: Arc<dyn WgController>,
    pub fetcher: Arc<dyn ServerPubkeyFetcher>,
    /// Max boot polls before giving up.
    pub max_boot_polls: u32,
}

/// A successful connection.
#[derive(Clone, Debug)]
pub struct Connection {
    pub instance: Instance,
    pub client_conf: String,
}

/// Emitter for state transitions (the UI subscribes via a watch channel wrapper).
pub type StateSink<'a> = dyn FnMut(ConnectState) + Send + 'a;

/// Drive a full connect. On ANY error, the created instance is destroyed before
/// returning, so no orphan is left. `emit` receives each state transition.
pub async fn connect(
    deps: &ConnectDeps,
    region: &str,
    instance_type: &str,
    emit: &mut StateSink<'_>,
) -> Result<Connection> {
    let mut created: Option<String> = None;
    let result = connect_inner(deps, region, instance_type, emit, &mut created).await;

    if let Err(ref e) = result {
        // Guaranteed cleanup: destroy whatever we created, whatever went wrong.
        if let Some(id) = &created {
            emit(ConnectState::Destroying);
            let _ = deps.cloud.delete(id).await;
        }
        emit(ConnectState::Failed {
            stage: stage_of(e),
            reason: e.to_string(),
        });
    }
    result
}

fn stage_of(e: &CoreError) -> &'static str {
    match e {
        CoreError::Provision { stage, .. } => stage,
        _ => "connect",
    }
}

async fn connect_inner(
    deps: &ConnectDeps,
    region: &str,
    instance_type: &str,
    emit: &mut StateSink<'_>,
    created: &mut Option<String>,
) -> Result<Connection> {
    // 1) Local key material + provisioning secrets.
    let client_kp = WgKeypair::generate();
    let mut token_b = [0u8; 32];
    let mut hmac_b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_b);
    rand::rngs::OsRng.fill_bytes(&mut hmac_b);
    let callback_token = hex(&token_b);
    let callback_hmac_key = hex(&hmac_b);

    let server_kp = WgKeypair::generate(); // server privkey travels only in user_data
    let cloud_init = provision::render_base64(&CloudInitParams {
        server_privkey: server_kp.private_base64(),
        client_pubkey: client_kp.public_base64(),
        client_ip: "10.66.0.2".into(),
        listen_port: 51820,
        callback_token: callback_token.clone(),
        callback_hmac_key: callback_hmac_key.clone(),
        deadman_secs: 900,
    })?;

    // 2) Create the instance. It is tagged ephemeral, so even if we crash right here the
    //    launch sweep will reap it.
    emit(ConnectState::CreatingInstance);
    let spec = InstanceSpec {
        region: region.into(),
        instance_type: instance_type.into(),
        user_data: cloud_init,
        label: format!("sentinel-{region}"),
    };
    let instance = deps.cloud.create(&spec).await?;
    *created = Some(instance.id.clone());

    // 3) Wait for boot.
    emit(ConnectState::Booting);
    let mut running = instance.clone();
    for _ in 0..deps.max_boot_polls {
        let cur = deps.cloud.get(&instance.id).await?;
        if cur.state == InstanceState::Running {
            running = cur;
            break;
        }
    }
    if running.state != InstanceState::Running {
        return Err(CoreError::Provision {
            stage: "boot",
            detail: "instance did not reach Running in time".into(),
        });
    }
    let ip = running.ipv4.clone().ok_or(CoreError::Provision {
        stage: "boot",
        detail: "no ipv4".into(),
    })?;

    // 4) Retrieve the server pubkey via the authenticated one-shot callback.
    emit(ConnectState::ExchangingKeys);
    let server_pubkey = deps
        .fetcher
        .fetch(&ip, &callback_token, &callback_hmac_key)
        .await?;

    // 5) Bring the tunnel up.
    emit(ConnectState::StartingTunnel);
    let conf = ClientConf {
        client_private_key: client_kp.private_base64(),
        client_address: "10.66.0.2/32".into(),
        dns: "1.1.1.1".into(),
        server_public_key: server_pubkey,
        server_endpoint: format!("{ip}:51820"),
        allowed_ips: full_tunnel(),
        keepalive: 25,
    };
    let rendered = render_client_conf(&conf);
    deps.wg.up(&conf).await?;

    emit(ConnectState::Connected {
        instance_id: running.id.clone(),
        egress_ip: running.ipv4.clone(),
    });
    Ok(Connection {
        instance: running,
        client_conf: rendered,
    })
}

/// Tear down a live connection: drop the tunnel, then destroy the instance.
pub async fn disconnect(
    deps: &ConnectDeps,
    instance_id: &str,
    emit: &mut StateSink<'_>,
) -> Result<()> {
    emit(ConnectState::Disconnecting);
    let _ = deps.wg.down().await;
    emit(ConnectState::Destroying);
    deps.cloud.delete(instance_id).await?;
    emit(ConnectState::Idle);
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- a mock pubkey fetcher for tests / demo -------------------------------

/// Returns a fixed valid server pubkey (its own key with a correct HMAC), or an error
/// to exercise the ExchangingKeys failure path.
pub struct MockPubkeyFetcher {
    pub fail: bool,
}

#[async_trait]
impl ServerPubkeyFetcher for MockPubkeyFetcher {
    async fn fetch(&self, ip: &str, _token: &str, hmac_key_hex: &str) -> Result<String> {
        if self.fail {
            return Err(CoreError::Provision {
                stage: "keys",
                detail: "callback timed out".into(),
            });
        }
        // Simulate the server producing a pubkey and a valid HMAC, then verifying it.
        let pubkey = "MOCKSERVERPUBKEYbase64000000000000000000000=";
        let mac = provision::compute_mac(pubkey, ip, hmac_key_hex)?;
        let body = provision::CallbackBody {
            pubkey: pubkey.into(),
            ip: ip.into(),
            mac,
        };
        provision::verify_callback(&body, hmac_key_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cloud::MockCloud;
    use crate::wg::MockWgController;

    fn deps(cloud: MockCloud, fetcher_fail: bool) -> ConnectDeps {
        ConnectDeps {
            cloud: Arc::new(cloud),
            wg: Arc::new(MockWgController::default()),
            fetcher: Arc::new(MockPubkeyFetcher { fail: fetcher_fail }),
            max_boot_polls: 10,
        }
    }

    #[tokio::test]
    async fn happy_path_connects_and_reports_states() {
        let cloud = MockCloud::new(2);
        let d = deps(cloud, false);
        let mut states = Vec::new();
        let mut sink = |s: ConnectState| states.push(s);
        let conn = connect(&d, "us-east", "g6-nanode-1", &mut sink)
            .await
            .unwrap();

        assert!(conn.instance.ipv4.is_some());
        assert!(conn.client_conf.contains("[Peer]"));
        assert_eq!(states.first(), Some(&ConnectState::CreatingInstance));
        assert!(states
            .iter()
            .any(|s| matches!(s, ConnectState::Connected { .. })));
    }

    #[tokio::test]
    async fn create_failure_leaves_no_instance() {
        let cloud = MockCloud::new(0);
        cloud.set_fail_create(true);
        let before = cloud.count();
        let d = deps(cloud.clone(), false);
        let mut sink = |_s: ConnectState| {};
        let r = connect(&d, "us-east", "g6-nanode-1", &mut sink).await;
        assert!(r.is_err());
        // No new instance beyond the seeded orphan.
        assert_eq!(cloud.count(), before);
    }

    #[tokio::test]
    async fn keys_failure_destroys_created_instance() {
        // The instance is created, then the pubkey callback fails → it MUST be deleted.
        let cloud = MockCloud::new(1);
        let baseline = cloud.count();
        let d = deps(cloud.clone(), true); // fetcher fails
        let mut states = Vec::new();
        let mut sink = |s: ConnectState| states.push(s);
        let r = connect(&d, "eu-central", "g6-nanode-1", &mut sink).await;

        assert!(r.is_err());
        assert!(
            states.contains(&ConnectState::Destroying),
            "must destroy on failure"
        );
        assert!(states
            .iter()
            .any(|s| matches!(s, ConnectState::Failed { .. })));
        // Count is back to baseline: the created instance was destroyed.
        assert_eq!(
            cloud.count(),
            baseline,
            "created instance was not cleaned up"
        );
    }

    #[tokio::test]
    async fn boot_timeout_destroys_instance() {
        // Instance never reaches Running within max_boot_polls → cleanup.
        let cloud = MockCloud::new(100);
        let baseline = cloud.count();
        let mut d = deps(cloud.clone(), false);
        d.max_boot_polls = 3;
        let mut sink = |_s: ConnectState| {};
        let r = connect(&d, "us-east", "g6-nanode-1", &mut sink).await;
        assert!(r.is_err());
        assert_eq!(cloud.count(), baseline);
    }

    #[tokio::test]
    async fn disconnect_destroys_instance() {
        let cloud = MockCloud::new(1);
        let d = deps(cloud.clone(), false);
        let mut sink = |_s: ConnectState| {};
        let conn = connect(&d, "us-east", "g6-nanode-1", &mut sink)
            .await
            .unwrap();
        let n = cloud.count();
        disconnect(&d, &conn.instance.id, &mut sink).await.unwrap();
        assert_eq!(cloud.count(), n - 1);
    }
}
