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
    /// Delay between boot polls, in milliseconds. Live: ~3s (a Linode takes ~1 min to reach
    /// Running, so `max_boot_polls * poll_interval_ms` must cover that). Tests/mock: 0 so the
    /// deterministic poll-count model never actually sleeps.
    pub poll_interval_ms: u64,
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
    allowed_ips: Vec<String>,
    emit: &mut StateSink<'_>,
) -> Result<Connection> {
    let mut created: Option<String> = None;
    let result = connect_inner(deps, region, instance_type, allowed_ips, emit, &mut created).await;

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
    allowed_ips: Vec<String>,
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
    let cloud_init = provision::render_base64(&CloudInitParams::single(
        server_kp.private_base64(),
        client_kp.public_base64(),
        "10.66.0.2".into(),
        51820,
        callback_token.clone(),
        callback_hmac_key.clone(),
        900,
    ))?;

    // 2) Create the instance. It is tagged ephemeral, so even if we crash right here the
    //    launch sweep will reap it.
    emit(ConnectState::CreatingInstance);
    let spec = InstanceSpec {
        region: region.into(),
        instance_type: instance_type.into(),
        user_data: cloud_init,
        label: format!("sentinel-{region}"),
        tags: vec![], // ephemeral VPN exit node — the sweep manages it
    };
    let instance = deps.cloud.create(&spec).await?;
    *created = Some(instance.id.clone());

    // 3) Wait for boot.
    emit(ConnectState::Booting);
    let mut running = instance.clone();
    for _ in 0..deps.max_boot_polls {
        // Wait between polls — a real Linode takes ~1 min to reach Running, so polling in a
        // tight loop (no delay) would exhaust every attempt in seconds and wrongly time out.
        if deps.poll_interval_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(deps.poll_interval_ms)).await;
        }
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

    // 4) Wait for the node to finish booting. The callback is an HMAC-authenticated *readiness*
    //    gate — it only answers once cloud-init has brought wg0 and its services up (the callback
    //    unit is ordered `After=wg-quick@wg0.service`). If it never answers we fail here and the
    //    caller destroys the created instance.
    //
    //    We deliberately DON'T use the pubkey it returns. The server's identity is the
    //    app-generated `server_kp`, whose PRIVATE key we baked into `wg0.conf` (step 1). Pinning
    //    the callback's key here was a bug: the node reported a *different*, freshly on-box-generated
    //    key, so every client handshake was sealed to a key `wg0` doesn't hold and was silently
    //    dropped — the "no handshake within 120s" failure, every time. The multi-hop path already
    //    pins the app-generated key directly; single-hop now matches it.
    emit(ConnectState::ExchangingKeys);
    let _ready = deps
        .fetcher
        .fetch(&ip, &callback_token, &callback_hmac_key)
        .await?;

    // 5) Bring the tunnel up, pinning the server key `wg0` actually runs.
    emit(ConnectState::StartingTunnel);
    let conf = ClientConf {
        client_private_key: client_kp.private_base64(),
        client_address: "10.66.0.2/32".into(),
        dns: "1.1.1.1".into(),
        server_public_key: server_kp.public_base64(),
        server_endpoint: format!("{ip}:51820"),
        allowed_ips,
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

// --- split-tunnel AllowedIPs decision -------------------------------------
//
// Include-mode split tunneling: the client's `AllowedIPs` is either the full-tunnel default or a
// user-chosen set of CIDRs. The decision is a pure function so it can be exhaustively unit tested
// independent of settings-file I/O (the platform layer reads `tunnelMode`/`splitRoutes` from disk
// and hands them here).

/// Permissive check that a string looks like a CIDR: an address part followed by a numeric prefix
/// (`addr/bits`). Accepts IPv4 (`10.0.0.0/8`) and IPv6 (`2001:db8::/32`) forms without fully
/// parsing them — the goal is to reject empty/garbage, not to be a full validator. The safe
/// fallback in [`decide_allowed_ips`] means a rejected entry can only ever widen routing back to
/// full-tunnel, never route "nothing".
fn looks_like_cidr(s: &str) -> bool {
    let s = s.trim();
    let Some((addr, prefix)) = s.split_once('/') else {
        return false;
    };
    if addr.is_empty() {
        return false;
    }
    // Prefix must be all digits and within the widest sane range (IPv6 = 128 bits).
    match prefix.parse::<u32>() {
        Ok(bits) if bits <= 128 => {}
        _ => return false,
    }
    // Address must at least look like IPv4 (has a dot) or IPv6 (has a colon).
    addr.contains('.') || addr.contains(':')
}

/// Pure decision: given the persisted tunnel mode and split routes, compute the client's WireGuard
/// `AllowedIPs`. In `"split"` mode with at least one valid CIDR, only those route through the VPN;
/// anything else — full mode, or split with an empty/all-invalid list — falls back to
/// [`full_tunnel`]. This is the load-bearing safety property: we never route "nothing".
pub fn decide_allowed_ips(tunnel_mode: Option<&str>, split_routes: &[String]) -> Vec<String> {
    if tunnel_mode == Some("split") {
        let cidrs: Vec<String> = split_routes
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| looks_like_cidr(s))
            .collect();
        if !cidrs.is_empty() {
            return cidrs;
        }
    }
    full_tunnel()
}

// --- a mock pubkey fetcher for tests / demo -------------------------------

/// The pubkey the mock callback reports. A connect must NOT pin this — the server's identity is
/// the app-generated key baked into wg0.conf, not whatever the node hands back over its callback.
pub const MOCK_CALLBACK_PUBKEY: &str = "MOCKSERVERPUBKEYbase64000000000000000000000=";

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
        let pubkey = MOCK_CALLBACK_PUBKEY;
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
            poll_interval_ms: 0, // deterministic poll-count model — never actually sleep in tests
        }
    }

    #[tokio::test]
    async fn happy_path_connects_and_reports_states() {
        let cloud = MockCloud::new(2);
        let d = deps(cloud, false);
        let mut states = Vec::new();
        let mut sink = |s: ConnectState| states.push(s);
        let conn = connect(&d, "us-east", "g6-nanode-1", full_tunnel(), &mut sink)
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
    async fn client_pins_server_key_not_the_callback_key() {
        // Regression for the v0.1.19 handshake bug. The exit node runs the server key we generated
        // (its private key is baked into wg0.conf via cloud-init); the callback reports a *separate*
        // key. If the client ever pins the callback's key again, every handshake is sealed to a key
        // the server doesn't hold and silently dropped — "no handshake," every time. Assert the
        // rendered client config does NOT contain the callback's key.
        let cloud = MockCloud::new(2);
        let d = deps(cloud, false);
        let mut sink = |_s: ConnectState| {};
        let conn = connect(&d, "us-east", "g6-nanode-1", full_tunnel(), &mut sink)
            .await
            .unwrap();
        assert!(
            !conn.client_conf.contains(MOCK_CALLBACK_PUBKEY),
            "client pinned the callback's key instead of the server key baked into wg0.conf"
        );
        // It must still pin *some* real server key (the app-generated one).
        assert!(conn.client_conf.contains("PublicKey = "));
    }

    #[tokio::test]
    async fn create_failure_leaves_no_instance() {
        let cloud = MockCloud::new(0);
        cloud.set_fail_create(true);
        let before = cloud.count();
        let d = deps(cloud.clone(), false);
        let mut sink = |_s: ConnectState| {};
        let r = connect(&d, "us-east", "g6-nanode-1", full_tunnel(), &mut sink).await;
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
        let r = connect(&d, "eu-central", "g6-nanode-1", full_tunnel(), &mut sink).await;

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
        let r = connect(&d, "us-east", "g6-nanode-1", full_tunnel(), &mut sink).await;
        assert!(r.is_err());
        assert_eq!(cloud.count(), baseline);
    }

    #[test]
    fn full_mode_uses_full_tunnel() {
        // Default / explicit full mode → full-tunnel, regardless of any routes present.
        assert_eq!(decide_allowed_ips(None, &[]), full_tunnel());
        assert_eq!(decide_allowed_ips(Some("full"), &[]), full_tunnel());
        assert_eq!(
            decide_allowed_ips(Some("full"), &["10.0.0.0/8".into()]),
            full_tunnel(),
            "full mode must ignore split routes"
        );
    }

    #[test]
    fn split_with_valid_routes_uses_those_cidrs() {
        let routes = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];
        assert_eq!(decide_allowed_ips(Some("split"), &routes), routes);
        // IPv6 CIDRs are accepted too.
        assert_eq!(
            decide_allowed_ips(Some("split"), &["2001:db8::/32".to_string()]),
            vec!["2001:db8::/32".to_string()]
        );
        // Surrounding whitespace is trimmed.
        assert_eq!(
            decide_allowed_ips(Some("split"), &["  10.0.0.0/8  ".to_string()]),
            vec!["10.0.0.0/8".to_string()]
        );
    }

    #[test]
    fn split_with_empty_routes_falls_back_to_full_tunnel() {
        assert_eq!(decide_allowed_ips(Some("split"), &[]), full_tunnel());
    }

    #[test]
    fn split_with_only_garbage_falls_back_to_full_tunnel() {
        // Missing prefix, empty address, non-numeric prefix, out-of-range prefix, plain junk.
        let garbage = vec![
            "not-a-cidr".to_string(),
            "10.0.0.0".to_string(),
            "/8".to_string(),
            "10.0.0.0/abc".to_string(),
            "10.0.0.0/999".to_string(),
            "".to_string(),
            "   ".to_string(),
        ];
        assert_eq!(decide_allowed_ips(Some("split"), &garbage), full_tunnel());
    }

    #[test]
    fn split_keeps_only_the_valid_routes() {
        // A mix drops the garbage and keeps the valid CIDRs (still narrower than full-tunnel).
        let mixed = vec![
            "10.0.0.0/8".to_string(),
            "garbage".to_string(),
            "192.168.0.0/16".to_string(),
        ];
        assert_eq!(
            decide_allowed_ips(Some("split"), &mixed),
            vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()]
        );
    }

    #[tokio::test]
    async fn disconnect_destroys_instance() {
        let cloud = MockCloud::new(1);
        let d = deps(cloud.clone(), false);
        let mut sink = |_s: ConnectState| {};
        let conn = connect(&d, "us-east", "g6-nanode-1", full_tunnel(), &mut sink)
            .await
            .unwrap();
        let n = cloud.count();
        disconnect(&d, &conn.instance.id, &mut sink).await.unwrap();
        assert_eq!(cloud.count(), n - 1);
    }
}
