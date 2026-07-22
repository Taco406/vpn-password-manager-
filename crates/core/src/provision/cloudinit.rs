//! Cloud-init user-data for a single-boot ephemeral WireGuard node. The rendered YAML:
//! installs `wireguard-tools` (userspace only — the WireGuard module ships in Linode's kernel,
//! so we skip the slow `wireguard` DKMS compile that delayed the pubkey callback), applies an
//! nftables default-drop firewall plus NAT (so forwarded
//! client traffic actually egresses — either to the internet, or to the next hop for a
//! multi-hop chain), disables SSH entirely, writes the server config, serves its public key
//! once over HTTPS authenticated by an HMAC, and arms a dead-man timer that powers the box
//! off if no handshake arrives (D10, D11).
//!
//! Multi-hop ("bounce"): when `next_hop` is set, the node also brings up a SECOND WireGuard
//! interface (`wg1`) as a *client* to the next hop and routes the traffic it receives on
//! `wg0` out through `wg1` instead of to the internet. The exit node (no `next_hop`) NATs to
//! the internet as usual. Only the entry node faces the user's client. See `provision/multihop.rs`.

use crate::error::{CoreError, Result};
use minijinja::{context, Environment};

const TEMPLATE: &str = r#"#cloud-config
package_update: true
packages:
  - wireguard-tools
  - nftables

write_files:
  - path: /etc/wireguard/wg0.conf
    permissions: '0600'
    content: |
      [Interface]
      PrivateKey = {{ server_privkey }}
      Address = 10.66.0.1/24
      ListenPort = {{ listen_port }}
      SaveConfig = false

      [Peer]
      PublicKey = {{ client_pubkey }}
      AllowedIPs = {{ client_ip }}/32
{% if next_hop %}
  - path: /etc/wireguard/wg1.conf
    permissions: '0600'
    content: |
      [Interface]
      PrivateKey = {{ nh_privkey }}
      Address = {{ nh_address }}

      [Peer]
      PublicKey = {{ nh_peer_pubkey }}
      Endpoint = {{ nh_peer_endpoint }}
      AllowedIPs = 0.0.0.0/0, ::/0
      PersistentKeepalive = 25
{% endif %}
  - path: /etc/nftables.conf
    permissions: '0644'
    content: |
      #!/usr/sbin/nft -f
      flush ruleset
      table inet filter {
        chain input {
          type filter hook input priority 0; policy drop;
          ct state established,related accept
          iif "lo" accept
          udp dport {{ listen_port }} accept
          tcp dport 443 accept
          # MUST be `iifname` (name match at runtime), NOT `iif` (interface INDEX resolved at
          # load time). cloud-init loads this ruleset BEFORE wg-quick brings wg0 up, so `iif
          # "wg0"` errors "Interface does not exist" and — because `nft -f` is atomic — rejects
          # the WHOLE file, including the NAT table below. With no masquerade the client's
          # packets egress with a private source and never get a reply: the tunnel handshakes
          # (so it looks "connected") but no real traffic flows.
          iifname "wg0" accept
        }
        chain forward { type filter hook forward priority 0; policy accept; }
        chain output { type filter hook output priority 0; policy accept; }
      }
      table ip nat {
        chain postrouting {
          type nat hook postrouting priority 100; policy accept;
          # Masquerade everything leaving via any interface EXCEPT the client tunnel — so return
          # traffic is NAT'd back regardless of what the provider names the public NIC (eth0, ens3,
          # enp0s3, …). A hardcoded interface name would silently break NAT (client gets upload but
          # zero download) on any host that doesn't use it. For a multi-hop node the egress is wg1,
          # which this also covers. `{{ egress_if }}` is kept in the render context but no longer
          # pinned here on purpose.
          oifname != "wg0" masquerade
        }
      }

  - path: /opt/sentinel/callback.py
    permissions: '0755'
    content: |
      #!/usr/bin/env python3
      # Serve the WG public key, authenticated by HMAC over (pubkey || ip) keyed by the
      # hex-decoded callback key. Authenticity is the HMAC, not the transport (D11, T6):
      # the pubkey is public and a tampered value fails the client's constant-time compare.
      # Guarded by the one-time bearer token so random scanners get nothing.
      import http.server, hmac, hashlib, json, urllib.request
      TOKEN = "{{ callback_token }}"
      KEY = bytes.fromhex("{{ callback_hmac_key }}")
      def pub():
          with open("/etc/wireguard/pub") as f:
              return f.read().strip()
      def myip():
          try:
              return urllib.request.urlopen("https://api.ipify.org", timeout=10).read().decode().strip()
          except Exception:
              return ""
      class H(http.server.BaseHTTPRequestHandler):
          def do_GET(self):
              if self.headers.get("Authorization", "") != "Bearer " + TOKEN:
                  self.send_response(403); self.end_headers(); return
              p = pub(); i = myip()
              mac = hmac.new(KEY, (p + i).encode(), hashlib.sha256).hexdigest()
              body = json.dumps({"pubkey": p, "ip": i, "mac": mac}).encode()
              self.send_response(200)
              self.send_header("Content-Type", "application/json")
              self.send_header("Content-Length", str(len(body)))
              self.end_headers()
              self.wfile.write(body)
          def log_message(self, *a):
              return
      http.server.HTTPServer(("0.0.0.0", 443), H).serve_forever()

  - path: /etc/systemd/system/sentinel-callback.service
    content: |
      [Unit]
      Description=SENTINEL pubkey callback
      After=network-online.target wg-quick@wg0.service
      [Service]
      ExecStart=/usr/bin/python3 /opt/sentinel/callback.py
      Restart=on-failure
      [Install]
      WantedBy=multi-user.target
{% if deadman_secs %}
  - path: /etc/systemd/system/sentinel-deadman.service
    content: |
      [Unit]
      Description=SENTINEL dead-man switch
      [Service]
      Type=oneshot
      ExecStart=/bin/bash -c 'hs=$(wg show wg0 latest-handshakes | awk "{print \$2}"); now=$(date +%s); if [ -z "$hs" ] || [ $((now - hs)) -gt {{ deadman_secs }} ]; then shutdown -h now; fi'

  - path: /etc/systemd/system/sentinel-deadman.timer
    content: |
      [Unit]
      Description=Run the SENTINEL dead-man switch
      [Timer]
      OnBootSec=60
      OnUnitActiveSec=60
      [Install]
      WantedBy=timers.target
{% endif %}

runcmd:
  - systemctl disable ssh || true
  - systemctl stop ssh || true
  - systemctl mask ssh.service || true
  - umask 077; echo '{{ server_privkey }}' | wg pubkey > /etc/wireguard/pub || true
  - sysctl -w net.ipv4.ip_forward=1
  - echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-sentinel.conf
  - nft -f /etc/nftables.conf
  # MSS clamp is BEST-EFFORT and applied AFTER the ruleset loads, so that if this node's nftables
  # build rejects the expression it can't fail `nft -f` and take masquerade down with it (which
  # would break all return traffic). The client also sets MTU=1420, which handles throughput on its
  # own; this is belt-and-suspenders for oversized-packet stalls.
  - nft add rule inet filter forward tcp flags syn tcp option maxseg size set rt mtu || true
  - systemctl enable wg-quick@wg0
  - systemctl start wg-quick@wg0
{% if next_hop %}
  - systemctl enable wg-quick@wg1
  - systemctl start wg-quick@wg1
{% endif %}
  - systemctl daemon-reload
  - systemctl enable --now sentinel-callback.service
{% if deadman_secs %}
  - systemctl enable --now sentinel-deadman.timer
{% endif %}
"#;

/// The downstream link for a chained (multi-hop) node: this node runs a `wg1` client to the
/// NEXT hop and routes its `wg0` traffic out through it. All keys are app-generated (the app
/// knows every hop's pubkey), so no per-hop callback is needed to wire the chain.
#[derive(Clone, Debug)]
pub struct NextHop {
    /// This node's `wg1` (downstream client) private key.
    pub wg1_privkey: String,
    /// This node's `wg1` address, e.g. "10.67.0.2/32".
    pub wg1_address: String,
    /// The next hop's `wg0` public key.
    pub peer_pubkey: String,
    /// The next hop's endpoint, "ip:port".
    pub peer_endpoint: String,
}

/// Inputs to the cloud-init template.
#[derive(Clone, Debug)]
pub struct CloudInitParams {
    pub server_privkey: String,
    pub client_pubkey: String,
    pub client_ip: String, // "10.66.0.2"
    pub listen_port: u16,
    /// Single-use bearer token guarding the one-shot pubkey callback.
    pub callback_token: String,
    /// HMAC key (hex) authenticating the returned pubkey. Delivered only in user_data.
    pub callback_hmac_key: String,
    /// Power off if no WG handshake within this many seconds.
    pub deadman_secs: u32,
    /// `Some` on a non-exit hop in a multi-hop chain: forward to the next hop instead of the
    /// internet. `None` (default) on a single node or the exit hop: NAT to the internet.
    pub next_hop: Option<NextHop>,
}

impl CloudInitParams {
    /// A single-node (or exit-hop) config: NAT straight to the internet, no downstream.
    pub fn single(
        server_privkey: String,
        client_pubkey: String,
        client_ip: String,
        listen_port: u16,
        callback_token: String,
        callback_hmac_key: String,
        deadman_secs: u32,
    ) -> Self {
        CloudInitParams {
            server_privkey,
            client_pubkey,
            client_ip,
            listen_port,
            callback_token,
            callback_hmac_key,
            deadman_secs,
            next_hop: None,
        }
    }
}

/// Render the cloud-init YAML for these parameters.
pub fn render(params: &CloudInitParams) -> Result<String> {
    let mut env = Environment::new();
    env.add_template("cloud-init", TEMPLATE)
        .map_err(|e| CoreError::Provision {
            stage: "template",
            detail: e.to_string(),
        })?;
    let tmpl = env.get_template("cloud-init").unwrap();
    // A chained node NATs onto its downstream tunnel (wg1); an exit/single node NATs to the NIC.
    let egress_if = if params.next_hop.is_some() {
        "wg1"
    } else {
        "eth0"
    };
    let (nh_privkey, nh_address, nh_peer_pubkey, nh_peer_endpoint) = match &params.next_hop {
        Some(n) => (
            n.wg1_privkey.as_str(),
            n.wg1_address.as_str(),
            n.peer_pubkey.as_str(),
            n.peer_endpoint.as_str(),
        ),
        None => ("", "", "", ""),
    };
    tmpl.render(context! {
        server_privkey => params.server_privkey,
        client_pubkey => params.client_pubkey,
        client_ip => params.client_ip,
        listen_port => params.listen_port,
        callback_token => params.callback_token,
        callback_hmac_key => params.callback_hmac_key,
        deadman_secs => params.deadman_secs,
        next_hop => params.next_hop.is_some(),
        egress_if => egress_if,
        nh_privkey => nh_privkey,
        nh_address => nh_address,
        nh_peer_pubkey => nh_peer_pubkey,
        nh_peer_endpoint => nh_peer_endpoint,
    })
    .map_err(|e| CoreError::Provision {
        stage: "render",
        detail: e.to_string(),
    })
}

/// Base64-encode the rendered cloud-init for Linode's `metadata.user_data`.
pub fn render_base64(params: &CloudInitParams) -> Result<String> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.encode(render(params)?))
}

// ---------------------------------------------------------------------------
// Sync server (durable): a Docker install of the prebuilt `sentinel-api` image + Postgres,
// serving HTTPS with an app-generated self-signed cert. Unlike the ephemeral VPN node, this box
// is meant to STAY UP (tagged `sentinel-sync`, excluded from the orphan sweep). No callback and
// no domain: the app generates the bootstrap token + TLS cert/key client-side and bakes them in,
// so it already knows the secrets to auth with and the exact cert to pin.
// ---------------------------------------------------------------------------

const SYNC_TEMPLATE: &str = r#"#cloud-config
package_update: true
packages:
  - openssl
  - curl

write_files:
  # Starting the API container lives in its own script so first boot AND every later update run
  # the exact same arguments — an update is just "pull, rm, start-api.sh" and can never drift.
  - path: /opt/sentinel/start-api.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      docker run -d --name sentinel-api --restart=always --network sentinel \
        -p 443:8787 \
        -e SENTINEL_ENV=production \
        -e SENTINEL_API_BIND=0.0.0.0:8787 \
        -e SENTINEL_BOOTSTRAP_TOKEN={{ bootstrap_token }} \
        -e SENTINEL_TOTP_ENC_KEY={{ totp_enc_key }} \
        -e GOOGLE_OAUTH_CLIENT_ID={{ google_client_id }} \
        -e SENTINEL_TLS_CERT_PEM=/tls/cert.pem \
        -e SENTINEL_TLS_KEY_PEM=/tls/key.pem \
        -e SENTINEL_JWT_ES256_PEM=/tls/jwt.pem \
        -e SENTINEL_AUTO_MIGRATE=1 \
        -e SENTINEL_UPDATE_FLAG_DIR=/flags \
        -e DATABASE_URL=postgres://sentinel:{{ db_password }}@sentinel-db:5432/sentinel \
        -v /opt/sentinel/tls:/tls:ro \
        -v /opt/sentinel/flags:/flags \
        {{ image_ref }}

  # Pull the latest image and recreate the API container. Run by the daily timer and by the
  # path unit the moment the app (via POST /v1/admin/update) drops the flag file. The API
  # container never gets the Docker socket — the host does the privileged work.
  - path: /opt/sentinel/update.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      rm -f /opt/sentinel/flags/update-requested
      docker pull {{ image_ref }}
      docker rm -f sentinel-api >/dev/null 2>&1 || true
      /opt/sentinel/start-api.sh

  - path: /etc/systemd/system/sentinel-update.service
    content: |
      [Unit]
      Description=NorthKey sync-server update (pull + recreate)
      [Service]
      Type=oneshot
      ExecStart=/opt/sentinel/update.sh

  - path: /etc/systemd/system/sentinel-update.path
    content: |
      [Unit]
      Description=Run the update when the app requests it
      [Path]
      PathExists=/opt/sentinel/flags/update-requested
      [Install]
      WantedBy=multi-user.target

  - path: /etc/systemd/system/sentinel-update.timer
    content: |
      [Unit]
      Description=Daily NorthKey sync-server update
      [Timer]
      OnCalendar=daily
      RandomizedDelaySec=1h
      Persistent=true
      [Install]
      WantedBy=timers.target

  - path: /opt/sentinel/run.sh
    permissions: '0755'
    content: |
      #!/usr/bin/env bash
      set -euo pipefail
      mkdir -p /opt/sentinel/tls /opt/sentinel/pgdata /opt/sentinel/flags
      # The TLS cert+key are app-generated (base64 here) so the app can pin the exact cert; the
      # JWT signing key is generated on-box (stable across restarts while the box lives).
      echo "{{ tls_cert_b64 }}" | base64 -d > /opt/sentinel/tls/cert.pem
      echo "{{ tls_key_b64 }}" | base64 -d > /opt/sentinel/tls/key.pem
      openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /opt/sentinel/tls/jwt.pem
      chown -R 10001:10001 /opt/sentinel/tls
      chmod 640 /opt/sentinel/tls/*.pem
      # The API runs as uid 10001 and must be able to write the update flag.
      chown 10001:10001 /opt/sentinel/flags
      curl -fsSL https://get.docker.com | sh
      docker network create sentinel || true
      docker rm -f sentinel-db sentinel-api >/dev/null 2>&1 || true
      docker run -d --name sentinel-db --restart=always --network sentinel \
        -e POSTGRES_PASSWORD={{ db_password }} -e POSTGRES_USER=sentinel -e POSTGRES_DB=sentinel \
        -v /opt/sentinel/pgdata:/var/lib/postgresql/data postgres:16
      for i in $(seq 1 60); do docker exec sentinel-db pg_isready -U sentinel -q && break || sleep 2; done
      /opt/sentinel/start-api.sh

runcmd:
  - systemctl disable ssh || true
  - systemctl stop ssh || true
  - systemctl mask ssh.service || true
  - bash /opt/sentinel/run.sh
  - systemctl daemon-reload
  - systemctl enable --now sentinel-update.path
  - systemctl enable --now sentinel-update.timer
"#;

/// Inputs to the sync-server cloud-init. All secrets are app-generated so the app knows the pin
/// (`tls_cert`/`tls_key` base64-encoded) and the bootstrap token without any callback.
#[derive(Clone, Debug)]
pub struct SyncServerParams {
    /// The prebuilt image to run, e.g. `ghcr.io/taco406/sentinel-api:latest`.
    pub image_ref: String,
    /// Shared secret the app exchanges at `/v1/auth/bootstrap` (hex).
    pub bootstrap_token: String,
    /// Postgres password (kept on-box only).
    pub db_password: String,
    /// Base64 of the self-signed TLS certificate PEM (SAN `sentinel-sync`).
    pub tls_cert_b64: String,
    /// Base64 of the matching private key PEM.
    pub tls_key_b64: String,
    /// Base64 of the 32-byte TOTP encryption key. REQUIRED: with `SENTINEL_ENV=production` the
    /// server refuses to boot (and `--restart=always` crash-loops it) unless this is set, so the
    /// container would never serve `/healthz` and the deploy could never sign in. Kept on-box only.
    pub totp_enc_key: String,
    /// Google OAuth client id (`*.apps.googleusercontent.com`). When non-empty the server
    /// validates real Google id_tokens (so "Sign in with Google" works); empty keeps the
    /// bootstrap-token-only personal server. Public value, not a secret.
    pub google_client_id: String,
}

/// Render the sync-server cloud-init YAML.
pub fn render_sync(params: &SyncServerParams) -> Result<String> {
    let mut env = Environment::new();
    env.add_template("sync", SYNC_TEMPLATE)
        .map_err(|e| CoreError::Provision {
            stage: "template",
            detail: e.to_string(),
        })?;
    let tmpl = env.get_template("sync").unwrap();
    tmpl.render(context! {
        image_ref => params.image_ref,
        bootstrap_token => params.bootstrap_token,
        db_password => params.db_password,
        tls_cert_b64 => params.tls_cert_b64,
        tls_key_b64 => params.tls_key_b64,
        totp_enc_key => params.totp_enc_key,
        google_client_id => params.google_client_id,
    })
    .map_err(|e| CoreError::Provision {
        stage: "render",
        detail: e.to_string(),
    })
}

/// Base64-encode the rendered sync-server cloud-init for Linode's `metadata.user_data`.
pub fn render_sync_base64(params: &SyncServerParams) -> Result<String> {
    use base64::Engine as _;
    Ok(base64::engine::general_purpose::STANDARD.encode(render_sync(params)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> CloudInitParams {
        CloudInitParams::single(
            "SPRIV".into(),
            "CPUB".into(),
            "10.66.0.2".into(),
            51820,
            "one-time-token-abc".into(),
            "deadbeef".into(),
            900,
        )
    }

    #[test]
    fn renders_hardened_cloud_init() {
        let yaml = render(&params()).unwrap();
        // WireGuard config present.
        assert!(yaml.contains("PrivateKey = SPRIV"));
        assert!(yaml.contains("PublicKey = CPUB"));
        assert!(yaml.contains("ListenPort = 51820"));
        // Firewall default-drop.
        assert!(yaml.contains("policy drop"));
        assert!(yaml.contains("udp dport 51820 accept"));
        // SSH disabled.
        assert!(yaml.contains("systemctl mask ssh.service"));
        // Dead-man switch armed.
        assert!(yaml.contains("sentinel-deadman.timer"));
        assert!(yaml.contains("gt 900"));
        // No SaveConfig persistence.
        assert!(yaml.contains("SaveConfig = false"));
    }

    #[test]
    fn deadman_switch_is_omitted_when_zero() {
        // An always-on node passes deadman_secs = 0 so it never powers itself off.
        let mut p = params();
        p.deadman_secs = 0;
        let yaml = render(&p).unwrap();
        assert!(!yaml.contains("sentinel-deadman"));
        assert!(!yaml.contains("dead-man"));
        // The rest of the hardened node is unaffected.
        assert!(yaml.contains("PrivateKey = SPRIV"));
        assert!(yaml.contains("oifname != \"wg0\" masquerade"));
        assert!(yaml.contains("sentinel-callback.service"));
    }

    #[test]
    fn single_node_nats_to_the_internet_and_has_no_wg1() {
        let yaml = render(&params()).unwrap();
        // Interface-agnostic NAT: masquerade everything except the client tunnel, so return
        // traffic is NAT'd regardless of the provider's public NIC name.
        assert!(yaml.contains("oifname != \"wg0\" masquerade"));
        assert!(!yaml.contains("/etc/wireguard/wg1.conf"));
        assert!(!yaml.contains("wg-quick@wg1"));
    }

    #[test]
    fn firewall_matches_wg0_by_name_so_the_ruleset_loads_before_the_tunnel() {
        // Regression: `nft -f` runs before wg-quick brings wg0 up. `iif "wg0"` resolves an
        // interface INDEX at load time and errors "Interface does not exist", which — because
        // `nft -f` is atomic — rejects the entire ruleset INCLUDING the NAT table, so no
        // masquerade ever loads and no client traffic egresses. `iifname` matches by name at
        // runtime and loads fine. Never regress to `iif "wg0"`.
        let yaml = render(&params()).unwrap();
        assert!(
            yaml.contains("iifname \"wg0\" accept"),
            "input chain must accept the tunnel by name (iifname), not by index (iif)"
        );
        assert!(
            !yaml.contains("iif \"wg0\""),
            "iif \"wg0\" fails to load before the tunnel exists and takes NAT down with it"
        );
    }

    #[test]
    fn chained_node_forwards_to_next_hop_over_wg1() {
        let mut p = params();
        p.next_hop = Some(NextHop {
            wg1_privkey: "W1PRIV".into(),
            wg1_address: "10.67.0.2/32".into(),
            peer_pubkey: "NEXTPUB".into(),
            peer_endpoint: "203.0.113.9:51820".into(),
        });
        let yaml = render(&p).unwrap();
        // A wg1 client interface to the next hop, full-tunnel to it.
        assert!(yaml.contains("/etc/wireguard/wg1.conf"));
        assert!(yaml.contains("PrivateKey = W1PRIV"));
        assert!(yaml.contains("PublicKey = NEXTPUB"));
        assert!(yaml.contains("Endpoint = 203.0.113.9:51820"));
        assert!(yaml.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        // Same interface-agnostic NAT (masquerade != wg0) covers the multi-hop egress (wg1) too,
        // and never pins a hardcoded NIC.
        assert!(yaml.contains("oifname != \"wg0\" masquerade"));
        assert!(!yaml.contains("oifname \"eth0\" masquerade"));
        // wg1 is brought up.
        assert!(yaml.contains("systemctl start wg-quick@wg1"));
    }

    #[test]
    fn base64_is_decodable() {
        use base64::Engine as _;
        let b64 = render_base64(&params()).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert!(String::from_utf8(decoded)
            .unwrap()
            .contains("#cloud-config"));
    }

    fn sync_params() -> SyncServerParams {
        SyncServerParams {
            image_ref: "ghcr.io/taco406/sentinel-api:latest".into(),
            bootstrap_token: "deadbeefcafe".into(),
            db_password: "pgpasswd123".into(),
            tls_cert_b64: "Q0VSVA==".into(),
            tls_key_b64: "S0VZ".into(),
            totp_enc_key: "dG90cGtleWJhc2U2NA==".into(),
            google_client_id: String::new(),
        }
    }

    #[test]
    fn sync_cloud_init_has_docker_image_tls_and_bootstrap() {
        let yaml = render_sync(&sync_params()).unwrap();
        assert!(yaml.starts_with("#cloud-config\n"));
        // Runs the prebuilt image and wires the generated secrets.
        assert!(yaml.contains("ghcr.io/taco406/sentinel-api:latest"));
        assert!(yaml.contains("SENTINEL_BOOTSTRAP_TOKEN=deadbeefcafe"));
        assert!(yaml.contains("SENTINEL_AUTO_MIGRATE=1"));
        assert!(yaml.contains("SENTINEL_ENV=production"));
        // The TOTP key MUST be set — without it the server refuses to boot under
        // SENTINEL_ENV=production and crash-loops, so /healthz never answers.
        assert!(yaml.contains("SENTINEL_TOTP_ENC_KEY=dG90cGtleWJhc2U2NA=="));
        // TLS cert/key are decoded on-box; HTTPS is served (host 443 → container 8787).
        assert!(yaml.contains("Q0VSVA==")); // tls_cert_b64
        assert!(yaml.contains("SENTINEL_TLS_CERT_PEM=/tls/cert.pem"));
        assert!(yaml.contains("-p 443:8787"));
        // Postgres with a persistent volume; SSH disabled.
        assert!(yaml.contains("postgres:16"));
        assert!(yaml.contains("/opt/sentinel/pgdata"));
        assert!(yaml.contains("systemctl mask ssh.service"));
    }

    #[test]
    fn sync_cloud_init_wires_the_self_updater() {
        let yaml = render_sync(&sync_params()).unwrap();
        // One start script shared by first boot and updates, so args can never drift.
        assert!(yaml.contains("/opt/sentinel/start-api.sh"));
        // The updater pulls + recreates on the host; the API only writes a flag into the shared
        // volume (never the docker socket).
        assert!(yaml.contains("/opt/sentinel/update.sh"));
        assert!(yaml.contains("SENTINEL_UPDATE_FLAG_DIR=/flags"));
        assert!(yaml.contains("-v /opt/sentinel/flags:/flags"));
        assert!(!yaml.contains("docker.sock"), "no socket in the container");
        // Path unit (instant, app-requested) + daily timer, both enabled.
        assert!(yaml.contains("PathExists=/opt/sentinel/flags/update-requested"));
        assert!(yaml.contains("systemctl enable --now sentinel-update.path"));
        assert!(yaml.contains("OnCalendar=daily"));
        assert!(yaml.contains("systemctl enable --now sentinel-update.timer"));
    }

    #[test]
    fn sync_cloud_init_threads_the_google_client_id() {
        // Empty client id → the env var is present but blank; the server filters empty and
        // runs bootstrap-only (a personal server with no Google sign-in).
        let yaml = render_sync(&sync_params()).unwrap();
        assert!(yaml.contains("GOOGLE_OAUTH_CLIENT_ID="));
        // A real client id is passed so the server validates real Google id_tokens.
        let mut p = sync_params();
        p.google_client_id = "123-abc.apps.googleusercontent.com".into();
        let yaml = render_sync(&p).unwrap();
        assert!(yaml.contains("GOOGLE_OAUTH_CLIENT_ID=123-abc.apps.googleusercontent.com"));
    }

    #[test]
    fn sync_cloud_init_base64_decodes() {
        use base64::Engine as _;
        let b64 = render_sync_base64(&sync_params()).unwrap();
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        assert!(String::from_utf8(decoded)
            .unwrap()
            .contains("#cloud-config"));
    }

    #[test]
    fn golden_snapshot_stable() {
        // Guards against accidental template drift changing what we provision.
        let yaml = render(&params()).unwrap();
        assert!(yaml.starts_with("#cloud-config\n"));
        assert!(yaml.contains("      Address = 10.66.0.1/24\n"));
        assert!(yaml.contains("      AllowedIPs = 10.66.0.2/32\n"));
    }
}
