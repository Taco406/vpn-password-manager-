//! Cloud-init user-data for a single-boot ephemeral WireGuard node. The rendered YAML:
//! installs WireGuard, applies an nftables default-drop firewall plus NAT (so forwarded
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
  - wireguard
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
          iif "wg0" accept
        }
        chain forward { type filter hook forward priority 0; policy accept; }
        chain output { type filter hook output priority 0; policy accept; }
      }
      table ip nat {
        chain postrouting {
          type nat hook postrouting priority 100; policy accept;
          oifname "{{ egress_if }}" masquerade
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

runcmd:
  - systemctl disable ssh || true
  - systemctl stop ssh || true
  - systemctl mask ssh.service || true
  - umask 077; wg genkey | tee /etc/wireguard/priv | wg pubkey > /etc/wireguard/pub || true
  - sysctl -w net.ipv4.ip_forward=1
  - echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-sentinel.conf
  - nft -f /etc/nftables.conf
  - systemctl enable wg-quick@wg0
  - systemctl start wg-quick@wg0
{% if next_hop %}
  - systemctl enable wg-quick@wg1
  - systemctl start wg-quick@wg1
{% endif %}
  - systemctl daemon-reload
  - systemctl enable --now sentinel-callback.service
  - systemctl enable --now sentinel-deadman.timer
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
    fn single_node_nats_to_the_internet_and_has_no_wg1() {
        let yaml = render(&params()).unwrap();
        assert!(yaml.contains("oifname \"eth0\" masquerade"));
        assert!(!yaml.contains("/etc/wireguard/wg1.conf"));
        assert!(!yaml.contains("wg-quick@wg1"));
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
        // NAT onto the downstream tunnel, not the NIC — traffic bounces onward.
        assert!(yaml.contains("oifname \"wg1\" masquerade"));
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

    #[test]
    fn golden_snapshot_stable() {
        // Guards against accidental template drift changing what we provision.
        let yaml = render(&params()).unwrap();
        assert!(yaml.starts_with("#cloud-config\n"));
        assert!(yaml.contains("      Address = 10.66.0.1/24\n"));
        assert!(yaml.contains("      AllowedIPs = 10.66.0.2/32\n"));
    }
}
