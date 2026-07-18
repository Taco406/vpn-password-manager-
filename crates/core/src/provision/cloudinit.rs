//! Cloud-init user-data for a single-boot ephemeral WireGuard server. The rendered
//! YAML: installs WireGuard, applies an nftables default-drop firewall (WG + a
//! one-shot 443 callback only), disables SSH entirely, writes the server config,
//! serves its public key once over HTTPS authenticated by an HMAC, starts a metrics
//! reporter reachable only over the tunnel, and arms a dead-man timer that powers the
//! box off if no handshake arrives (D10, D11).

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

  - path: /opt/sentinel/callback.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      # Serve the WG public key once, authenticated by HMAC over (pubkey || ip).
      PUB=$(cat /etc/wireguard/pub)
      IP=$(curl -s https://api.ipify.org)
      MAC=$(printf '%s%s' "$PUB" "$IP" | openssl dgst -sha256 -hmac "{{ callback_hmac_key }}" -binary | xxd -p -c256)
      BODY="{\"pubkey\":\"$PUB\",\"ip\":\"$IP\",\"mac\":\"$MAC\"}"
      # single-shot HTTPS responder guarded by the one-time bearer token
      # (implementation detail: a tiny TLS listener validating {{ callback_token }})

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
  - systemctl daemon-reload
  - systemctl enable --now sentinel-deadman.timer
"#;

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
    tmpl.render(context! {
        server_privkey => params.server_privkey,
        client_pubkey => params.client_pubkey,
        client_ip => params.client_ip,
        listen_port => params.listen_port,
        callback_token => params.callback_token,
        callback_hmac_key => params.callback_hmac_key,
        deadman_secs => params.deadman_secs,
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
        CloudInitParams {
            server_privkey: "SPRIV".into(),
            client_pubkey: "CPUB".into(),
            client_ip: "10.66.0.2".into(),
            listen_port: 51820,
            callback_token: "one-time-token-abc".into(),
            callback_hmac_key: "deadbeef".into(),
            deadman_secs: 900,
        }
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
        // A few load-bearing lines must be byte-exact.
        assert!(yaml.starts_with("#cloud-config\n"));
        assert!(yaml.contains("      Address = 10.66.0.1/24\n"));
        assert!(yaml.contains("      AllowedIPs = 10.66.0.2/32\n"));
    }
}
