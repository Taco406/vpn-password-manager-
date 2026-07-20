//! Rendering of WireGuard `.conf` files for the client and the ephemeral server.

/// Parameters for a client tunnel config.
#[derive(Clone, Debug)]
pub struct ClientConf {
    pub client_private_key: String,
    pub client_address: String, // e.g. "10.66.0.2/32"
    pub dns: String,            // e.g. "1.1.1.1"
    pub server_public_key: String,
    pub server_endpoint: String, // "ip:port"
    /// Full-tunnel = ["0.0.0.0/0", "::/0"]; split = specific CIDRs.
    pub allowed_ips: Vec<String>,
    pub keepalive: u16,
}

/// Parameters for the server config injected via cloud-init.
#[derive(Clone, Debug)]
pub struct ServerConf {
    pub server_private_key: String,
    pub server_address: String, // "10.66.0.1/24"
    pub listen_port: u16,
    pub client_public_key: String,
    pub client_allowed_ip: String, // "10.66.0.2/32"
}

/// Render the client tunnel config.
pub fn render_client_conf(c: &ClientConf) -> String {
    // DNS is optional: an empty string omits the line entirely. The VPN self-test uses this so it
    // can bring a tunnel up to verify the handshake without redirecting the host's DNS resolution.
    let dns_line = if c.dns.trim().is_empty() {
        String::new()
    } else {
        format!("DNS = {}\n", c.dns)
    };
    format!(
        "[Interface]\n\
         PrivateKey = {priv}\n\
         Address = {addr}\n\
         {dns_line}\
         MTU = 1280\n\
         \n\
         [Peer]\n\
         PublicKey = {spub}\n\
         Endpoint = {endpoint}\n\
         AllowedIPs = {allowed}\n\
         PersistentKeepalive = {ka}\n",
        priv = c.client_private_key,
        addr = c.client_address,
        dns_line = dns_line,
        spub = c.server_public_key,
        endpoint = c.server_endpoint,
        allowed = c.allowed_ips.join(", "),
        ka = c.keepalive,
    )
}

/// Render the server config (written to /etc/wireguard/wg0.conf by cloud-init).
pub fn render_server_conf(s: &ServerConf) -> String {
    format!(
        "[Interface]\n\
         PrivateKey = {priv}\n\
         Address = {addr}\n\
         ListenPort = {port}\n\
         # SaveConfig deliberately off — the server keeps nothing at shutdown.\n\
         SaveConfig = false\n\
         \n\
         [Peer]\n\
         PublicKey = {cpub}\n\
         AllowedIPs = {cip}\n",
        priv = s.server_private_key,
        addr = s.server_address,
        port = s.listen_port,
        cpub = s.client_public_key,
        cip = s.client_allowed_ip,
    )
}

/// Standard full-tunnel AllowedIPs.
pub fn full_tunnel() -> Vec<String> {
    vec!["0.0.0.0/0".into(), "::/0".into()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_conf_has_required_sections() {
        let c = ClientConf {
            client_private_key: "CPRIV".into(),
            client_address: "10.66.0.2/32".into(),
            dns: "1.1.1.1".into(),
            server_public_key: "SPUB".into(),
            server_endpoint: "203.0.113.7:51820".into(),
            allowed_ips: full_tunnel(),
            keepalive: 25,
        };
        let out = render_client_conf(&c);
        assert!(out.contains("[Interface]"));
        assert!(out.contains("[Peer]"));
        assert!(out.contains("Endpoint = 203.0.113.7:51820"));
        assert!(out.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(out.contains("PersistentKeepalive = 25"));
        // A conservative 1280 tunnel MTU (the IPv6 minimum) survives low-MTU underlays
        // (PPPoE, LTE, DS-Lite) where 1420 blackholes large packets — the classic
        // "connects but pages stall" symptom.
        assert!(out.contains("MTU = 1280"));
    }

    #[test]
    fn server_conf_disables_saveconfig() {
        let s = ServerConf {
            server_private_key: "SPRIV".into(),
            server_address: "10.66.0.1/24".into(),
            listen_port: 51820,
            client_public_key: "CPUB".into(),
            client_allowed_ip: "10.66.0.2/32".into(),
        };
        let out = render_server_conf(&s);
        assert!(out.contains("SaveConfig = false"));
        assert!(out.contains("ListenPort = 51820"));
    }

    #[test]
    fn empty_dns_omits_the_line() {
        // The self-test passes an empty DNS so the tunnel never redirects host DNS resolution.
        let c = ClientConf {
            client_private_key: "x".into(),
            client_address: "10.66.0.2/32".into(),
            dns: String::new(),
            server_public_key: "y".into(),
            server_endpoint: "z:1".into(),
            allowed_ips: vec!["10.66.0.0/24".into()],
            keepalive: 25,
        };
        let out = render_client_conf(&c);
        assert!(
            !out.contains("DNS ="),
            "empty DNS must omit the line entirely"
        );
        assert!(out.contains("Address = 10.66.0.2/32"));
        assert!(out.contains("AllowedIPs = 10.66.0.0/24"));
    }

    #[test]
    fn split_tunnel_lists_specific_cidrs() {
        let c = ClientConf {
            client_private_key: "x".into(),
            client_address: "10.66.0.2/32".into(),
            dns: "1.1.1.1".into(),
            server_public_key: "y".into(),
            server_endpoint: "z:1".into(),
            allowed_ips: vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()],
            keepalive: 25,
        };
        let out = render_client_conf(&c);
        assert!(out.contains("AllowedIPs = 10.0.0.0/8, 192.168.0.0/16"));
        assert!(!out.contains("0.0.0.0/0"));
    }
}
