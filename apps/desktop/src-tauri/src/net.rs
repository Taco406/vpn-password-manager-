//! Networking diagnostics for the Tools screen: "what's my IP + location", a TCP-connect
//! latency probe ("ping"), and DNS resolution. Each goes out the same route the app uses, so
//! with the VPN connected they reflect the exit node — which is the whole point of the IP/location
//! check (confirm your apparent location actually changed).
//!
//! Privacy: `net_myip` asks a public geo-IP service — there is no other way to learn your
//! *apparent* public location, and the UI says so. `net_ping`/`net_dns` stay on-device apart from
//! the single connection or lookup they measure.

use serde::Serialize;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

fn estr<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

/// Strip scheme/path/port from user input, leaving a bare host.
fn clean_host(input: &str) -> String {
    let s = input.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    // Drop any :port the user typed (but keep IPv6 colons: only strip a trailing :digits).
    let s = match s.rsplit_once(':') {
        Some((h, p))
            if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') =>
        {
            h
        }
        _ => s,
    };
    s.trim().to_string()
}

#[derive(Serialize)]
pub struct MyIp {
    pub ip: String,
    pub city: String,
    pub region: String,
    pub country: String,
    pub org: String,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

/// Public IP + coarse geolocation as seen from this device's current route (reflects the VPN exit
/// when connected). Uses a public HTTPS geo-IP service.
#[tauri::command]
pub async fn net_myip() -> Result<MyIp, String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(12))
        .build()
        .map_err(estr)?;
    let resp = client
        .get("https://ipapi.co/json/")
        .header("User-Agent", "SENTINEL")
        .send()
        .await
        .map_err(|e| {
            format!("lookup failed (no internet, or the geo service is unreachable): {e}")
        })?;
    if !resp.status().is_success() {
        return Err(format!("geo service returned HTTP {}", resp.status()));
    }
    let v: serde_json::Value = resp.json().await.map_err(estr)?;
    // ipapi.co returns {"error": true, "reason": "..."} on rate limit / bad input.
    if v.get("error").and_then(|e| e.as_bool()).unwrap_or(false) {
        return Err(v
            .get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("geo service unavailable")
            .to_string());
    }
    Ok(MyIp {
        ip: v["ip"].as_str().unwrap_or_default().to_string(),
        city: v["city"].as_str().unwrap_or_default().to_string(),
        region: v["region"].as_str().unwrap_or_default().to_string(),
        country: v["country_name"].as_str().unwrap_or_default().to_string(),
        org: v["org"].as_str().unwrap_or_default().to_string(),
        lat: v["latitude"].as_f64(),
        lon: v["longitude"].as_f64(),
    })
}

#[derive(Serialize)]
pub struct PingResult {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub ms: f64,
    pub attempts: u32,
}

/// A TCP-connect latency probe: resolve `host`, connect to 443 (then 80), and report the best
/// round-trip of a few attempts in milliseconds. TCP, not ICMP — so it needs no admin rights and
/// behaves the same on every OS.
#[tauri::command]
pub async fn net_ping(host: String) -> Result<PingResult, String> {
    let host = clean_host(&host);
    if host.is_empty() {
        return Err("enter a host, e.g. example.com".into());
    }
    for port in [443u16, 80u16] {
        let mut addrs = match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(a) => a.collect::<Vec<SocketAddr>>(),
            Err(e) => return Err(format!("could not resolve {host}: {e}")),
        };
        // Prefer IPv4 for a stable, comparable number.
        addrs.sort_by_key(|a| a.is_ipv6());
        let Some(&addr) = addrs.first() else { continue };
        let attempts = 3u32;
        let mut best: Option<f64> = None;
        for _ in 0..attempts {
            let start = Instant::now();
            if let Ok(Ok(_)) =
                tokio::time::timeout(Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
                    .await
            {
                let ms = start.elapsed().as_secs_f64() * 1000.0;
                best = Some(best.map_or(ms, |b: f64| b.min(ms)));
            }
        }
        if let Some(ms) = best {
            return Ok(PingResult {
                host,
                ip: addr.ip().to_string(),
                port,
                ms,
                attempts,
            });
        }
    }
    Err(format!(
        "{host} did not answer on port 443 or 80 (it may be down or blocking connections)"
    ))
}

/// Resolve a hostname to its IP addresses (deduplicated, IPv4 first).
#[tauri::command]
pub async fn net_dns(host: String) -> Result<Vec<String>, String> {
    let host = clean_host(&host);
    if host.is_empty() {
        return Err("enter a host, e.g. example.com".into());
    }
    let addrs = tokio::net::lookup_host((host.as_str(), 0u16))
        .await
        .map_err(|e| format!("could not resolve {host}: {e}"))?;
    let mut ips: Vec<String> = addrs.map(|a| a.ip().to_string()).collect();
    ips.sort();
    ips.dedup();
    if ips.is_empty() {
        return Err(format!("no addresses found for {host}"));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::clean_host;

    #[test]
    fn clean_host_strips_scheme_path_and_port() {
        assert_eq!(clean_host("https://example.com/path?q=1"), "example.com");
        assert_eq!(clean_host("http://example.com:8080"), "example.com");
        assert_eq!(clean_host("  example.com  "), "example.com");
        assert_eq!(clean_host("1.1.1.1"), "1.1.1.1");
        // A bare IPv6 literal keeps its colons (only a trailing :port is stripped).
        assert_eq!(clean_host("2606:4700:4700::1111"), "2606:4700:4700::1111");
    }
}
