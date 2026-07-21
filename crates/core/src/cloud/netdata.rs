//! Netdata agent HTTP client + pure response parsers. A Netdata agent on a server exposes
//! per-second metrics on port 19999 (`/api/v1/...`); when reachable, the Servers screen
//! upgrades that server's graphs to live data and surfaces Netdata's own alarms.
//!
//! Parsing and aggregation are pure functions (fixture-tested): `/api/v1/data` returns a
//! `{labels: [...], data: [[ts, v1, v2...]]}` table whose meaning depends on the chart —
//! `system.cpu` needs its dimensions SUMMED for total CPU %, `system.ram` needs
//! used/(total)×100, `disk_space./` used/(used+avail)×100. Those rules live here, not in
//! the UI.

use crate::error::{CoreError, Result};
use serde::Deserialize;
use std::time::Duration;

use super::manager::MetricPoint;

/// How to reach one server's Netdata agent.
#[derive(Clone, Debug)]
pub struct NetdataEndpoint {
    pub https: bool,
    pub host: String,
    pub port: u16,
    /// Full `Authorization` header value (e.g. `Basic base64…`), when the agent is proxied
    /// behind auth. None for a plain open agent.
    pub auth_header: Option<String>,
}

impl NetdataEndpoint {
    pub fn base_url(&self) -> String {
        let scheme = if self.https { "https" } else { "http" };
        format!("{scheme}://{}:{}", self.host, self.port)
    }

    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(3))
            .danger_accept_invalid_certs(self.https) // self-signed agent certs are the norm
            .build()
            .unwrap_or_default()
    }

    async fn get_text(&self, path: &str) -> Result<String> {
        let mut req = self.client().get(format!("{}{path}", self.base_url()));
        if let Some(auth) = &self.auth_header {
            req = req.header("Authorization", auth);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| CoreError::Network(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| CoreError::Network(e.to_string()))?;
        if !status.is_success() {
            return Err(CoreError::Network(format!(
                "Netdata HTTP {}: {}",
                status.as_u16(),
                text.trim().chars().take(200).collect::<String>()
            )));
        }
        Ok(text)
    }

    /// Agent identity — proves reachability.
    pub async fn info(&self) -> Result<NetdataInfo> {
        parse_info(&self.get_text("/api/v1/info").await?)
    }

    /// One chart's raw table for roughly the last `after_secs` seconds at `points` samples.
    pub async fn data(&self, chart: &str, after_secs: u32, points: u32) -> Result<NetdataSeries> {
        let path = format!(
            "/api/v1/data?chart={chart}&after=-{after_secs}&points={points}&format=json&options=seconds"
        );
        parse_data(&self.get_text(&path).await?)
    }

    /// Active alarms (warnings + critical).
    pub async fn alarms_active(&self) -> Result<Vec<NetdataAlarm>> {
        parse_alarms(&self.get_text("/api/v1/alarms?active").await?)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetdataInfo {
    pub version: String,
    pub hostname: String,
}

/// A raw chart table: labels[0] is "time"; each row is `(ts, values…)` ASCENDING by ts.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct NetdataSeries {
    pub labels: Vec<String>,
    pub rows: Vec<(i64, Vec<f64>)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NetdataAlarm {
    pub name: String,
    pub status: String,
    pub value: String,
}

/// Parse `/api/v1/info`.
pub fn parse_info(body: &str) -> Result<NetdataInfo> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Netdata: bad info response ({e})")))?;
    let version = v
        .get("version")
        .and_then(|x| x.as_str())
        .unwrap_or("unknown")
        .to_string();
    let hostname = v
        .get("hostname")
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .or_else(|| {
            v.get("mirrored_hosts")
                .and_then(|m| m.get(0))
                .and_then(|h| h.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    Ok(NetdataInfo { version, hostname })
}

/// Parse `/api/v1/data` (json format). Rows are normalized to ASCENDING timestamps and
/// null values to 0.0.
pub fn parse_data(body: &str) -> Result<NetdataSeries> {
    #[derive(Deserialize)]
    struct Raw {
        labels: Vec<String>,
        data: Vec<Vec<serde_json::Value>>,
    }
    let raw: Raw = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Netdata: bad data response ({e})")))?;
    let mut rows: Vec<(i64, Vec<f64>)> = raw
        .data
        .iter()
        .filter_map(|row| {
            let ts = row.first()?.as_f64()? as i64;
            let values = row[1..].iter().map(|v| v.as_f64().unwrap_or(0.0)).collect();
            Some((ts, values))
        })
        .collect();
    rows.sort_by_key(|(ts, _)| *ts);
    Ok(NetdataSeries {
        labels: raw.labels,
        rows,
    })
}

/// Parse `/api/v1/alarms?active` — `alarms` is a map of alarm-id → details.
pub fn parse_alarms(body: &str) -> Result<Vec<NetdataAlarm>> {
    let v: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| CoreError::Network(format!("Netdata: bad alarms response ({e})")))?;
    let mut out = Vec::new();
    if let Some(map) = v.get("alarms").and_then(|a| a.as_object()) {
        for (id, a) in map {
            let name = a
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or(id)
                .to_string();
            let status = a
                .get("status")
                .and_then(|s| s.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let value = a
                .get("value_string")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            out.push(NetdataAlarm {
                name,
                status,
                value,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// --- chart aggregation rules -------------------------------------------------

/// `system.cpu`: dimensions are per-mode percentages — total CPU % = row sum.
pub fn cpu_total_pct(s: &NetdataSeries) -> Vec<MetricPoint> {
    s.rows
        .iter()
        .map(|(ts, vals)| MetricPoint {
            ts: *ts,
            value: vals.iter().sum::<f64>().clamp(0.0, 100.0),
        })
        .collect()
}

/// `system.ram` (labels like [time, free, used, cached, buffers], MiB): used% = used/total×100.
pub fn ram_used_pct(s: &NetdataSeries) -> Vec<MetricPoint> {
    let used_idx = s.labels.iter().position(|l| l == "used");
    s.rows
        .iter()
        .filter_map(|(ts, vals)| {
            let total: f64 = vals.iter().sum();
            let used = used_idx.and_then(|i| vals.get(i.checked_sub(1)?))?;
            if total <= 0.0 {
                return None;
            }
            Some(MetricPoint {
                ts: *ts,
                value: (used / total * 100.0).clamp(0.0, 100.0),
            })
        })
        .collect()
}

/// `disk_space./` (labels like [time, avail, used, "reserved for root"], GiB):
/// used% = used/(avail+used)×100 (root reserve excluded, matching `df`).
pub fn disk_used_pct(s: &NetdataSeries) -> Vec<MetricPoint> {
    let idx = |name: &str| {
        s.labels
            .iter()
            .position(|l| l == name)
            .and_then(|i| i.checked_sub(1))
    };
    let (Some(avail_i), Some(used_i)) = (idx("avail"), idx("used")) else {
        return Vec::new();
    };
    s.rows
        .iter()
        .filter_map(|(ts, vals)| {
            let avail = *vals.get(avail_i)?;
            let used = *vals.get(used_i)?;
            let denom = avail + used;
            if denom <= 0.0 {
                return None;
            }
            Some(MetricPoint {
                ts: *ts,
                value: (used / denom * 100.0).clamp(0.0, 100.0),
            })
        })
        .collect()
}

/// `system.load` (labels [time, load1, load5, load15]): take load1.
pub fn load1(s: &NetdataSeries) -> Vec<MetricPoint> {
    s.rows
        .iter()
        .filter_map(|(ts, vals)| {
            Some(MetricPoint {
                ts: *ts,
                value: *vals.first()?,
            })
        })
        .collect()
}

/// `system.net` (KiB/s; received positive, sent negative): total throughput in BYTES/s
/// (absolute sum), so it plots on the same scale as provider network graphs.
pub fn net_total_bps(s: &NetdataSeries) -> Vec<MetricPoint> {
    s.rows
        .iter()
        .map(|(ts, vals)| MetricPoint {
            ts: *ts,
            value: vals.iter().map(|v| v.abs()).sum::<f64>() * 1024.0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_info_with_mirrored_host_fallback() {
        let i =
            parse_info(r#"{"version":"v1.44.3","mirrored_hosts":["web-1"],"os":"linux"}"#).unwrap();
        assert_eq!(i.version, "v1.44.3");
        assert_eq!(i.hostname, "web-1");
        let i2 = parse_info(r#"{"version":"v2.1.0","hostname":"db-1"}"#).unwrap();
        assert_eq!(i2.hostname, "db-1");
    }

    #[test]
    fn parses_data_sorts_ascending_and_zeroes_nulls() {
        let body = r#"{"labels":["time","user","system"],
            "data":[[1700000060, 5.0, null],[1700000000, 3.0, 2.0]]}"#;
        let s = parse_data(body).unwrap();
        assert_eq!(s.rows[0].0, 1700000000); // sorted ascending
        assert_eq!(s.rows[1].1, vec![5.0, 0.0]); // null → 0
    }

    #[test]
    fn cpu_total_sums_dimensions() {
        let s = NetdataSeries {
            labels: vec![
                "time".into(),
                "user".into(),
                "system".into(),
                "iowait".into(),
            ],
            rows: vec![(1, vec![10.0, 5.0, 2.5]), (2, vec![60.0, 55.0, 0.0])],
        };
        let t = cpu_total_pct(&s);
        assert!((t[0].value - 17.5).abs() < 1e-9);
        assert!((t[1].value - 100.0).abs() < 1e-9); // clamped
    }

    #[test]
    fn ram_used_pct_uses_used_over_total() {
        let s = NetdataSeries {
            labels: vec![
                "time".into(),
                "free".into(),
                "used".into(),
                "cached".into(),
                "buffers".into(),
            ],
            rows: vec![(1, vec![1000.0, 2000.0, 900.0, 100.0])],
        };
        let r = ram_used_pct(&s);
        assert!((r[0].value - 50.0).abs() < 1e-9); // 2000 / 4000
    }

    #[test]
    fn disk_used_pct_excludes_root_reserve() {
        let s = NetdataSeries {
            labels: vec![
                "time".into(),
                "avail".into(),
                "used".into(),
                "reserved for root".into(),
            ],
            rows: vec![(1, vec![20.0, 60.0, 5.0])],
        };
        let d = disk_used_pct(&s);
        assert!((d[0].value - 75.0).abs() < 1e-9); // 60 / (20+60)
    }

    #[test]
    fn net_total_abs_sum_kib_to_bytes() {
        let s = NetdataSeries {
            labels: vec!["time".into(), "received".into(), "sent".into()],
            rows: vec![(1, vec![100.0, -50.0])],
        };
        let n = net_total_bps(&s);
        assert!((n[0].value - 150.0 * 1024.0).abs() < 1e-9);
    }

    #[test]
    fn parses_active_alarms_map() {
        let body = r#"{"alarms":{
            "disk_space._":{"name":"disk_space_usage","status":"WARNING","value_string":"91.2%"},
            "cpu.cpu":{"name":"cpu_usage","status":"CRITICAL"}
        }}"#;
        let a = parse_alarms(body).unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].name, "cpu_usage");
        assert_eq!(a[0].status, "CRITICAL");
        assert_eq!(a[1].value, "91.2%");
        assert!(parse_alarms(r#"{"alarms":{}}"#).unwrap().is_empty());
    }
}
