//! Local session history (SQLite, never synced by default) and the aggregations that
//! power the history view and the monthly report card.

use crate::error::Result;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionRecord {
    pub id: String,
    pub region: String,
    pub instance_type: String,
    pub started_at: i64,
    pub ended_at: i64,
    pub bytes_rx: i64,
    pub bytes_tx: i64,
    pub cost_usd: f64,
    pub peak_cpu_pct: i64,
    pub down_mbps: i64,
    pub up_mbps: i64,
}

pub struct HistoryStore {
    conn: Connection,
}

/// Aggregate totals across a set of sessions.
#[derive(Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Totals {
    pub sessions: usize,
    pub hours: f64,
    pub bytes: i64,
    pub cost_usd: f64,
}

/// Per-region breakdown for the donut chart.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionBreakdown {
    pub region: String,
    pub sessions: usize,
    pub hours: f64,
    pub bytes: i64,
}

/// The monthly report card.
#[derive(Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MonthlyReport {
    pub year: i32,
    pub month: u32,
    pub totals: Totals,
    pub by_region: Vec<RegionBreakdown>,
    pub best_down_mbps: i64,
    pub worst_down_mbps: i64,
    /// What a flat commercial VPN subscription would have cost for the same month.
    pub commercial_vpn_usd: f64,
}

const COMMERCIAL_VPN_MONTHLY_USD: f64 = 12.99;

impl HistoryStore {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sessions (
                 id TEXT PRIMARY KEY,
                 region TEXT NOT NULL,
                 instance_type TEXT NOT NULL,
                 started_at INTEGER NOT NULL,
                 ended_at INTEGER NOT NULL,
                 bytes_rx INTEGER NOT NULL,
                 bytes_tx INTEGER NOT NULL,
                 cost_usd REAL NOT NULL,
                 peak_cpu_pct INTEGER NOT NULL,
                 down_mbps INTEGER NOT NULL,
                 up_mbps INTEGER NOT NULL
             );",
        )?;
        Ok(HistoryStore { conn })
    }

    pub fn insert(&self, s: &SessionRecord) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions
             (id, region, instance_type, started_at, ended_at, bytes_rx, bytes_tx, cost_usd, peak_cpu_pct, down_mbps, up_mbps)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            rusqlite::params![
                s.id, s.region, s.instance_type, s.started_at, s.ended_at,
                s.bytes_rx, s.bytes_tx, s.cost_usd, s.peak_cpu_pct, s.down_mbps, s.up_mbps
            ],
        )?;
        Ok(())
    }

    /// Sessions started within `[from, to)`, newest first.
    pub fn list(&self, from: i64, to: i64) -> Result<Vec<SessionRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, region, instance_type, started_at, ended_at, bytes_rx, bytes_tx, cost_usd, peak_cpu_pct, down_mbps, up_mbps
             FROM sessions WHERE started_at >= ?1 AND started_at < ?2 ORDER BY started_at DESC",
        )?;
        let rows = stmt.query_map([from, to], Self::map_row)?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    pub fn all(&self) -> Result<Vec<SessionRecord>> {
        self.list(i64::MIN, i64::MAX)
    }

    fn map_row(row: &rusqlite::Row) -> rusqlite::Result<SessionRecord> {
        Ok(SessionRecord {
            id: row.get(0)?,
            region: row.get(1)?,
            instance_type: row.get(2)?,
            started_at: row.get(3)?,
            ended_at: row.get(4)?,
            bytes_rx: row.get(5)?,
            bytes_tx: row.get(6)?,
            cost_usd: row.get(7)?,
            peak_cpu_pct: row.get(8)?,
            down_mbps: row.get(9)?,
            up_mbps: row.get(10)?,
        })
    }

    /// Aggregate a monthly report for the calendar month containing `[from, to)`.
    pub fn monthly_report(
        &self,
        year: i32,
        month: u32,
        from: i64,
        to: i64,
    ) -> Result<MonthlyReport> {
        let sessions = self.list(from, to)?;
        Ok(build_report(year, month, &sessions))
    }
}

/// Pure aggregation so it is trivially testable.
pub fn totals(sessions: &[SessionRecord]) -> Totals {
    let mut t = Totals::default();
    for s in sessions {
        t.sessions += 1;
        t.hours += (s.ended_at - s.started_at) as f64 / 3600.0;
        t.bytes += s.bytes_rx + s.bytes_tx;
        t.cost_usd += s.cost_usd;
    }
    t
}

pub fn build_report(year: i32, month: u32, sessions: &[SessionRecord]) -> MonthlyReport {
    use std::collections::BTreeMap;
    let mut regions: BTreeMap<String, RegionBreakdown> = BTreeMap::new();
    let mut best = i64::MIN;
    let mut worst = i64::MAX;
    for s in sessions {
        let e = regions.entry(s.region.clone()).or_insert(RegionBreakdown {
            region: s.region.clone(),
            sessions: 0,
            hours: 0.0,
            bytes: 0,
        });
        e.sessions += 1;
        e.hours += (s.ended_at - s.started_at) as f64 / 3600.0;
        e.bytes += s.bytes_rx + s.bytes_tx;
        best = best.max(s.down_mbps);
        worst = worst.min(s.down_mbps);
    }
    MonthlyReport {
        year,
        month,
        totals: totals(sessions),
        by_region: regions.into_values().collect(),
        best_down_mbps: if best == i64::MIN { 0 } else { best },
        worst_down_mbps: if worst == i64::MAX { 0 } else { worst },
        commercial_vpn_usd: COMMERCIAL_VPN_MONTHLY_USD,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, region: &str, start: i64, dur: i64, down: i64, cost: f64) -> SessionRecord {
        SessionRecord {
            id: id.into(),
            region: region.into(),
            instance_type: "g6-nanode-1".into(),
            started_at: start,
            ended_at: start + dur,
            bytes_rx: 1_000_000_000,
            bytes_tx: 100_000_000,
            cost_usd: cost,
            peak_cpu_pct: 40,
            down_mbps: down,
            up_mbps: 200,
        }
    }

    #[test]
    fn insert_list_survives_and_orders() {
        let store = HistoryStore::open(":memory:").unwrap();
        store
            .insert(&rec("a", "us-east", 100, 3600, 500, 0.0075))
            .unwrap();
        store
            .insert(&rec("b", "eu-central", 200, 1800, 400, 0.004))
            .unwrap();
        let all = store.all().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].id, "b"); // newest first
    }

    #[test]
    fn totals_are_correct() {
        let sessions = vec![
            rec("a", "us-east", 0, 3600, 500, 0.0075),
            rec("b", "us-east", 0, 1800, 400, 0.004),
        ];
        let t = totals(&sessions);
        assert_eq!(t.sessions, 2);
        assert!((t.hours - 1.5).abs() < 1e-9);
        assert!((t.cost_usd - 0.0115).abs() < 1e-9);
    }

    #[test]
    fn report_aggregates_by_region_and_extremes() {
        let sessions = vec![
            rec("a", "us-east", 0, 3600, 620, 0.0075),
            rec("b", "us-east", 0, 3600, 410, 0.0075),
            rec("c", "eu-central", 0, 3600, 500, 0.0075),
        ];
        let r = build_report(2026, 6, &sessions);
        assert_eq!(r.totals.sessions, 3);
        assert_eq!(r.by_region.len(), 2);
        assert_eq!(r.best_down_mbps, 620);
        assert_eq!(r.worst_down_mbps, 410);
        // Self-hosted cost is far below a flat commercial subscription.
        assert!(r.totals.cost_usd < r.commercial_vpn_usd);
    }

    #[test]
    fn empty_report_is_safe() {
        let r = build_report(2026, 1, &[]);
        assert_eq!(r.best_down_mbps, 0);
        assert_eq!(r.worst_down_mbps, 0);
        assert_eq!(r.totals.sessions, 0);
    }
}
