//! The server watchdog's pure alert engine. Every tick the desktop poller builds one
//! [`ServerSample`] per known server and calls [`evaluate`]; this module decides which
//! alerts actually fire. All the noise-control logic lives here, headless and unit-tested:
//!
//! - **Transitions, not states**: "down" fires when a server that was running stops being
//!   running (or vanishes) — a server that was already stopped at first sight never alerts.
//! - **Sustain**: CPU must stay over threshold for N consecutive ticks (flap suppression).
//! - **Latching**: every alert latches until the condition clears, so a down server toasts
//!   once, not every tick. Recovery unlatches (and "down" also emits a Recovered alert).

use std::collections::HashMap;

use super::provider::InstanceState;

/// Thresholds and pacing (mirrors the user-editable config file).
#[derive(Clone, Copy, Debug)]
pub struct WatchdogCfg {
    /// CPU percent threshold (e.g. 90.0).
    pub cpu_pct: f64,
    /// Consecutive over-threshold ticks before a CPU alert fires.
    pub cpu_sustain_ticks: u32,
    /// Disk-used percent threshold (e.g. 90.0).
    pub disk_pct: f64,
}

impl Default for WatchdogCfg {
    fn default() -> Self {
        WatchdogCfg {
            cpu_pct: 90.0,
            cpu_sustain_ticks: 3,
            disk_pct: 90.0,
        }
    }
}

/// One server's observation for a tick. `key` is `"provider:id"` and must be stable.
#[derive(Clone, Debug)]
pub struct ServerSample {
    pub key: String,
    pub label: String,
    pub state: InstanceState,
    /// Total CPU percent (from Netdata when available; provider metrics otherwise). None = unknown.
    pub cpu_pct: Option<f64>,
    /// Root-filesystem used percent (Netdata only). None = unknown.
    pub disk_used_pct: Option<f64>,
    /// Active Netdata alarm count. None = Netdata not configured/reachable.
    pub netdata_alarms: Option<u32>,
}

/// An alert the app should surface (toast + in-app feed).
#[derive(Clone, Debug, PartialEq)]
pub enum Alert {
    Down {
        key: String,
        label: String,
    },
    Recovered {
        key: String,
        label: String,
    },
    CpuHigh {
        key: String,
        label: String,
        pct: f64,
    },
    DiskHigh {
        key: String,
        label: String,
        pct: f64,
    },
    NetdataAlarm {
        key: String,
        label: String,
        count: u32,
    },
}

impl Alert {
    /// Human message for the notification body.
    pub fn message(&self) -> String {
        match self {
            Alert::Down { label, .. } => format!("{label} is DOWN (stopped or unreachable)."),
            Alert::Recovered { label, .. } => format!("{label} is back up."),
            Alert::CpuHigh { label, pct, .. } => {
                format!("{label}: CPU pegged at {pct:.0}% (sustained).")
            }
            Alert::DiskHigh { label, pct, .. } => {
                format!("{label}: disk {pct:.0}% full.")
            }
            Alert::NetdataAlarm { label, count, .. } => {
                format!(
                    "{label}: {count} active Netdata alarm{}.",
                    if *count == 1 { "" } else { "s" }
                )
            }
        }
    }
}

#[derive(Default, Clone)]
struct EntryState {
    was_running: bool,
    down_latched: bool,
    cpu_over_ticks: u32,
    cpu_latched: bool,
    disk_latched: bool,
    alarm_latched: bool,
}

/// Persistent (per-poller-lifetime) latch state. Keep one instance across ticks.
#[derive(Default)]
pub struct WatchdogState {
    entries: HashMap<String, EntryState>,
}

/// Evaluate one tick. `providers_ok` lists the provider prefixes (e.g. `"linode"`) whose
/// listings SUCCEEDED this tick — a server missing from a successful listing counts as gone,
/// but a failed provider fetch never marks its servers down (that would alert on every
/// API hiccup).
pub fn evaluate(
    state: &mut WatchdogState,
    samples: &[ServerSample],
    providers_ok: &[&str],
    cfg: &WatchdogCfg,
) -> Vec<Alert> {
    let mut alerts = Vec::new();

    // Missing-server detection: previously-running keys of a succeeded provider, absent now.
    let present: std::collections::HashSet<&str> = samples.iter().map(|s| s.key.as_str()).collect();
    let missing: Vec<String> = state
        .entries
        .iter()
        .filter(|(key, e)| {
            e.was_running
                && !e.down_latched
                && !present.contains(key.as_str())
                && providers_ok
                    .iter()
                    .any(|p| key.starts_with(&format!("{p}:")))
        })
        .map(|(key, _)| key.clone())
        .collect();
    for key in missing {
        let e = state.entries.get_mut(&key).unwrap();
        e.down_latched = true;
        e.was_running = false;
        alerts.push(Alert::Down {
            key: key.clone(),
            label: key,
        });
    }

    for s in samples {
        let e = state.entries.entry(s.key.clone()).or_default();
        let running = s.state == InstanceState::Running;

        // Down / recovered (transition-based, latched).
        if e.was_running && !running && !e.down_latched {
            e.down_latched = true;
            alerts.push(Alert::Down {
                key: s.key.clone(),
                label: s.label.clone(),
            });
        } else if e.down_latched && running {
            e.down_latched = false;
            alerts.push(Alert::Recovered {
                key: s.key.clone(),
                label: s.label.clone(),
            });
        }
        e.was_running = running;

        // CPU: sustain + latch; re-arm below threshold.
        match s.cpu_pct {
            Some(p) if p >= cfg.cpu_pct => {
                e.cpu_over_ticks += 1;
                if e.cpu_over_ticks >= cfg.cpu_sustain_ticks && !e.cpu_latched {
                    e.cpu_latched = true;
                    alerts.push(Alert::CpuHigh {
                        key: s.key.clone(),
                        label: s.label.clone(),
                        pct: p,
                    });
                }
            }
            Some(_) => {
                e.cpu_over_ticks = 0;
                e.cpu_latched = false;
            }
            None => {}
        }

        // Disk: immediate + latch; re-arm 5 points under threshold (hysteresis).
        match s.disk_used_pct {
            Some(p) if p >= cfg.disk_pct => {
                if !e.disk_latched {
                    e.disk_latched = true;
                    alerts.push(Alert::DiskHigh {
                        key: s.key.clone(),
                        label: s.label.clone(),
                        pct: p,
                    });
                }
            }
            Some(p) if p < cfg.disk_pct - 5.0 => e.disk_latched = false,
            _ => {}
        }

        // Netdata alarms: latch on any-active; re-arm when clear.
        match s.netdata_alarms {
            Some(n) if n > 0 => {
                if !e.alarm_latched {
                    e.alarm_latched = true;
                    alerts.push(Alert::NetdataAlarm {
                        key: s.key.clone(),
                        label: s.label.clone(),
                        count: n,
                    });
                }
            }
            Some(_) => e.alarm_latched = false,
            None => {}
        }
    }

    alerts
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(key: &str, state: InstanceState) -> ServerSample {
        ServerSample {
            key: key.into(),
            label: key.into(),
            state,
            cpu_pct: None,
            disk_used_pct: None,
            netdata_alarms: None,
        }
    }

    #[test]
    fn down_fires_once_then_recovers() {
        let mut st = WatchdogState::default();
        let cfg = WatchdogCfg::default();
        // Tick 1: running — no alerts (baseline).
        assert!(evaluate(
            &mut st,
            &[sample("h:1", InstanceState::Running)],
            &["h"],
            &cfg
        )
        .is_empty());
        // Tick 2: stopped — one Down.
        let a = evaluate(
            &mut st,
            &[sample("h:1", InstanceState::Stopped)],
            &["h"],
            &cfg,
        );
        assert_eq!(a.len(), 1);
        assert!(matches!(a[0], Alert::Down { .. }));
        // Tick 3: still stopped — silence (latched).
        assert!(evaluate(
            &mut st,
            &[sample("h:1", InstanceState::Stopped)],
            &["h"],
            &cfg
        )
        .is_empty());
        // Tick 4: running again — one Recovered.
        let a = evaluate(
            &mut st,
            &[sample("h:1", InstanceState::Running)],
            &["h"],
            &cfg,
        );
        assert_eq!(a.len(), 1);
        assert!(matches!(a[0], Alert::Recovered { .. }));
        // Tick 5: still running — silence.
        assert!(evaluate(
            &mut st,
            &[sample("h:1", InstanceState::Running)],
            &["h"],
            &cfg
        )
        .is_empty());
    }

    #[test]
    fn already_stopped_at_first_sight_never_alerts() {
        let mut st = WatchdogState::default();
        let cfg = WatchdogCfg::default();
        for _ in 0..3 {
            assert!(evaluate(
                &mut st,
                &[sample("h:1", InstanceState::Stopped)],
                &["h"],
                &cfg
            )
            .is_empty());
        }
    }

    #[test]
    fn missing_from_successful_listing_is_down_but_failed_provider_is_not() {
        let mut st = WatchdogState::default();
        let cfg = WatchdogCfg::default();
        evaluate(
            &mut st,
            &[sample("linode:9", InstanceState::Running)],
            &["linode"],
            &cfg,
        );
        // Provider fetch failed this tick (not in providers_ok) — no alert.
        assert!(evaluate(&mut st, &[], &[], &cfg).is_empty());
        // Provider fetch succeeded and the server is gone — Down.
        let a = evaluate(&mut st, &[], &["linode"], &cfg);
        assert_eq!(a.len(), 1);
        assert!(matches!(a[0], Alert::Down { .. }));
        // And only once.
        assert!(evaluate(&mut st, &[], &["linode"], &cfg).is_empty());
    }

    #[test]
    fn cpu_needs_sustain_then_latches_then_rearms() {
        let mut st = WatchdogState::default();
        let cfg = WatchdogCfg {
            cpu_pct: 90.0,
            cpu_sustain_ticks: 3,
            disk_pct: 90.0,
        };
        let hot = |pct: f64| ServerSample {
            cpu_pct: Some(pct),
            ..sample("h:1", InstanceState::Running)
        };
        // Two hot ticks: not yet.
        assert!(evaluate(&mut st, &[hot(95.0)], &["h"], &cfg).is_empty());
        assert!(evaluate(&mut st, &[hot(97.0)], &["h"], &cfg).is_empty());
        // Third: fires.
        let a = evaluate(&mut st, &[hot(99.0)], &["h"], &cfg);
        assert!(matches!(a[0], Alert::CpuHigh { pct, .. } if pct == 99.0));
        // Fourth hot tick: latched, silent.
        assert!(evaluate(&mut st, &[hot(99.0)], &["h"], &cfg).is_empty());
        // Cool tick resets; a flap (2 hot ticks) stays silent.
        assert!(evaluate(&mut st, &[hot(10.0)], &["h"], &cfg).is_empty());
        assert!(evaluate(&mut st, &[hot(95.0)], &["h"], &cfg).is_empty());
        assert!(evaluate(&mut st, &[hot(95.0)], &["h"], &cfg).is_empty());
        // Third consecutive hot fires again (re-armed).
        assert_eq!(evaluate(&mut st, &[hot(95.0)], &["h"], &cfg).len(), 1);
    }

    #[test]
    fn disk_latches_with_hysteresis() {
        let mut st = WatchdogState::default();
        let cfg = WatchdogCfg::default();
        let disk = |pct: f64| ServerSample {
            disk_used_pct: Some(pct),
            ..sample("h:1", InstanceState::Running)
        };
        assert_eq!(evaluate(&mut st, &[disk(92.0)], &["h"], &cfg).len(), 1);
        assert!(evaluate(&mut st, &[disk(93.0)], &["h"], &cfg).is_empty());
        // 88% is inside the hysteresis band (>= 85): still latched.
        assert!(evaluate(&mut st, &[disk(88.0)], &["h"], &cfg).is_empty());
        assert!(evaluate(&mut st, &[disk(92.0)], &["h"], &cfg).is_empty());
        // Drops under threshold-5 → re-arms; next cross fires again.
        assert!(evaluate(&mut st, &[disk(80.0)], &["h"], &cfg).is_empty());
        assert_eq!(evaluate(&mut st, &[disk(95.0)], &["h"], &cfg).len(), 1);
    }

    #[test]
    fn netdata_alarms_latch_until_clear() {
        let mut st = WatchdogState::default();
        let cfg = WatchdogCfg::default();
        let al = |n: u32| ServerSample {
            netdata_alarms: Some(n),
            ..sample("h:1", InstanceState::Running)
        };
        assert_eq!(evaluate(&mut st, &[al(2)], &["h"], &cfg).len(), 1);
        assert!(evaluate(&mut st, &[al(3)], &["h"], &cfg).is_empty()); // still latched
        assert!(evaluate(&mut st, &[al(0)], &["h"], &cfg).is_empty()); // clears silently
        assert_eq!(evaluate(&mut st, &[al(1)], &["h"], &cfg).len(), 1); // re-fires
    }

    #[test]
    fn unknown_metrics_never_alert() {
        let mut st = WatchdogState::default();
        let cfg = WatchdogCfg::default();
        // cpu/disk/alarms all None — only state transitions can alert.
        assert!(evaluate(
            &mut st,
            &[sample("h:1", InstanceState::Running)],
            &["h"],
            &cfg
        )
        .is_empty());
        assert!(evaluate(
            &mut st,
            &[sample("h:1", InstanceState::Running)],
            &["h"],
            &cfg
        )
        .is_empty());
    }
}
