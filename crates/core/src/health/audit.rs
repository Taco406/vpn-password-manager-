//! The health audit: reused, weak, and old passwords, plus breach checks.

use super::hibp::HibpClient;
use crate::generator::strength;
use crate::vault::model::Item;
use std::collections::HashMap;
use uuid::Uuid;

/// A set of items that share the same password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusedGroup {
    pub item_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditReport {
    pub reused: Vec<ReusedGroup>,
    /// (item, zxcvbn score) for items scoring < 3.
    pub weak: Vec<(Uuid, u8)>,
    /// (item, age in days) for passwords older than the threshold.
    pub old: Vec<(Uuid, i64)>,
    /// (item, breach count) for passwords found in HIBP.
    pub breached: Vec<(Uuid, u32)>,
    /// Overall health, 0 (bad) .. 100 (perfect).
    pub score: u8,
}

const OLD_THRESHOLD_DAYS: i64 = 180;
const SECS_PER_DAY: i64 = 86_400;

/// Run the full audit. `now` is the current unix time; `hibp` supplies breach counts
/// (a mock in tests / the demo, the real k-anonymity client behind `live-hibp`).
pub async fn run_audit(items: &[Item], now: i64, hibp: &dyn HibpClient) -> AuditReport {
    let mut report = AuditReport::default();

    // Reused: group login items by password.
    let mut by_password: HashMap<&str, Vec<Uuid>> = HashMap::new();
    for it in items {
        if let Some(pw) = it.password() {
            by_password.entry(pw).or_default().push(it.id);
        }
    }
    for ids in by_password.values() {
        if ids.len() > 1 {
            report.reused.push(ReusedGroup {
                item_ids: ids.clone(),
            });
        }
    }

    for it in items {
        let Some(pw) = it.password() else { continue };

        // Weak.
        let user_inputs: Vec<&str> = it
            .username()
            .into_iter()
            .chain(std::iter::once(it.title.as_str()))
            .collect();
        let s = strength::assess(pw, &user_inputs);
        if s.score < 3 {
            report.weak.push((it.id, s.score));
        }

        // Old.
        if let Some(changed) = it.password_changed_at {
            let age_days = (now - changed) / SECS_PER_DAY;
            if age_days > OLD_THRESHOLD_DAYS {
                report.old.push((it.id, age_days));
            }
        }

        // Breached.
        if let Ok(count) = hibp.breach_count(pw).await {
            if count > 0 {
                report.breached.push((it.id, count));
            }
        }
    }

    report.score = compute_score(items.len(), &report);
    report
}

/// A simple 0..100 health score: start at 100, deduct per issue, floor at 0.
fn compute_score(total_items: usize, r: &AuditReport) -> u8 {
    if total_items == 0 {
        return 100;
    }
    let reused_items: usize = r.reused.iter().map(|g| g.item_ids.len()).sum();
    let penalties = reused_items as i32 * 8
        + r.weak.len() as i32 * 6
        + r.breached.len() as i32 * 12
        + r.old.len() as i32 * 3;
    (100 - penalties).clamp(0, 100) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::hibp::MockHibp;
    use crate::vault::model::{Item, Login};

    fn login(title: &str, pw: &str, changed: i64) -> Item {
        let mut it = Item::new_login(title, changed);
        it.login = Some(Login {
            username: Some(format!("{title}@example.com")),
            password: Some(pw.to_string()),
            totp: None,
        });
        it.password_changed_at = Some(changed);
        it
    }

    #[tokio::test]
    async fn detects_seeded_issues_exactly() {
        // Seed: 3 items reuse "hunter2-reused", 2 weak, 1 known-breached.
        // "hunter2-reused" is BOTH reused (x3) and breached (in MockHibp).
        let now = 1_700_000_000;
        let old = now - 200 * SECS_PER_DAY;
        let items = vec![
            login("a", "hunter2-reused", now),              // reused + breached
            login("b", "hunter2-reused", now),              // reused + breached
            login("c", "hunter2-reused", now),              // reused + breached
            login("d", "password", now),                    // weak + breached
            login("e", "12345678", old),                    // weak + old
            login("f", "Xq7!vmZ2-strong-unique-pass", now), // healthy
        ];
        let report = run_audit(&items, now, &MockHibp).await;

        // Exactly one reused group of size 3.
        assert_eq!(report.reused.len(), 1);
        assert_eq!(report.reused[0].item_ids.len(), 3);

        // Weak: "password" and "12345678" (score < 3).
        let weak_ids: Vec<_> = report.weak.iter().map(|(id, _)| *id).collect();
        assert!(weak_ids.contains(&items[3].id));
        assert!(weak_ids.contains(&items[4].id));

        // Old: item e only.
        assert_eq!(report.old.len(), 1);
        assert_eq!(report.old[0].0, items[4].id);

        // Breached: the three reused + "password".
        assert_eq!(report.breached.len(), 4);

        assert!(report.score < 100);
    }

    #[tokio::test]
    async fn empty_vault_is_perfect() {
        let report = run_audit(&[], 0, &MockHibp).await;
        assert_eq!(report.score, 100);
    }
}
