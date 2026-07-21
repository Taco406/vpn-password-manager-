//! Attack monitor: record security-relevant auth outcomes, enforce (opt-in) IP bans, and
//! answer the desktop app's `/v1/security-*` queries. Recording is best-effort — it never
//! fails a request. Nothing sensitive is stored (no tokens, no plaintext); see the
//! `0008_security_events` migration and the schema guard.

use crate::state::AppState;
use sqlx::PgPool;
use uuid::Uuid;

/// The failure kinds that count toward auto-ban.
const FAILURE_KINDS: &[&str] = &[
    "login_fail_bootstrap",
    "google_reject",
    "totp_fail",
    "refresh_reuse",
];

/// Keep only a real IP literal. The in-process test harness has no peer, so `client_ip`
/// yields `"local"` — store NULL for those rather than blowing up the `inet` cast.
fn ip_opt(ip: &str) -> Option<String> {
    ip.parse::<std::net::IpAddr>().ok().map(|p| p.to_string())
}

/// Record one security event. Best-effort: logs and swallows any DB error so it can never
/// turn a normal auth failure into a 500.
pub async fn record(
    pool: &PgPool,
    account: Option<Uuid>,
    kind: &str,
    ip: &str,
    detail: Option<&str>,
) {
    let res = sqlx::query(
        "INSERT INTO security_events (account_id, kind, ip, detail) VALUES ($1, $2, $3::inet, $4)",
    )
    .bind(account)
    .bind(kind)
    .bind(ip_opt(ip))
    .bind(detail)
    .execute(pool)
    .await;
    if let Err(e) = res {
        tracing::warn!(error = %e, kind, "failed to record security event");
    }
}

/// Whether `ip` currently has an active (unexpired) ban.
pub async fn is_banned(pool: &PgPool, ip: &str) -> bool {
    let Some(ip) = ip_opt(ip) else {
        return false;
    };
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM banned_ips WHERE ip = $1::inet AND (until IS NULL OR until > now()))",
    )
    .bind(ip)
    .fetch_one(pool)
    .await
    .unwrap_or(false)
}

/// After a failed attempt from `ip`, ban it if it has produced at least
/// `config.autoban_threshold` failure events within the window — UNLESS a successful login
/// came from that IP recently (the owner-lockout guard). No-op when the threshold is 0.
pub async fn maybe_autoban(st: &AppState, ip: &str) {
    let threshold = st.config.autoban_threshold;
    if threshold == 0 {
        return;
    }
    let Some(ip_lit) = ip_opt(ip) else {
        return; // never auto-ban the (IP-less) test/local caller
    };

    let fails: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM security_events
         WHERE ip = $1::inet
           AND created_at > now() - ($2::double precision * interval '1 second')
           AND kind = ANY($3)",
    )
    .bind(&ip_lit)
    .bind(st.config.autoban_window_secs as f64)
    .bind(FAILURE_KINDS)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);
    if fails < threshold as i64 {
        return;
    }

    // Owner-lockout guard: never ban an IP that has signed in successfully in the last day —
    // that's almost certainly the owner fat-fingering their code, not an attacker.
    let owner: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM security_events
         WHERE ip = $1::inet AND kind = 'login_ok' AND created_at > now() - interval '1 day')",
    )
    .bind(&ip_lit)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(false);
    if owner {
        return;
    }

    let reason = format!("auto: {fails} failed attempts in window");
    let _ = sqlx::query(
        "INSERT INTO banned_ips (ip, reason, until)
         VALUES ($1::inet, $2, now() + ($3::double precision * interval '1 minute'))
         ON CONFLICT (ip) DO UPDATE SET until = EXCLUDED.until, reason = EXCLUDED.reason",
    )
    .bind(&ip_lit)
    .bind(&reason)
    .bind(st.config.autoban_minutes as f64)
    .execute(&st.pool)
    .await;
    record(&st.pool, None, "auto_ban", ip, Some(&reason)).await;
}

/// Manually ban an IP (the "block this IP" button). `minutes = None` ⇒ permanent.
pub async fn ban(pool: &PgPool, ip: &str, minutes: Option<i64>) -> Result<(), sqlx::Error> {
    let Some(ip_lit) = ip_opt(ip) else {
        return Ok(()); // ignore non-IP input
    };
    match minutes {
        Some(m) if m > 0 => {
            sqlx::query(
                "INSERT INTO banned_ips (ip, reason, until)
                 VALUES ($1::inet, 'manual', now() + ($2::double precision * interval '1 minute'))
                 ON CONFLICT (ip) DO UPDATE SET until = EXCLUDED.until, reason = 'manual'",
            )
            .bind(&ip_lit)
            .bind(m as f64)
            .execute(pool)
            .await?;
        }
        _ => {
            sqlx::query(
                "INSERT INTO banned_ips (ip, reason, until) VALUES ($1::inet, 'manual', NULL)
                 ON CONFLICT (ip) DO UPDATE SET until = NULL, reason = 'manual'",
            )
            .bind(&ip_lit)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// Remove any ban on an IP.
pub async fn unban(pool: &PgPool, ip: &str) -> Result<(), sqlx::Error> {
    if let Some(ip_lit) = ip_opt(ip) {
        sqlx::query("DELETE FROM banned_ips WHERE ip = $1::inet")
            .bind(ip_lit)
            .execute(pool)
            .await?;
    }
    Ok(())
}
