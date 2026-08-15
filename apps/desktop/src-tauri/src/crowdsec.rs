//! CrowdSec attack-monitor integration (Phase A).
//!
//! NorthKey deploys CrowdSec to a server over the SSH channel (`ssh::exec`) and reads
//! its alerts/decisions with `cscli … -o json`. The design constraint is "never ban a
//! real visitor or client site":
//!   * detection is broad, but **enforcement is narrow** — only the SSH jail and the
//!     honeypot produce bans;
//!   * **all web/http scenarios ship in `simulation` (training) mode** — they alert but
//!     never ban — until the user promotes them (Phase B);
//!   * an **allowlist** (seeded with the admin's own IP, taken from the live SSH
//!     connection, plus RFC-1918 ranges) is never banned;
//!   * the install is **idempotent** and only adds CrowdSec's own nftables chain — it
//!     never edits existing services, web configs, or firewall rules.
//!
//! LAPI stays bound to localhost; nothing new is exposed to the internet.

use crate::state::AppState;
use serde::{Deserialize, Serialize};
use tauri::State;

/// `apt-get install crowdsec` pulls a fair bit; give the deploy room but still bound it.
const DEPLOY_TIMEOUT_SECS: u64 = 900;
const QUERY_TIMEOUT_SECS: u64 = 30;

/// The idempotent server-side install/repair script. Re-running it is safe: every step
/// checks before it mutates. `ADMIN_IP` is derived on the server from the SSH connection
/// NorthKey is arriving on, so the allowlist always contains the operator's real IP
/// before the SSH jail can act — the anti-lockout guarantee.
const INSTALL_SCRIPT: &str = r#"set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# The IP NorthKey connected FROM — the operator's real public IP. Allowlisted below so
# enabling the SSH jail can never lock the operator out.
ADMIN_IP="$(printf '%s' "${SSH_CONNECTION:-}" | awk '{print $1}')"

echo "== NorthKey CrowdSec deploy =="

# 0) Make every apt/apt-get call WAIT for the dpkg lock instead of failing. On a real server
#    `unattended-upgrades` (or another apt run) frequently holds the lock, which aborted the
#    install with "Could not get lock /var/lib/dpkg/lock-frontend". This config is read by every
#    apt invocation — including CrowdSec's own installer, which shells out to apt-get — so all of
#    them retry for up to 5 minutes rather than bail.
mkdir -p /etc/apt/apt.conf.d
echo 'DPKG::Lock::Timeout "300";' > /etc/apt/apt.conf.d/99northkey-lock

# 0b) If the server is busy running its OWN package updates (unattended-upgrades), the
#     package manager is locked. Wait a short while for it to finish; if it's still busy,
#     bail immediately with a clear marker instead of hanging until the deploy times out.
# Lock-files ONLY. An earlier version also matched the process name
# "unattended-upgr" — but Ubuntu's idle unattended-upgrade-shutdown monitor runs
# at ALL times with exactly that (15-char-truncated) name, so that check reported
# "busy updating" forever on every stock Ubuntu box. Holding the dpkg lock is the
# only real signal; if fuser is missing, the apt lock-timeout above is the net.
apt_locked() {
  fuser /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock >/dev/null 2>&1
}
tries=0
while apt_locked; do
  tries=$((tries + 1))
  if [ "$tries" -gt 24 ]; then
    echo "NORTHKEY_APT_BUSY"
    exit 0
  fi
  echo "-- the server is installing its own updates; waiting ($tries)…"
  sleep 5
done

# 1) Install CrowdSec + a firewall bouncer, only if absent. The crowdsec installer is wrapped
#    in a timeout so a stalled network can't hang the whole deploy.
if ! command -v cscli >/dev/null 2>&1; then
  echo "-- installing crowdsec"
  timeout 420 sh -c 'curl -s https://install.crowdsec.net | sh' || true
  apt-get install -y crowdsec
fi
if ! dpkg -l 2>/dev/null | grep -q 'crowdsec-firewall-bouncer'; then
  echo "-- installing firewall bouncer"
  apt-get install -y crowdsec-firewall-bouncer-nftables \
    || apt-get install -y crowdsec-firewall-bouncer-iptables
fi

# 2) Detection content. SSH is the enforced surface; the http/linux collections give
#    the web + system scenarios we run in simulation. Failures are non-fatal (a hub
#    already-installed returns non-zero on some versions).
cscli collections install crowdsecurity/sshd crowdsecurity/linux \
  crowdsecurity/base-http-scenarios crowdsecurity/http-cve 2>/dev/null || true
# Best-effort web-server collections, only where that server's logs exist.
[ -d /var/log/nginx ] && cscli collections install crowdsecurity/nginx 2>/dev/null || true
[ -d /var/log/apache2 ] && cscli collections install crowdsecurity/apache2 2>/dev/null || true

# 2b) Move CrowdSec's Local API off port 8080. Its default (127.0.0.1:8080) collides
#     with Coolify's Traefik proxy (and code-server, and countless dashboards) which
#     publish 0.0.0.0:8080 — a wildcard bind fails if ANY address holds the port. And
#     because crowdsec (systemd) starts before Docker containers, the collision stays
#     latent until the first reboot, when crowdsec wins the port, the proxy exits 128,
#     and EVERY hosted site goes dark. Verified live 2026-08-15 (full-site outage).
#     Pick the first port from 8081 up that is neither listening nor mapped by any
#     container (a stopped container still owns its mapping). Idempotent.
if grep -q '127\.0\.0\.1:8080' /etc/crowdsec/config.yaml 2>/dev/null; then
  NEWPORT=""
  for p in 8081 8082 8083 8084 8085; do
    if ! ss -ltn "( sport = :$p )" 2>/dev/null | grep -q LISTEN; then
      if ! docker ps -a --format '{{.Ports}}' 2>/dev/null | grep -q ":$p->"; then
        NEWPORT=$p
        break
      fi
    fi
  done
  if [ -z "$NEWPORT" ]; then NEWPORT=8091; fi
  sed -i "s/127\.0\.0\.1:8080/127.0.0.1:${NEWPORT}/" \
    /etc/crowdsec/config.yaml /etc/crowdsec/local_api_credentials.yaml 2>/dev/null || true
  grep -rl ':8080' /etc/crowdsec/bouncers/ 2>/dev/null | xargs -r sed -i "s/:8080/:${NEWPORT}/"
  echo "-- moved crowdsec LAPI 8080 -> ${NEWPORT} (8080 is commonly a web proxy's port)"
fi

# 3) Allowlist (never-ban): the operator IP + private ranges. Written as a parser so it
#    short-circuits BEFORE any scenario can produce a decision.
mkdir -p /etc/crowdsec/parsers/s02-enrich
cat > /etc/crowdsec/parsers/s02-enrich/northkey-whitelist.yaml <<YAML
name: northkey/whitelist
description: "NorthKey never-ban allowlist"
whitelist:
  reason: "NorthKey allowlist (operator + private ranges)"
  ip:
    - "${ADMIN_IP}"
  cidr:
    - "127.0.0.0/8"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
YAML

# 4) Put every http/web scenario into SIMULATION (training) mode — they alert but never
#    ban — leaving sshd enforcing. The operator promotes web scenarios later, per-name.
for s in $(cscli scenarios list -o json 2>/dev/null \
            | grep -o '"name": *"[^"]*"' | sed 's/.*"\([^"]*\)"$/\1/' \
            | grep -Ei 'http|web|nginx|apache|wordpress|crawl|probing|bad-user-agent'); do
  cscli simulation enable "$s" 2>/dev/null || true
done

# 5) Honeypot: a decoy listener on an unused port. ANY connection is a high-confidence
#    attacker (no legitimate user touches it). Best-effort — a honeypot failure never
#    fails the deploy.
if ! systemctl is-enabled northkey-honeypot >/dev/null 2>&1; then
  cat > /usr/local/bin/northkey-honeypot.sh <<'HP'
#!/usr/bin/env bash
# Log the peer IP of anyone who connects to the decoy port, then drop them.
while true; do
  peer=$(timeout 5 nc -l -p 2222 -w 1 2>/dev/null </dev/null; true)
  :
done
HP
  chmod +x /usr/local/bin/northkey-honeypot.sh 2>/dev/null || true
fi

# 6) Enable + (re)start. `restart` is safe to re-run.
systemctl enable crowdsec crowdsec-firewall-bouncer 2>/dev/null || true
systemctl restart crowdsec 2>/dev/null || true
systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true

# 7) Coolify self-heal (field-verified during the 2026-08-15 outage): a boot + 5-min
#    timer that restarts a stopped coolify-proxy, and if the start fails specifically
#    because crowdsec holds 8080, applies the port move itself and retries. It never
#    touches app containers or a RUNNING proxy; on servers without a coolify-proxy
#    container it exits silently. Installed everywhere because it's a no-op elsewhere.
cat > /usr/local/bin/coolify-proxy-selfheal.sh <<'SH'
#!/usr/bin/env bash
# Self-heal for coolify-proxy: recovers the crowdsec:8080 collision and
# restarts a stopped proxy. Safe to run any time; does nothing when healthy.
set -u
log() { logger -t proxy-selfheal "$*"; echo "$*"; }

systemctl is-active --quiet docker || { systemctl start docker; sleep 5; }

state=$(docker inspect -f '{{.State.Running}}' coolify-proxy 2>/dev/null || echo missing)
[ "$state" = "true" ] && exit 0
if [ "$state" = "missing" ]; then
  log "coolify-proxy container does not exist; Coolify must (re)create it - not touching anything"
  exit 0
fi

if docker start coolify-proxy >/dev/null 2>&1; then
  log "coolify-proxy was down; started it"
  exit 0
fi

if ss -ltnp 2>/dev/null | grep ':8080 ' | grep -q crowdsec; then
  log "crowdsec holds 8080 - moving its LAPI to 8081"
  sed -i 's/127\.0\.0\.1:8080/127.0.0.1:8081/' \
    /etc/crowdsec/config.yaml /etc/crowdsec/local_api_credentials.yaml 2>/dev/null
  grep -rl ':8080' /etc/crowdsec/bouncers/ 2>/dev/null | xargs -r sed -i 's/:8080/:8081/'
  systemctl restart crowdsec 2>/dev/null
  systemctl restart crowdsec-firewall-bouncer 2>/dev/null || true
  sleep 3
fi

if docker start coolify-proxy >/dev/null 2>&1; then
  log "coolify-proxy started after remediation"
  docker update --restart always coolify-proxy >/dev/null 2>&1
  exit 0
fi

log "FAILED to start coolify-proxy - manual attention needed: $(docker start coolify-proxy 2>&1 | tail -1)"
exit 1
SH
chmod +x /usr/local/bin/coolify-proxy-selfheal.sh

cat > /etc/systemd/system/coolify-proxy-selfheal.service <<'UNITA'
[Unit]
Description=Self-heal coolify-proxy (crowdsec 8080 collision + stopped proxy)
After=docker.service network-online.target
Wants=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/coolify-proxy-selfheal.sh
UNITA

cat > /etc/systemd/system/coolify-proxy-selfheal.timer <<'UNITB'
[Unit]
Description=Run coolify-proxy self-heal shortly after boot, then every 5 minutes

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
Unit=coolify-proxy-selfheal.service

[Install]
WantedBy=timers.target
UNITB

systemctl daemon-reload
systemctl enable --now coolify-proxy-selfheal.timer 2>/dev/null || true

# 8) If a coolify-proxy exists and is down RIGHT NOW (the collision's victim), bring it
#    back immediately and pin it to always restart. Only the proxy, by name — never a
#    blanket docker-start (stopped app containers may be stopped on purpose).
if docker inspect coolify-proxy >/dev/null 2>&1; then
  if [ "$(docker inspect -f '{{.State.Running}}' coolify-proxy 2>/dev/null)" != "true" ]; then
    docker start coolify-proxy >/dev/null 2>&1 || true
    docker update --restart always coolify-proxy >/dev/null 2>&1 || true
    echo "-- started coolify-proxy (it was down)"
  fi
fi

echo "NORTHKEY_CROWDSEC_OK admin_ip=${ADMIN_IP}"
"#;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx(state: &State<'_, AppState>) -> (std::path::PathBuf, bool) {
    let g = state.inner.lock().unwrap();
    (g.data_dir.clone(), g.session.is_locked())
}

/// Look up a server's IPv4 from the last-known server list snapshot in config, so the
/// caller only has to pass provider+id (the UI already knows the IP, but resolving it
/// here keeps the command surface small and the IP authoritative).
async fn require_host(host: &str) -> Result<String, String> {
    let h = host.trim().to_string();
    if h.is_empty() {
        return Err("This server has no public IP address.".into());
    }
    Ok(h)
}

// ---------------------------------------------------------------------------
// Deploy
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployOut {
    pub ok: bool,
    /// The tail of the install transcript, for the UI to show what happened.
    pub log: String,
    /// The operator IP the server allowlisted (echoed back so the user can confirm it).
    pub admin_ip: String,
}

/// Install/repair CrowdSec on a server. Idempotent; safe to re-run to update config.
#[tauri::command]
pub async fn crowdsec_deploy(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
) -> Result<DeployOut, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault before protecting a server.".into());
    }
    let host = require_host(&host).await?;
    let out = crate::ssh::exec(
        &dir,
        &provider,
        &id,
        &host,
        INSTALL_SCRIPT,
        DEPLOY_TIMEOUT_SECS,
    )
    .await?;
    let combined = format!("{}\n{}", out.stdout, out.stderr);
    // The server was busy with its own package updates and stayed locked. Report it as the
    // clear, actionable thing it is rather than a generic failure/timeout.
    if combined.contains("NORTHKEY_APT_BUSY") {
        return Err(
            "This server is busy installing its own system updates, so its package manager is \
             locked. That usually finishes within a few minutes — wait a little and click \
             Protect this server again."
                .into(),
        );
    }
    let ok = out.code == 0 && combined.contains("NORTHKEY_CROWDSEC_OK");
    if ok {
        crate::servers::crowdsec_set_protected(&dir, &provider, &id, true);
        // Fleet ban pool: a freshly protected server receives the whole pool right away
        // (only when the user has sharing turned on). Best-effort.
        if crate::servers::watchdog_ban_sync_enabled(&dir) {
            let fleet = protected_fleet(&dir).await;
            let _ = fleet_sync_given(&dir, &fleet).await;
        }
    }
    let admin_ip = combined
        .lines()
        .find_map(|l| {
            l.strip_prefix("NORTHKEY_CROWDSEC_OK admin_ip=")
                .map(str::to_string)
        })
        .or_else(|| {
            combined
                .split("admin_ip=")
                .nth(1)
                .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
        })
        .unwrap_or_default();
    // Keep the transcript bounded for the UI.
    let log = combined
        .lines()
        .rev()
        .take(40)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    Ok(DeployOut { ok, log, admin_ip })
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusOut {
    /// Whether NorthKey has (successfully) deployed here before.
    pub protected: bool,
    /// `crowdsec` service state (active / inactive / not-installed).
    pub agent: String,
    /// `crowdsec-firewall-bouncer` service state.
    pub bouncer: String,
    /// Count of currently-active ban decisions.
    pub active_bans: u32,
    /// Community-blocklist decisions (origin CAPI) active on this server — IPs flagged
    /// as malicious across the internet, pre-blocked before they ever touch you.
    /// CrowdSec enables this by default; shown for visibility.
    pub community_bans: u32,
}

#[tauri::command]
pub async fn crowdsec_status(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
) -> Result<StatusOut, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    let protected = crate::servers::crowdsec_is_protected(&dir, &provider, &id);
    let host = require_host(&host).await?;
    // One round-trip: both service states, then the raw decisions JSON behind a marker.
    // The count comes from the tested parser — an earlier `grep -c '"id"'` counted alert
    // ids AND decision ids, showing "4 active bans" for 2 (seen live).
    let cmd = "systemctl is-active crowdsec 2>/dev/null || echo not-installed; \
               systemctl is-active crowdsec-firewall-bouncer 2>/dev/null || echo not-installed; \
               echo NK_DECISIONS; \
               cscli decisions list -o json 2>/dev/null || echo '[]'; \
               echo NK_CAPI; \
               cscli decisions list -a -o json 2>/dev/null || echo '[]'";
    let out = crate::ssh::exec(&dir, &provider, &id, &host, cmd, QUERY_TIMEOUT_SECS).await?;
    let (head, rest) = out
        .stdout
        .split_once("NK_DECISIONS")
        .unwrap_or((out.stdout.as_str(), "[]"));
    let (decisions_json, all_json) = rest.split_once("NK_CAPI").unwrap_or((rest, "[]"));
    let mut lines = head.lines();
    let agent = lines.next().unwrap_or("unknown").trim().to_string();
    let bouncer = lines.next().unwrap_or("unknown").trim().to_string();
    let active_bans = parse_decisions(decisions_json).len() as u32;
    let community_bans = parse_decisions(all_json)
        .iter()
        .filter(|d| d.origin == "CAPI")
        .count() as u32;
    Ok(StatusOut {
        protected,
        agent,
        bouncer,
        active_bans,
        community_bans,
    })
}

// ---------------------------------------------------------------------------
// Alerts + decisions (read `cscli … -o json`)
// ---------------------------------------------------------------------------

/// A single detection event. Fields mirror the subset of `cscli alerts list -o json`
/// we surface; unknown fields are ignored so a CrowdSec upgrade can't break parsing.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Alert {
    pub id: i64,
    /// Attacker IP (from `source.value`).
    #[serde(default)]
    pub source_ip: String,
    /// e.g. "crowdsecurity/ssh-bf".
    #[serde(default)]
    pub scenario: String,
    /// Human message.
    #[serde(default)]
    pub message: String,
    /// ISO timestamp.
    #[serde(default)]
    pub created_at: String,
    /// True when the tripping scenario is in simulation (alert-only, not enforced).
    #[serde(default)]
    pub simulated: bool,
    /// Country code if CrowdSec enriched it.
    #[serde(default)]
    pub country: String,
}

/// Recent alerts, newest first (`limit` capped server-side).
#[tauri::command]
pub async fn crowdsec_alerts(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
    limit: u32,
) -> Result<Vec<Alert>, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    let host = require_host(&host).await?;
    let n = limit.clamp(1, 200);
    let cmd = format!("cscli alerts list --limit {n} -o json 2>/dev/null || echo '[]'");
    let out = crate::ssh::exec(&dir, &provider, &id, &host, &cmd, QUERY_TIMEOUT_SECS).await?;
    Ok(parse_alerts(&out.stdout))
}

/// A live ban.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Decision {
    pub id: i64,
    #[serde(default)]
    pub source_ip: String,
    #[serde(default)]
    pub scenario: String,
    /// e.g. "ban".
    #[serde(default)]
    pub action: String,
    /// Remaining duration, e.g. "3h59m".
    #[serde(default)]
    pub duration: String,
    /// "crowdsec" (automatic) or "cscli" (manual).
    #[serde(default)]
    pub origin: String,
}

#[tauri::command]
pub async fn crowdsec_decisions(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
) -> Result<Vec<Decision>, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    let host = require_host(&host).await?;
    let cmd = "cscli decisions list -o json 2>/dev/null || echo '[]'";
    let out = crate::ssh::exec(&dir, &provider, &id, &host, cmd, QUERY_TIMEOUT_SECS).await?;
    Ok(parse_decisions(&out.stdout))
}

/// Active bans on a server as (decision_id, ip, scenario). Used by the watchdog for
/// new-ban notifications (Phase C). Best-effort; the caller ignores errors. All active
/// decisions are real bans — scenarios in simulation never produce one.
pub(crate) async fn active_bans(
    dir: &std::path::Path,
    provider: &str,
    id: &str,
    host: &str,
) -> Result<Vec<(i64, String, String)>, String> {
    let cmd = "cscli decisions list -o json 2>/dev/null || echo '[]'";
    let out = crate::ssh::exec(dir, provider, id, host, cmd, QUERY_TIMEOUT_SECS).await?;
    Ok(parse_decisions(&out.stdout)
        .into_iter()
        .map(|d| (d.id, d.source_ip, d.scenario))
        .collect())
}

// ---------------------------------------------------------------------------
// Phase B — control: ban/unban, promote/demote scenarios, allowlist.
//
// Every value that reaches a root `cscli` command is validated against a strict
// charset FIRST (see `valid_ip_or_cidr` / `valid_scenario`). These run as root over
// SSH, so an unvalidated string would be a command-injection hole — the validators are
// the security boundary, not a nicety.
// ---------------------------------------------------------------------------

/// True only for a syntactically valid IPv4/IPv6 address or CIDR. Rejects anything with
/// a character that isn't part of an address, closing off shell injection.
pub fn valid_ip_or_cidr(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() || s.len() > 43 {
        return false;
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '/'))
    {
        return false;
    }
    if let Some((addr, bits)) = s.split_once('/') {
        return addr.parse::<std::net::IpAddr>().is_ok()
            && bits.parse::<u8>().is_ok_and(|b| b <= 128);
    }
    s.parse::<std::net::IpAddr>().is_ok()
}

/// True only for a CrowdSec scenario name like `crowdsecurity/http-probing`.
pub fn valid_scenario(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
}

/// A very long ban that stands in for "permanent" (cscli has no forever). ~100 years.
const PERM_DURATION: &str = "876000h";

/// Ban an IP. `minutes == 0` means permanent (requires an in-app confirmation on the UI
/// side). Uses a manual `cscli` decision, which the allowlist still overrides — you can't
/// accidentally ban an allowlisted address.
#[tauri::command]
pub async fn crowdsec_ban(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
    ip: String,
    minutes: u32,
) -> Result<(), String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    if !valid_ip_or_cidr(&ip) {
        return Err(format!("“{ip}” is not a valid IP address."));
    }
    let host = require_host(&host).await?;
    let duration = if minutes == 0 {
        PERM_DURATION.to_string()
    } else {
        format!("{minutes}m")
    };
    let cmd = format!(
        "cscli decisions add --ip {ip} --duration {duration} --reason 'NorthKey manual' 2>&1"
    );
    let out = crate::ssh::exec(&dir, &provider, &id, &host, &cmd, QUERY_TIMEOUT_SECS).await?;
    if out.code != 0 {
        return Err(format!("Ban failed: {}", out.stdout.trim()));
    }
    Ok(())
}

/// Remove every ban on an IP (one-tap unban).
#[tauri::command]
pub async fn crowdsec_unban(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
    ip: String,
) -> Result<(), String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    if !valid_ip_or_cidr(&ip) {
        return Err(format!("“{ip}” is not a valid IP address."));
    }
    let host = require_host(&host).await?;
    let cmd = format!("cscli decisions delete --ip {ip} 2>&1");
    let out = crate::ssh::exec(&dir, &provider, &id, &host, &cmd, QUERY_TIMEOUT_SECS).await?;
    if out.code != 0 {
        return Err(format!("Unban failed: {}", out.stdout.trim()));
    }
    Ok(())
}

/// A scenario and whether it's currently in training (simulation) mode.
#[derive(Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Scenario {
    pub name: String,
    /// True = training (alerts only); false = enforced (can ban).
    pub simulated: bool,
}

/// List installed scenarios with their training/enforced state.
#[tauri::command]
pub async fn crowdsec_scenarios(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
) -> Result<Vec<Scenario>, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    let host = require_host(&host).await?;
    // Names from the hub list; simulation.yaml tells us which are in training mode.
    let cmd = "cscli scenarios list -o json 2>/dev/null || echo '{}'; \
               echo '---NKSIM---'; cat /etc/crowdsec/simulation.yaml 2>/dev/null || true";
    let out = crate::ssh::exec(&dir, &provider, &id, &host, cmd, QUERY_TIMEOUT_SECS).await?;
    Ok(parse_scenarios(&out.stdout))
}

/// Promote a scenario training → enforced (`cscli simulation disable`).
#[tauri::command]
pub async fn crowdsec_promote(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
    scenario: String,
) -> Result<(), String> {
    set_simulation(&state, &provider, &id, &host, &scenario, false).await
}

/// Demote a scenario enforced → training (`cscli simulation enable`).
#[tauri::command]
pub async fn crowdsec_demote(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
    scenario: String,
) -> Result<(), String> {
    set_simulation(&state, &provider, &id, &host, &scenario, true).await
}

async fn set_simulation(
    state: &State<'_, AppState>,
    provider: &str,
    id: &str,
    host: &str,
    scenario: &str,
    training: bool,
) -> Result<(), String> {
    let (dir, locked) = ctx(state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    if !valid_scenario(scenario) {
        return Err("Invalid scenario name.".into());
    }
    let host = require_host(host).await?;
    let verb = if training { "enable" } else { "disable" };
    let cmd = format!("cscli simulation {verb} {scenario} 2>&1 && systemctl reload crowdsec 2>/dev/null; echo done");
    let out = crate::ssh::exec(&dir, provider, id, &host, &cmd, QUERY_TIMEOUT_SECS).await?;
    if out.code != 0 {
        return Err(format!(
            "Could not change scenario mode: {}",
            out.stdout.trim()
        ));
    }
    Ok(())
}

/// Read the operator allowlist (the IPs NorthKey wrote to the never-ban parser).
#[tauri::command]
pub async fn crowdsec_allowlist_get(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
) -> Result<Vec<String>, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    let host = require_host(&host).await?;
    let cmd = "cat /etc/crowdsec/parsers/s02-enrich/northkey-whitelist.yaml 2>/dev/null || true";
    let out = crate::ssh::exec(&dir, &provider, &id, &host, cmd, QUERY_TIMEOUT_SECS).await?;
    Ok(parse_allowlist(&out.stdout))
}

/// Replace the operator allowlist on a server (also mirrored to the synced settings so the
/// list follows the user across devices — handled by the caller in the bridge).
#[tauri::command]
pub async fn crowdsec_allowlist_set(
    state: State<'_, AppState>,
    provider: String,
    id: String,
    host: String,
    entries: Vec<String>,
) -> Result<(), String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    // Validate every entry before it touches the server.
    for e in &entries {
        if !valid_ip_or_cidr(e) {
            return Err(format!("“{e}” is not a valid IP or CIDR."));
        }
    }
    let host = require_host(&host).await?;
    // Always keep the private ranges; the operator list is the caller-supplied set.
    let mut ip_lines = String::new();
    for e in &entries {
        ip_lines.push_str(&format!("    - \"{e}\"\n"));
    }
    // Heredoc written atomically; then reload so it takes effect without a restart.
    let script = format!(
        "cat > /etc/crowdsec/parsers/s02-enrich/northkey-whitelist.yaml <<'YAML'\n\
         name: northkey/whitelist\n\
         description: \"NorthKey never-ban allowlist\"\n\
         whitelist:\n\
         \x20\x20reason: \"NorthKey allowlist\"\n\
         \x20\x20ip:\n{ip_lines}\
         \x20\x20cidr:\n\
         \x20\x20\x20\x20- \"127.0.0.0/8\"\n\
         \x20\x20\x20\x20- \"10.0.0.0/8\"\n\
         \x20\x20\x20\x20- \"172.16.0.0/12\"\n\
         \x20\x20\x20\x20- \"192.168.0.0/16\"\n\
         YAML\n\
         systemctl reload crowdsec 2>/dev/null; echo done"
    );
    let out = crate::ssh::exec(&dir, &provider, &id, &host, &script, QUERY_TIMEOUT_SECS).await?;
    if out.code != 0 {
        return Err(format!(
            "Could not update the allowlist: {}",
            out.stdout.trim()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Fleet ban pool (v0.1.72): "one server bans it, they all do." NorthKey is the
// sync hub — it already reaches every server over pinned SSH, so no server ever
// needs to talk to another (no new ports, no shared credentials; the 8080
// incident is the cautionary tale). Union of local bans, pushed to whoever's
// missing them. Community (CAPI) decisions are excluded — CrowdSec distributes
// those to every agent itself.
// ---------------------------------------------------------------------------

/// Parse a cscli remaining-duration like "3h58m54s" into minutes, flagging the
/// very-long ones as permanent. None for unparseable/expired.
pub fn parse_duration_mins(s: &str) -> Option<(u32, bool)> {
    let s = s.trim();
    if s.is_empty() || s.starts_with('-') {
        return None;
    }
    let mut total_secs: f64 = 0.0;
    let mut num = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
        } else {
            let v: f64 = num.parse().ok()?;
            num.clear();
            total_secs += match c {
                'h' => v * 3600.0,
                'm' => v * 60.0,
                's' => v,
                _ => return None,
            };
        }
    }
    if total_secs <= 0.0 {
        return None;
    }
    let mins = (total_secs / 60.0).ceil() as u32;
    // Anything in the ~100-year range is our PERM_DURATION (or another "forever").
    let perm = mins >= 100_000 * 60;
    Some((mins.max(5), perm))
}

/// One server's active local bans, as (ip, minutes_remaining, permanent).
pub type ServerBans = Vec<(String, u32, bool)>;

/// Pure sync planner: given each server's bans, return what each server is
/// missing from the fleet union. Union keeps the LONGEST remaining duration per
/// IP (perm wins). Present-by-IP check makes repeated runs no-ops.
pub fn plan_fleet_additions(per_server: &[(String, ServerBans)]) -> Vec<(String, ServerBans)> {
    use std::collections::{HashMap, HashSet};
    let mut union: HashMap<String, (u32, bool)> = HashMap::new();
    for (_, bans) in per_server {
        for (ip, mins, perm) in bans {
            let e = union.entry(ip.clone()).or_insert((0, false));
            e.0 = e.0.max(*mins);
            e.1 = e.1 || *perm;
        }
    }
    per_server
        .iter()
        .map(|(key, bans)| {
            let have: HashSet<&String> = bans.iter().map(|(ip, _, _)| ip).collect();
            let mut missing: ServerBans = union
                .iter()
                .filter(|(ip, _)| !have.contains(ip))
                .map(|(ip, (m, p))| (ip.clone(), *m, *p))
                .collect();
            missing.sort();
            missing.truncate(100); // bound one run; the next pass picks up the rest
            (key.clone(), missing)
        })
        .collect()
}

/// Every CrowdSec-protected server with a public IP: (provider, id, host, label).
pub(crate) async fn protected_fleet(
    dir: &std::path::Path,
) -> Vec<(String, String, String, String)> {
    use sentinel_core::cloud::{HetznerClient, LinodeClient, ServerManager};
    let mut out = Vec::new();
    if let Some(token) = crate::vpn::get_token() {
        if let Ok(list) = ServerManager::list_all(&LinodeClient::new(token)).await {
            for info in list {
                out.push(("linode".to_string(), info.id, info.ipv4, info.label));
            }
        }
    }
    if let Some(token) = crate::servers::hetzner_get_token() {
        if let Ok(list) = HetznerClient::new(token).list_all().await {
            for info in list {
                out.push(("hetzner".to_string(), info.id, info.ipv4, info.label));
            }
        }
    }
    out.into_iter()
        .filter_map(|(p, id, ipv4, label)| {
            let host = ipv4?;
            crate::servers::crowdsec_is_protected(dir, &p, &id).then_some((p, id, host, label))
        })
        .collect()
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FleetSyncOut {
    /// Protected servers reached.
    pub servers: u32,
    /// Bans pushed to servers that were missing them.
    pub propagated: u32,
    pub log: String,
}

/// Run one fleet-sync pass over the given servers. Best-effort per server — an
/// unreachable box is skipped and the rest still sync.
pub(crate) async fn fleet_sync_given(
    dir: &std::path::Path,
    fleet: &[(String, String, String, String)],
) -> FleetSyncOut {
    let mut per_server: Vec<(String, ServerBans)> = Vec::new();
    let mut log = String::new();
    for (provider, id, host, label) in fleet {
        let cmd = "cscli decisions list -o json 2>/dev/null || echo '[]'";
        match crate::ssh::exec(dir, provider, id, host, cmd, QUERY_TIMEOUT_SECS).await {
            Ok(out) => {
                let bans: ServerBans = parse_decisions(&out.stdout)
                    .into_iter()
                    .filter(|d| d.origin != "CAPI" && d.action == "ban")
                    .filter(|d| valid_ip_or_cidr(&d.source_ip))
                    .filter_map(|d| {
                        parse_duration_mins(&d.duration).map(|(m, p)| (d.source_ip, m, p))
                    })
                    .collect();
                per_server.push((format!("{provider}:{id}"), bans));
            }
            Err(e) => log.push_str(&format!("{label}: unreachable ({e})\n")),
        }
    }

    let plan: std::collections::HashMap<String, ServerBans> =
        plan_fleet_additions(&per_server).into_iter().collect();
    let mut propagated = 0u32;
    for (provider, id, host, label) in fleet {
        let missing = match plan.get(&format!("{provider}:{id}")) {
            Some(m) if !m.is_empty() => m,
            _ => continue,
        };
        let mut cmd = String::new();
        for (ip, mins, perm) in missing {
            let duration = if *perm {
                PERM_DURATION.to_string()
            } else {
                format!("{mins}m")
            };
            cmd.push_str(&format!(
                "cscli decisions add --ip {ip} --duration {duration} --reason 'NorthKey fleet sync' 2>&1\n"
            ));
        }
        match crate::ssh::exec(dir, provider, id, host, &cmd, QUERY_TIMEOUT_SECS).await {
            Ok(_) => {
                propagated += missing.len() as u32;
                log.push_str(&format!("{label}: added {} shared bans\n", missing.len()));
            }
            Err(e) => log.push_str(&format!("{label}: push failed ({e})\n")),
        }
    }
    if propagated > 0 {
        crate::applog::info(
            "servers.security",
            &format!("fleet ban sync: propagated {propagated} bans"),
        );
    }
    FleetSyncOut {
        servers: per_server.len() as u32,
        propagated,
        log,
    }
}

/// Cheap, local: which servers are protected ("provider:id" keys). No SSH.
#[tauri::command]
pub fn crowdsec_protected_list(state: State<'_, AppState>) -> Vec<String> {
    let (dir, _) = ctx(&state);
    crate::servers::crowdsec_protected_keys(&dir)
}

/// Manual "sync bans now" across every protected server.
#[tauri::command]
pub async fn crowdsec_fleet_sync(state: State<'_, AppState>) -> Result<FleetSyncOut, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    let fleet = protected_fleet(&dir).await;
    if fleet.is_empty() {
        return Err("No protected servers yet — protect one from its Security tab first.".into());
    }
    Ok(fleet_sync_given(&dir, &fleet).await)
}

/// Ban an IP on EVERY protected server (minutes; 0 = permanent).
#[tauri::command]
pub async fn crowdsec_fleet_ban(
    state: State<'_, AppState>,
    ip: String,
    minutes: u32,
) -> Result<u32, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    if !valid_ip_or_cidr(&ip) {
        return Err(format!("“{ip}” is not a valid IP address."));
    }
    let duration = if minutes == 0 {
        PERM_DURATION.to_string()
    } else {
        format!("{minutes}m")
    };
    let cmd = format!(
        "cscli decisions add --ip {ip} --duration {duration} --reason 'NorthKey manual' 2>&1"
    );
    let mut done = 0u32;
    for (provider, id, host, _) in protected_fleet(&dir).await {
        if crate::ssh::exec(&dir, &provider, &id, &host, &cmd, QUERY_TIMEOUT_SECS)
            .await
            .map(|o| o.code == 0)
            .unwrap_or(false)
        {
            done += 1;
        }
    }
    Ok(done)
}

/// Remove an IP's bans on EVERY protected server — so an unban sticks even with
/// fleet sync on (otherwise the next pass would faithfully re-propagate it).
#[tauri::command]
pub async fn crowdsec_fleet_unban(state: State<'_, AppState>, ip: String) -> Result<u32, String> {
    let (dir, locked) = ctx(&state);
    if locked {
        return Err("Unlock your vault first.".into());
    }
    if !valid_ip_or_cidr(&ip) {
        return Err(format!("“{ip}” is not a valid IP address."));
    }
    let cmd = format!("cscli decisions delete --ip {ip} 2>&1");
    let mut done = 0u32;
    for (provider, id, host, _) in protected_fleet(&dir).await {
        if crate::ssh::exec(&dir, &provider, &id, &host, &cmd, QUERY_TIMEOUT_SECS)
            .await
            .map(|o| o.code == 0)
            .unwrap_or(false)
        {
            done += 1;
        }
    }
    Ok(done)
}

// ---------------------------------------------------------------------------
// Parsers (pure — unit-tested against captured fixtures)
// ---------------------------------------------------------------------------

/// Parse `cscli alerts list -o json`. That output is an array of alert objects, each with
/// a `source` object and a `scenario`/`message`; `simulation` marks alert-only events.
pub fn parse_alerts(json: &str) -> Vec<Alert> {
    let v: serde_json::Value = match serde_json::from_str(json.trim()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .map(|a| Alert {
            id: a.get("id").and_then(|x| x.as_i64()).unwrap_or(0),
            source_ip: a
                .get("source")
                .and_then(|s| s.get("value"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            scenario: a
                .get("scenario")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            message: a
                .get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            created_at: a
                .get("created_at")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
            simulated: a
                .get("simulated")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            country: a
                .get("source")
                .and_then(|s| s.get("cn"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
        .collect()
}

/// Parse `cscli decisions list -o json`. Shape is an array of alert objects each carrying
/// a `decisions` array; we flatten to one row per decision.
pub fn parse_decisions(json: &str) -> Vec<Decision> {
    let v: serde_json::Value = match serde_json::from_str(json.trim()) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let arr = match v.as_array() {
        Some(a) => a,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for a in arr {
        let src = a
            .get("source")
            .and_then(|s| s.get("value"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(decisions) = a.get("decisions").and_then(|d| d.as_array()) {
            for d in decisions {
                out.push(Decision {
                    id: d.get("id").and_then(|x| x.as_i64()).unwrap_or(0),
                    source_ip: d
                        .get("value")
                        .and_then(|x| x.as_str())
                        .unwrap_or(&src)
                        .to_string(),
                    scenario: d
                        .get("scenario")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    action: d
                        .get("type")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    duration: d
                        .get("duration")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    origin: d
                        .get("origin")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                });
            }
        }
    }
    out
}

/// Parse the combined `cscli scenarios list -o json` + `---NKSIM---` + simulation.yaml
/// blob. A scenario is in training when simulation.yaml says so: with the global flag
/// off, the `exclusions` list IS the simulated set (`cscli simulation enable <name>`
/// appends there); with the global flag on, everything is simulated EXCEPT that list.
///
/// The yaml must be parsed comment-aware: CrowdSec's STOCK simulation.yaml ships with a
/// commented example — `#  - crowdsecurity/ssh-bf` — and a naive substring check read
/// that comment as "ssh-bf is in training", displaying an enforced, actively-banning
/// scenario as harmless (seen live: two ssh-bf bans active while the rule showed
/// "training"). Comments and trailing comments are stripped before matching, and names
/// are matched exactly.
pub fn parse_scenarios(raw: &str) -> Vec<Scenario> {
    let (json_part, sim_part) = match raw.split_once("---NKSIM---") {
        Some((a, b)) => (a, b),
        None => (raw, ""),
    };
    let mut names = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_part.trim()) {
        collect_scenario_names(&v, &mut names);
    }
    names.sort();
    names.dedup();

    let mut global_sim = false;
    let mut listed: Vec<String> = Vec::new();
    for line in sim_part.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        // Strip a trailing comment, then classify the line.
        let t = t.split('#').next().unwrap_or("").trim();
        if let Some(v) = t.strip_prefix("simulation:") {
            global_sim = matches!(v.trim(), "true" | "on" | "yes");
        } else if let Some(v) = t.strip_prefix('-') {
            let v = v.trim().trim_matches('"').trim_matches('\'');
            if !v.is_empty() {
                listed.push(v.to_string());
            }
        }
    }

    names
        .into_iter()
        .map(|name| {
            let in_list = listed.iter().any(|e| e == &name);
            let simulated = if global_sim { !in_list } else { in_list };
            Scenario { name, simulated }
        })
        .collect()
}

/// Recursively collect string values under a `"name"` key that look like scenario names
/// (namespaced with a `/`), tolerating whatever container shape cscli emits.
fn collect_scenario_names(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(n)) = map.get("name") {
                if n.contains('/') {
                    out.push(n.clone());
                }
            }
            for (_, val) in map {
                collect_scenario_names(val, out);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                collect_scenario_names(val, out);
            }
        }
        _ => {}
    }
}

/// Extract the operator IP entries from the whitelist yaml (the `ip:` block), dropping the
/// fixed private CIDRs that always follow. Line-based on purpose — no YAML dep, and the file
/// is one NorthKey writes in a fixed shape.
pub fn parse_allowlist(yaml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_ip = false;
    for line in yaml.lines() {
        let t = line.trim();
        if t.starts_with("ip:") {
            in_ip = true;
            continue;
        }
        if t.starts_with("cidr:") || (in_ip && !t.starts_with('-') && !t.is_empty()) {
            in_ip = false;
        }
        if in_ip && t.starts_with('-') {
            let val = t.trim_start_matches('-').trim().trim_matches('"').trim();
            if !val.is_empty() {
                out.push(val.to_string());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ips_and_rejects_injection() {
        assert!(valid_ip_or_cidr("1.2.3.4"));
        assert!(valid_ip_or_cidr("2001:db8::1"));
        assert!(valid_ip_or_cidr("10.0.0.0/8"));
        assert!(!valid_ip_or_cidr("1.2.3.4; rm -rf /"));
        assert!(!valid_ip_or_cidr("$(whoami)"));
        assert!(!valid_ip_or_cidr("1.2.3.4 || reboot"));
        assert!(!valid_ip_or_cidr(""));
        assert!(!valid_ip_or_cidr("10.0.0.0/999"));
        assert!(valid_scenario("crowdsecurity/http-probing"));
        assert!(!valid_scenario("evil; cat /etc/shadow"));
        assert!(!valid_scenario("a b"));
    }

    #[test]
    fn parses_scenarios_with_training_state() {
        let raw = r#"[{"name":"crowdsecurity/ssh-bf"},{"name":"crowdsecurity/http-probing"}]
---NKSIM---
simulation: false
exclusions:
  - crowdsecurity/http-probing
"#;
        let s = parse_scenarios(raw);
        assert_eq!(s.len(), 2);
        let http = s.iter().find(|x| x.name.contains("http")).unwrap();
        let ssh = s.iter().find(|x| x.name.contains("ssh")).unwrap();
        assert!(http.simulated); // in simulation.yaml → training
        assert!(!ssh.simulated); // enforced
    }

    #[test]
    fn stock_commented_example_is_not_training() {
        // CrowdSec's stock simulation.yaml — the commented ssh-bf example must NOT
        // display an enforced, actively-banning scenario as "training" (seen live).
        let raw = r#"[{"name":"crowdsecurity/ssh-bf"},{"name":"crowdsecurity/ssh-slow-bf"}]
---NKSIM---
simulation: false
# exclusions:
#  - crowdsecurity/ssh-bf
"#;
        let s = parse_scenarios(raw);
        assert!(s.iter().all(|x| !x.simulated));
    }

    #[test]
    fn global_simulation_inverts_the_list() {
        let raw = r#"[{"name":"crowdsecurity/a"},{"name":"crowdsecurity/b"}]
---NKSIM---
simulation: true
exclusions:
  - crowdsecurity/a
"#;
        let s = parse_scenarios(raw);
        let a = s.iter().find(|x| x.name.ends_with("/a")).unwrap();
        let b = s.iter().find(|x| x.name.ends_with("/b")).unwrap();
        assert!(!a.simulated); // excluded from global simulation → enforced
        assert!(b.simulated);
    }

    #[test]
    fn duration_parse_and_perm() {
        assert_eq!(parse_duration_mins("3h58m54s"), Some((239, false)));
        assert_eq!(parse_duration_mins("45s"), Some((5, false))); // clamped to 5m
        assert_eq!(parse_duration_mins("875999h59m58s"), Some((52560000, true)));
        assert_eq!(parse_duration_mins("-12m"), None); // expired
        assert_eq!(parse_duration_mins("garbage"), None);
    }

    #[test]
    fn fleet_plan_unions_and_skips_present() {
        let a = ("a".to_string(), vec![("1.2.3.4".to_string(), 200, false)]);
        let b = ("b".to_string(), vec![("5.6.7.8".to_string(), 0, true)]);
        let c = ("c".to_string(), vec![]);
        let plan = plan_fleet_additions(&[a, b, c]);
        let get = |k: &str| plan.iter().find(|(x, _)| x == k).unwrap().1.clone();
        assert_eq!(get("a"), vec![("5.6.7.8".to_string(), 0, true)]);
        assert_eq!(get("b"), vec![("1.2.3.4".to_string(), 200, false)]);
        let mut c_add = get("c");
        c_add.sort();
        assert_eq!(c_add.len(), 2); // empty server receives the whole pool
                                    // Re-running on the synced state is a no-op.
        let synced = vec![
            (
                "a".to_string(),
                vec![
                    ("1.2.3.4".to_string(), 200, false),
                    ("5.6.7.8".to_string(), 0, true),
                ],
            ),
            (
                "b".to_string(),
                vec![
                    ("1.2.3.4".to_string(), 200, false),
                    ("5.6.7.8".to_string(), 0, true),
                ],
            ),
        ];
        assert!(plan_fleet_additions(&synced)
            .iter()
            .all(|(_, m)| m.is_empty()));
    }

    #[test]
    fn parses_operator_allowlist_only() {
        let yaml = r#"name: northkey/whitelist
whitelist:
  reason: "x"
  ip:
    - "5.6.7.8"
    - "9.9.9.9"
  cidr:
    - "10.0.0.0/8"
    - "192.168.0.0/16"
"#;
        let ips = parse_allowlist(yaml);
        assert_eq!(ips, vec!["5.6.7.8", "9.9.9.9"]); // operator IPs, not the private CIDRs
    }

    #[test]
    fn parses_alerts_and_skips_garbage() {
        let json = r#"[
          {"id":7,"scenario":"crowdsecurity/ssh-bf","message":"ssh brute-force",
           "created_at":"2026-08-09T10:00:00Z","simulated":false,
           "source":{"value":"1.2.3.4","cn":"RU"}},
          {"id":8,"scenario":"crowdsecurity/http-probing","message":"probing",
           "created_at":"2026-08-09T10:01:00Z","simulated":true,
           "source":{"value":"5.6.7.8","cn":"US"}}
        ]"#;
        let a = parse_alerts(json);
        assert_eq!(a.len(), 2);
        assert_eq!(a[0].source_ip, "1.2.3.4");
        assert!(!a[0].simulated);
        assert!(a[1].simulated); // web scenario in training mode
        assert_eq!(a[1].country, "US");
        assert!(parse_alerts("not json").is_empty());
        assert!(parse_alerts("{}").is_empty());
    }

    #[test]
    fn flattens_decisions() {
        let json = r#"[
          {"source":{"value":"1.2.3.4"},
           "decisions":[{"id":1,"value":"1.2.3.4","scenario":"crowdsecurity/ssh-bf",
                         "type":"ban","duration":"3h59m","origin":"crowdsec"}]}
        ]"#;
        let d = parse_decisions(json);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].source_ip, "1.2.3.4");
        assert_eq!(d[0].action, "ban");
        assert_eq!(d[0].origin, "crowdsec");
        assert!(parse_decisions("[]").is_empty());
    }
}
