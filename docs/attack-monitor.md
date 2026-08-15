# NorthKey Attack Monitor — plan (CrowdSec-based fleet IDS)

Turn NorthKey into a **monitoring + control plane** for detecting and blocking attacks on the
user's own servers (Hetzner `coolify`/`serverdedi`, Linode `JB-Web-Server`, and any future box),
with alerts, attacker intel, a **tiered temp → perm ban** ladder, and a **honeypot** — engineered
so it **never bans real visitors or clients' websites**.

This is a defensive-security feature protecting the user's own infrastructure. It is built and
shipped autonomously across four phases (A–D); each phase merges to `main`. A single build ships
at the end.

## Locked decisions (from the user)

- **Engine: CrowdSec.** Chosen because it cleanly *separates detection from remediation* — every
  scenario can detect + alert while only a chosen subset actually bans.
- **Enforced from day one:** SSH brute-force + honeypot (near-zero false-positive surfaces).
- **Web-attack scenarios: training/simulation mode** — full detection + alerts, **zero bans** —
  until the user reviews real data and promotes scenarios one at a time.

## Architecture

```
 ┌─────────────┐   SSH (existing v0.1.64 channel)   ┌────────────────────────────┐
 │  NorthKey    │  ── cscli … -o json / deploy ──▶  │  Server (coolify, …)        │
 │  desktop     │                                   │   crowdsec  (agent + LAPI)  │
 │  (control    │  ◀── alerts / decisions (JSON) ── │   cs-firewall-bouncer       │
 │   plane)     │                                   │     └ nftables bans         │
 └─────────────┘                                   │   honeypot decoy listener   │
        │ encrypted settings item (synced)          └────────────────────────────┘
        ▼
   allowlist · which scenarios enforced · per-server protection flag
```

- **CrowdSec agent + `cs-firewall-bouncer` (nftables)** run on each protected server. The agent's
  Local API (LAPI) stays bound to localhost — **nothing new is exposed to the internet.**
- **NorthKey talks to it over the SSH channel we already ship** (`ssh_exec`, added in Phase A): it
  runs `cscli alerts list -o json`, `cscli decisions list -o json`, etc., parses, and surfaces it.
- **Deploy over SSH** for existing boxes; **cloud-init** for future NorthKey-provisioned nodes
  (Phase D).
- **Config/state** — the allowlist, which scenarios are enforced vs simulated, and the per-server
  protection flag — ride the **encrypted settings item** (synced across the user's devices), the
  same end-to-end-encrypted channel as the API tokens. The sync server only ever sees ciphertext.

## The safety contract — "don't ban real people / clients"

This is the primary design constraint, built in from Phase A:

1. **Web scenarios ship in `simulation` mode** (`cscli simulation enable …`) — they generate alerts
   but **never a ban decision** — until the user promotes them.
2. **Allowlist that is never banned** (`/etc/crowdsec/parsers/s02-enrich/whitelists.yaml`):
   the user's own IPs, known client IPs, uptime monitors, Cloudflare/CDN ranges, and RFC-1918
   private ranges. The user's **current public IP is auto-added at deploy time.**
3. **SSH-lockout prevention:** the user's IP is in the allowlist **before** the SSH jail can act,
   and the Linode/Hetzner web console (which bypasses the host firewall) is the documented backstop.
4. **Permanent bans require explicit in-app confirmation.** Auto-escalation to a very long ban only
   happens above a high sustained-abuse bar; true "permanent" is always a human decision.
5. **One-tap unban** is always available.
6. **The deploy is idempotent and conservative** — it adds only CrowdSec's own nftables chain and
   never edits existing web services, existing firewall rules, or SSH config.

## Cross-component contracts touched (change both sides or neither)

- New desktop bridge commands (`crowdsec_*`) — interop-check guards names (both bridge sides ↔
  `main.rs` registrations).
- New settings-item fields (`SET_CROWDSEC_ALLOWLIST`, `SET_CROWDSEC_ENFORCED`, protection flags) —
  additive, phone ignores unknown fields (same rule as every shipped settings field).
- Server-side install script is byte-reviewed like `cloudinit.rs`; a golden test asserts it stays
  idempotent + simulation-on-for-web.

---

## Phase A — Foundation: deploy + read + display

**Server side** — `crates/core/src/provision/crowdsec.rs`: a `render_install_script()` producing an
idempotent bash script that:
- adds the CrowdSec APT repo and installs `crowdsec` + `crowdsec-firewall-bouncer-nftables`;
- installs collections: `crowdsecurity/sshd`, `crowdsecurity/linux`, `crowdsecurity/base-http-scenarios`,
  `crowdsecurity/http-cve`, and (best-effort, if the log path exists) `crowdsecurity/nginx` /
  `crowdsecurity/apache2`;
- writes the **whitelist** file seeded with private ranges + the caller's public IP;
- puts **all web/http scenarios into `simulation`**, leaving `sshd` enforcing;
- sets up the **honeypot**: a decoy listener on an unused port (e.g. `2222`) whose connections are
  logged to a file that a small custom acquis + scenario turns into an instant high-confidence
  decision;
- enables + starts `crowdsec` and `crowdsec-firewall-bouncer`;
- is safe to re-run (checks before each mutation).

**Desktop backend**
- `ssh.rs`: **`ssh_exec(host, command) → { stdout, stderr, code }`** — non-interactive channel exec
  (reuses the keychain key + host-key pin). The foundational primitive for everything here.
- `crowdsec.rs` module + commands:
  - `crowdsec_deploy(provider, id)` — SSH in, upload + run the install script, return a transcript.
  - `crowdsec_status(provider, id)` — `systemctl is-active` + `cscli metrics` summary.
  - `crowdsec_alerts(provider, id)` — `cscli alerts list -o json` → typed structs.
  - `crowdsec_decisions(provider, id)` — `cscli decisions list -o json` → typed structs.
- Per-server `protected` flag in `servers-config.json`, synced.

**Frontend** — a **Security** section in the server side-panel: deploy button + status; a live list
of recent alerts (IP · scenario · time · **simulated** vs **enforced**); active bans. High-severity
alerts feed the existing Servers alert feed.

**Guards/tests** — interop-check picks up the new commands; core unit-tests the `cscli` JSON parsers
against captured fixtures; a golden test asserts the install script keeps web in simulation.

## Phase B — Control & tiers

- **Tiered ban ladder** via CrowdSec `profiles.yaml`: escalating durations (e.g. 1st 4h → repeat 24h
  → persistent 1w), plus a `manual`/perm decision type. NorthKey renders the ladder and edits durations.
- **Actions:** one-tap ban (manual decision), unban (`cscli decisions delete`), **promote** a training
  scenario → enforce (`cscli simulation disable <scenario>`), **demote** (re-enable simulation).
- **Allowlist management UI** (add/remove IPs + CIDRs), synced across devices, pushed to each server's
  whitelist on change.
- **Permanent ban = explicit confirmation dialog**; sustained-abuse auto-perm only above a high bar.

## Phase C — Intel & alerts

- **Attacker cards:** geo + rDNS (reuse the app's existing IP-geo/rDNS tools), first/last seen, hit
  count, scenarios tripped.
- **Notifications:** desktop toast + phone push for high-severity alerts and new perm-ban candidates;
  a weekly security digest.
- **Optional:** CrowdSec community blocklist (CAPI) in **observe-only** — show what it *would* block.

## Phase D — iPhone parity + docs + cloud-init

- **iOS Security tab** — the phone can't SSH, so it reads the **synced** security summary + alert feed
  (read-only) and can **approve/deny perm-ban requests**, which the desktop applies on next sync.
- **cloud-init:** bake CrowdSec into new NorthKey-provisioned nodes (`cloudinit.rs`).
- **Docs:** a user click-path (this file's "How to use" section) + a `morning-test.md`-style script.
- **Final build** ships here.

## Rollout order + who tests what

Deploy first to a **non-client box** (`serverdedi` or a throwaway) to build confidence, then
`coolify`. Web stays in simulation on every box until the user has reviewed a week of real alerts.

---

## How to use it (click-path)

Everything lives under a server's **Security** tab (Servers → click a server → **Security**).

1. **Set up SSH first.** The monitor deploys over SSH, so the server must already trust
   NorthKey's key: server → **Access** → **Set up access**, paste the one line onto the box.
   (One key covers all your computers — v0.1.65.)
2. **Protect the server.** Security tab → **Protect this server**. It installs CrowdSec + a
   firewall bouncer over SSH (a couple of minutes). Your current IP is added to the never-ban
   allowlist automatically, so the SSH block can't lock you out.
3. **Watch, don't block (for the web).** SSH brute-force and the honeypot are enforced from the
   start. Every web/http rule is in **training** — it logs attacks but blocks nothing. Leave it
   like that for a week and read the **Top attackers** + **Recent detections**.
4. **Promote when you trust it.** Security tab → **Detection rules** → a training rule →
   **enforce** (it warns you and reminds you to check the allowlist). Demote any time.
5. **Manual control.** Block an IP yourself (4 h or permanent — permanent asks to confirm), and
   **unban** with one tap. Manage the **allowlist** (your IP, clients, uptime monitors) — the
   private ranges are always kept.
6. **Alerts while the app is closed** (optional). Servers screen → Watchdog card → turn on
   **“Alert me about attacks.”** It checks each protected server for new blocks in the background
   (this makes a background SSH connection per server) and toasts you.

**Order:** protect `serverdedi` first, watch it, then `coolify`. Never promote a web rule the
same day you protect a busy client site — give it real traffic to prove it's clean.

## Incident log — the port-8080 collision (2026-08-15)

The first fleet deploy surfaced a serious latent bug: CrowdSec's Local API defaults to
`127.0.0.1:8080`, Coolify's Traefik proxy publishes `0.0.0.0:8080`, and crowdsec (systemd)
starts before Docker after a reboot — so on the first reboot after protecting a Coolify
server, crowdsec won the port, `coolify-proxy` exited with code 128, and **every hosted
site went dark** until the LAPI was moved to 8081. Fixed in v0.1.70 at three layers, per
the field-verified write-up:
1. **Prevention** — the installer moves the LAPI to the first free port ≥8081 (checking
   both live listeners and Docker port mappings, since a stopped container still owns its
   mapping) before anything restarts.
2. **Heal** — the same installer step runs on "Re-run setup", so already-protected servers
   get the port move + their blocked proxy started (only `coolify-proxy`, by name — never a
   blanket `docker start`).
3. **Self-heal** — a systemd oneshot + timer (`coolify-proxy-selfheal`) on every protected
   server: ~90 s after each boot and every 5 min, it restarts a stopped proxy and applies
   the port move itself if crowdsec ever holds 8080 again. It never touches app containers
   or a running proxy.

Lesson recorded: a "localhost-only, no security impact" default can still be an
availability landmine — check the *port*, not just the bind address, before installing
anything next to a reverse proxy.

## Not yet (honest follow-ups)

- **iPhone parity.** The phone can't SSH, so a phone Security tab needs the desktop to sync a
  security summary through the encrypted vault and the phone to queue ban-approvals back. That's a
  new sync contract plus Swift that only compiles in the TestFlight job — deferred rather than
  shipped unverified.
- **cloud-init for new NorthKey nodes.** New VPN/sync nodes NorthKey provisions aren't
  auto-protected yet; protect them from the Security tab like any other box for now.
- **Weekly digest** and the **CrowdSec community blocklist** (observe-only) — planned, not built.
