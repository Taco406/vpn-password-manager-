# Real VPN — ephemeral Linode exit nodes (Stage 2)

By default SENTINEL's VPN screen runs a **simulation** (the pretty connect animation + a fake
throughput chart). This page turns on the **real** thing: pressing **Connect** spins up a
throwaway Linode server, brings up a WireGuard tunnel to it, routes all your traffic through it,
and **destroys the server on Disconnect**.

It is **opt-in** — nothing here happens until you paste a Linode API token. And it's
**experimental**: it works end-to-end on paper, but it hasn't been battle-tested on every
machine, so treat the first few connects as a test (watch your Linode billing page).

## What you need

1. **A Linode account + API token.**
   - Sign up at [linode.com](https://www.linode.com/) (Akamai). Add a payment method.
   - Create a **Personal Access Token**: Linode Cloud Manager → your profile → **API Tokens** →
     **Create a Personal Access Token**. Give it **Read/Write** on **Linodes** (that's all it
     needs). Copy the token.
   - Cost: a Nanode is **~$0.0075/hour** (~1¢/hr). You're only billed while a node exists, and
     SENTINEL destroys it on disconnect. A safety **dead-man switch** also powers the node off if
     it sees no tunnel handshake for 15 minutes, and an **orphan-sweep** runs every launch to reap
     any node a crash left behind — so a bug can't quietly run up a bill.

2. **WireGuard for Windows**, installed from [wireguard.com/install](https://www.wireguard.com/install/).
   SENTINEL brings the tunnel up *through* it.

3. **Run SENTINEL as administrator.** Creating a VPN tunnel is a privileged operation; without
   elevation, Connect will fail with a permissions error. (Right-click SENTINEL → *Run as
   administrator*, or set that in the shortcut's Properties → Compatibility.)

## Turn it on

1. Open **Settings → Real VPN (Linode)**.
2. Paste your API token and click **Save**. The badge flips to **On · real exit nodes**.
3. Go to the **VPN** screen, pick a region, and **Connect**. You'll see the real state sequence
   (provisioning → booting → exchanging keys → tunnel up), then a live throughput chart from the
   real tunnel and a running cost estimate.
4. **Disconnect** tears the tunnel down and destroys the Linode.

To go back to the simulation, clear the token (Settings → Real VPN → blank → Save).

## Verify it's actually working (do this the first time)

- After Connect, check your public IP (e.g. open [ifconfig.me](https://ifconfig.me)) — it should
  be the exit node's IP, not your home IP.
- After Disconnect, open the [Linode Cloud Manager](https://cloud.linode.com/linodes) and confirm
  the `sentinel-*` Linode is **gone**. (It should be — but verify while you're getting comfortable.)

## How it works (the short version)

- On Connect, SENTINEL creates a Linode tagged `sentinel-ephemeral`, handing it a hardened
  cloud-init that installs WireGuard, locks the firewall down to just the WireGuard port + a
  one-time key-exchange port, **disables SSH entirely**, and arms the dead-man switch.
- The node runs the WireGuard server key SENTINEL generated for it (the private key is delivered
  only inside the node's cloud-init), so the app already knows the exact key to pin — no key is
  ever trusted from the network. The node's one-shot callback, **authenticated by an HMAC**, is
  used only as a "finished booting" signal before the tunnel is brought up.
- SENTINEL then brings up the local WireGuard tunnel (full-tunnel: all traffic + DNS via the node)
  and only reports **Connected** once a real handshake lands.
- On Disconnect (or on any failure at all), the tunnel comes down and the Linode is deleted.

## VPN depth (experimental): kill switch, auto-connect, live latency

These three extras are **opt-in** and only do anything in real-VPN (Linode) mode. They're
**Windows-first**; on macOS/Linux they're safe no-ops.

### Kill switch (Windows)

Turn it on with **Settings → Security → "Kill switch on by default"**. When it's on, pressing
**Connect** adds Windows Firewall rules — all tagged with the name/group `SENTINEL-KillSwitch` —
that block outbound traffic except the WireGuard tunnel, loopback, and your local subnet. If the
tunnel drops, traffic is blocked rather than leaking to your normal connection.

**Safety — it can never strand you offline.** The rules are removed on Disconnect, on any connect
failure, unconditionally on every launch (so a crash while connected self-heals next start), and
on app exit. There's also a manual panic button: **Settings → Auto-connect & kill switch → "Clear
kill-switch rules"**.

As a last resort you can remove the rules yourself from an **Administrator** terminal:

```
netsh advfirewall firewall delete rule name="SENTINEL-KillSwitch"
```

(Every rule shares that name, so this one command removes them all. Equivalently, from an admin
PowerShell: `Remove-NetFirewallRule -Group "SENTINEL-KillSwitch"`.)

### Auto-connect on untrusted Wi-Fi

In **Settings → Auto-connect & kill switch**, toggle **Auto-connect on untrusted Wi-Fi** and build
a **trusted-networks** list (your home/office SSIDs; "Trust current" adds the one you're on). While
on, SENTINEL checks your Wi-Fi every ~30s and, if you join a network that *isn't* on the trusted
list and you're not already connected, it spins up the tunnel to your **default region**. It never
auto-connects on a trusted network, and it waits a few minutes after a manual Disconnect so it
won't fight you.

### Live region latency

The region picker now measures a best-effort round-trip (a quick TCP connect to a per-region
Linode speedtest host, ~1s timeout, all regions probed in parallel) and shows it as `latencyMs`.
If a probe fails it's simply omitted — the list never blocks or hangs on it.

## Node management: power off vs destroy, and the fleet (experimental)

By default a Connect creates a throwaway node and Disconnect **destroys** it — you pay only while
connected. If you'd rather keep a node around (same IP, instant restart), **Settings → VPN exit
nodes** lets you manage the fleet:

- **Stop** — powers a node **off** but keeps it. ⚠️ **A stopped Linode still bills** (you pay for its
  disk until it's destroyed) — only **Destroy** stops the meter. The card shows a running
  **$/hour** total across all your nodes so there's no surprise.
- **Start / Reboot** — power a stopped node back on, or reboot a running one.
- **Destroy** — delete a node for good (stops its billing).
- **Destroy all nodes** — panic button: disconnect and delete everything, stopping all billing.

Kept nodes are recorded locally so the launch/pre-connect orphan-sweep won't reap them, and there's
a **cap of 5 kept nodes** so a bug can't quietly run up an unbounded bill. Only one tunnel is active
at a time; running traffic through several nodes at once (multi-hop) is a later addition.

## Multi-hop "bounce" (experimental)

**Settings → Multi-hop (bounce)** routes your traffic through **2–3 exit nodes in a row**
(entry → exit) instead of one. Your device holds a single WireGuard tunnel to the *entry* node;
each hop forwards to the next **server-side** (each runs a second WireGuard interface to the next
hop), and only the **last** node egresses to the internet. So no single server sees both your home
IP and your destination.

- Pick a region per hop (entry first, exit last), then **Connect**. It provisions one node per hop
  (a minute or two) and brings up the tunnel to the entry.
- **Cost is N× a single node** and latency compounds with each hop — the UI says so, and chains are
  capped at **3 hops**.
- **Disconnect destroys every hop.** If any step of building the chain fails, all nodes provisioned
  so far are destroyed automatically — a half-built chain never leaves paid servers running.
- Keys for the whole chain are generated on your device, so the app wires every hop without a
  network round-trip; the inter-hop links are authenticated by those keys.

This is the newest and least-exercised feature: the config generation is covered by tests, but the
live path (like the rest of the real VPN) hasn't been run against live Linode from CI — treat your
first bounce as a test and watch your Linode billing page.

## Known limitations (this is a first cut)

- **Windows-first.** The controller drives the official WireGuard app; macOS/Linux use `wg-quick`
  but are less exercised. The kill switch and SSID detection are Windows-only (no-ops elsewhere).
- The kill switch uses Windows Firewall rules; because it couldn't be exercised against a live
  Windows machine + Linode from the build environment, treat it as experimental — if you ever lose
  connectivity while connected, hit **Clear kill-switch rules** (or run the `netsh` command above).

### If your internet won't work after using the VPN

A WireGuard full-tunnel can, on an unclean teardown, leave routing/DNS behind that even a
`netsh int ip reset` + reboot won't clear. SENTINEL now scrubs these automatically on disconnect and
on launch, but if you're ever stuck:

1. **Settings → WireGuard → Restore internet** — removes any leftover tunnel, clears firewall rules,
   and deletes WireGuard's capture-all routes + its DNS policy. Just **relaunching SENTINEL** does the
   same scrub on startup.
2. **Last resort (removes a stuck adapter):** uninstall **WireGuard** (Windows Settings → Apps →
   Installed apps → WireGuard → Uninstall) and **reboot**. You can reinstall it afterward.
- Because this couldn't be tested against a live Linode from the build environment, **you are the
  first real-world test** — if a connect fails, the error message on the VPN screen says which
  stage failed; send it over and it's usually a quick fix.
