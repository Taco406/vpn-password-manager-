# Test script — the v0.1.61 monitoring build

This release turns the server dashboard into a full monitoring station: **every Docker
container on your servers gets its own live row**, a **searchable browser over every metric
Netdata measures**, **Disks / Network interfaces / Services** shortcuts, and a **Recent
alerts** feed. It also carries the fix that finally lets the **Hetzner server reach your
phone**, and phone builds upload to TestFlight again.

Total time: ~15 minutes. Do the steps in order. One terminal command per line — copy one
line at a time.

## Phase 1 — Windows: get on 0.1.61

1. Open NorthKey. If it offers **0.1.61**, accept it. If it doesn't, download the
   `NorthKey_0.1.61_x64-setup.exe` from the newest GitHub release and run it — it installs
   over the old one, no admin prompt.
2. Check the version badge in Settings says **0.1.61**.

## Phase 2 — Windows: the new monitoring

1. Go to **Servers** and open your `serverdedi` (Hetzner) box's dashboard — the one with
   the tiles and charts.
2. First check from last night's fix: the **Network (in · out)** and **Disk I/O** charts
   should be drawing lines now, not stuck on "waiting for data…".
3. Scroll below the alarms line. You should see **Containers (N)** — one row per Docker
   container running on that server (your Coolify apps each get a row). Each row shows
   live CPU% and memory.
4. Click a container row — it expands into full CPU and Memory charts.
5. Below that: **Disks**, **Network interfaces**, and **Services** — click one open, pick
   an item from the list, and a live chart appears.
6. Below that: **All charts (hundreds)**. Click it open and type `docker` in the search
   box, then click any result — it renders live. Try `postgres` or an app name too.
7. If any alarm fired in the last day you'll also see **Recent alerts (N in 24h)** — it
   lists what fired AND what cleared, with times.
8. Do the same quick check on the **Linode** server's dashboard — the sync server runs in
   Docker, so it should show containers too.

## Phase 3 — iPhone: 1.61 from TestFlight

1. Open **TestFlight** on the phone. You should see NorthKey **0.1.61** (or at least
   0.1.60 — both are newer than the 0.1.57 you've been stuck on). Install the newest.
2. Open NorthKey → **Servers**. THE BIG CHECK: after the sync fix, **both** servers —
   Linode and Hetzner — should be listed. If Hetzner is still missing: on the computer go
   to Settings → Hetzner Cloud, press **Save** again, then on the phone pull down to
   refresh. Tell me either way — this is the fix I most need confirmed.
3. Tap a server → the dashboard. Scroll down: **Containers** rows with live CPU/memory,
   tap one to expand its charts.
4. Below it, tap **All charts** → a searchable list of every metric. Search `docker`,
   tap one, watch it draw.

## If something's off

- Phone still shows only Linode after step 3.2 → tell me, and note whether the phone's
  version says 0.1.61 or something older.
- A dashboard section is missing on one device but present on the other → tell me which
  device and which section; that's a data-path issue, not a build issue.
- TestFlight doesn't show 0.1.60/0.1.61 at all → tell me; that's an upload/processing
  problem on my side, not something you did.
