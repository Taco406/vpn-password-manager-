# Test script — the v0.1.53 “everything moves together” build

This release adds four things and brings the iPhone up to speed: a real server dashboard,
one-click Hetzner firewall, automatic sync (your servers just appear when you sign in), and
sending files between your devices. This is also the first **signed** Mac app.

Total time: ~20 minutes. Do the steps in order. One terminal command per line — copy one line
at a time.

## Phase 1 — Windows: update + see the new dashboard

1. Open NorthKey. Accept the update to **v0.1.53** (or Settings → Updates → check).
2. Go to **Servers**. Your Linode and Hetzner servers should already be listed.
3. On a server that runs monitoring, you should now see a **grid of tiles** — CPU, RAM, Swap,
   Disk, Load, CPU steal, processes, uptime, and three “pressure” tiles — plus live charts for
   Network and Disk I/O. (Numbers filling in over a few seconds is normal.)
4. If a Hetzner server shows *“Netdata unreachable”*, see Phase 4 (the firewall button).

## Phase 2 — Mac: sign in and watch your servers appear by themselves

1. Update the Mac app to **v0.1.53**. It should open **without** the “unidentified developer”
   warning now (it’s signed). If macOS still warns, right-click the app → **Open** once.
2. If the Mac is already signed in, click **Sign out** first (your vault stays put) so you can
   see the new flow.
3. **Account & Sync** → **Sign in to your NorthKey server** → type your server address →
   **Connect** → check the identity code matches Windows → **Trust this server** → master
   password → **Sign in**.
4. Now just **wait** on the **Servers** screen. Within about a minute your Linode **and Hetzner**
   servers should appear on their own — you should **not** need to press “Sync now”.
   - Before this release the Mac never showed the Hetzner box; that was the bug this fixes.
5. Go to **Devices** → the **Shared settings** panel. It should show *Linode*, *Hetzner*,
   *Google*, and *Netdata monitors* as **synced ✓**, with no token values shown.

## Phase 3 — Send a file between your computers

1. On Windows, go to **Transfers** → **Choose File** → pick a small file (a photo or PDF).
   Leave the recipient as **All my devices** → it says *“Sent …”*.
2. On the Mac, open **Transfers**. The file shows under **Incoming** → click **Save** → it lands
   in your Downloads.
3. Send one back from the Mac to confirm both directions.
   - Files are encrypted before they leave; the server holds only scrambled bytes for 24 hours.

## Phase 4 — Hetzner firewall (only if monitoring was blocked)

1. On the server that showed *“Netdata unreachable”*, look for the blue box **“Open port 19999
   on the Hetzner firewall.”**
2. Click it. Leave *restrict to my IP* **unchecked** (your home IP changes on Starlink).
3. It should say the port was opened and re-check; the dashboard tiles then fill in.
   - If you’d rather lock it down, tick *restrict to my IP* — but you’ll have to redo it whenever
     your home IP changes.

## Phase 5 — iPhone: rebuild, then the new tabs

If you use TestFlight, just update to the newest build and skip the rebuild. Otherwise rebuild
once on the Mac (one line at a time):

```bash
cd ~/vpn-password-manager-
```
```bash
git pull
```
```bash
cd apps/ios-key
```
```bash
xcodegen generate
```
```bash
open NorthKey.xcodeproj
```

Then in Xcode: press **⌘U** first (the crypto self-tests must pass — that’s the compatibility
gate), then pick your iPhone at the top and press **▶**. When the app opens:

1. Unlock with your master password. You now have three tabs at the bottom: **Vault**,
   **Servers**, **Transfers**.
2. **Servers**: your Linode/Hetzner servers appear, with live CPU/RAM/Disk/Load tiles for any
   server whose monitoring is reachable.
3. **Transfers**: you should see the file you sent earlier under **Incoming** → tap **Save** to
   keep it. Tap **Choose a file** to send one back to your computers.

## Honest notes

- The phone reads monitoring directly from your servers using the tokens that rode your encrypted
  vault — the sync server never sees them. If a server’s monitoring needs a username/password
  (rare), the phone skips it; set those up from the computer.
- The dashboard tiles each load independently: if one shows **—**, that single metric isn’t
  available on that server, and the rest still work.
- Transfers are capped at **25 MB** per file and auto-expire after 24 hours.
