# Test script — one login on Windows, Mac, and iPhone (v0.1.48)

The login is now the same everywhere: **server address + master password** (+ your 6-digit
code if 2-step sign-in is on). This script assumes you already ran the v0.1.47 setup once
(server redeployed, signed in on Windows). Total time: ~15 minutes.

## Phase 1 — Windows: update + turn on the new sign-in (one time)

1. Open NorthKey, accept the update to **v0.1.48**.
2. Account & Sync → **Advanced — server management** → **Update server to the latest version**.
   Wait ~1 minute (it pulls the new image and health-checks it).
3. Account & Sync → **Advanced — recovery kit & restore options** → **Turn on master-password
   sign-in** → type your master password → **Turn on**. You should see *"Master-password
   sign-in is ON"*.
4. Note the line on the account card: *"To sign in on another device: server address `x.x.x.x`
   · identity code `XXXX-XXXX-XXXX-XXXX` + your master password."* That's everything another
   device needs.

## Phase 2 — Mac: the new login

1. Update NorthKey to **v0.1.48** (restart the app; Settings → Updates if it doesn't prompt).
2. If the Mac is already signed in from yesterday, click **Sign out** first so you can see the
   new flow (your vault stays put).
3. Account & Sync → **Sign in to your NorthKey server**: type the server address from Phase 1
   step 4 → **Connect**.
4. It shows the server's **identity code** — check it matches what Windows shows → **Trust
   this server**.
5. Type your **master password** (and the 6-digit code if asked) → **Sign in**. Your vault
   appears. That's the entire login.

## Phase 3 — iPhone: same login

Rebuild once (Terminal on the Mac, one line at a time):

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

Press **⌘U** (crypto self-tests must pass), then Run to your iPhone.

Then EITHER scan the QR (Account & Sync → Add a device on any computer) OR tap **"No camera
handy? Type the server address instead"** and do exactly what the Mac did: address → compare
identity code → master password (+ code) → vault. Both paths are the same login.

## If something doesn't work

- **"Master-password sign-in isn't turned on yet"** — do Phase 1 step 3 on Windows.
- **"That server didn't identify itself / may be too old"** — do Phase 1 step 2 (Update
  server), then try again.
- **Identity codes don't match** — stop; don't trust. Re-check you typed the right address
  (matching codes = you're talking to YOUR server).
- **Wrong master password** — it's the one that unlocks NorthKey on Windows.
- **6-digit code rejected repeatedly** — after 5 misses it locks for 15 minutes; wait and retry.
