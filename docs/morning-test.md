# Test script — the v0.1.54 quality-of-life build

This release is about making NorthKey easier to get into: a **Getting started checklist**, clearer
messages when something goes wrong, a friendlier empty vault, a working monthly report, and the
iPhone app now runs **full-screen on iPad**.

Total time: ~15 minutes. Do the steps in order. One terminal command per line — copy one line at a
time.

## Phase 1 — Windows (or Mac): the setup checklist

1. Open NorthKey and accept the update to **v0.1.54** (or Settings → Updates → check).
2. Look at the left sidebar — there's a new **Get started** item near the top with a small counter
   (like `1/2`). Click it.
3. You'll see two sections: **Essentials** (protect your vault, add your first login) and
   **Power-ups** (sync, add a device, autofill, VPN, servers). Each has a **one-click button** on the
   right that jumps straight to that setup.
4. Click **Add a login** on the checklist → save a quick test login → come back to **Get started**.
   That row should now show a green **done**, and the sidebar counter should tick up.
5. Once both essentials are done, the **Get started** item disappears from the sidebar on its own.
   (You can still reach it from the command palette — press **Ctrl-K**, type "getting started".)

## Phase 2 — Clearer feedback

1. Go to **Vault**. If your vault were empty you'd now see an **“Add your first login”** button in the
   middle instead of “select an item.”
2. Go to **VPN**. If WireGuard isn't installed or the app isn't running as administrator, pressing
   **Connect** now shows a small message explaining why (before, it did nothing). If your VPN is set
   up, connect as usual — that still works.
3. Press **Ctrl-K** → type "report" → open **Monthly report**. Use the **‹ ›** arrows to change month,
   then click **Export PNG** — it should save an image of the report to your Downloads.

## Phase 3 — Mac: same checklist

1. Update the Mac app to **v0.1.54** (it's signed, so it opens without the “unidentified developer”
   warning).
2. Confirm the **Get started** checklist looks and behaves the same as on Windows.

## Phase 4 — iPad: the app is now full-screen

If you use TestFlight, update to the newest build and skip the rebuild. Otherwise rebuild once on the
Mac (one line at a time):

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

Then in Xcode: press **⌘U** first (the crypto self-tests must pass), then pick an **iPad** simulator
(or your real iPad) at the top and press **▶**. When it opens:

1. The app fills the whole iPad screen — no more little phone-sized window in the middle.
2. Rotate the iPad to **landscape**; the app should rotate and stay full-screen.
3. On the **Vault** tab you should see the list on the left and the selected item's details on the
   right, side by side (on iPhone it stays a single column that pushes to the detail — unchanged).

## Honest notes

- The checklist reads what's already set up on this device; on a brand-new install everything except
  “add your first login” will start unchecked, which is expected.
- The iPad layout is a first pass — the Servers and Transfers tabs center their content so cards
  don't stretch, and the Vault is a proper split view. If anything looks off in landscape, note it and
  we'll refine.
