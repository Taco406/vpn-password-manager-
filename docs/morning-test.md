# Morning test — one login on Windows, Mac, and iPhone (v0.1.47)

The goal you asked for: **set up on the desktop, sign in on the Mac and iPhone, and the same
vault appears — one login (sign in + master password), no scattered settings.** This is the
click-by-click script. Expected total time: ~25 minutes, most of it the one-time server redeploy
and the Xcode build.

> **Why there's a one-time redeploy:** your current sync server was deployed before servers could
> update themselves. v0.1.47 servers self-update (daily, plus an "Update server to the latest
> version" button), but the running one predates that, so this morning you redeploy it once. Your
> vault is safe — it lives on your Windows machine and re-uploads automatically after sign-in.

---

## Phase 1 — Windows (your original machine): update + redeploy the server

1. Open NorthKey. Accept the update to **v0.1.47** (or Settings → Updates → check now).
2. Go to **Account & Sync**.
3. Open **Advanced — server management & attack monitor** → **Destroy sync server (stop
   billing)** → confirm. (Your local vault is untouched.)
4. The main card now shows the deploy form. Pick your region → **Deploy**. Wait ~2–3 minutes
   until it reports the server is up.
5. Click **Sign in with Google**. When it completes, your vault pushes to the fresh server
   automatically — the status line should say you're signed in.
6. Open **Advanced — recovery kit & restore options** → **Enable master-password unlock**.
   You should see *"Master-password unlock enabled and vault pushed (version N)"*.
   This is the step that lets every other device use just your master password.

That's the whole Windows part. Everything below is "sign in + master password."

## Phase 2 — Mac: join with a code + master password

1. Update/install NorthKey **v0.1.47** on the Mac.
2. On **Windows**: Account & Sync → **Add a device** → copy the **text code** (it expires in
   ~5 minutes — mint a fresh one if you dawdle).
3. On the **Mac**: Account & Sync → **Join with a device code** → paste → connect. The card
   should flip to **Connected**.
4. Still on the Mac: **Unlock this device with your master password** → type your master
   password → **Unlock**. It should report *"pulled N items"* — reopen the vault and your
   passwords are there.
5. Two-way check: add or edit an item on the Mac, click **Sync now**, then on Windows click
   **Sync now** — the change appears.

## Phase 3 — iPhone: build once, then scan + master password

Build (one-time, ~10 min):

1. On the Mac, in Terminal:
   ```bash
   cd <repo> && git pull
   brew install xcodegen
   cd apps/ios-key && xcodegen generate && open NorthKey.xcodeproj
   ```
2. In Xcode: click the **NorthKey** project → Signing & Capabilities → pick your **Team**
   (your free Apple ID works; builds last 7 days before needing a re-run).
3. Optional but recommended: press **⌘U** — the crypto self-tests must pass (they prove the
   phone decrypts exactly what the desktop encrypts; the simulator is fine for this).
4. Plug in your iPhone, select it as the run target, press **Run**. On the phone, trust the
   developer profile if asked (Settings → General → VPN & Device Management).

Connect (the part that used to be impossible — the desktop now shows the QR):

5. On **Windows or Mac**: Account & Sync → **Add a device** — a **QR code** is displayed next
   to the text code.
6. On the iPhone: point the camera view at the QR. It connects, pins the server's certificate,
   and enrolls — no tokens to type.
7. Enter your **master password** → your vault list appears.
8. Optional: menu (⋯) → **Unlock with Face ID next time**.
9. Round-trip check: tap **+** on the phone, add a login, save. On the desktop click
   **Sync now** — the phone's item appears. Edit it on the desktop, Sync now, then pull down
   to refresh on the phone — the edit comes back.

---

## If something doesn't work

- **"That QR isn't a NorthKey device code" / enroll fails** — codes expire after ~5 minutes and
  are single-use. Click **Add a device** again for a fresh one.
- **Phone says "no master-password unlock set up yet"** — redo Phase 1 step 6 on Windows
  (Enable master-password unlock), then unlock on the phone again.
- **"Wrong master password"** — it's the master password you set on Windows (the one that
  unlocks the app there), not your Google password.
- **Mac join says the code is stale** — codes are minted against the *new* server; make sure
  Windows finished Phase 1 (signed in to the redeployed server) before minting.
- **Server deploy stuck** — Account & Sync shows the server state; the Servers screen has
  console access. Destroy + Deploy again is always safe: your vault re-uploads on sign-in.
- Going forward you never redeploy for updates again: the new server checks for updates daily,
  and **Update server to the latest version** (Advanced) applies one immediately.
