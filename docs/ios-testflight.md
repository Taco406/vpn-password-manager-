# iPhone updates via TestFlight (no Mac, no Xcode)

Once this one-time setup is done, updating NorthKey on your iPhone is: **open the TestFlight
app → tap Update.** Every published NorthKey release automatically builds and uploads the phone
app. Your Apple Developer membership (already paid) is the only requirement.

Everything below is done in a web browser — nothing touches Keychain Access, and no
certificates are exported. Signing happens in Apple's cloud from an API key.

## One-time setup (~10 minutes, all in the browser)

### A. Make the API key

1. Go to https://appstoreconnect.apple.com and sign in with your Apple ID.
2. Click **Users and Access** → the **Integrations** tab → **App Store Connect API** →
   **Team Keys**.
3. Click **+** (Generate API Key). Name: `NorthKey CI`. Access: **App Manager**. Click
   **Generate**.
4. On that page, note two values and download one file:
   - **Issuer ID** (long id at the top of the page)
   - **Key ID** (in the new key's row)
   - Click **Download API Key** — you get a file like `AuthKey_ABC123XYZ.p8`.
     **This is downloadable only once** — keep the file.

### B. Put the three values into GitHub (never into chat)

1. Go to the repo on GitHub → **Settings** → **Secrets and variables** → **Actions** →
   **New repository secret**, three times:
   - Name `APPSTORE_API_KEY_ID` — value: the Key ID
   - Name `APPSTORE_API_ISSUER_ID` — value: the Issuer ID
   - Name `APPSTORE_API_PRIVATE_KEY` — value: open the `.p8` file in a text editor and paste
     its entire contents (including the BEGIN/END lines)
2. Check `APPLE_TEAM_ID` is already there (it's part of the Mac-signing set). If not:
   https://developer.apple.com/account → **Membership details** → copy the 10-character
   **Team ID** and add it as a secret with that name.

### C. Register the app (one time)

1. Go to https://developer.apple.com/account → **Identifiers** → **+** → **App IDs** →
   **App** → Continue.
   - Description: `NorthKey`
   - Bundle ID: **Explicit** → `com.northkey.app`
   - Capabilities: tick **Push Notifications**
   - Continue → Register.
2. Go to https://appstoreconnect.apple.com → **My Apps** → **+** → **New App**:
   - Platform: **iOS**
   - Name: `NorthKey` (if taken, any name works — it's just the store label)
   - Language: English (U.S.), Bundle ID: pick `com.northkey.app`, SKU: `northkey`
   - Create.
3. Still in App Store Connect: your own Apple ID (under Users and Access) is automatically an
   internal tester once you add yourself to the app's **TestFlight → Internal Testing** group
   (App → TestFlight tab → Internal Testing → **+** → add yourself).

### D. First build

1. GitHub repo → **Actions** → **iOS TestFlight** → **Run workflow**.
2. Wait ~10 minutes (build + Apple's processing).
3. On your iPhone: install **TestFlight** from the App Store, open it, and NorthKey appears
   under your apps → **Install**.

## Every update after that

Nothing. Each published NorthKey release uploads a fresh phone build automatically; TestFlight
pops a notification on the phone and **Update** installs it. The Xcode/`git pull` path keeps
working if you ever want it, but you'll never need it.

## Troubleshooting

- **Workflow fails at "Check secrets"** — one of the four secrets is missing/misnamed; the
  error names which.
- **"No profiles / provisioning" errors** — usually the bundle ID step (C1) was skipped, or
  Push Notifications wasn't ticked on it.
- **Upload succeeds but no app in TestFlight** — Apple processes for ~5–15 minutes first;
  also check you completed C2 (the app record) and C3 (added yourself as internal tester).
- **App Store next**: this same setup is 90% of shipping to the real App Store — that adds
  screenshots, a privacy questionnaire, and Apple review on the same app record.
