# macOS code signing + notarization

NorthKey's release workflow already builds a universal macOS `.dmg`/`.app`, and the app config is
wired for **Developer ID signing + notarization** (`apps/desktop/src-tauri/tauri.conf.json`
`bundle.macOS` + `entitlements.plist`). Signing stays **off until you add the Apple secrets below** —
until then the workflow builds an *unsigned* macOS app exactly as before (users must right-click →
Open to get past Gatekeeper). Once the secrets are present, `tauri-action` signs with your Developer
ID certificate, hardens the runtime, and submits the app to Apple's notary service automatically.

You need an **Apple Developer Program** membership ($99/yr). Do this once.

## 1. Create a "Developer ID Application" certificate

1. In Xcode → **Settings → Accounts**, add your Apple ID, select your team, **Manage Certificates → +
   → Developer ID Application**. (Or create it at
   [developer.apple.com/account → Certificates](https://developer.apple.com/account/resources/certificates/list).)
2. In **Keychain Access**, find the new *Developer ID Application: Your Name (TEAMID)* certificate,
   right-click → **Export** → save a `.p12` and set a strong password.
3. Base64-encode the `.p12` for GitHub:
   ```bash
   base64 -i Certificates.p12 | pbcopy   # now on your clipboard
   ```
4. Note the **exact signing identity string** — it looks like
   `Developer ID Application: Your Name (TEAMID)`:
   ```bash
   security find-identity -v -p codesigning
   ```

## 2. Notarization credential — already done if TestFlight is set up

If the `APPSTORE_API_KEY_ID` / `APPSTORE_API_ISSUER_ID` / `APPSTORE_API_PRIVATE_KEY` secrets
exist (the iOS TestFlight setup adds them — see `docs/ios-testflight.md`), the release workflow
notarizes the Mac app with that same App Store Connect API key. **Nothing more to create.**

Only if those don't exist: generate an app-specific password at
[appleid.apple.com](https://appleid.apple.com) → Sign-In and Security → App-Specific Passwords,
and add it as `APPLE_PASSWORD` plus your Apple ID email as `APPLE_ID`.

## 3. Add the GitHub Actions secrets

Repo → **Settings → Secrets and variables → Actions → New repository secret**. Add these **exact
names** (the release workflow already reads them; blank ⇒ unsigned build):

| Secret name | Value |
|---|---|
| `APPLE_CERTIFICATE` | the base64 of your `.p12` (step 1.3) |
| `APPLE_CERTIFICATE_PASSWORD` | the `.p12` export password (step 1.2) |
| `APPLE_SIGNING_IDENTITY` | `Developer ID Application: Your Name (TEAMID)` (step 1.4) |

`APPLE_TEAM_ID` and the `APPSTORE_*` notarization key are already in place from the TestFlight
setup — reused automatically.

## 4. Cut a release and verify

Run the release (dispatch `release.yml`, or push a `vX.Y.Z` tag). On the resulting `.dmg`/`.app`:

```bash
spctl -a -vv -t install NorthKey.app     # → "accepted, source=Notarized Developer ID"
codesign -dv --verbose=4 NorthKey.app    # → Authority: Developer ID Application: …
```

A signed + notarized app opens with a normal double-click — no right-click→Open, no "unidentified
developer" warning. The Tauri **updater** signs the `.app.tar.gz` with the separate minisign key
(already configured), and because signing runs before the updater artifact is packed, self-updates
install a properly notarized app too.

> The same Apple Developer account, Team ID, and notarization credentials are reused when the iOS
> app ships — nothing here is throwaway.
