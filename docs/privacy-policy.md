# SENTINEL browser extension — Privacy Policy

_Last updated: 2026-07-19_

The SENTINEL browser extension is designed so that **your data never leaves your device**.

## What the extension does

The extension lets you fill logins saved in the SENTINEL desktop app into web pages. It communicates
**only** with the SENTINEL app running locally on your computer, using Chrome's native-messaging API.
It does not have its own server and makes no network requests to us or any third party.

## Data collection

**We collect nothing.** The extension:

- does **not** send your passwords, usernames, TOTP codes, browsing history, or any other data to any
  remote server;
- does **not** contain analytics, tracking, or advertising;
- stores only a small amount of local UI state (such as whether the vault is currently locked).

## How your credentials are handled

- Credentials live in the SENTINEL desktop app's encrypted vault, never in the extension.
- When you choose to fill a login, the app releases **only** the credentials saved for the site you
  are on (origin-matched), and **only** while the vault is unlocked.
- While the vault is locked, every request returns "locked" with no data.

## Permissions

- **nativeMessaging** — to talk to the local SENTINEL app.
- **activeTab**, **clipboardWrite** — to fill or copy a credential into the page you're on.
- **host access** — so autofill can be offered on any site; a site only ever receives credentials you
  explicitly saved for it.

## Contact

Questions: open an issue at the project repository.
