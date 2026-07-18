//! Account identity: Google OAuth 2.0 with PKCE, plus TOTP helpers. This gates the
//! *account and sync only* (D16) — the vault and VPN work with no account at all.
//!
//! The OAuth flow uses the system browser and a loopback redirect (never an embedded
//! webview). Browser-open and token-exchange are traits so the flow is fully testable
//! and so the desktop can supply the real loopback listener.

pub mod google;

pub use google::{
    BrowserOpener, GoogleAuth, MockBrowserOpener, MockTokenExchanger, PkceParams, TokenExchanger,
    TokenSet,
};
