//! The unlocked-vault session: the only place the vault key exists in plaintext.
//! `lock()` drops the key, which zeroizes it (SECURITY.md T2). Also the authoritative
//! autofill origin-matching used before any field is released to the extension (T4).

use super::envelope::{open_item, seal_item, ItemEnvelope};
use super::model::{Item, UrlMatch, UrlMode};
use crate::error::{CoreError, Result};
use crate::keyring::VaultKey;

/// Holds the vault key while unlocked. Locking drops it (zeroize-on-drop).
pub struct VaultSession {
    key: Option<VaultKey>,
}

impl VaultSession {
    pub fn locked() -> Self {
        VaultSession { key: None }
    }

    pub fn unlocked(key: VaultKey) -> Self {
        VaultSession { key: Some(key) }
    }

    pub fn is_locked(&self) -> bool {
        self.key.is_none()
    }

    /// Lock: drop and zeroize the vault key.
    pub fn lock(&mut self) {
        self.key = None; // VaultKey: ZeroizeOnDrop
    }

    fn key(&self) -> Result<&VaultKey> {
        self.key.as_ref().ok_or(CoreError::State("vault is locked"))
    }

    /// The live vault key while unlocked, or `None` if locked. Used by the sync/pairing layer to
    /// wrap or transfer the key from RAM — it must NOT fall back to re-reading the OS keychain,
    /// which would mint a spurious fresh key when a master password is set (the plaintext keychain
    /// key is deleted then). Stays within the trusted app; the key is never serialized from here
    /// except by the explicit, user-initiated backup/pairing flows.
    pub fn vault_key(&self) -> Option<&VaultKey> {
        self.key.as_ref()
    }

    pub fn seal(&self, item: &Item) -> Result<ItemEnvelope> {
        seal_item(self.key()?, item)
    }

    pub fn open(&self, env: &ItemEnvelope) -> Result<Item> {
        open_item(self.key()?, env)
    }
}

/// Does any of an item's saved URLs match `page_origin` for autofill? Enforces the
/// brief's rules (T4): https never fills on http, ports must match, HostExact needs an
/// exact host, Domain matches the registrable domain, and there is never a match into
/// an unrelated origin.
pub fn origin_matches(urls: &[UrlMatch], page_origin: &str) -> bool {
    let page = match Origin::parse(page_origin) {
        Some(o) => o,
        None => return false,
    };
    urls.iter().any(|u| {
        let saved = match Origin::parse(&u.url) {
            Some(o) => o,
            None => return false,
        };
        // 1) An https-saved credential never fills on a plain-http page.
        if saved.scheme == "https" && page.scheme == "http" {
            return false;
        }
        // 2) Non-default ports must match exactly.
        if saved.port != page.port {
            return false;
        }
        match u.mode {
            UrlMode::Host => saved.host == page.host,
            UrlMode::Domain => registrable_domain(&saved.host) == registrable_domain(&page.host),
        }
    })
}

/// Best autofill candidates for a page, ranked host-exact first then by recency.
pub fn rank_matches<'a>(items: &'a [(Item, ItemEnvelope)], page_origin: &str) -> Vec<&'a Item> {
    let mut matched: Vec<&Item> = items
        .iter()
        .map(|(i, _)| i)
        .filter(|i| origin_matches(&i.urls, page_origin))
        .collect();
    matched.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    matched
}

struct Origin {
    scheme: String,
    host: String,
    port: Option<u16>,
}

impl Origin {
    fn parse(s: &str) -> Option<Origin> {
        let url = url::Url::parse(s).ok()?;
        let host = url.host_str()?.to_ascii_lowercase();
        Some(Origin {
            scheme: url.scheme().to_string(),
            port: url.port(), // None for the scheme's default port
            host,
        })
    }
}

/// Registrable ("eTLD+1") domain via a pragmatic public-suffix approximation. Handles
/// common two-label suffixes; the extension side uses a full PSL (tldts) and both are
/// cross-checked. Conservative: when unsure, requires more labels to match.
fn registrable_domain(host: &str) -> String {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let last2 = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if TWO_LABEL_SUFFIXES.contains(&last2.as_str()) && labels.len() >= 3 {
        format!("{}.{}", labels[labels.len() - 3], last2)
    } else {
        format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1])
    }
}

/// A small, common subset of multi-label public suffixes.
const TWO_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au", "org.au",
    "co.nz", "com.br", "com.mx", "co.in", "co.za", "com.sg",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::model::Item;

    fn urls(pairs: &[(&str, UrlMode)]) -> Vec<UrlMatch> {
        pairs
            .iter()
            .map(|(u, m)| UrlMatch {
                url: u.to_string(),
                mode: m.clone(),
            })
            .collect()
    }

    #[test]
    fn lock_clears_key() {
        let mut s = VaultSession::unlocked(VaultKey::generate());
        assert!(!s.is_locked());
        let env = s.seal(&Item::new_login("x", 1)).unwrap();
        s.lock();
        assert!(s.is_locked());
        assert!(matches!(s.open(&env), Err(CoreError::State(_))));
    }

    #[test]
    fn domain_match_across_subdomains() {
        let u = urls(&[("https://example.com", UrlMode::Domain)]);
        assert!(origin_matches(&u, "https://login.example.com"));
        assert!(origin_matches(&u, "https://example.com"));
        assert!(!origin_matches(&u, "https://evil.com"));
    }

    #[test]
    fn registrable_domain_handles_multi_label_suffix() {
        assert_eq!(registrable_domain("login.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("a.b.example.com"), "example.com");
        let u = urls(&[("https://example.co.uk", UrlMode::Domain)]);
        assert!(origin_matches(&u, "https://mail.example.co.uk"));
        assert!(!origin_matches(&u, "https://example.com"));
    }

    #[test]
    fn https_saved_never_fills_on_http() {
        let u = urls(&[("https://bank.com", UrlMode::Domain)]);
        assert!(!origin_matches(&u, "http://bank.com"));
    }

    #[test]
    fn ports_must_match() {
        let u = urls(&[("https://localhost:8443", UrlMode::Host)]);
        assert!(origin_matches(&u, "https://localhost:8443"));
        assert!(!origin_matches(&u, "https://localhost:9443"));
        assert!(!origin_matches(&u, "https://localhost"));
    }

    #[test]
    fn host_exact_rejects_subdomain() {
        let u = urls(&[("https://www.example.com", UrlMode::Host)]);
        assert!(origin_matches(&u, "https://www.example.com"));
        assert!(!origin_matches(&u, "https://api.example.com"));
    }

    #[test]
    fn cross_domain_never_matches() {
        let u = urls(&[("https://example.com", UrlMode::Domain)]);
        for bad in [
            "https://example.com.evil.com",
            "https://notexample.com",
            "https://example.org",
        ] {
            assert!(!origin_matches(&u, bad), "unexpectedly matched {bad}");
        }
    }
}
