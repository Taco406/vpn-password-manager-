//! Google OAuth 2.0 Authorization Code flow with PKCE (RFC 7636).

use crate::error::{CoreError, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

const AUTH_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const SCOPE: &str = "openid email profile";

/// PKCE material for one authorization attempt.
#[derive(Clone)]
pub struct PkceParams {
    pub verifier: String,
    pub challenge: String,
    pub state: String,
    pub redirect_uri: String,
}

impl PkceParams {
    /// Generate a fresh verifier (43-char base64url of 32 random bytes), its S256
    /// challenge, an anti-CSRF `state`, and the loopback redirect URI for `port`.
    pub fn generate(port: u16) -> Self {
        let mut vb = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut vb);
        let verifier = URL_SAFE_NO_PAD.encode(vb);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let mut sb = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut sb);
        let state = URL_SAFE_NO_PAD.encode(sb);
        PkceParams {
            verifier,
            challenge,
            state,
            redirect_uri: format!("http://127.0.0.1:{port}/callback"),
        }
    }
}

/// Tokens returned by the exchange.
#[derive(Clone, Debug)]
pub struct TokenSet {
    /// Google-signed id_token (a JWT) proving the user's identity to our API.
    pub id_token: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: u64,
}

/// Opens the system browser at the given URL. Real impl uses the OS opener; the mock
/// records the URL and simulates the user completing consent.
#[async_trait]
pub trait BrowserOpener: Send + Sync {
    async fn open(&self, url: &str) -> Result<()>;
}

/// Exchanges an authorization code (+ verifier) for tokens at Google's token endpoint.
#[async_trait]
pub trait TokenExchanger: Send + Sync {
    async fn exchange(&self, code: &str, verifier: &str, redirect_uri: &str) -> Result<TokenSet>;
}

/// Drives the PKCE flow given a client id and the two transport traits.
pub struct GoogleAuth {
    client_id: String,
    opener: std::sync::Arc<dyn BrowserOpener>,
    exchanger: std::sync::Arc<dyn TokenExchanger>,
}

impl GoogleAuth {
    pub fn new(
        client_id: impl Into<String>,
        opener: std::sync::Arc<dyn BrowserOpener>,
        exchanger: std::sync::Arc<dyn TokenExchanger>,
    ) -> Self {
        GoogleAuth {
            client_id: client_id.into(),
            opener,
            exchanger,
        }
    }

    /// Build the authorization URL for the given PKCE params.
    pub fn authorize_url(&self, p: &PkceParams) -> String {
        let q = [
            ("client_id", self.client_id.as_str()),
            ("response_type", "code"),
            ("redirect_uri", p.redirect_uri.as_str()),
            ("scope", SCOPE),
            ("code_challenge", p.challenge.as_str()),
            ("code_challenge_method", "S256"),
            ("state", p.state.as_str()),
            ("access_type", "offline"),
            ("prompt", "consent"),
        ]
        .iter()
        .map(|(k, v)| format!("{k}={}", urlencode(v)))
        .collect::<Vec<_>>()
        .join("&");
        format!("{AUTH_ENDPOINT}?{q}")
    }

    /// Start the flow: open the browser at the authorization URL.
    pub async fn start(&self, p: &PkceParams) -> Result<()> {
        self.opener.open(&self.authorize_url(p)).await
    }

    /// Complete the flow with the `code`/`state` delivered to the loopback redirect.
    /// Validates `state` against the params (CSRF) before exchanging.
    pub async fn complete(
        &self,
        p: &PkceParams,
        returned_state: &str,
        code: &str,
    ) -> Result<TokenSet> {
        if returned_state != p.state {
            return Err(CoreError::Unauthorized("oauth state mismatch"));
        }
        self.exchanger
            .exchange(code, &p.verifier, &p.redirect_uri)
            .await
    }
}

/// Percent-encode a query component (RFC 3986 unreserved kept as-is).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

// --- mocks ----------------------------------------------------------------

/// Records the opened URL; never launches anything.
#[derive(Default, Clone)]
pub struct MockBrowserOpener {
    pub last_url: std::sync::Arc<std::sync::Mutex<Option<String>>>,
}

#[async_trait]
impl BrowserOpener for MockBrowserOpener {
    async fn open(&self, url: &str) -> Result<()> {
        *self.last_url.lock().unwrap() = Some(url.to_string());
        Ok(())
    }
}

/// Returns a fixed fixture token set, echoing back the code so tests can assert wiring.
#[derive(Clone)]
pub struct MockTokenExchanger {
    pub id_token: String,
}

impl Default for MockTokenExchanger {
    fn default() -> Self {
        MockTokenExchanger {
            id_token: "fixture.id.token".into(),
        }
    }
}

#[async_trait]
impl TokenExchanger for MockTokenExchanger {
    async fn exchange(&self, code: &str, verifier: &str, _redirect: &str) -> Result<TokenSet> {
        if code.is_empty() || verifier.is_empty() {
            return Err(CoreError::Unauthorized("missing code or verifier"));
        }
        Ok(TokenSet {
            id_token: self.id_token.clone(),
            access_token: format!("access-for-{code}"),
            refresh_token: Some("refresh-fixture".into()),
            expires_in: 3600,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn auth() -> (GoogleAuth, MockBrowserOpener) {
        let opener = MockBrowserOpener::default();
        let auth = GoogleAuth::new(
            "client-123.apps.googleusercontent.com",
            Arc::new(opener.clone()),
            Arc::new(MockTokenExchanger::default()),
        );
        (auth, opener)
    }

    #[test]
    fn challenge_is_s256_of_verifier() {
        let p = PkceParams::generate(51789);
        let expect = URL_SAFE_NO_PAD.encode(Sha256::digest(p.verifier.as_bytes()));
        assert_eq!(p.challenge, expect);
        assert!(p.redirect_uri.starts_with("http://127.0.0.1:51789/"));
    }

    #[test]
    fn url_carries_pkce_and_loopback() {
        let (auth, _) = auth();
        let p = PkceParams::generate(8080);
        let url = auth.authorize_url(&p);
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("code_challenge="));
        assert!(url.contains("response_type=code"));
        // redirect uri is percent-encoded loopback
        assert!(url.contains("127.0.0.1%3A8080"));
    }

    #[tokio::test]
    async fn full_flow_with_mock_transport() {
        let (auth, opener) = auth();
        let p = PkceParams::generate(9099);
        auth.start(&p).await.unwrap();
        assert!(opener.last_url.lock().unwrap().is_some());
        let tokens = auth.complete(&p, &p.state, "auth-code-xyz").await.unwrap();
        assert_eq!(tokens.id_token, "fixture.id.token");
        assert_eq!(tokens.access_token, "access-for-auth-code-xyz");
    }

    #[tokio::test]
    async fn state_mismatch_is_rejected() {
        let (auth, _) = auth();
        let p = PkceParams::generate(9100);
        let r = auth.complete(&p, "not-the-state", "code").await;
        assert!(matches!(r, Err(CoreError::Unauthorized(_))));
    }
}
