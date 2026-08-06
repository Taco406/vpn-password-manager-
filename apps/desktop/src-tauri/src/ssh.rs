//! Embedded SSH root terminal (v0.1.64).
//!
//! This is the highest-stakes surface in the app: a live root shell on the
//! user's own servers, driven from inside NorthKey. The design is built around
//! *bounding and gating* that power. The security-critical decisions — how a
//! host key is fingerprinted, and whether a presented key matches the one we
//! pinned — live in `sentinel_core::ssh` (unit-tested on Linux CI, which cannot
//! build this desktop crate). This module is the plumbing: keychain-stored key,
//! the russh PTY session, streaming to the UI over Tauri events, and the gates.
//!
//! Security properties enforced here:
//!  * **Host-key pinning (TOFU).** First connect records the server's SHA256
//!    fingerprint (in `servers-config.json`); every later connect refuses if the
//!    fingerprint changed. The old pop-out terminal trusted `root@ip` blindly —
//!    this is the biggest upgrade over that.
//!  * **Open gate.** The vault must be unlocked, and — when a biometric is
//!    available — a fresh Windows Hello / Touch ID confirmation is required
//!    before a root shell opens. A shell should never open on a stray click.
//!  * **Kill on lock.** `close_all` terminates every live session the instant
//!    the vault locks (wired into `commands::lock`), so no root shell outlives
//!    the unlock that authorised it.
//!  * **Desktop-only key.** The private key lives in the OS keychain and never
//!    rides the encrypted vault sync — the phone never receives SSH anything.
//!  * **Local audit.** Each session open/close is appended to a local
//!    `ssh-audit.jsonl` (never synced, never in the app log — output can contain
//!    secrets) so the user can always see what NorthKey did as root.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use tokio::sync::mpsc;

use russh::client::{self, Handler};
use russh::keys::ssh_key::{self, private::Ed25519Keypair, private::Ed25519PrivateKey};
use russh::keys::{decode_secret_key, PrivateKey, PrivateKeyWithHashAlg};
use russh::ChannelMsg;

use crate::state::AppState;

/// OS keychain service (matches sync.rs / state.rs — one service per app).
const KC_SERVICE: &str = "com.sentinel.desktop";
/// Keychain account holding the OpenSSH-format ed25519 private key. Desktop-only:
/// this is deliberately NOT one of the settings that sync to the phone.
const KC_SSH_KEY: &str = "ssh-terminal-key";
const KEY_COMMENT: &str = "northkey";
/// SSH is always to root on port 22 (NorthKey servers, and the user's own boxes).
const SSH_USER: &str = "root";
const SSH_PORT: u16 = 22;

// ---------------------------------------------------------------------------
// Keychain helpers (mirror sync.rs; kept local so the SSH key lives behind the
// same service without coupling the two modules).
// ---------------------------------------------------------------------------

fn kc_get(account: &str) -> Option<String> {
    let entry = keyring::Entry::new(KC_SERVICE, account).ok()?;
    entry
        .get_password()
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn kc_set(account: &str, value: &str) -> Result<(), String> {
    let entry = keyring::Entry::new(KC_SERVICE, account).map_err(|e| e.to_string())?;
    entry.set_password(value).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// The NorthKey-managed SSH key.
// ---------------------------------------------------------------------------

/// Load the app's ed25519 SSH key from the keychain, generating and storing one
/// on first use. The key is generated from a fresh 32-byte seed drawn from the
/// workspace's `rand` (0.8) OsRng — building the key from a seed rather than
/// `PrivateKey::random` avoids coupling to the `rand_core` version that the
/// `ssh-key` crate's `CryptoRng` bound expects.
fn load_or_create_key() -> Result<PrivateKey, String> {
    if let Some(pem) = kc_get(KC_SSH_KEY) {
        return decode_secret_key(&pem, None).map_err(|e| format!("read stored SSH key: {e}"));
    }
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let keypair = Ed25519Keypair::from(Ed25519PrivateKey::from_bytes(&seed));
    seed.iter_mut().for_each(|b| *b = 0); // wipe the seed off the stack
    let key = PrivateKey::new(ssh_key::private::KeypairData::from(keypair), KEY_COMMENT)
        .map_err(|e| format!("build SSH key: {e}"))?;
    let pem = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| format!("encode SSH key: {e}"))?;
    kc_set(KC_SSH_KEY, &pem)?;
    Ok(key)
}

/// The `ssh-ed25519 AAAA… northkey` line to install in a server's
/// `~/.ssh/authorized_keys`.
fn public_line(key: &PrivateKey) -> Result<String, String> {
    key.public_key()
        .to_openssh()
        .map_err(|e| format!("encode public key: {e}"))
}

/// Return the public key line (generating the keypair on first call). Shown in
/// the UI with a one-line install snippet.
#[tauri::command]
pub fn ssh_pubkey() -> Result<String, String> {
    let key = load_or_create_key()?;
    public_line(&key)
}

// ---------------------------------------------------------------------------
// Host-key verification handler.
// ---------------------------------------------------------------------------

/// russh client handler that pins the server host key. It never *decides* trust
/// on its own beyond the pin compare: on first connect (`pinned` empty) it
/// captures the fingerprint and accepts (trust-on-first-use), and `ssh_open`
/// persists it afterwards; on a later connect it accepts only an exact match and
/// flags a mismatch so the caller can explain it.
struct PinHandler {
    pinned: String,
    captured: Arc<Mutex<String>>,
    mismatch: Arc<Mutex<bool>>,
}

impl Handler for PinHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let blob = server_public_key.to_bytes().unwrap_or_default();
        let fp = sentinel_core::ssh::sha256_fingerprint(&blob);
        if let Ok(mut g) = self.captured.lock() {
            *g = fp.clone();
        }
        // Accept on first connect (empty pin — trust-on-first-use, `ssh_open`
        // persists it) or on an exact match; otherwise refuse and flag the
        // mismatch so the caller can explain it (rebuilt host, or a MITM).
        let accept = self.pinned.trim().is_empty()
            || sentinel_core::ssh::fingerprint_matches(&self.pinned, &fp);
        if !accept {
            if let Ok(mut g) = self.mismatch.lock() {
                *g = true;
            }
        }
        Ok(accept)
    }
}

// ---------------------------------------------------------------------------
// Live session registry.
// ---------------------------------------------------------------------------

enum Input {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

struct SessionHandle {
    input: mpsc::UnboundedSender<Input>,
}

/// Registry of live SSH sessions, keyed by an opaque session id. Cloneable
/// (an `Arc` inside) so the per-session driver task can hold a handle to remove
/// itself on exit.
#[derive(Clone, Default)]
pub struct SshState {
    sessions: Arc<Mutex<HashMap<String, SessionHandle>>>,
}

impl SshState {
    fn insert(&self, id: String, h: SessionHandle) {
        if let Ok(mut g) = self.sessions.lock() {
            g.insert(id, h);
        }
    }
    fn take(&self, id: &str) -> Option<SessionHandle> {
        self.sessions.lock().ok().and_then(|mut g| g.remove(id))
    }
    fn send(&self, id: &str, input: Input) -> Result<(), String> {
        let g = self
            .sessions
            .lock()
            .map_err(|_| "session lock".to_string())?;
        match g.get(id) {
            Some(h) => h
                .input
                .send(input)
                .map_err(|_| "That terminal session has closed.".to_string()),
            None => Err("That terminal session is no longer open.".into()),
        }
    }
    fn ids(&self) -> Vec<String> {
        self.sessions
            .lock()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default()
    }
}

/// Terminate every live SSH session. Called from `commands::lock` so locking the
/// vault (manually or via auto-lock) tears down any open root shell.
pub fn close_all(state: &SshState) {
    for id in state.ids() {
        if let Some(h) = state.take(&id) {
            let _ = h.input.send(Input::Close);
        }
    }
}

// ---------------------------------------------------------------------------
// Open / write / resize / close.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SshOpenOut {
    pub session_id: String,
    /// The server's host-key fingerprint (SHA256:…), for display.
    pub fingerprint: String,
    /// True when this connect just pinned the host key (show the fingerprint
    /// prominently so the user can verify it once).
    pub first_connect: bool,
}

/// Open an interactive root PTY on a server and start streaming it to the UI.
///
/// Output is emitted as base64 on the per-session event `ssh:data:<sessionId>`;
/// the session ends with `ssh:closed:<sessionId>`. Gated on: vault unlocked, a
/// biometric confirmation when one is available, and host-key pin verification.
#[tauri::command]
pub async fn ssh_open(
    app: AppHandle,
    state: State<'_, AppState>,
    ssh: State<'_, SshState>,
    provider: String,
    id: String,
    host: String,
) -> Result<SshOpenOut, String> {
    // Gate 1 — the vault must be open (the human authenticated at unlock).
    let (data_dir, locked) = {
        let g = state.inner.lock().unwrap();
        (g.data_dir.clone(), g.session.is_locked())
    };
    if locked {
        return Err("Unlock your vault before opening a terminal.".into());
    }
    let host = host.trim().to_string();
    if host.is_empty() {
        return Err("No server address.".into());
    }

    // Gate 2 — a fresh biometric confirmation, when the device has one. Opening a
    // root shell should take a deliberate second step, not a single click.
    if crate::hello::available() {
        match crate::hello::verify(&format!("Confirm to open a root terminal on {host}")) {
            Ok(true) => {}
            Ok(false) => return Err("Cancelled.".into()),
            Err(e) => return Err(e),
        }
    }

    let key = load_or_create_key()?;
    let pinned = crate::servers::ssh_hostkey_get(&data_dir, &provider, &id);
    let first_connect = pinned.trim().is_empty();
    let captured = Arc::new(Mutex::new(String::new()));
    let mismatch = Arc::new(Mutex::new(false));
    let handler = PinHandler {
        pinned,
        captured: captured.clone(),
        mismatch: mismatch.clone(),
    };

    // Disable russh's idle-drop; the vault-lock kill is the real session bound.
    let config = Arc::new(client::Config {
        inactivity_timeout: None,
        ..Default::default()
    });

    let connect = client::connect(config, (host.as_str(), SSH_PORT), handler);
    let mut handle = match tokio::time::timeout(std::time::Duration::from_secs(15), connect).await {
        Err(_) => {
            return Err(format!(
                "Timed out connecting to {host} on port {SSH_PORT}."
            ))
        }
        Ok(Ok(h)) => h,
        Ok(Err(e)) => {
            if *mismatch.lock().unwrap() {
                let now = captured.lock().unwrap().clone();
                return Err(format!(
                    "HOST KEY CHANGED for {host}.\r\n\r\nThe server is presenting a different SSH \
                     key ({now}) than the one NorthKey pinned. If you rebuilt this server this is \
                     expected — reset the pinned key in the Access tab, then reconnect. If you did \
                     NOT rebuild it, something may be intercepting the connection; do not proceed."
                ));
            }
            return Err(format!("Could not connect to {host}: {e}"));
        }
    };

    // Authenticate with the NorthKey key (ed25519 → no RSA hash alg).
    let auth = handle
        .authenticate_publickey(SSH_USER, PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
        .map_err(|e| format!("SSH authentication error: {e}"))?;
    if !auth.success() {
        return Err(
            "The server rejected NorthKey's key. Open the Access tab, copy the one-line install \
             command onto this server, then reconnect."
                .into(),
        );
    }

    // Trust-on-first-use: persist the fingerprint we just captured.
    let fingerprint = captured.lock().unwrap().clone();
    if first_connect && !fingerprint.is_empty() {
        crate::servers::ssh_hostkey_set(&data_dir, &provider, &id, &fingerprint)?;
    }

    // Open the PTY + shell.
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open SSH channel: {e}"))?;
    channel
        .request_pty(false, "xterm-256color", 80, 24, 0, 0, &[])
        .await
        .map_err(|e| format!("request PTY: {e}"))?;
    channel
        .request_shell(false)
        .await
        .map_err(|e| format!("request shell: {e}"))?;

    let session_id = uuid::Uuid::new_v4().to_string();
    audit(&data_dir, "open", &provider, &id, &host, &fingerprint);

    let (tx, mut rx) = mpsc::unbounded_channel::<Input>();
    ssh.insert(session_id.clone(), SessionHandle { input: tx });

    // Driver task owns the channel and the connection handle (dropping the handle
    // closes the connection, so it must live as long as the loop).
    let app2 = app.clone();
    let sid = session_id.clone();
    let ssh_owned: SshState = ssh.inner().clone();
    let dir2 = data_dir.clone();
    let provider2 = provider.clone();
    let id2 = id.clone();
    let host2 = host.clone();
    tokio::spawn(async move {
        let _handle = handle; // keep the connection alive
        loop {
            tokio::select! {
                msg = channel.wait() => match msg {
                    Some(ChannelMsg::Data { data }) => {
                        let _ = app2.emit(
                            &format!("ssh:data:{sid}"),
                            base64::engine::general_purpose::STANDARD.encode(&data),
                        );
                    }
                    Some(ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = app2.emit(
                            &format!("ssh:data:{sid}"),
                            base64::engine::general_purpose::STANDARD.encode(&data),
                        );
                    }
                    Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => break,
                    _ => {}
                },
                inp = rx.recv() => match inp {
                    Some(Input::Data(d)) => { let _ = channel.data_bytes(d).await; }
                    Some(Input::Resize(c, r)) => { let _ = channel.window_change(c, r, 0, 0).await; }
                    Some(Input::Close) | None => { let _ = channel.eof().await; break; }
                }
            }
        }
        ssh_owned.take(&sid);
        audit(&dir2, "close", &provider2, &id2, &host2, "");
        let _ = app2.emit(&format!("ssh:closed:{sid}"), ());
    });

    Ok(SshOpenOut {
        session_id,
        fingerprint,
        first_connect,
    })
}

/// Send keystrokes (base64) to a live session's PTY.
#[tauri::command]
pub fn ssh_write(ssh: State<SshState>, session_id: String, data_b64: String) -> Result<(), String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .map_err(|e| format!("bad input encoding: {e}"))?;
    ssh.send(&session_id, Input::Data(bytes))
}

/// Tell the remote PTY the terminal was resized (so full-screen TUIs redraw).
#[tauri::command]
pub fn ssh_resize(
    ssh: State<SshState>,
    session_id: String,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    ssh.send(&session_id, Input::Resize(cols.max(1), rows.max(1)))
}

/// Close a live session.
#[tauri::command]
pub fn ssh_close(ssh: State<SshState>, session_id: String) -> Result<(), String> {
    // Best-effort: a already-gone session is not an error to the caller.
    let _ = ssh.send(&session_id, Input::Close);
    Ok(())
}

// ---------------------------------------------------------------------------
// Local, never-synced audit log (session open/close).
// ---------------------------------------------------------------------------

fn audit(dir: &std::path::Path, event: &str, provider: &str, id: &str, host: &str, fp: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = serde_json::json!({
        "ts": ts,
        "event": event,
        "provider": provider,
        "id": id,
        "host": host,
        "fingerprint": fp,
    });
    let path = dir.join("ssh-audit.jsonl");
    // Best-effort append; the audit log must never block or fail a session.
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = writeln!(f, "{line}");
    }
}

/// Read the local SSH audit log (newest last), for the Access-tab viewer.
#[tauri::command]
pub fn ssh_audit_read(state: State<AppState>) -> Result<String, String> {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    Ok(std::fs::read_to_string(dir.join("ssh-audit.jsonl")).unwrap_or_default())
}

/// Clear the local SSH audit log.
#[tauri::command]
pub fn ssh_audit_clear(state: State<AppState>) -> Result<(), String> {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    let path = dir.join("ssh-audit.jsonl");
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}
