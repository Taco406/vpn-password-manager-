//! Tauri command surface — the real backend the desktop UI talks to through the
//! SentinelBridge contract. Every command is thin glue into `sentinel-core`, operating on
//! the persistent, unlocked vault in `AppState`. VPN/auth/pairing are still served by the
//! in-browser simulation (delegated in the frontend bridge); everything here is real.

use crate::state::AppState;
use sentinel_core::generator::{self, PassphraseSpec, PasswordSpec};
use sentinel_core::health::{run_audit, HibpClient, NoHibp, RealHibp};
use sentinel_core::totp::TotpSecret;
use sentinel_core::vault::model::{Card, Identity, Item, ItemType, Login, UrlMatch, UrlMode};
use sentinel_core::vault::VaultSession;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

// ---------------------------------------------------------------------------
// error + helpers
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct ApiError {
    code: String,
    message: String,
}
impl From<sentinel_core::CoreError> for ApiError {
    fn from(e: sentinel_core::CoreError) -> Self {
        ApiError {
            code: "core".into(),
            message: e.to_string(),
        }
    }
}
fn err(code: &str, message: impl Into<String>) -> ApiError {
    ApiError {
        code: code.into(),
        message: message.into(),
    }
}
type R<T> = Result<T, ApiError>;

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn iso(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}

fn parse_uid(id: &str) -> R<uuid::Uuid> {
    uuid::Uuid::parse_str(id).map_err(|_| err("bad_id", "bad item id"))
}

/// Best-effort host extraction for favicons ("https://a.example.com/x" -> "a.example.com").
fn host_of(url: &str) -> String {
    let after = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    after.split('/').next().unwrap_or(after).to_string()
}

fn type_str(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "login",
        ItemType::Note => "note",
        ItemType::Card => "card",
        ItemType::Identity => "identity",
        ItemType::Passkey => "passkey",
    }
}
fn type_from_str(s: &str) -> ItemType {
    match s {
        "note" => ItemType::Note,
        "card" => ItemType::Card,
        "identity" => ItemType::Identity,
        "passkey" => ItemType::Passkey,
        _ => ItemType::Login,
    }
}
fn mode_str(m: &UrlMode) -> &'static str {
    match m {
        UrlMode::Domain => "domain",
        UrlMode::Host => "host",
    }
}

// ---------------------------------------------------------------------------
// keyring / unlock
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WrapperInfo {
    #[serde(rename = "type")]
    kind: String,
    enrolled: bool,
    label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyringStatus {
    locked: bool,
    wrappers: Vec<WrapperInfo>,
    recovery_verified: bool,
}

#[tauri::command]
pub fn keyring_status(state: State<AppState>) -> KeyringStatus {
    let inner = state.inner.lock().unwrap();
    KeyringStatus {
        locked: inner.session.is_locked(),
        wrappers: vec![
            WrapperInfo {
                kind: "platform".into(),
                enrolled: true,
                label: "This device".into(),
                created_at: None,
            },
            WrapperInfo {
                kind: "phone".into(),
                enrolled: false,
                label: "iPhone".into(),
                created_at: None,
            },
            WrapperInfo {
                kind: "recovery".into(),
                enrolled: false,
                label: "Recovery Kit".into(),
                created_at: None,
            },
        ],
        recovery_verified: false,
    }
}

#[tauri::command]
pub fn lock(app: AppHandle, state: State<AppState>) -> R<()> {
    state.inner.lock().unwrap().session.lock();
    let _ = app.emit("vault:locked", ());
    Ok(())
}

/// Re-unlock by re-reading the vault key from the OS keychain (the biometric / phone / recovery
/// paths). If a master password is set, the plaintext keychain key was deleted and the vault
/// only opens via the password — so refuse here and route the user to the password unlock,
/// rather than minting a fresh, wrong key.
fn reunlock(state: &State<AppState>) -> R<()> {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    if crate::state::password_protected(&dir) {
        return Err(err(
            "password",
            "a master password is set — unlock with your password",
        ));
    }
    let vk = crate::state::load_key_strict().map_err(|m| err("keychain", m))?;
    state.inner.lock().unwrap().session = VaultSession::unlocked(vk);
    Ok(())
}

#[tauri::command]
pub fn unlock_platform(state: State<AppState>) -> R<()> {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    if crate::state::require_hello(&dir)
        && !crate::hello::verify("Unlock NorthKey").map_err(|m| err("hello", m))?
    {
        return Err(err("hello", "Windows Hello verification did not pass"));
    }
    reunlock(&state)
}

/// The host OS ("windows" | "macos" | "linux" | …), so the UI can honestly hide platform-specific
/// controls (e.g. the Windows-only VPN kill switch / untrusted-Wi-Fi auto-connect) on macOS
/// instead of showing dead toggles that silently do nothing.
#[tauri::command]
pub fn app_platform() -> String {
    std::env::consts::OS.to_string()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HelloStatus {
    available: bool,
    enabled: bool,
}

#[tauri::command]
pub fn hello_status(state: State<AppState>) -> HelloStatus {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    HelloStatus {
        available: crate::hello::available(),
        enabled: crate::state::require_hello(&dir),
    }
}

/// Turn the Windows Hello unlock gate on/off. Enabling verifies Hello once first, then
/// persists the choice to settings.json (takes effect next launch/lock).
#[tauri::command]
pub fn hello_set(state: State<AppState>, enabled: bool) -> R<()> {
    if enabled {
        if !crate::hello::available() {
            return Err(err("hello", "Windows Hello isn't set up on this device"));
        }
        if !crate::hello::verify("Confirm Windows Hello for NorthKey")
            .map_err(|m| err("hello", m))?
        {
            return Err(err("hello", "Windows Hello verification cancelled"));
        }
    }
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    let path = dir.join("settings.json");
    let mut cur = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(default_settings);
    if let Some(obj) = cur.as_object_mut() {
        obj.insert("requireHello".into(), serde_json::Value::Bool(enabled));
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&cur).unwrap_or_default(),
    )
    .map_err(|e| err("io", e.to_string()))?;
    Ok(())
}

#[tauri::command]
pub fn unlock_recovery(state: State<AppState>, _key: String) -> R<()> {
    reunlock(&state)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PhoneBegin {
    request_id: String,
}

#[tauri::command]
pub fn unlock_phone_begin() -> PhoneBegin {
    PhoneBegin {
        request_id: uuid::Uuid::new_v4().to_string(),
    }
}

#[tauri::command]
pub fn unlock_phone_await(state: State<AppState>, _request_id: String) -> R<()> {
    reunlock(&state)
}

// ---------------------------------------------------------------------------
// vault
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    favicon_domain: Option<String>,
    has_totp: bool,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_changed_at: Option<String>,
}

fn summary_of(it: &Item) -> ItemSummary {
    ItemSummary {
        id: it.id.to_string(),
        kind: type_str(it.item_type).into(),
        title: it.title.clone(),
        username: it.username().map(str::to_string),
        tags: it.tags.clone(),
        favicon_domain: it.urls.first().map(|u| host_of(&u.url)),
        has_totp: it.login.as_ref().and_then(|l| l.totp.as_ref()).is_some(),
        updated_at: iso(it.updated_at),
        password_changed_at: it.password_changed_at.map(iso),
    }
}

#[tauri::command]
pub fn vault_list(state: State<AppState>) -> R<Vec<ItemSummary>> {
    let inner = state.inner.lock().unwrap();
    let mut out = Vec::new();
    for env in inner.vault.list_envelopes()? {
        let it = inner.session.open(&env)?;
        // System items (synced app settings) never show next to real logins.
        if it.tags.iter().any(|t| t == crate::sync::SYSTEM_TAG) {
            continue;
        }
        out.push(summary_of(&it));
    }
    Ok(out)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UrlOut {
    url: String,
    mode: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CustomOut {
    name: String,
    value: String,
    secret: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CardOut {
    brand: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    last4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp_month: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    exp_year: Option<u16>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityOut {
    #[serde(skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
}
/// Passkey projection — SAFE fields only. The private key is deliberately absent and is
/// never serialized to the UI by any command.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PasskeyOut {
    rp_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rp_name: Option<String>,
    user_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_display_name: Option<String>,
    credential_id: String,
    algorithm: i32,
    sign_count: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemDetail {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    favicon_domain: Option<String>,
    has_totp: bool,
    updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    password_changed_at: Option<String>,
    urls: Vec<UrlOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    custom_fields: Vec<CustomOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card: Option<CardOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity: Option<IdentityOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    passkey: Option<PasskeyOut>,
}

#[tauri::command]
pub fn vault_get(state: State<AppState>, id: String) -> R<ItemDetail> {
    let uid = parse_uid(&id)?;
    let inner = state.inner.lock().unwrap();
    let env = inner
        .vault
        .get(uid)?
        .ok_or_else(|| err("not_found", "no such item"))?;
    let it = inner.session.open(&env)?;
    let s = summary_of(&it);
    let card = it.card.as_ref().map(|c| CardOut {
        brand: c.brand.clone().unwrap_or_default(),
        last4: c.number.as_ref().map(|n| {
            n.chars()
                .rev()
                .take(4)
                .collect::<String>()
                .chars()
                .rev()
                .collect()
        }),
        exp_month: c.exp_month,
        exp_year: c.exp_year,
    });
    let identity = it.identity.as_ref().map(|d| IdentityOut {
        full_name: d.full_name.clone(),
        email: d.email.clone(),
        phone: d.phone.clone(),
    });
    // Passkey projection: safe metadata only. `private_key` is never included.
    let passkey = it.passkey.as_ref().map(|p| PasskeyOut {
        rp_id: p.rp_id.clone(),
        rp_name: p.rp_name.clone(),
        user_name: p.user_name.clone(),
        user_display_name: p.user_display_name.clone(),
        credential_id: p.credential_id.clone(),
        algorithm: p.algorithm,
        sign_count: p.sign_count,
    });
    Ok(ItemDetail {
        id: s.id,
        kind: s.kind,
        title: s.title,
        username: s.username,
        tags: s.tags,
        favicon_domain: s.favicon_domain,
        has_totp: s.has_totp,
        updated_at: s.updated_at,
        password_changed_at: s.password_changed_at,
        urls: it
            .urls
            .iter()
            .map(|u| UrlOut {
                url: u.url.clone(),
                mode: mode_str(&u.mode).into(),
            })
            .collect(),
        notes: it.notes.clone(),
        custom_fields: it
            .custom_fields
            .iter()
            .map(|c| CustomOut {
                name: c.name.clone(),
                value: c.value.clone(),
                secret: c.secret,
            })
            .collect(),
        card,
        identity,
        passkey,
    })
}

#[tauri::command]
pub fn vault_reveal_field(state: State<AppState>, id: String, field: String) -> R<String> {
    let uid = parse_uid(&id)?;
    let inner = state.inner.lock().unwrap();
    let env = inner
        .vault
        .get(uid)?
        .ok_or_else(|| err("not_found", "no such item"))?;
    let it = inner.session.open(&env)?;
    Ok(match field.as_str() {
        "password" => it.password().unwrap_or_default().to_string(),
        "username" => it.username().unwrap_or_default().to_string(),
        "totp" => it
            .login
            .as_ref()
            .and_then(|l| l.totp.clone())
            .unwrap_or_default(),
        "number" => it
            .card
            .as_ref()
            .and_then(|c| c.number.clone())
            .unwrap_or_default(),
        "cvv" => it
            .card
            .as_ref()
            .and_then(|c| c.cvv.clone())
            .unwrap_or_default(),
        _ => String::new(),
    })
}

// The item shape the editor sends. Superset of the TS ItemInput; extra fields are ignored
// if absent (serde defaults), so login/note/card/identity all round-trip.
#[derive(Deserialize)]
struct UrlIn {
    url: String,
    #[serde(default)]
    mode: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CustomIn {
    name: String,
    value: String,
    #[serde(default)]
    secret: bool,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CardIn {
    cardholder: Option<String>,
    number: Option<String>,
    brand: Option<String>,
    exp_month: Option<u8>,
    exp_year: Option<u16>,
    cvv: Option<String>,
}
#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct IdentityIn {
    full_name: Option<String>,
    email: Option<String>,
    phone: Option<String>,
    address: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemInput {
    id: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    title: String,
    username: Option<String>,
    password: Option<String>,
    #[serde(default)]
    urls: Vec<UrlIn>,
    notes: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    totp_uri: Option<String>,
    #[serde(default)]
    custom_fields: Vec<CustomIn>,
    card: Option<CardIn>,
    identity: Option<IdentityIn>,
}

#[tauri::command]
pub fn vault_save(state: State<AppState>, item: ItemInput) -> R<String> {
    let ts = now();
    let kind = type_from_str(&item.kind);
    let inner = state.inner.lock().unwrap();

    // On edit, load the prior item to preserve created_at and password-age tracking.
    let prior: Option<Item> = match &item.id {
        Some(id) => {
            let uid = parse_uid(id)?;
            match inner.vault.get(uid)? {
                Some(env) => Some(inner.session.open(&env)?),
                None => None,
            }
        }
        None => None,
    };

    let uid = match &item.id {
        Some(id) => parse_uid(id)?,
        None => uuid::Uuid::new_v4(),
    };
    let created_at = prior.as_ref().map(|p| p.created_at).unwrap_or(ts);

    let urls = item
        .urls
        .iter()
        .filter(|u| !u.url.trim().is_empty())
        .map(|u| UrlMatch {
            url: u.url.clone(),
            mode: if u.mode == "host" {
                UrlMode::Host
            } else {
                UrlMode::Domain
            },
        })
        .collect::<Vec<_>>();
    let custom_fields = item
        .custom_fields
        .into_iter()
        .map(|c| sentinel_core::vault::model::CustomField {
            name: c.name,
            value: c.value,
            secret: c.secret,
        })
        .collect::<Vec<_>>();

    let (login, card, identity, password_changed_at) = match kind {
        ItemType::Login => {
            let password_changed_at = match (&prior, &item.password) {
                (Some(p), Some(np)) if p.password() == Some(np.as_str()) => p.password_changed_at,
                (_, None) => prior.as_ref().and_then(|p| p.password_changed_at),
                _ => Some(ts),
            };
            let login = Login {
                username: item.username.clone().filter(|s| !s.is_empty()),
                password: item.password.clone().filter(|s| !s.is_empty()),
                totp: item.totp_uri.clone().filter(|s| !s.is_empty()),
            };
            (Some(login), None, None, password_changed_at)
        }
        ItemType::Card => {
            let c = item.card.unwrap_or_default();
            (
                None,
                Some(Card {
                    cardholder: c.cardholder,
                    number: c.number,
                    brand: c.brand,
                    exp_month: c.exp_month,
                    exp_year: c.exp_year,
                    cvv: c.cvv,
                }),
                None,
                None,
            )
        }
        ItemType::Identity => {
            let d = item.identity.unwrap_or_default();
            (
                None,
                None,
                Some(Identity {
                    full_name: d.full_name,
                    email: d.email,
                    phone: d.phone,
                    address: d.address,
                }),
                None,
            )
        }
        ItemType::Note => (None, None, None, None),
        // Passkeys are minted, never hand-typed: a save only carries title/tags/notes edits.
        ItemType::Passkey => (None, None, None, None),
    };

    // Never fabricate key material on save. Only when editing an existing passkey item do we
    // carry its sealed sub-object forward (so title/tags/notes can be edited); otherwise None.
    let passkey = if matches!(kind, ItemType::Passkey) {
        prior.as_ref().and_then(|p| p.passkey.clone())
    } else {
        None
    };

    let built = Item {
        id: uid,
        item_type: kind,
        title: item.title,
        tags: item.tags,
        urls,
        notes: item.notes.filter(|s| !s.is_empty()),
        custom_fields,
        login,
        card,
        identity,
        passkey,
        created_at,
        updated_at: ts,
        password_changed_at,
    };

    let env = inner.session.seal(&built)?;
    inner.vault.upsert(&env)?;
    Ok(uid.to_string())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasskeyCreated {
    id: String,
    credential_id: String,
    /// base64 (std) of the 65-byte uncompressed SEC1 public point. The private key is
    /// never returned.
    public_key_b64: String,
}

/// Mint an ES256 passkey, seal it into a new Passkey vault item, and return the ids the
/// caller needs. This is the seam Stage B's browser registration flow calls; the returned
/// public key gets COSE-encoded there. The private key stays sealed in the vault and is
/// never exposed by this (or any) command.
#[tauri::command]
pub fn vault_passkey_create(
    state: State<AppState>,
    rp_id: String,
    rp_name: Option<String>,
    user_name: String,
    user_display_name: Option<String>,
    user_handle_b64u: String,
) -> R<PasskeyCreated> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;

    let user_handle = URL_SAFE_NO_PAD
        .decode(user_handle_b64u.as_bytes())
        .map_err(|_| err("bad_handle", "user handle is not base64url"))?;

    let pk = sentinel_core::vault::mint_passkey(
        &rp_id,
        rp_name,
        &user_name,
        user_display_name,
        &user_handle,
    );
    // Derive the public key before the key material is moved into the item.
    let public_key = sentinel_core::vault::public_key_sec1(&pk)?;
    let credential_id = pk.credential_id.clone();

    let ts = now();
    let item = Item {
        id: uuid::Uuid::new_v4(),
        item_type: ItemType::Passkey,
        title: format!("{user_name} @ {rp_id}"),
        tags: vec![],
        urls: vec![],
        notes: None,
        custom_fields: vec![],
        login: None,
        card: None,
        identity: None,
        passkey: Some(pk),
        created_at: ts,
        updated_at: ts,
        password_changed_at: None,
    };
    let id = item.id.to_string();

    let inner = state.inner.lock().unwrap();
    let env = inner.session.seal(&item)?;
    inner.vault.upsert(&env)?;

    Ok(PasskeyCreated {
        id,
        credential_id,
        public_key_b64: STANDARD.encode(public_key),
    })
}

#[tauri::command]
pub fn vault_delete(state: State<AppState>, id: String) -> R<()> {
    let uid = parse_uid(&id)?;
    state.inner.lock().unwrap().vault.delete(uid, now())?;
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpOut {
    code: String,
    remaining_ms: u64,
}

#[tauri::command]
pub fn vault_totp(state: State<AppState>, id: String) -> R<TotpOut> {
    let uid = parse_uid(&id)?;
    let inner = state.inner.lock().unwrap();
    let env = inner
        .vault
        .get(uid)?
        .ok_or_else(|| err("not_found", "no such item"))?;
    let it = inner.session.open(&env)?;
    let uri = it
        .login
        .as_ref()
        .and_then(|l| l.totp.clone())
        .ok_or_else(|| err("no_totp", "item has no TOTP"))?;
    let secret = TotpSecret::parse(&uri)?;
    let n = now();
    Ok(TotpOut {
        code: secret.code_at(n as u64),
        remaining_ms: secret.remaining_ms((n as u64) * 1000),
    })
}

// ---------------------------------------------------------------------------
// generator
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Generated {
    value: String,
    score: u8,
    crack_display: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenPasswordSpec {
    length: usize,
    lower: bool,
    upper: bool,
    digits: bool,
    symbols: bool,
    exclude_ambiguous: bool,
}

#[tauri::command]
pub fn generator_password(spec: GenPasswordSpec) -> R<Generated> {
    let s = PasswordSpec {
        length: spec.length,
        lower: spec.lower,
        upper: spec.upper,
        digits: spec.digits,
        symbols: spec.symbols,
        exclude_ambiguous: spec.exclude_ambiguous,
    };
    let value = generator::password(&s)?;
    let st = generator::assess(&value, &[]);
    Ok(Generated {
        value,
        score: st.score,
        crack_display: st.crack_display,
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenPassphraseSpec {
    words: usize,
    separator: String,
    capitalize: bool,
    include_number: bool,
}

#[tauri::command]
pub fn generator_passphrase(spec: GenPassphraseSpec) -> R<Generated> {
    let s = PassphraseSpec {
        words: spec.words,
        separator: spec.separator,
        capitalize: spec.capitalize,
        include_number: spec.include_number,
    };
    let (value, _entropy) = generator::passphrase(&s)?;
    let st = generator::assess(&value, &[]);
    Ok(Generated {
        value,
        score: st.score,
        crack_display: st.crack_display,
    })
}

// ---------------------------------------------------------------------------
// health
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ReusedOut {
    password_group: usize,
    #[serde(rename = "itemIds")]
    item_ids: Vec<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WeakOut {
    item_id: String,
    score: u8,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OldOut {
    item_id: String,
    days: i64,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct BreachedOut {
    item_id: String,
    count: u32,
}
#[derive(Serialize)]
pub struct AuditOut {
    reused: Vec<ReusedOut>,
    weak: Vec<WeakOut>,
    old: Vec<OldOut>,
    breached: Vec<BreachedOut>,
    score: u8,
}

/// Run the audit with a given HIBP client and shape it for the UI. Splitting the client out lets
/// the Health tab render the *instant* local checks (reused/weak/old) first via `NoHibp`, then
/// fill in the slow network breach check via `RealHibp` — so the tab no longer blocks on HIBP.
async fn audit_with(state: &State<'_, AppState>, hibp: &dyn HibpClient) -> R<AuditOut> {
    let items = {
        let inner = state.inner.lock().unwrap();
        inner
            .vault
            .list_envelopes()?
            .iter()
            .filter_map(|e| inner.session.open(e).ok())
            .collect::<Vec<_>>()
    };
    let report = run_audit(&items, now(), hibp).await;
    Ok(AuditOut {
        reused: report
            .reused
            .iter()
            .enumerate()
            .map(|(i, g)| ReusedOut {
                password_group: i,
                item_ids: g.item_ids.iter().map(|u| u.to_string()).collect(),
            })
            .collect(),
        weak: report
            .weak
            .iter()
            .map(|(id, s)| WeakOut {
                item_id: id.to_string(),
                score: *s,
            })
            .collect(),
        old: report
            .old
            .iter()
            .map(|(id, d)| OldOut {
                item_id: id.to_string(),
                days: *d,
            })
            .collect(),
        breached: report
            .breached
            .iter()
            .map(|(id, c)| BreachedOut {
                item_id: id.to_string(),
                count: *c,
            })
            .collect(),
        score: report.score,
    })
}

/// Full audit including the live HIBP breach check (the breach part needs the network, so it may
/// take a moment on first load).
#[tauri::command]
pub async fn health_audit(state: State<'_, AppState>) -> R<AuditOut> {
    audit_with(&state, &RealHibp::default()).await
}

/// Instant local audit (reused / weak / old — no network). The Health tab renders this immediately,
/// then swaps in `health_audit` once the breach check returns.
#[tauri::command]
pub async fn health_audit_fast(state: State<'_, AppState>) -> R<AuditOut> {
    audit_with(&state, &NoHibp).await
}

// ---------------------------------------------------------------------------
// import (Bitwarden JSON/CSV, Chrome CSV) — parsed by core, sealed + stored here
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportOut {
    imported: usize,
    skipped: usize,
}

#[tauri::command]
pub fn vault_import(state: State<AppState>, kind: String, content: String) -> R<ImportOut> {
    let ts = now();
    let items = match kind.as_str() {
        "bitwarden_json" => sentinel_core::import::parse_bitwarden_json(&content, ts),
        "bitwarden_csv" => sentinel_core::import::parse_bitwarden_csv(&content, ts),
        "chrome_csv" => sentinel_core::import::parse_chrome_csv(&content, ts),
        _ => return Err(err("bad_kind", "unsupported import format")),
    }
    .map_err(ApiError::from)?;

    let inner = state.inner.lock().unwrap();
    let mut imported = 0usize;
    let mut skipped = 0usize;
    for it in items {
        match inner
            .session
            .seal(&it)
            .and_then(|env| inner.vault.upsert(&env))
        {
            Ok(()) => imported += 1,
            Err(_) => skipped += 1,
        }
    }
    Ok(ImportOut { imported, skipped })
}

// ---------------------------------------------------------------------------
// settings (persisted to <data_dir>/settings.json)
// ---------------------------------------------------------------------------

fn default_settings() -> serde_json::Value {
    serde_json::json!({
        "theme": "dark",
        "reducedMotion": false,
        "autoLockMinutes": 10,
        "clipboardClearSeconds": 30,
        "killSwitchDefault": true,
        "defaultRegion": "us-east",
        "ssidAllowlist": ["home", "office"],
        "tunnelMode": "full",
        "splitRoutes": [],
        "telemetry": false
    })
}

#[tauri::command]
pub fn settings_get(state: State<AppState>) -> serde_json::Value {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    let path = dir.join("settings.json");
    let mut v = default_settings();
    if let Ok(text) = std::fs::read_to_string(&path) {
        if let Ok(stored) = serde_json::from_str::<serde_json::Value>(&text) {
            if let (Some(base), Some(over)) = (v.as_object_mut(), stored.as_object()) {
                for (k, val) in over {
                    base.insert(k.clone(), val.clone());
                }
            }
        }
    }
    if let Some(obj) = v.as_object_mut() {
        obj.insert("telemetry".into(), serde_json::Value::Bool(false));
    }
    v
}

#[tauri::command]
pub fn settings_set(state: State<AppState>, patch: serde_json::Value) -> R<()> {
    let dir = { state.inner.lock().unwrap().data_dir.clone() };
    let path = dir.join("settings.json");
    let mut cur = std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .unwrap_or_else(default_settings);
    if let (Some(obj), Some(p)) = (cur.as_object_mut(), patch.as_object()) {
        for (k, val) in p {
            obj.insert(k.clone(), val.clone());
        }
        obj.insert("telemetry".into(), serde_json::Value::Bool(false));
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&cur).unwrap_or_default(),
    )
    .map_err(|e| err("io", e.to_string()))?;
    Ok(())
}
