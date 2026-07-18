//! Tauri command surface. Each command is thin glue into `sentinel-core`; the frontend
//! calls these through the SentinelBridge contract. A representative set is wired here;
//! the remaining bridge methods follow the identical one-line-into-core pattern.

use crate::state::{vpn_deps, AppState};
use sentinel_core::generator::{self, PassphraseSpec, PasswordSpec};
use sentinel_core::health::{run_audit, MockHibp};
use sentinel_core::vault::model::ItemType;
use serde::Serialize;
use tauri::State;

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
type R<T> = Result<T, ApiError>;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ItemSummary {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    title: String,
    username: Option<String>,
    tags: Vec<String>,
    favicon_domain: Option<String>,
    has_totp: bool,
    updated_at: String,
    password_changed_at: Option<String>,
}

fn type_str(t: ItemType) -> &'static str {
    match t {
        ItemType::Login => "login",
        ItemType::Note => "note",
        ItemType::Card => "card",
        ItemType::Identity => "identity",
    }
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

#[tauri::command]
pub fn vault_list(state: State<AppState>) -> R<Vec<ItemSummary>> {
    let inner = state.inner.lock().unwrap();
    let mut out = Vec::new();
    for env in inner.vault.list_envelopes()? {
        let it = inner.session.open(&env)?;
        out.push(ItemSummary {
            id: it.id.to_string(),
            kind: type_str(it.item_type).into(),
            title: it.title.clone(),
            username: it.username().map(str::to_string),
            tags: it.tags.clone(),
            favicon_domain: it.urls.first().map(|u| u.url.clone()),
            has_totp: it.login.as_ref().and_then(|l| l.totp.as_ref()).is_some(),
            updated_at: iso(it.updated_at),
            password_changed_at: it.password_changed_at.map(iso),
        });
    }
    Ok(out)
}

#[tauri::command]
pub fn vault_reveal_field(state: State<AppState>, id: String, field: String) -> R<String> {
    let uid = id.parse().map_err(|_| ApiError {
        code: "bad_id".into(),
        message: "bad item id".into(),
    })?;
    let inner = state.inner.lock().unwrap();
    let env = inner.vault.get(uid)?.ok_or_else(|| ApiError {
        code: "not_found".into(),
        message: "no such item".into(),
    })?;
    let item = inner.session.open(&env)?;
    Ok(match field.as_str() {
        "password" => item.password().unwrap_or_default().to_string(),
        "username" => item.username().unwrap_or_default().to_string(),
        _ => String::new(),
    })
}

#[tauri::command]
pub fn lock(state: State<AppState>) -> R<()> {
    state.inner.lock().unwrap().session.lock();
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyringStatus {
    locked: bool,
    platform_wrapper: String,
}

#[tauri::command]
pub fn keyring_status(state: State<AppState>) -> KeyringStatus {
    use sentinel_core::keyring::KeyWrapper;
    let inner = state.inner.lock().unwrap();
    KeyringStatus {
        locked: inner.session.is_locked(),
        platform_wrapper: format!("{:?}", inner.platform.wrapper_type()),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Generated {
    value: String,
    score: u8,
    crack_display: String,
}

#[tauri::command]
pub fn generator_password(spec_len: usize, symbols: bool) -> R<Generated> {
    let spec = PasswordSpec {
        length: spec_len,
        symbols,
        ..Default::default()
    };
    let value = generator::password(&spec)?;
    let s = generator::assess(&value, &[]);
    Ok(Generated {
        value,
        score: s.score,
        crack_display: s.crack_display,
    })
}

#[tauri::command]
pub fn generator_passphrase(words: usize) -> R<Generated> {
    let (value, _entropy) = generator::passphrase(&PassphraseSpec {
        words,
        ..Default::default()
    })?;
    let s = generator::assess(&value, &[]);
    Ok(Generated {
        value,
        score: s.score,
        crack_display: s.crack_display,
    })
}

#[derive(Serialize)]
pub struct AuditSummary {
    score: u8,
    reused: usize,
    weak: usize,
    old: usize,
    breached: usize,
}

#[tauri::command]
pub async fn health_audit(state: State<'_, AppState>) -> R<AuditSummary> {
    // Collect decrypted items, then audit (the audit itself needs no session).
    let items = {
        let inner = state.inner.lock().unwrap();
        inner
            .vault
            .list_envelopes()?
            .iter()
            .filter_map(|e| inner.session.open(e).ok())
            .collect::<Vec<_>>()
    };
    let report = run_audit(&items, sentinel_core::seed::DEMO_NOW, &MockHibp).await;
    Ok(AuditSummary {
        score: report.score,
        reused: report.reused.iter().map(|g| g.item_ids.len()).sum(),
        weak: report.weak.len(),
        old: report.old.len(),
        breached: report.breached.len(),
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RegionOut {
    id: String,
    label: String,
    country: String,
    lat: f64,
    lon: f64,
    latency_ms: u32,
}

#[tauri::command]
pub fn vpn_regions() -> Vec<RegionOut> {
    sentinel_core::seed::demo_regions()
        .into_iter()
        .map(|r| RegionOut {
            id: r.id,
            label: r.label,
            country: r.country,
            lat: r.lat,
            lon: r.lon,
            latency_ms: r.latency_ms,
        })
        .collect()
}

/// Run the mock connect flow to completion and return the egress IP. The real,
/// event-streaming version emits `vpn:state`/`vpn:metrics` as the FSM advances.
#[tauri::command]
pub async fn vpn_connect(region: String, instance_type: String) -> R<String> {
    let deps = vpn_deps();
    let mut sink = |_s: sentinel_core::vpn::ConnectState| {};
    let conn = sentinel_core::vpn::connect(&deps, &region, &instance_type, &mut sink).await?;
    Ok(conn.instance.ipv4.unwrap_or_default())
}
