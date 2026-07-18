//! Deterministic demo data — the single source of truth for the seeded vault, VPN
//! regions, instance sizes, session history, and connection profiles. The CLI emits
//! this as `seed.json` for the in-browser mock bridge (D14), and tests use the item
//! list directly. Realistic on purpose (no lorem ipsum): includes deliberately
//! reused / weak / breached passwords so the health screen has real findings.

use crate::vault::model::{Card, Identity, Item, ItemType, Login, UrlMatch, UrlMode};
use serde::Serialize;
use uuid::Uuid;

/// Stable base timestamp for reproducible demo data (2026-06-01T12:00:00Z).
pub const DEMO_NOW: i64 = 1_780_660_800;
const DAY: i64 = 86_400;

fn uid(n: u8) -> Uuid {
    Uuid::from_bytes([n; 16])
}

fn login(n: u8, title: &str, url: &str, user: &str, pass: &str, changed_days_ago: i64) -> Item {
    let mut it = Item::new_login(title, DEMO_NOW);
    it.id = uid(n);
    it.urls = vec![UrlMatch {
        url: url.into(),
        mode: UrlMode::Domain,
    }];
    it.login = Some(Login {
        username: Some(user.into()),
        password: Some(pass.into()),
        totp: None,
    });
    it.password_changed_at = Some(DEMO_NOW - changed_days_ago * DAY);
    it
}

/// The 24-item demo vault.
pub fn demo_items() -> Vec<Item> {
    let mut items = vec![
        login(
            1,
            "GitHub",
            "https://github.com",
            "octocat",
            "Gh-9x!Kp2vLm@2026",
            40,
        ),
        login(
            2,
            "GitLab",
            "https://gitlab.com",
            "octocat",
            "hunter2-reused",
            320,
        ), // reused + breached + old
        login(
            3,
            "Bitbucket",
            "https://bitbucket.org",
            "octocat",
            "hunter2-reused",
            300,
        ), // reused
        login(
            4,
            "NPM",
            "https://npmjs.com",
            "octocat",
            "hunter2-reused",
            280,
        ), // reused
        login(
            5,
            "AWS Console",
            "https://aws.amazon.com",
            "sentinel-ops",
            "Aws#Prod-7431-xQ!z",
            20,
        ),
        login(
            6,
            "Google",
            "https://accounts.google.com",
            "jackson@example.com",
            "G00gle-strong-Pass-91!",
            55,
        ),
        login(
            7,
            "Cloudflare",
            "https://dash.cloudflare.com",
            "jackson@example.com",
            "Cf!edge-2026-Zx7q",
            15,
        ),
        login(
            8,
            "Linode",
            "https://cloud.linode.com",
            "sentinel-ops",
            "Ln0de-Ephemeral-88!x",
            10,
        ),
        login(
            9,
            "Fastmail",
            "https://fastmail.com",
            "jackson",
            "Fm-secure-mail-42-Qz!",
            70,
        ),
        login(
            10,
            "Reddit",
            "https://reddit.com",
            "throwaway99",
            "password",
            400,
        ), // weak + breached + old
        login(
            11,
            "Old Forum",
            "https://forum.example",
            "jb5470",
            "12345678",
            500,
        ), // weak + old
        login(
            12,
            "Stripe",
            "https://dashboard.stripe.com",
            "jackson@example.com",
            "Str!pe-live-key-guard-7",
            5,
        ),
        login(
            13,
            "Vercel",
            "https://vercel.com",
            "jackson",
            "Vrc3l-deploy-Zx91!q",
            30,
        ),
        login(
            14,
            "Discord",
            "https://discord.com",
            "jack#0001",
            "D!scord-chat-2026-Kp7",
            90,
        ),
        login(
            15,
            "Steam",
            "https://store.steampowered.com",
            "jbgamer",
            "St3am-lib-guard-Qx8!",
            120,
        ),
    ];

    // A login with TOTP.
    let mut proton = login(
        16,
        "Proton Mail",
        "https://proton.me",
        "jackson@proton.me",
        "Pr0ton-e2e-mail-Zq9!",
        60,
    );
    proton.login.as_mut().unwrap().totp =
        Some("otpauth://totp/Proton:jackson?secret=JBSWY3DPEHPK3PXP&issuer=Proton".into());
    items.push(proton);

    // Secure note.
    let mut note = Item::new_login("Server Recovery Codes", DEMO_NOW);
    note.id = uid(17);
    note.item_type = ItemType::Note;
    note.login = None;
    note.notes = Some("sentinel-demo-note-body: backup codes 4821-9930, 5567-1180".into());
    note.tags = vec!["infra".into()];
    items.push(note);

    // Card.
    let mut card = Item::new_login("Personal Visa", DEMO_NOW);
    card.id = uid(18);
    card.item_type = ItemType::Card;
    card.login = None;
    card.card = Some(Card {
        cardholder: Some("Jackson B".into()),
        number: Some("4242 4242 4242 4242".into()),
        brand: Some("Visa".into()),
        exp_month: Some(8),
        exp_year: Some(2029),
        cvv: Some("831".into()),
    });
    card.tags = vec!["finance".into()];
    items.push(card);

    // Identity.
    let mut id = Item::new_login("Primary Identity", DEMO_NOW);
    id.id = uid(19);
    id.item_type = ItemType::Identity;
    id.login = None;
    id.identity = Some(Identity {
        full_name: Some("Jackson B".into()),
        email: Some("jackson@example.com".into()),
        phone: Some("+1 555 0142".into()),
        address: Some("221B Baker Street".into()),
    });
    items.push(id);

    items.extend([
        login(
            20,
            "Netflix",
            "https://netflix.com",
            "jackson@example.com",
            "N3tflix-stream-Qz!7",
            100,
        ),
        login(
            21,
            "Spotify",
            "https://spotify.com",
            "jackson",
            "Sp0tify-music-guard-9!",
            110,
        ),
        login(
            22,
            "Amazon",
            "https://amazon.com",
            "jackson@example.com",
            "Amz!shop-2026-Kx7q",
            45,
        ),
        login(
            23,
            "PayPal",
            "https://paypal.com",
            "jackson@example.com",
            "PyPl-pay-secure-Zx9!q",
            25,
        ),
        login(
            24,
            "Bank of Example",
            "https://bankofexample.com",
            "jb5470",
            "B@nk-vault-2026-Qp7!z",
            12,
        ),
    ]);

    items
}

// --- frontend demo bundle -------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoBundle {
    pub generated_note: String,
    pub items: Vec<DemoItem>,
    pub regions: Vec<DemoRegion>,
    pub instance_types: Vec<DemoInstanceType>,
    pub history: Vec<DemoSession>,
    pub profiles: Vec<DemoProfile>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoItem {
    pub id: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub title: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub tags: Vec<String>,
    pub favicon_domain: Option<String>,
    pub has_totp: bool,
    pub totp_uri: Option<String>,
    pub urls: Vec<String>,
    pub notes: Option<String>,
    pub updated_at: String,
    pub password_changed_at: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoRegion {
    pub id: String,
    pub label: String,
    pub country: String,
    pub lat: f64,
    pub lon: f64,
    pub latency_ms: u32,
    pub median_down_mbps: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoInstanceType {
    pub id: String,
    pub label: String,
    pub vcpus: u32,
    pub memory_mb: u32,
    pub hourly_usd: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoSession {
    pub id: String,
    pub region: String,
    pub instance_type: String,
    pub started_at: String,
    pub ended_at: String,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub cost_usd: f64,
    pub peak_cpu_pct: u32,
    pub down_mbps: u32,
    pub up_mbps: u32,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DemoProfile {
    pub id: String,
    pub name: String,
    pub region_id: String,
    pub instance_type: String,
    pub kill_switch: bool,
    pub split_tunnel_apps: Vec<String>,
    pub ssid_triggers: Vec<String>,
}

fn iso(unix: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp(unix)
        .map(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default()
        })
        .unwrap_or_default()
}

fn favicon_domain(urls: &[UrlMatch]) -> Option<String> {
    urls.first().and_then(|u| {
        url::Url::parse(&u.url)
            .ok()
            .and_then(|p| p.host_str().map(|h| h.to_string()))
    })
}

/// Build the full frontend demo bundle.
pub fn demo_bundle() -> DemoBundle {
    let items = demo_items()
        .into_iter()
        .map(|it| DemoItem {
            id: it.id.to_string(),
            item_type: match it.item_type {
                ItemType::Login => "login",
                ItemType::Note => "note",
                ItemType::Card => "card",
                ItemType::Identity => "identity",
            }
            .to_string(),
            username: it.username().map(|s| s.to_string()),
            password: it.password().map(|s| s.to_string()),
            tags: it.tags.clone(),
            favicon_domain: favicon_domain(&it.urls),
            has_totp: it.login.as_ref().and_then(|l| l.totp.as_ref()).is_some(),
            totp_uri: it.login.as_ref().and_then(|l| l.totp.clone()),
            urls: it.urls.iter().map(|u| u.url.clone()).collect(),
            notes: it.notes.clone(),
            updated_at: iso(it.updated_at),
            password_changed_at: it.password_changed_at.map(iso),
            title: it.title,
        })
        .collect();

    DemoBundle {
        generated_note: "Generated by `sentinel-cli seed --json`.".into(),
        items,
        regions: demo_regions(),
        instance_types: demo_instance_types(),
        history: demo_history(),
        profiles: demo_profiles(),
    }
}

pub fn demo_regions() -> Vec<DemoRegion> {
    vec![
        DemoRegion {
            id: "us-east".into(),
            label: "Newark, NJ".into(),
            country: "US".into(),
            lat: 40.74,
            lon: -74.17,
            latency_ms: 18,
            median_down_mbps: 940,
        },
        DemoRegion {
            id: "us-west".into(),
            label: "Fremont, CA".into(),
            country: "US".into(),
            lat: 37.55,
            lon: -121.99,
            latency_ms: 62,
            median_down_mbps: 880,
        },
        DemoRegion {
            id: "eu-central".into(),
            label: "Frankfurt".into(),
            country: "DE".into(),
            lat: 50.11,
            lon: 8.68,
            latency_ms: 96,
            median_down_mbps: 910,
        },
        DemoRegion {
            id: "eu-west".into(),
            label: "London".into(),
            country: "GB".into(),
            lat: 51.51,
            lon: -0.13,
            latency_ms: 88,
            median_down_mbps: 900,
        },
        DemoRegion {
            id: "ap-south".into(),
            label: "Singapore".into(),
            country: "SG".into(),
            lat: 1.35,
            lon: 103.82,
            latency_ms: 214,
            median_down_mbps: 760,
        },
        DemoRegion {
            id: "ap-northeast".into(),
            label: "Tokyo".into(),
            country: "JP".into(),
            lat: 35.68,
            lon: 139.69,
            latency_ms: 156,
            median_down_mbps: 820,
        },
        DemoRegion {
            id: "ap-southeast".into(),
            label: "Sydney".into(),
            country: "AU".into(),
            lat: -33.87,
            lon: 151.21,
            latency_ms: 198,
            median_down_mbps: 700,
        },
        DemoRegion {
            id: "sa-east".into(),
            label: "São Paulo".into(),
            country: "BR".into(),
            lat: -23.55,
            lon: -46.63,
            latency_ms: 128,
            median_down_mbps: 680,
        },
    ]
}

pub fn demo_instance_types() -> Vec<DemoInstanceType> {
    vec![
        DemoInstanceType {
            id: "g6-nanode-1".into(),
            label: "Nanode 1GB".into(),
            vcpus: 1,
            memory_mb: 1024,
            hourly_usd: 0.0075,
        },
        DemoInstanceType {
            id: "g6-standard-2".into(),
            label: "Linode 4GB".into(),
            vcpus: 2,
            memory_mb: 4096,
            hourly_usd: 0.036,
        },
        DemoInstanceType {
            id: "g6-standard-4".into(),
            label: "Linode 8GB".into(),
            vcpus: 4,
            memory_mb: 8192,
            hourly_usd: 0.072,
        },
        DemoInstanceType {
            id: "g6-dedicated-4".into(),
            label: "Dedicated 8GB".into(),
            vcpus: 4,
            memory_mb: 8192,
            hourly_usd: 0.108,
        },
    ]
}

pub fn demo_history() -> Vec<DemoSession> {
    let base = DEMO_NOW - 20 * DAY;
    let regions = [
        "us-east",
        "eu-central",
        "eu-west",
        "ap-northeast",
        "us-east",
        "us-west",
    ];
    (0..18)
        .map(|i| {
            let start = base + i * DAY + (i % 3) * 3600;
            let dur = 1800 + (i % 5) * 1200;
            let region = regions[(i as usize) % regions.len()];
            let rx = 200_000_000u64 + (i as u64) * 47_000_000;
            DemoSession {
                id: format!("sess-{i:02}"),
                region: region.into(),
                instance_type: if i % 4 == 0 {
                    "g6-standard-2"
                } else {
                    "g6-nanode-1"
                }
                .into(),
                started_at: iso(start),
                ended_at: iso(start + dur),
                bytes_rx: rx,
                bytes_tx: rx / 6,
                cost_usd: (dur as f64 / 3600.0) * 0.0075,
                peak_cpu_pct: 30 + (i as u32 * 7) % 60,
                down_mbps: 420 + (i as u32 * 23) % 500,
                up_mbps: 180 + (i as u32 * 11) % 220,
            }
        })
        .collect()
}

pub fn demo_profiles() -> Vec<DemoProfile> {
    vec![
        DemoProfile {
            id: "max-privacy".into(),
            name: "Max Privacy".into(),
            region_id: "eu-central".into(),
            instance_type: "g6-nanode-1".into(),
            kill_switch: true,
            split_tunnel_apps: vec![],
            ssid_triggers: vec!["*".into()],
        },
        DemoProfile {
            id: "streaming".into(),
            name: "Streaming".into(),
            region_id: "us-east".into(),
            instance_type: "g6-standard-2".into(),
            kill_switch: false,
            split_tunnel_apps: vec!["com.netflix.app".into()],
            ssid_triggers: vec![],
        },
        DemoProfile {
            id: "eu-testing".into(),
            name: "EU Testing".into(),
            region_id: "eu-west".into(),
            instance_type: "g6-nanode-1".into(),
            kill_switch: false,
            split_tunnel_apps: vec![],
            ssid_triggers: vec![],
        },
        DemoProfile {
            id: "public-wifi".into(),
            name: "Public WiFi".into(),
            region_id: "us-east".into(),
            instance_type: "g6-nanode-1".into(),
            kill_switch: true,
            split_tunnel_apps: vec![],
            ssid_triggers: vec!["airport-wifi".into(), "cafe-guest".into()],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twenty_four_items_with_variety() {
        let items = demo_items();
        assert_eq!(items.len(), 24);
        assert!(items.iter().any(|i| i.item_type == ItemType::Card));
        assert!(items.iter().any(|i| i.item_type == ItemType::Note));
        assert!(items.iter().any(|i| i.item_type == ItemType::Identity));
        assert!(items
            .iter()
            .any(|i| i.login.as_ref().and_then(|l| l.totp.as_ref()).is_some()));
    }

    #[test]
    fn bundle_serializes_to_camel_case_json() {
        let bundle = demo_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        assert!(json.contains("\"instanceTypes\""));
        assert!(json.contains("\"faviconDomain\""));
        assert!(json.contains("\"killSwitch\""));
        assert_eq!(bundle.regions.len(), 8);
        assert_eq!(bundle.profiles.len(), 4);
    }
}
