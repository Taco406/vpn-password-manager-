//! Real Linode API v4 client (behind `live-linode`). Never compiled into normal test
//! builds; the token comes from the OS keychain, never from source.

#![cfg(feature = "live-linode")]

use super::provider::{
    CloudProvider, Instance, InstanceSpec, InstanceState, Region, EPHEMERAL_TAG,
};
use crate::error::{CoreError, Result};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Deserialize;

const API: &str = "https://api.linode.com/v4";

pub struct LinodeClient {
    http: reqwest::Client,
    token: String,
    root_pass: String,
}

impl LinodeClient {
    pub fn new(token: impl Into<String>) -> Self {
        LinodeClient {
            http: reqwest::Client::new(),
            token: token.into(),
            // A random unused root password; SSH is disabled by cloud-init anyway.
            root_pass: {
                use rand::RngCore;
                let mut b = [0u8; 24];
                rand::rngs::OsRng.fill_bytes(&mut b);
                base64::engine::general_purpose::STANDARD_NO_PAD.encode(b)
            },
        }
    }

    fn net(e: reqwest::Error) -> CoreError {
        CoreError::Network(e.to_string())
    }

    /// Read a Linode error response body and pull out its human reason. Linode returns
    /// `{"errors":[{"reason":"...","field":"..."}]}`; surfacing that (instead of a bare HTTP
    /// status) is what tells the user *why* a create failed — bad token scope, an un-activated
    /// account, an unsupported region, etc.
    fn linode_reason(status: reqwest::StatusCode, body: &str) -> CoreError {
        let reason = serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|v| {
                v.get("errors")
                    .and_then(|e| e.get(0))
                    .map(|e0| {
                        let r = e0.get("reason").and_then(|r| r.as_str()).unwrap_or("");
                        match e0.get("field").and_then(|f| f.as_str()) {
                            Some(f) if !f.is_empty() => format!("{r} ({f})"),
                            _ => r.to_string(),
                        }
                    })
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| body.trim().chars().take(300).collect());
        CoreError::Network(format!("Linode API {}: {reason}", status.as_u16()))
    }

    /// Send a request and decode JSON, surfacing Linode's error reason on non-2xx.
    async fn json_ok<T: DeserializeOwned>(resp: reqwest::Response) -> Result<T> {
        let status = resp.status();
        let text = resp.text().await.map_err(Self::net)?;
        if !status.is_success() {
            return Err(Self::linode_reason(status, &text));
        }
        serde_json::from_str(&text)
            .map_err(|e| CoreError::Network(format!("Linode API: bad response ({e})")))
    }

    /// Send a request expecting an empty 2xx, surfacing Linode's error reason on non-2xx.
    async fn empty_ok(resp: reqwest::Response) -> Result<()> {
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let text = resp.text().await.unwrap_or_default();
        Err(Self::linode_reason(status, &text))
    }
}

fn map_state(status: &str) -> InstanceState {
    match status {
        "provisioning" | "migrating" | "rebuilding" => InstanceState::Provisioning,
        "booting" | "rebooting" => InstanceState::Booting,
        "running" => InstanceState::Running,
        "offline" | "stopped" => InstanceState::Stopped,
        "shutting_down" | "deleting" => InstanceState::Deleting,
        _ => InstanceState::Provisioning,
    }
}

#[derive(Deserialize)]
struct LinodeInstance {
    id: u64,
    region: String,
    #[serde(rename = "type")]
    kind: String,
    status: String,
    ipv4: Vec<String>,
    tags: Vec<String>,
}

impl From<LinodeInstance> for Instance {
    fn from(l: LinodeInstance) -> Self {
        Instance {
            id: l.id.to_string(),
            region: l.region,
            instance_type: l.kind,
            state: map_state(&l.status),
            ipv4: l.ipv4.into_iter().next(),
            tags: l.tags,
        }
    }
}

use base64::Engine as _;

#[async_trait]
impl CloudProvider for LinodeClient {
    async fn create(&self, spec: &InstanceSpec) -> Result<Instance> {
        // Empty tags = ephemeral (managed by the orphan sweep); a durable node passes its own.
        let tags: Vec<String> = if spec.tags.is_empty() {
            vec![EPHEMERAL_TAG.to_string()]
        } else {
            spec.tags.clone()
        };
        let body = serde_json::json!({
            "region": spec.region,
            "type": spec.instance_type,
            "label": spec.label,
            "image": "linode/debian12",
            "root_pass": self.root_pass,
            "tags": tags,
            "backups_enabled": false,
            "private_ip": false,
            "metadata": { "user_data": spec.user_data },
        });
        let resp = self
            .http
            .post(format!("{API}/linode/instances"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(Self::net)?;
        let inst: LinodeInstance = Self::json_ok(resp).await?;
        Ok(inst.into())
    }

    async fn get(&self, id: &str) -> Result<Instance> {
        let resp = self
            .http
            .get(format!("{API}/linode/instances/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        let inst: LinodeInstance = Self::json_ok(resp).await?;
        Ok(inst.into())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{API}/linode/instances/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        Self::empty_ok(resp).await
    }

    async fn list_ephemeral(&self) -> Result<Vec<Instance>> {
        #[derive(Deserialize)]
        struct Page {
            data: Vec<LinodeInstance>,
        }
        let filter = serde_json::json!({ "tags": EPHEMERAL_TAG }).to_string();
        let resp = self
            .http
            .get(format!("{API}/linode/instances"))
            .bearer_auth(&self.token)
            .header("X-Filter", filter)
            .send()
            .await
            .map_err(Self::net)?;
        let page: Page = Self::json_ok(resp).await?;
        Ok(page.data.into_iter().map(Instance::from).collect())
    }

    async fn regions(&self) -> Result<Vec<Region>> {
        #[derive(Deserialize)]
        struct Page {
            data: Vec<RegionRow>,
        }
        #[derive(Deserialize)]
        struct RegionRow {
            id: String,
            label: String,
            country: String,
        }
        let resp = self
            .http
            .get(format!("{API}/regions"))
            .send()
            .await
            .map_err(Self::net)?;
        let page: Page = Self::json_ok(resp).await?;
        Ok(page
            .data
            .into_iter()
            .map(|r| Region {
                id: r.id,
                label: r.label,
                country: r.country,
            })
            .collect())
    }

    fn price_per_hour(&self, instance_type: &str) -> f64 {
        match instance_type {
            "g6-nanode-1" => 0.0075,
            "g6-standard-2" => 0.036,
            "g6-standard-4" => 0.072,
            "g6-dedicated-4" => 0.108,
            _ => 0.0075,
        }
    }

    async fn shutdown(&self, id: &str) -> Result<()> {
        self.power(id, "shutdown").await
    }

    async fn boot(&self, id: &str) -> Result<()> {
        self.power(id, "boot").await
    }

    async fn reboot(&self, id: &str) -> Result<()> {
        self.power(id, "reboot").await
    }
}

impl LinodeClient {
    /// POST a power action (`boot`/`shutdown`/`reboot`) to a Linode instance.
    async fn power(&self, id: &str, action: &str) -> Result<()> {
        let resp = self
            .http
            .post(format!("{API}/linode/instances/{id}/{action}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?;
        Self::empty_ok(resp).await
    }
}
