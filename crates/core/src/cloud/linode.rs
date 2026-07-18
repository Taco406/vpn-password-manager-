//! Real Linode API v4 client (behind `live-linode`). Never compiled into normal test
//! builds; the token comes from the OS keychain, never from source.

#![cfg(feature = "live-linode")]

use super::provider::{
    CloudProvider, Instance, InstanceSpec, InstanceState, Region, EPHEMERAL_TAG,
};
use crate::error::{CoreError, Result};
use async_trait::async_trait;
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
}

fn map_state(status: &str) -> InstanceState {
    match status {
        "provisioning" | "migrating" | "rebuilding" => InstanceState::Provisioning,
        "booting" | "rebooting" => InstanceState::Booting,
        "running" => InstanceState::Running,
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
        let body = serde_json::json!({
            "region": spec.region,
            "type": spec.instance_type,
            "label": spec.label,
            "image": "linode/debian12",
            "root_pass": self.root_pass,
            "tags": [EPHEMERAL_TAG],
            "backups_enabled": false,
            "private_ip": false,
            "metadata": { "user_data": spec.user_data },
        });
        let inst: LinodeInstance = self
            .http
            .post(format!("{API}/linode/instances"))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(Self::net)?
            .error_for_status()
            .map_err(Self::net)?
            .json()
            .await
            .map_err(Self::net)?;
        Ok(inst.into())
    }

    async fn get(&self, id: &str) -> Result<Instance> {
        let inst: LinodeInstance = self
            .http
            .get(format!("{API}/linode/instances/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?
            .error_for_status()
            .map_err(Self::net)?
            .json()
            .await
            .map_err(Self::net)?;
        Ok(inst.into())
    }

    async fn delete(&self, id: &str) -> Result<()> {
        self.http
            .delete(format!("{API}/linode/instances/{id}"))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(Self::net)?
            .error_for_status()
            .map_err(Self::net)?;
        Ok(())
    }

    async fn list_ephemeral(&self) -> Result<Vec<Instance>> {
        #[derive(Deserialize)]
        struct Page {
            data: Vec<LinodeInstance>,
        }
        let filter = serde_json::json!({ "tags": EPHEMERAL_TAG }).to_string();
        let page: Page = self
            .http
            .get(format!("{API}/linode/instances"))
            .bearer_auth(&self.token)
            .header("X-Filter", filter)
            .send()
            .await
            .map_err(Self::net)?
            .error_for_status()
            .map_err(Self::net)?
            .json()
            .await
            .map_err(Self::net)?;
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
        let page: Page = self
            .http
            .get(format!("{API}/regions"))
            .send()
            .await
            .map_err(Self::net)?
            .json()
            .await
            .map_err(Self::net)?;
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
}
