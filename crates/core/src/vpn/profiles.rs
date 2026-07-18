//! Connection profiles: named presets bundling region + instance size + kill switch +
//! split-tunnel rules + SSID triggers. Four are seeded (Max Privacy, Streaming, EU
//! Testing, Public WiFi).

use crate::error::{CoreError, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionProfile {
    pub id: String,
    pub name: String,
    pub region_id: String,
    pub instance_type: String,
    pub kill_switch: bool,
    pub split_tunnel_apps: Vec<String>,
    /// SSIDs that auto-trigger this profile ("*" = any untrusted network).
    pub ssid_triggers: Vec<String>,
}

impl ConnectionProfile {
    /// Validate a profile before saving.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(CoreError::Invalid("profile name required".into()));
        }
        if self.region_id.trim().is_empty() {
            return Err(CoreError::Invalid("profile region required".into()));
        }
        if self.instance_type.trim().is_empty() {
            return Err(CoreError::Invalid("profile instance type required".into()));
        }
        Ok(())
    }

    /// Does an SSID trigger this profile? "*" matches any network.
    pub fn triggered_by(&self, ssid: &str) -> bool {
        self.ssid_triggers.iter().any(|t| t == "*" || t == ssid)
    }
}

/// The four seeded profiles.
pub fn seeded() -> Vec<ConnectionProfile> {
    vec![
        ConnectionProfile {
            id: "max-privacy".into(),
            name: "Max Privacy".into(),
            region_id: "eu-central".into(),
            instance_type: "g6-nanode-1".into(),
            kill_switch: true,
            split_tunnel_apps: vec![],
            ssid_triggers: vec!["*".into()],
        },
        ConnectionProfile {
            id: "streaming".into(),
            name: "Streaming".into(),
            region_id: "us-east".into(),
            instance_type: "g6-standard-2".into(),
            kill_switch: false,
            split_tunnel_apps: vec!["com.netflix.app".into()],
            ssid_triggers: vec![],
        },
        ConnectionProfile {
            id: "eu-testing".into(),
            name: "EU Testing".into(),
            region_id: "eu-west".into(),
            instance_type: "g6-nanode-1".into(),
            kill_switch: false,
            split_tunnel_apps: vec![],
            ssid_triggers: vec![],
        },
        ConnectionProfile {
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
    fn four_seeded_profiles() {
        let p = seeded();
        assert_eq!(p.len(), 4);
        for prof in &p {
            prof.validate().unwrap();
        }
    }

    #[test]
    fn ssid_trigger_matching() {
        let profiles = seeded();
        let max_privacy = &profiles[0];
        assert!(max_privacy.triggered_by("any-network")); // "*"
        let public = profiles.iter().find(|p| p.id == "public-wifi").unwrap();
        assert!(public.triggered_by("airport-wifi"));
        assert!(!public.triggered_by("home"));
    }

    #[test]
    fn validation_rejects_empty() {
        let mut p = seeded()[0].clone();
        p.name = "".into();
        assert!(p.validate().is_err());
    }
}
