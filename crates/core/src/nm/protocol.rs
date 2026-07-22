//! Native-messaging message types. These serde shapes are mirrored in
//! `packages/shared/src/nmProtocol.ts`; golden JSON fixtures keep them in lockstep.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NmEnvelope {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: NmType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<NmError>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NmType {
    Hello,
    #[serde(rename = "status.subscribe")]
    StatusSubscribe,
    #[serde(rename = "status.event")]
    StatusEvent,
    #[serde(rename = "vault.search")]
    VaultSearch,
    #[serde(rename = "vault.fields.get")]
    VaultFieldsGet,
    #[serde(rename = "vault.totp.get")]
    VaultTotpGet,
    #[serde(rename = "vault.generate")]
    VaultGenerate,
    #[serde(rename = "vault.save_candidate")]
    VaultSaveCandidate,
    #[serde(rename = "vault.passkey.register")]
    VaultPasskeyRegister,
    #[serde(rename = "vault.passkey.assert")]
    VaultPasskeyAssert,
    #[serde(rename = "lock.event")]
    LockEvent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NmError {
    pub code: NmErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NmErrorCode {
    Locked,
    BadOrigin,
    NotFound,
    BadRequest,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultSearchRequest {
    pub query: String,
    pub origin: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSearchResultItem {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub favicon_domain: Option<String>,
    /// 0..1 — higher is a closer origin match.
    pub match_quality: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultFieldsGetRequest {
    pub id: String,
    pub fields: Vec<String>,
    pub origin: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusEvent {
    pub locked: bool,
    pub vpn: StatusVpn,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatusVpn {
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub rx: f64,
    pub tx: f64,
}

impl NmEnvelope {
    /// Build a `LOCKED` error reply carrying no credential data.
    pub fn locked(id: &str) -> Self {
        NmEnvelope {
            id: id.to_string(),
            kind: NmType::LockEvent,
            ok: Some(false),
            payload: None,
            err: Some(NmError {
                code: NmErrorCode::Locked,
                message: "vault is locked".into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_round_trips_json() {
        let env = NmEnvelope {
            id: "abc".into(),
            kind: NmType::VaultSearch,
            ok: Some(true),
            payload: Some(serde_json::json!({ "query": "git", "origin": "https://github.com" })),
            err: None,
        };
        let json = serde_json::to_string(&env).unwrap();
        assert!(json.contains("\"type\":\"vault.search\""));
        let back: NmEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }

    #[test]
    fn type_names_match_wire_format() {
        // These strings are the contract with the TS side; a golden check.
        let cases = [
            (NmType::Hello, "\"hello\""),
            (NmType::VaultFieldsGet, "\"vault.fields.get\""),
            (NmType::VaultSaveCandidate, "\"vault.save_candidate\""),
            (NmType::VaultPasskeyRegister, "\"vault.passkey.register\""),
            (NmType::VaultPasskeyAssert, "\"vault.passkey.assert\""),
            (NmType::LockEvent, "\"lock.event\""),
        ];
        for (t, want) in cases {
            assert_eq!(serde_json::to_string(&t).unwrap(), want);
        }
    }

    #[test]
    fn error_codes_are_screaming_snake() {
        assert_eq!(
            serde_json::to_string(&NmErrorCode::Locked).unwrap(),
            "\"LOCKED\""
        );
        assert_eq!(
            serde_json::to_string(&NmErrorCode::BadOrigin).unwrap(),
            "\"BAD_ORIGIN\""
        );
    }

    #[test]
    fn locked_reply_has_no_payload() {
        let env = NmEnvelope::locked("req-1");
        assert!(env.payload.is_none());
        assert_eq!(env.err.unwrap().code, NmErrorCode::Locked);
    }
}
