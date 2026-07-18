//! Vault item model. These structs represent an item's *plaintext*; they exist only
//! in memory while the vault is unlocked and are sealed per-item at rest.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type ItemId = Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ItemType {
    Login,
    Note,
    Card,
    Identity,
}

/// How a saved URL is matched against a page origin during autofill.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UrlMode {
    /// Registrable-domain match (default): login.example.co.uk ~ example.co.uk.
    Domain,
    /// Exact host match.
    Host,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlMatch {
    pub url: String,
    pub mode: UrlMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub secret: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Per-entry TOTP as an `otpauth://` URI or bare base32 secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Card {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cardholder: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brand: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_month: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp_year: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cvv: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// A full vault item (plaintext).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: ItemId,
    #[serde(rename = "type")]
    pub item_type: ItemType,
    pub title: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub urls: Vec<UrlMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<Login>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card: Option<Card>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Identity>,
    pub created_at: i64,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_changed_at: Option<i64>,
}

impl Item {
    /// A new login with sensible defaults and matching timestamps.
    pub fn new_login(title: impl Into<String>, now: i64) -> Self {
        Item {
            id: Uuid::new_v4(),
            item_type: ItemType::Login,
            title: title.into(),
            tags: vec![],
            urls: vec![],
            notes: None,
            custom_fields: vec![],
            login: Some(Login::default()),
            card: None,
            identity: None,
            created_at: now,
            updated_at: now,
            password_changed_at: Some(now),
        }
    }

    /// The item's primary password, if it is a login.
    pub fn password(&self) -> Option<&str> {
        self.login.as_ref().and_then(|l| l.password.as_deref())
    }

    /// The item's username, if any.
    pub fn username(&self) -> Option<&str> {
        self.login.as_ref().and_then(|l| l.username.as_deref())
    }
}
