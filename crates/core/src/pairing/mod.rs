//! Device pairing: the E2E channel, the QR ceremony payload, and the pinned-device
//! record used to gate later unlock approvals.

pub mod channel;

pub use channel::{parse_public, transcript, verification_code, Channel, PairKey, Role};

use serde::{Deserialize, Serialize};

/// The QR payload the desktop shows during pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QrPayload {
    pub v: u8,
    pub pairing_id: String,
    pub relay_url: String,
    /// base64 SEC1 desktop ephemeral public key.
    pub desktop_pub: String,
    /// Expiry (unix seconds).
    pub expires: i64,
}

/// A paired device: its pinned public key never changes after pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedDevice {
    pub pairing_id: String,
    /// base64 SEC1 phone public key, pinned forever.
    pub phone_pub: String,
    pub created_at: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_payload_round_trips() {
        let qr = QrPayload {
            v: 1,
            pairing_id: "abc".into(),
            relay_url: "https://sync.local".into(),
            desktop_pub: "BASE64==".into(),
            expires: 1_780_000_000,
        };
        let json = serde_json::to_string(&qr).unwrap();
        assert!(json.contains("\"pairingId\""));
        assert!(json.contains("\"desktopPub\""));
        let back: QrPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(qr, back);
    }
}
