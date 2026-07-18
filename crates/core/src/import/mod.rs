//! Importers (Bitwarden JSON/CSV, Chrome CSV) and exporters (encrypted, plaintext
//! CSV behind an explicit confirm). Importers produce plaintext [`Item`]s; the caller
//! seals and stores them.

pub mod bitwarden;
pub mod chrome;
pub mod csv;
pub mod export;

pub use bitwarden::{parse_bitwarden_csv, parse_bitwarden_json};
pub use chrome::parse_chrome_csv;
pub use export::{export_encrypted, export_plain_csv, import_encrypted};

/// Result of an import.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ImportReport {
    pub imported: usize,
    pub skipped: usize,
}
