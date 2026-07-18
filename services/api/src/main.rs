//! sentinel-api — the optional zero-knowledge sync backend.
//!
//! Routes, JWT/refresh, and the Postgres layer land in Phase 1. The schema
//! (migrations/) and its zero-knowledge constraints are authored first and tested
//! directly against Postgres.

fn main() {
    eprintln!(
        "sentinel-api {} (routes: Phase 1)",
        env!("CARGO_PKG_VERSION")
    );
}
