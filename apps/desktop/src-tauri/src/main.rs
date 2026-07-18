//! sentinel-desktop — Tauri shell entry point.
//!
//! Tauri command handlers are 1-line-per-command glue into `sentinel-core` and are
//! wired in Phase 1 once the command surface stabilizes. Kept minimal here so the
//! crate compiles without the full Tauri toolchain during core development.

fn main() {
    eprintln!(
        "sentinel-desktop {} (Tauri glue: Phase 1)",
        env!("CARGO_PKG_VERSION")
    );
}
