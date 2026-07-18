//! sentinel-nm-host — Chrome native-messaging stdio host.
//!
//! Full message routing lands in Phase 5. This stub keeps the binary in the
//! workspace and documents the framing (u32 LE length prefix + UTF-8 JSON).

fn main() {
    eprintln!(
        "sentinel-nm-host {} (protocol wiring: Phase 5)",
        env!("CARGO_PKG_VERSION")
    );
}
