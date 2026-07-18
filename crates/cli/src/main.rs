//! sentinel-cli — developer/demo driver.
//!
//! Subcommands are added as the core crate grows. For now it exposes crate wiring so
//! the workspace builds; `seed --json` and `recovery-pdf` land with Phases 1–2.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("version") | None => {
            println!("sentinel-cli {}", env!("CARGO_PKG_VERSION"));
        }
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(2);
        }
    }
}
