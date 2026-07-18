//! sentinel-cli — developer/demo driver.
//!
//! Subcommands:
//!   seed --json         emit the demo bundle for the mock bridge (seed.json)
//!   recovery-pdf PATH    render a sample recovery-kit PDF to PATH
//!   audit                print a health audit of the seeded vault
//!   version

use sentinel_core::health::{run_audit, MockHibp};
use sentinel_core::recovery_kit::{self, pdf, RecoveryKey};
use sentinel_core::seed;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("seed") => cmd_seed(&args[1..]),
        Some("recovery-pdf") => cmd_recovery_pdf(&args[1..]),
        Some("audit") => cmd_audit(),
        Some("version") | None => println!("sentinel-cli {}", env!("CARGO_PKG_VERSION")),
        Some(other) => {
            eprintln!("unknown subcommand: {other}");
            std::process::exit(2);
        }
    }
}

fn cmd_seed(args: &[String]) {
    let bundle = seed::demo_bundle();
    if args.iter().any(|a| a == "--json") {
        println!("{}", serde_json::to_string_pretty(&bundle).unwrap());
    } else {
        eprintln!(
            "{} demo items, {} regions",
            bundle.items.len(),
            bundle.regions.len()
        );
    }
}

fn cmd_recovery_pdf(args: &[String]) {
    let path = args
        .first()
        .map(String::as_str)
        .unwrap_or("recovery-kit.pdf");
    let rk = RecoveryKey::random();
    let display = recovery_kit::encode(&rk);
    let bytes = pdf::render_kit_pdf(&display, "demo@example.com", "2026-06-01");
    std::fs::write(path, bytes).expect("write pdf");
    eprintln!("wrote {path} ({display})");
}

fn cmd_audit() {
    let items = seed::demo_items();
    let report = tokio_block(run_audit(&items, seed::DEMO_NOW, &MockHibp));
    println!("Health score: {}/100", report.score);
    println!("  reused groups: {}", report.reused.len());
    println!("  weak:          {}", report.weak.len());
    println!("  old:           {}", report.old.len());
    println!("  breached:      {}", report.breached.len());
}

/// Minimal blocking executor so the CLI can call the async audit without pulling a
/// full runtime dependency into this bin.
fn tokio_block<F: std::future::Future>(fut: F) -> F::Output {
    use std::task::{Context, Poll};
    let mut fut = Box::pin(fut);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        // The audit's only await points (MockHibp) are immediately ready, so this
        // spin never actually loops in practice.
    }
}

fn noop_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    fn no_op(_: *const ()) {}
    fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}
