//! A tiny persistent diagnostics log. Errors and notable events are appended to
//! `<app_data>/logs/sentinel.log` (newest last), viewable in **Settings → Diagnostics**. It's
//! deliberately small: no secrets are ever logged (only error messages and high-level events),
//! and the file self-caps so it can't grow without bound.

use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

/// Max log size before it's truncated (keeps the file bounded on disk).
const MAX_BYTES: u64 = 256 * 1024;

fn log_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("com.sentinel.desktop")
        .join("logs")
}

fn log_file() -> PathBuf {
    log_dir().join("sentinel.log")
}

static LOCK: Mutex<()> = Mutex::new(());

/// Append a timestamped line. `level` e.g. "ERROR"/"INFO"; `scope` e.g. "vpn.connect".
pub fn log(level: &str, scope: &str, msg: &str) {
    let _guard = LOCK.lock();
    let ts = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let line = format!("{ts} [{level}] {scope}: {}\n", msg.replace('\n', " "));
    let _ = std::fs::create_dir_all(log_dir());
    // Truncate if it got large, so the log is always bounded.
    if std::fs::metadata(log_file())
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = std::fs::write(log_file(), b"");
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file())
    {
        let _ = f.write_all(line.as_bytes());
    }
    eprintln!("{}", line.trim_end());
}

/// Log an error (the common case).
pub fn error(scope: &str, msg: &str) {
    log("ERROR", scope, msg);
}

/// Log a notable event.
pub fn info(scope: &str, msg: &str) {
    log("INFO", scope, msg);
}

/// Return the last `limit` lines of the log (most recent last).
#[tauri::command]
pub fn log_tail(limit: usize) -> String {
    let content = std::fs::read_to_string(log_file()).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    let start = lines.len().saturating_sub(limit.max(1));
    lines[start..].join("\n")
}

/// Clear the log.
#[tauri::command]
pub fn log_clear() -> std::result::Result<(), String> {
    std::fs::write(log_file(), b"").map_err(|e| e.to_string())
}

/// The folder holding the log file (so the UI can offer "Open folder").
#[tauri::command]
pub fn log_dir_path() -> String {
    log_dir().to_string_lossy().to_string()
}
