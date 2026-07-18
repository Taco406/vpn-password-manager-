//! sentinel-desktop — Tauri shell entry point. Opens the persistent vault (keyed from the
//! OS keychain) in the app-data dir, then registers the command handlers (each a thin call
//! into sentinel-core).

// Hide the console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir().join("sentinel"));
            match state::AppState::new_persistent(data_dir) {
                Ok(s) => {
                    app.manage(s);
                }
                Err(e) => {
                    eprintln!("SENTINEL: could not open persistent vault ({e}); running in-memory");
                    app.manage(state::AppState::new_memory_fallback());
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::keyring_status,
            commands::lock,
            commands::unlock_platform,
            commands::unlock_recovery,
            commands::unlock_phone_begin,
            commands::unlock_phone_await,
            commands::vault_list,
            commands::vault_get,
            commands::vault_reveal_field,
            commands::vault_save,
            commands::vault_delete,
            commands::vault_totp,
            commands::generator_password,
            commands::generator_passphrase,
            commands::health_audit,
            commands::settings_get,
            commands::settings_set,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SENTINEL");
}
