//! sentinel-desktop — Tauri shell entry point. Registers the command handlers (each a
//! thin call into sentinel-core) and the app state.

// Hide the console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

fn main() {
    tauri::Builder::default()
        .manage(state::AppState::new_demo())
        .invoke_handler(tauri::generate_handler![
            commands::vault_list,
            commands::vault_reveal_field,
            commands::lock,
            commands::keyring_status,
            commands::generator_password,
            commands::generator_passphrase,
            commands::health_audit,
            commands::vpn_regions,
            commands::vpn_connect,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SENTINEL");
}
