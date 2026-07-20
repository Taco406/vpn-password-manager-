//! sentinel-desktop — Tauri shell entry point. Opens the persistent vault (keyed from the
//! OS keychain) in the app-data dir, then registers the command handlers (each a thin call
//! into sentinel-core).

// Hide the console window on Windows in release.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod applock;
mod applog;
mod commands;
mod hello;
mod nmhost;
mod state;
mod sync;
mod vpn;

use tauri::Manager;

fn main() {
    // When Chrome/Edge launch us as their native-messaging host they pass the extension
    // origin as an argument. Detect that before building the UI and run the stdio host
    // loop instead (see nmhost). A normal double-click never takes this path.
    if nmhost::is_host_mode() {
        nmhost::run();
        return;
    }

    // Headless VPN self-test: `SENTINEL --vpn-selftest [region]` runs a real end-to-end connect
    // (minimal routing, no full-tunnel), verifies the WireGuard handshake, destroys the node, and
    // exits with 0/1. Lets the shipped app double as a live VPN tester for a human or a CI runner.
    if let Some(region) = vpn::selftest_region() {
        vpn::run_selftest(region); // diverges (exits the process)
    }

    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .setup(|app| {
            // SAFETY: unconditionally clear any stale kill-switch firewall rules FIRST, before
            // anything else, so a crash/kill while connected can never leave the user offline.
            vpn::killswitch_clear_all();
            // Also scrub any WireGuard routing/DNS leftovers from an unclean prior teardown, so the
            // app self-heals a stranded connection on the very next launch (no netsh needed).
            vpn::flush_wg_network();

            let data_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir().join("sentinel"));
            match state::AppState::new_persistent(data_dir.clone()) {
                Ok(s) => {
                    app.manage(s);
                }
                Err(e) => {
                    eprintln!("SENTINEL: could not open persistent vault ({e}); running in-memory");
                    app.manage(state::AppState::new_memory_fallback());
                }
            }
            // If real VPN is configured, reap any orphaned ephemeral nodes from a prior crash
            // (keeping any nodes the user deliberately kept — see the VPN node registry).
            vpn::sweep_on_launch(data_dir);
            // Background poller: auto-connect on untrusted Wi-Fi (opt-in; self-gating each tick).
            vpn::spawn_autoconnect_poller(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::keyring_status,
            commands::lock,
            commands::unlock_platform,
            commands::hello_status,
            commands::hello_set,
            commands::unlock_recovery,
            commands::unlock_phone_begin,
            commands::unlock_phone_await,
            applock::auth_status,
            applock::auth_set_password,
            applock::auth_unlock_password,
            applock::auth_change_password,
            applock::auth_remove_password,
            applock::applock_totp_enroll,
            applock::applock_totp_confirm,
            applock::applock_totp_disable,
            commands::vault_list,
            commands::vault_get,
            commands::vault_reveal_field,
            commands::vault_save,
            commands::vault_passkey_create,
            commands::vault_delete,
            commands::vault_totp,
            commands::vault_import,
            commands::generator_password,
            commands::generator_passphrase,
            commands::health_audit,
            commands::settings_get,
            commands::settings_set,
            vpn::vpn_config,
            vpn::vpn_set_token,
            vpn::vpn_regions_real,
            vpn::vpn_instance_types_real,
            vpn::vpn_connect,
            vpn::vpn_disconnect,
            vpn::vpn_state,
            vpn::vpn_cost_estimate,
            vpn::vpn_history,
            vpn::net_status,
            vpn::net_set,
            vpn::killswitch_clear,
            vpn::vpn_connect_multihop,
            vpn::vpn_disconnect_keep,
            vpn::vpn_nodes,
            vpn::vpn_cost_summary,
            vpn::vpn_node_action,
            vpn::vpn_nodes_destroy_all,
            vpn::wg_status,
            vpn::open_url,
            vpn::vpn_repair_tunnel,
            sync::sync_status,
            sync::sync_set_config,
            sync::auth_google_signin,
            sync::auth_totp_enroll,
            sync::auth_totp_verify,
            sync::auth_logout,
            sync::sync_backup,
            sync::sync_now,
            sync::sync_restore,
            sync::sync_devices,
            sync::sync_device_revoke,
            sync::sync_deploy,
            sync::sync_server_status,
            sync::sync_server_destroy,
            nmhost::autofill_status,
            nmhost::autofill_install,
            nmhost::autofill_uninstall,
            nmhost::autofill_prepare,
            nmhost::open_folder,
            applog::log_tail,
            applog::log_clear,
            applog::log_dir_path,
        ])
        .build(tauri::generate_context!())
        .expect("error while building SENTINEL")
        .run(|_app, event| {
            // SAFETY: on exit, tear down any kill-switch rules so quitting the app can never
            // leave the user's internet blocked (self-heal on next launch also covers crashes).
            if let tauri::RunEvent::Exit = event {
                vpn::killswitch_clear_all();
            }
        });
}
