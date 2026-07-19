//! Single-boot provisioning of the ephemeral WireGuard server.

pub mod callback;
pub mod cloudinit;

pub use callback::{compute_mac, verify_callback, CallbackBody};
pub use cloudinit::{
    render, render_base64, render_sync, render_sync_base64, CloudInitParams, NextHop,
    SyncServerParams,
};
