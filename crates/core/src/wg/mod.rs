//! WireGuard: key generation, config rendering, and tunnel control (real + mock).

pub mod config;
pub mod controller;
pub mod keys;

pub use config::{full_tunnel, render_client_conf, render_server_conf, ClientConf, ServerConf};
pub use controller::{
    cumulative_bytes, throughput_rate, MockWgController, WgController, WgCounters,
};
pub use keys::{validate_key, WgKeypair};
