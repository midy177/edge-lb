//! xDS-like gRPC control plane facade.
//!
//! Gateways publish desired network snapshots; backends subscribe, ACK the
//! accepted version, and apply the snapshot directly to the backend datapath.

use anyhow::Result;

use crate::config::Config;

mod auth;
mod backend;
mod gateway;
pub mod pb;
mod peer;
mod registry;
mod snapshot;

pub fn spawn_gateway(cfg: &Config) {
    gateway::spawn(cfg);
}

pub fn run_backend(cfg: &Config) -> Result<()> {
    backend::run(cfg)
}

pub fn merge_active_backend_subscriptions(cfg: &mut Config) -> Result<bool> {
    registry::merge_into(&mut cfg.file)
}

pub fn active_backend_subscriptions_status() -> Result<serde_json::Value> {
    registry::status()
}

pub fn active_backend_nodes(cfg: &Config) -> Result<Vec<crate::config::BackendNode>> {
    registry::active_backend_nodes(&cfg.file)
}

pub fn pair_gateway(
    cfg: &Config,
    endpoint: &str,
    bootstrap_token: &str,
    desired: &crate::runtime::ha::GatewayHaRuntimeConfig,
) -> Result<peer::PairGatewayResult> {
    peer::pair_gateway(cfg, endpoint, bootstrap_token, desired)
}
