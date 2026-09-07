//! Backend nftables return-path facade.

use anyhow::Result;

use crate::config::Config;

use super::{nft, route};

pub struct ManagedReturnPath;

impl ManagedReturnPath {
    fn nft() -> Self {
        Self
    }
}

pub fn apply(cfg: &Config) -> Result<()> {
    if cfg.backend_return_ports().is_empty() {
        nft::delete_table(cfg);
        return Ok(());
    }
    nft::apply(cfg)
}

pub fn apply_managed_reusing(
    cfg: &Config,
    _existing: Option<ManagedReturnPath>,
) -> Result<ManagedReturnPath> {
    if cfg.backend_return_ports().is_empty() {
        nft::delete_table(cfg);
    } else {
        nft::apply(cfg)?;
    }
    Ok(ManagedReturnPath::nft())
}

pub fn ensure_policy_routing(cfg: &Config) -> Result<()> {
    route::ensure_policy_routing(cfg)
}

pub fn cleanup(cfg: &Config) -> Result<()> {
    nft::delete_table(cfg);
    route::cleanup_policy_routing(cfg);
    Ok(())
}

pub fn heal(cfg: &Config) -> Result<()> {
    if cfg.backend_return_ports().is_empty() {
        nft::delete_table(cfg);
    } else if !nft::table_exists(cfg) {
        nft::apply(cfg)?;
    }
    route::ensure_policy_routing(cfg)
}
