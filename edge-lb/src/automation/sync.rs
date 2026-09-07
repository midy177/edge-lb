use anyhow::{Result, bail};
use serde::Serialize;

use super::{model::AutomationConfig, store};
use crate::{
    config::Config,
    runtime::{
        ha,
        ha_write::{self, WriteRole},
    },
};

#[derive(Debug, Clone, Serialize)]
pub struct SyncResult {
    pub status: String,
    pub authority: String,
    pub forwarded_to: Option<String>,
    pub replicated_to: Option<String>,
}

pub fn save_authoritative(cfg: &Config, value: &AutomationConfig) -> Result<SyncResult> {
    match ha_write::write_role(cfg)? {
        WriteRole::LocalMaster(peer) => save_as_master(cfg, value, peer),
        WriteRole::Backup(peer) => forward_to_master(cfg, &peer, value),
    }
}

pub fn save_from_peer_active(cfg: &Config, value: &AutomationConfig) -> Result<SyncResult> {
    let WriteRole::LocalMaster(peer) = ha_write::write_role(cfg)? else {
        bail!("local gateway is not MASTER");
    };
    save_as_master(cfg, value, peer)
}

pub fn save_from_peer_replica(cfg: &Config, value: &AutomationConfig) -> Result<SyncResult> {
    store::save(cfg, value)?;
    Ok(SyncResult {
        status: "replica_saved".to_string(),
        authority: cfg.node_name.clone(),
        forwarded_to: None,
        replicated_to: None,
    })
}

fn save_as_master(
    cfg: &Config,
    value: &AutomationConfig,
    peer: Option<ha::GatewayHaPeer>,
) -> Result<SyncResult> {
    store::save(cfg, value)?;
    let replicated_to = match peer {
        Some(peer) => {
            put_peer_config(
                cfg,
                &peer,
                "/api/v1/ha/peer/automation-templates/replica",
                value,
            )?;
            Some(peer.name)
        }
        None => None,
    };
    Ok(SyncResult {
        status: "saved".to_string(),
        authority: cfg.node_name.clone(),
        forwarded_to: None,
        replicated_to,
    })
}

fn forward_to_master(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    value: &AutomationConfig,
) -> Result<SyncResult> {
    put_peer_config(
        cfg,
        peer,
        "/api/v1/ha/peer/automation-templates/active",
        value,
    )?;
    Ok(SyncResult {
        status: "forwarded".to_string(),
        authority: peer.name.clone(),
        forwarded_to: Some(peer.name.clone()),
        replicated_to: Some(cfg.node_name.clone()),
    })
}

fn put_peer_config(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    path: &str,
    value: &AutomationConfig,
) -> Result<()> {
    let response = ha_write::put_peer_json(cfg, peer, path, value)?;
    if !(200..300).contains(&response.status) {
        bail!(
            "HA peer automation sync {} failed with HTTP {}: {}",
            peer.name,
            response.status,
            response.body
        );
    }
    Ok(())
}
