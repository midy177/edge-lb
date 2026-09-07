//! Shared HA write-authority helpers for gateway-local configuration APIs.

use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::Serialize;

use crate::{config::Config, runtime::ha};

const MASTER: &str = "MASTER";
const BACKUP: &str = "BACKUP";
const STOP: &str = "STOP";

pub enum WriteRole {
    LocalMaster(Option<ha::GatewayHaPeer>),
    Backup(ha::GatewayHaPeer),
}

pub struct PeerHttpResponse {
    pub status: u16,
    pub body: String,
}

pub fn write_role(cfg: &Config) -> Result<WriteRole> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled {
        return Ok(WriteRole::LocalMaster(None));
    }
    let peer = ha_cfg.peers.first().cloned();
    let state = local_ha_state(cfg).unwrap_or_else(|e| {
        tracing::warn!("[ha-write] reading local HA state failed: {e:#}");
        active_gateway_state(cfg)
    });
    match state.as_deref() {
        Some(MASTER) => Ok(WriteRole::LocalMaster(peer)),
        Some(BACKUP | STOP) => peer
            .map(WriteRole::Backup)
            .context("local gateway is not MASTER and no HA peer is configured"),
        _ => {
            if active_gateway_is_local(cfg) {
                Ok(WriteRole::LocalMaster(peer))
            } else {
                peer.map(WriteRole::Backup)
                    .context("local gateway is not active and no HA peer is configured")
            }
        }
    }
}

pub fn put_peer_json<T: Serialize>(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    path: &str,
    value: &T,
) -> Result<PeerHttpResponse> {
    send_peer_json(cfg, peer, reqwest::Method::PUT, path, value)
}

pub fn post_peer_json<T: Serialize>(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    path: &str,
    value: &T,
) -> Result<PeerHttpResponse> {
    send_peer_json(cfg, peer, reqwest::Method::POST, path, value)
}

#[allow(dead_code)]
pub fn get_peer(cfg: &Config, peer: &ha::GatewayHaPeer, path: &str) -> Result<PeerHttpResponse> {
    let secrets = ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir))?
        .context("HA peer token is not available")?;
    if secrets.session_token.trim().is_empty() {
        bail!("HA peer token is empty");
    }
    let base = peer_api_base(peer)?;
    let url = format!("{base}{path}");
    let response = Client::builder()
        .timeout(Duration::from_secs(5))
        .user_agent("edge-lb/0.1")
        .build()
        .context("building HA peer read client")?
        .get(&url)
        .bearer_auth(&secrets.session_token)
        .send()
        .with_context(|| format!("reading HA peer {}", peer.name))?;
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    Ok(PeerHttpResponse { status, body })
}

pub fn peer_api_base(peer: &ha::GatewayHaPeer) -> Result<String> {
    let addr = peer
        .api_addr
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{}:18080", peer.underlay_ip));
    if addr.starts_with("http://") || addr.starts_with("https://") {
        Ok(addr.trim_end_matches('/').to_string())
    } else {
        Ok(format!("http://{}", addr.trim_end_matches('/')))
    }
}

fn send_peer_json<T: Serialize>(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    method: reqwest::Method,
    path: &str,
    value: &T,
) -> Result<PeerHttpResponse> {
    let secrets = ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir))?
        .context("HA peer token is not available")?;
    if secrets.session_token.trim().is_empty() {
        bail!("HA peer token is empty");
    }
    let base = peer_api_base(peer)?;
    let url = format!("{base}{path}");
    let response = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("edge-lb/0.1")
        .build()
        .context("building HA peer write client")?
        .request(method, &url)
        .bearer_auth(&secrets.session_token)
        .json(value)
        .send()
        .with_context(|| format!("sending HA write to peer {}", peer.name))?;
    let status = response.status().as_u16();
    let body = response.text().unwrap_or_default();
    Ok(PeerHttpResponse { status, body })
}

fn local_ha_state(cfg: &Config) -> Result<Option<String>> {
    Ok(active_gateway_state(cfg))
}

fn active_gateway_state(cfg: &Config) -> Option<String> {
    active_gateway_is_local(cfg).then(|| MASTER.to_string())
}

fn active_gateway_is_local(cfg: &Config) -> bool {
    cfg.active_gateway()
        .map(|gateway| gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip)
        .unwrap_or(false)
}
