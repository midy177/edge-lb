use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::{
    config::Config,
    runtime::{
        ha::{self, VipBindDevice, VipProvider},
        ka_hook::KaHookEvent,
    },
};

#[derive(Debug, Clone, Serialize)]
pub struct NativeHaState {
    pub node: String,
    pub active_gateway: Option<String>,
    pub active_revision: Option<i64>,
    pub state: String,
    pub enabled: bool,
    pub peer_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwitchActiveResult {
    pub gateway: String,
    pub vip: Option<String>,
    pub garp_announced: bool,
    pub vip_bound: bool,
}

pub fn state(cfg: &Config) -> Result<NativeHaState> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    let active = cfg
        .active_gateway()
        .ok()
        .map(|gateway| gateway.name.clone());
    let local_active = cfg.active_gateway().ok().is_some_and(|gateway| {
        gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip
    });
    let state = if !ha_cfg.enabled {
        "disabled"
    } else if local_active {
        "MASTER"
    } else {
        "BACKUP"
    };
    Ok(NativeHaState {
        node: cfg.node_name.clone(),
        active_gateway: active,
        active_revision: cfg.active_gateway_revision().ok().flatten(),
        state: state.to_string(),
        enabled: ha_cfg.enabled,
        peer_count: ha_cfg.peers.len(),
    })
}

/// Reconcile the local L2 VIP with the currently selected gateway.
///
/// Binding is checked before changing anything, so the periodic gateway
/// watcher does not emit gratuitous ARP on every pass. A newly promoted local
/// gateway binds first and then announces the VIP on the underlay device.
pub fn reconcile_vip(cfg: &Config) -> Result<bool> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    let Some(vip_text) = ha_cfg.vip.private_vip.as_deref() else {
        return Ok(false);
    };
    let vip = vip_text
        .parse()
        .with_context(|| format!("bad private VIP {vip_text}"))?;
    let device = vip_device(cfg, ha_cfg.vip.bind_device);
    let bound = crate::linux::addr::vip_bound_on_device(cfg, vip, &device);
    let should_bind = ha_cfg.enabled
        && matches!(ha_cfg.vip.provider, VipProvider::L2)
        && cfg
            .active_gateway()
            .map(|gateway| gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip)
            .unwrap_or(false);
    if should_bind && !bound {
        crate::linux::addr::bind_vip_on_device(cfg, vip, &device)?;
        crate::runtime::ka_hook::announce_vip(cfg, vip, &ha_cfg.vip)?;
        tracing::info!(
            "[ha] VIP {} bound to {} and announced with GARP",
            vip,
            device
        );
        return Ok(true);
    }
    if !should_bind && bound {
        crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
        tracing::info!("[ha] VIP {} released from {}", vip, device);
        return Ok(true);
    }
    Ok(false)
}

pub fn release_local_vip(cfg: &Config) -> Result<bool> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled || !matches!(ha_cfg.vip.provider, VipProvider::L2) {
        return Ok(false);
    }
    let Some(vip_text) = ha_cfg.vip.private_vip.as_deref() else {
        return Ok(false);
    };
    let vip = vip_text
        .parse()
        .with_context(|| format!("bad private VIP {vip_text}"))?;
    let device = vip_device(cfg, ha_cfg.vip.bind_device);
    if !crate::linux::addr::vip_bound_on_device(cfg, vip, &device) {
        return Ok(false);
    }
    crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
    tracing::info!("[ha] VIP {} released from {}", vip, device);
    Ok(true)
}

pub fn handoff_or_release_on_shutdown(cfg: &Config) -> Result<()> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled || !matches!(ha_cfg.vip.provider, VipProvider::L2) {
        return Ok(());
    }
    let local_master = state(cfg)?.state == "MASTER";
    if local_master && let Some(peer) = ha_cfg.peers.first() {
        match switch_active_gateway(cfg, &peer.name) {
            Ok(result) => {
                tracing::info!(
                    "[ha] graceful shutdown handed active gateway to {} vip_bound={} garp={}",
                    result.gateway,
                    result.vip_bound,
                    result.garp_announced
                );
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(
                    "[ha] graceful shutdown handoff to {} failed: {error:#}; releasing local VIP",
                    peer.name
                );
            }
        }
    }
    release_local_vip(cfg)?;
    Ok(())
}

pub fn switch_active_gateway(cfg: &Config, target_key: &str) -> Result<SwitchActiveResult> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    let target = cfg
        .gateway_by_key(target_key)
        .cloned()
        .or_else(|| {
            ha_cfg.peers.iter().find_map(|peer| {
                if peer.name != target_key && peer.underlay_ip != target_key {
                    return None;
                }
                let underlay_ip = peer.underlay_ip.parse().ok()?;
                Some(crate::config::GatewayNode {
                    name: peer.name.clone(),
                    public_ip: peer
                        .public_ip
                        .as_deref()
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(underlay_ip),
                    underlay_ip,
                    overlay_ip: peer
                        .overlay_ip
                        .clone()
                        .unwrap_or_else(|| cfg.gateway_cfg().overlay_ip.clone()),
                })
            })
        })
        .with_context(|| format!("unknown gateway {target_key:?}"))?;
    if ha_cfg.enabled && target.name != cfg.node_name {
        let peer = ha_cfg
            .peers
            .iter()
            .find(|peer| {
                peer.name == target.name || peer.underlay_ip == target.underlay_ip.to_string()
            })
            .context("failover target is not the configured HA peer")?;
        let response = crate::runtime::ha_write::post_peer_json(
            cfg,
            peer,
            "/api/v1/ha/peer/activate",
            &serde_json::json!({ "gateway": target.name }),
        )?;
        if !(200..300).contains(&response.status) {
            bail!(
                "peer activation failed with HTTP {}: {}",
                response.status,
                response.body
            );
        }
    }
    cfg.write_active_gateway(&target.name)?;

    let mut garp_announced = false;
    let mut vip_now_bound = false;
    let vip = ha_cfg.vip.private_vip.clone();
    if ha_cfg.enabled
        && matches!(ha_cfg.vip.provider, VipProvider::L2)
        && let Some(vip) = vip.as_deref()
    {
        let vip = vip
            .parse()
            .with_context(|| format!("bad private VIP {vip}"))?;
        if target.name == cfg.node_name {
            // Promote: bind the VIP so the kernel accepts VPC ingress for it,
            // then re-point the L2 network at this node.
            let device = vip_device(cfg, ha_cfg.vip.bind_device);
            crate::linux::addr::bind_vip_on_device(cfg, vip, &device)?;
            vip_now_bound = true;
            crate::runtime::ka_hook::announce_vip(cfg, vip, &ha_cfg.vip)?;
            garp_announced = true;
        } else {
            // Demote to the peer: drop the address so the pair never holds
            // it twice; the new MASTER's GARP claims the network.
            let device = vip_device(cfg, ha_cfg.vip.bind_device);
            crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
        }
    }

    Ok(SwitchActiveResult {
        gateway: target.name.clone(),
        vip,
        garp_announced,
        vip_bound: vip_now_bound,
    })
}

pub fn handle_ka_hook_event(cfg: &Config, event: &KaHookEvent) -> Result<()> {
    match event.state.trim().to_ascii_uppercase().as_str() {
        "MASTER" => {
            cfg.write_active_gateway(&cfg.node_name)?;
            if !event.vip.trim().is_empty() {
                let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
                let vip = event
                    .vip
                    .parse()
                    .with_context(|| format!("bad ka_hook VIP {}", event.vip))?;
                // BFD-driven promotion must bind the address too — GARP alone
                // leaves the VPC dropping VIP ingress on this node.
                let device = vip_device(cfg, ha_cfg.vip.bind_device);
                crate::linux::addr::bind_vip_on_device(cfg, vip, &device)?;
                crate::runtime::ka_hook::announce_vip(cfg, vip, &ha_cfg.vip)?;
            }
            Ok(())
        }
        "BACKUP" | "STOP" => {
            if !event.vip.trim().is_empty() {
                let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
                let vip = event
                    .vip
                    .parse()
                    .with_context(|| format!("bad ka_hook VIP {}", event.vip))?;
                let device = vip_device(cfg, ha_cfg.vip.bind_device);
                crate::linux::addr::release_vip_on_device(cfg, vip, &device)?;
            }
            Ok(())
        }
        other => bail!("unsupported HA hook state {other:?}"),
    }
}

fn vip_device(cfg: &Config, bind_device: VipBindDevice) -> String {
    match bind_device {
        VipBindDevice::Underlay => cfg.network().underlay_dev.clone(),
        VipBindDevice::Loopback => "lo".to_string(),
    }
}
