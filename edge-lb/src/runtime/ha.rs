//! Runtime-only gateway HA configuration.

use std::{
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(test)]
use std::fs;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::config::{Config, FileConfig, GatewayNode, NodeRole};

#[cfg(test)]
const DEFAULT_GATEWAY_HA_PATH: &str = "/var/lib/edge-lb/gateway-ha.json";
const HA_SECRET_RESOURCE: &str = "ha_peer_secret";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayHaRuntimeConfig {
    pub enabled: bool,
    pub mode: GatewayHaMode,
    pub self_index: u32,
    pub preferred_active: Option<String>,
    pub connection_sync: bool,
    pub xsync_rpc: XsyncRpc,
    pub failover: FailoverMode,
    pub peers: Vec<GatewayHaPeer>,
    pub vip: VipConfig,
    pub bgp: BgpConfig,
    pub bfd: BfdConfig,
    pub xsync: XsyncConfig,
}

impl Default for GatewayHaRuntimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: GatewayHaMode::ActiveBackup,
            self_index: 0,
            preferred_active: None,
            connection_sync: true,
            xsync_rpc: XsyncRpc::Grpc,
            failover: FailoverMode::BfdAuto,
            peers: Vec::new(),
            vip: VipConfig::default(),
            bgp: BgpConfig::default(),
            bfd: BfdConfig::default(),
            xsync: XsyncConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BfdConfig {
    pub bind_addr: String,
    pub port: u16,
    pub interval_ms: u64,
    pub detect_multiplier: u32,
}

impl Default for BfdConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            port: 3784,
            interval_ms: 300,
            detect_multiplier: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct XsyncConfig {
    pub bind_addr: String,
    pub port: u16,
    pub reconnect_min_ms: u64,
    pub reconnect_max_ms: u64,
}

impl Default for XsyncConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0".to_string(),
            port: 22222,
            reconnect_min_ms: 250,
            reconnect_max_ms: 5000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayHaMode {
    #[default]
    ActiveBackup,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XsyncRpc {
    #[default]
    Grpc,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailoverMode {
    Manual,
    #[default]
    BfdAuto,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayHaPeer {
    pub name: String,
    pub underlay_ip: String,
    pub public_ip: Option<String>,
    pub api_addr: Option<String>,
    pub xds_addr: Option<String>,
    pub overlay_cidr: Option<String>,
    pub overlay_ip: Option<String>,
    pub dscp: Option<u32>,
    pub vni: Option<u32>,
    pub vxlan_port: Option<u16>,
    pub mtu: Option<u32>,
    pub version: Option<String>,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayHaPeerSecrets {
    pub peer_name: String,
    pub peer_underlay_ip: String,
    #[serde(default)]
    pub session_token: String,
    #[serde(default)]
    pub session_token_id: String,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayIdentity {
    pub name: String,
    pub underlay_ip: String,
    pub public_ip: String,
    pub api_addr: String,
    pub xds_addr: String,
    pub overlay_cidr: String,
    pub overlay_ip: String,
    pub dscp: u32,
    pub vni: u32,
    pub vxlan_port: u16,
    pub mtu: u32,
    pub version: String,
    pub capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VipConfig {
    pub provider: VipProvider,
    pub owner: VipOwner,
    pub bind_device: VipBindDevice,
    /// Interface used to send gratuitous ARP. Empty means the local
    /// underlay device.
    pub garp_device: Option<String>,
    pub private_vip: Option<String>,
    pub bind_timeout_secs: u64,
    pub verify_timeout_secs: u64,
    pub garp: GarpConfig,
    pub promote_hook: Option<PathBuf>,
    pub demote_hook: Option<PathBuf>,
    pub verify_hook: Option<PathBuf>,
}

impl Default for VipConfig {
    fn default() -> Self {
        Self {
            provider: VipProvider::Hook,
            owner: VipOwner::EdgeLb,
            bind_device: VipBindDevice::Loopback,
            garp_device: None,
            private_vip: None,
            bind_timeout_secs: 15,
            verify_timeout_secs: 10,
            garp: GarpConfig::default(),
            promote_hook: None,
            demote_hook: None,
            verify_hook: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VipBindDevice {
    #[default]
    Loopback,
    Underlay,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GarpConfig {
    pub count: u32,
    pub interval_ms: u64,
    pub repeat_after_ms: u64,
    pub repeat_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BgpConfig {
    pub local_as: Option<u32>,
    pub router_id: String,
    pub peers: Vec<String>,
    pub hold_time_secs: u64,
    pub keepalive_secs: u64,
}

impl Default for BgpConfig {
    fn default() -> Self {
        Self {
            local_as: None,
            router_id: "auto".to_string(),
            peers: Vec::new(),
            hold_time_secs: 90,
            keepalive_secs: 30,
        }
    }
}

impl Default for GarpConfig {
    fn default() -> Self {
        Self {
            count: 10,
            interval_ms: 100,
            repeat_after_ms: 1000,
            repeat_count: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VipProvider {
    #[serde(rename = "l2")]
    L2,
    Bgp,
    #[default]
    Hook,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VipOwner {
    #[default]
    EdgeLb,
}

#[cfg(test)]
fn default_path() -> PathBuf {
    PathBuf::from(DEFAULT_GATEWAY_HA_PATH)
}

#[cfg(test)]
fn path_for_state_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("gateway-ha.json")
}

#[cfg(test)]
fn secrets_path_for_state_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("gateway-ha-peer-token.json")
}

#[cfg(test)]
pub fn load_for_state_dir(state_dir: &Path) -> Result<GatewayHaRuntimeConfig> {
    load(&path_for_state_dir(state_dir))
}

#[cfg(not(test))]
pub fn load_for_state_dir(_state_dir: &Path) -> Result<GatewayHaRuntimeConfig> {
    let repository = crate::storage::repository()?;
    if let Some(payload) = repository.get("ha", "config")? {
        let value: GatewayHaRuntimeConfig =
            serde_json::from_str(&payload).context("parsing stored HA config")?;
        return Ok(normalize_runtime_config(value));
    }

    Ok(GatewayHaRuntimeConfig::default())
}

#[cfg(test)]
pub fn save_for_state_dir(state_dir: &Path, value: &GatewayHaRuntimeConfig) -> Result<()> {
    save(&path_for_state_dir(state_dir), value)
}

#[cfg(not(test))]
pub fn save_for_state_dir(_state_dir: &Path, value: &GatewayHaRuntimeConfig) -> Result<()> {
    let value = normalize_runtime_config(value.clone());
    let payload = serde_json::to_string(&value).context("encoding HA config")?;
    crate::storage::repository()?.put("ha", "config", crate::storage::next_revision(), payload)
}

#[cfg(test)]
pub fn load_secrets_for_state_dir(state_dir: &Path) -> Result<Option<GatewayHaPeerSecrets>> {
    let path = secrets_path_for_state_dir(state_dir);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    if text.trim().is_empty() {
        return Ok(None);
    }
    let value: GatewayHaPeerSecrets =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(value))
}

#[cfg(not(test))]
pub fn load_secrets_for_state_dir(_state_dir: &Path) -> Result<Option<GatewayHaPeerSecrets>> {
    let Some(payload) = crate::storage::repository()?.get(HA_SECRET_RESOURCE, "config")? else {
        return Ok(None);
    };
    serde_json::from_str(&payload)
        .context("parsing stored HA peer secret")
        .map(Some)
}

pub fn session_token_matches(state_dir: &Path, token: &str) -> Result<bool> {
    let Some(secrets) = load_secrets_for_state_dir(state_dir)? else {
        return Ok(false);
    };
    if secrets.session_token.is_empty() || token.is_empty() {
        return Ok(false);
    }
    Ok(constant_time_eq(
        secrets.session_token.as_bytes(),
        token.as_bytes(),
    ))
}

#[cfg(test)]
pub fn save_secrets_for_state_dir(state_dir: &Path, value: &GatewayHaPeerSecrets) -> Result<()> {
    let path = secrets_path_for_state_dir(state_dir);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let text = serde_json::to_string_pretty(value).context("serializing gateway HA peer token")?;
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", tmp.display()))?;
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))
}

#[cfg(not(test))]
pub fn save_secrets_for_state_dir(_state_dir: &Path, value: &GatewayHaPeerSecrets) -> Result<()> {
    let payload = serde_json::to_string(value).context("serializing HA peer secret")?;
    crate::storage::repository()?.put(
        HA_SECRET_RESOURCE,
        "config",
        crate::storage::next_revision(),
        payload,
    )
}

#[cfg(test)]
pub fn delete_secrets_for_state_dir(state_dir: &Path) -> Result<bool> {
    let path = secrets_path_for_state_dir(state_dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).with_context(|| format!("deleting {}", path.display())),
    }
}

#[cfg(not(test))]
pub fn delete_secrets_for_state_dir(_state_dir: &Path) -> Result<bool> {
    crate::storage::repository()?.delete(HA_SECRET_RESOURCE, "config")
}

pub fn unpair_for_state_dir(state_dir: &Path) -> Result<(GatewayHaRuntimeConfig, bool, bool)> {
    let mut cfg = load_for_state_dir(state_dir)?;
    let restart_required =
        cfg.enabled && (cfg.connection_sync || matches!(cfg.vip.provider, VipProvider::Bgp));
    cfg.enabled = false;
    cfg.preferred_active = None;
    cfg.peers.clear();
    save_for_state_dir(state_dir, &cfg)?;
    let deleted_secret = delete_secrets_for_state_dir(state_dir)?;
    Ok((cfg, deleted_secret, restart_required))
}

pub fn local_identity(cfg: &Config) -> GatewayIdentity {
    let network = cfg.network();
    GatewayIdentity {
        name: cfg.node_name.clone(),
        underlay_ip: cfg.underlay_ip.to_string(),
        public_ip: cfg.public_ip.to_string(),
        api_addr: advertised_addr(&cfg.api.listen, cfg.underlay_ip),
        xds_addr: advertised_addr(&cfg.control_plane.listen, cfg.underlay_ip),
        overlay_cidr: network.overlay_cidr.clone(),
        overlay_ip: cfg.gateway_cfg().overlay_ip.clone(),
        dscp: network.dscp,
        vni: network.vni,
        vxlan_port: network.vxlan_port,
        mtu: network.vxlan_mtu,
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![
            "ha.active_backup".to_string(),
            "ha.peer_token".to_string(),
            "vip.l2".to_string(),
            "vip.bgp".to_string(),
            "vip.hook".to_string(),
        ],
    }
}

pub fn peer_from_identity(identity: &GatewayIdentity) -> GatewayHaPeer {
    GatewayHaPeer {
        name: identity.name.clone(),
        underlay_ip: identity.underlay_ip.clone(),
        public_ip: non_empty(identity.public_ip.clone()),
        api_addr: non_empty(identity.api_addr.clone()),
        xds_addr: non_empty(identity.xds_addr.clone()),
        overlay_cidr: non_empty(identity.overlay_cidr.clone()),
        overlay_ip: non_empty(identity.overlay_ip.clone()),
        dscp: Some(identity.dscp),
        vni: Some(identity.vni),
        vxlan_port: Some(identity.vxlan_port),
        mtu: Some(identity.mtu),
        version: non_empty(identity.version.clone()),
        capabilities: identity.capabilities.clone(),
    }
}

pub fn reciprocal_config(
    cfg: &GatewayHaRuntimeConfig,
    local: &GatewayIdentity,
    peer: &GatewayIdentity,
) -> Result<GatewayHaRuntimeConfig> {
    validate_identity_pair(local, peer)?;
    let mut next = cfg.clone();
    next.enabled = true;
    next.mode = GatewayHaMode::ActiveBackup;
    next.peers = vec![peer_from_identity(peer)];
    next.self_index = if cfg.self_index == 0 { 1 } else { 0 };
    if next.preferred_active.as_deref().is_some_and(str::is_empty) {
        next.preferred_active = None;
    }
    validate(&next)?;
    Ok(next)
}

pub fn config_with_peer(
    cfg: &GatewayHaRuntimeConfig,
    local: &GatewayIdentity,
    peer: &GatewayIdentity,
) -> Result<GatewayHaRuntimeConfig> {
    validate_identity_pair(local, peer)?;
    ensure_peer_slot_available(cfg, peer)?;
    let mut next = cfg.clone();
    next.enabled = true;
    next.mode = GatewayHaMode::ActiveBackup;
    next.peers = vec![peer_from_identity(peer)];
    validate(&next)?;
    Ok(next)
}

pub fn validate_identity_pair(local: &GatewayIdentity, peer: &GatewayIdentity) -> Result<()> {
    if local.name.trim().is_empty() {
        bail!("local gateway name is required");
    }
    if peer.name.trim().is_empty() {
        bail!("peer gateway name is required");
    }
    if local.name == peer.name {
        bail!("HA peer must have a different node_name");
    }
    let local_underlay: IpAddr = local.underlay_ip.parse().context("bad local underlay_ip")?;
    let peer_underlay: IpAddr = peer.underlay_ip.parse().context("bad peer underlay_ip")?;
    if local_underlay.is_unspecified() || peer_underlay.is_unspecified() {
        bail!("HA peer underlay_ip must not be unspecified");
    }
    if local_underlay == peer_underlay {
        bail!("HA peer underlay_ip must differ from local underlay_ip");
    }
    if local.dscp == peer.dscp {
        bail!("HA peer dscp must differ from local dscp");
    }
    if cidr_overlaps(&local.overlay_cidr, &peer.overlay_cidr)? {
        bail!("HA peer overlay_cidr must not overlap local overlay_cidr");
    }
    if local.vni != peer.vni {
        bail!("HA peer vni must match local vni");
    }
    if local.vxlan_port != peer.vxlan_port {
        bail!("HA peer vxlan_port must match local vxlan_port");
    }
    if local.mtu != peer.mtu {
        bail!("HA peer mtu must match local mtu");
    }
    Ok(())
}

pub fn ensure_peer_slot_available(
    cfg: &GatewayHaRuntimeConfig,
    peer: &GatewayIdentity,
) -> Result<()> {
    if cfg.peers.len() > 1 {
        bail!("active-backup HA supports exactly one peer");
    }
    let Some(existing) = cfg.peers.first() else {
        return Ok(());
    };
    if existing.name == peer.name || existing.underlay_ip == peer.underlay_ip {
        return Ok(());
    }
    bail!(
        "gateway is already paired with {} ({})",
        existing.name,
        existing.underlay_ip
    )
}

pub fn new_session_token_secret(
    peer: &GatewayIdentity,
    session_token: String,
) -> GatewayHaPeerSecrets {
    GatewayHaPeerSecrets {
        peer_name: peer.name.clone(),
        peer_underlay_ip: peer.underlay_ip.clone(),
        session_token_id: token_id(&session_token),
        session_token,
        updated_at_unix: now_unix(),
    }
}

pub fn generate_session_token() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    let addr = (&now as *const u128 as usize) as u128;
    format!("elp_{:x}{:x}{:x}", now, pid, addr)
}

fn token_id(token: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in token.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b) {
        diff |= left ^ right;
    }
    diff == 0
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

fn advertised_addr(listen: &str, fallback_ip: IpAddr) -> String {
    let Ok(addr) = listen.parse::<std::net::SocketAddr>() else {
        return listen.to_string();
    };
    let ip = match addr.ip() {
        IpAddr::V4(v) if v.is_unspecified() => fallback_ip,
        IpAddr::V6(v) if v.is_unspecified() => fallback_ip,
        ip => ip,
    };
    format!("{}:{}", ip, addr.port())
}

fn non_empty(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn cidr_overlaps(a: &str, b: &str) -> Result<bool> {
    let (a_ip, a_prefix) =
        parse_ipv4_cidr(a).with_context(|| format!("bad local overlay_cidr {a}"))?;
    let (b_ip, b_prefix) =
        parse_ipv4_cidr(b).with_context(|| format!("bad peer overlay_cidr {b}"))?;
    let prefix = a_prefix.min(b_prefix);
    let mask = if prefix == 0 {
        0u32
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Ok((u32::from(a_ip) & mask) == (u32::from(b_ip) & mask))
}

fn parse_ipv4_cidr(value: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = value.split_once('/').context("CIDR must include prefix")?;
    let addr = addr.parse::<Ipv4Addr>().context("bad IPv4 address")?;
    let prefix = prefix.parse::<u8>().context("bad prefix")?;
    if prefix > 32 {
        bail!("IPv4 prefix out of range");
    }
    Ok((addr, prefix))
}

pub fn merge_gateway_peers(file: &mut FileConfig) -> Result<bool> {
    if !matches!(file.node_role, NodeRole::Gateway) {
        return Ok(false);
    }
    let cfg = load_for_state_dir(&file.state_dir)?;
    let mut changed = false;
    let mut peer_underlays = Vec::new();
    for peer in cfg.peers {
        let name = peer.name.trim();
        if name.is_empty() {
            continue;
        }
        let underlay_ip = peer
            .underlay_ip
            .trim()
            .parse::<IpAddr>()
            .with_context(|| format!("bad HA peer {name} underlay_ip"))?;
        peer_underlays.push(underlay_ip);
        let public_ip = match peer
            .public_ip
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            Some(value) => value
                .parse::<IpAddr>()
                .with_context(|| format!("bad HA peer {name} public_ip"))?,
            None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        };
        let overlay_ip = peer
            .overlay_ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| file.gateway.overlay_ip.clone());
        if let Some(existing) = file
            .gateway_nodes
            .iter_mut()
            .find(|gw| gw.name == name || gw.underlay_ip == underlay_ip)
        {
            if existing.name != name {
                existing.name = name.to_string();
                changed = true;
            }
            if existing.underlay_ip != underlay_ip {
                existing.underlay_ip = underlay_ip;
                changed = true;
            }
            if !public_ip.is_unspecified() && existing.public_ip != public_ip {
                existing.public_ip = public_ip;
                changed = true;
            }
            if !overlay_ip.trim().is_empty() && existing.overlay_ip != overlay_ip {
                existing.overlay_ip = overlay_ip;
                changed = true;
            }
        } else {
            file.gateway_nodes.push(GatewayNode {
                name: name.to_string(),
                public_ip,
                underlay_ip,
                overlay_ip,
            });
            changed = true;
        }
    }
    let before = file.backend_nodes.len();
    file.backend_nodes
        .retain(|backend| !peer_underlays.contains(&backend.underlay_ip));
    changed |= file.backend_nodes.len() != before;
    if changed {
        file.normalize();
    }
    Ok(changed)
}

pub fn merge_gateway_peers_best_effort(file: &mut FileConfig) -> bool {
    match merge_gateway_peers(file) {
        Ok(changed) => changed,
        Err(e) => {
            tracing::warn!("[gateway] loading HA gateway peers skipped: {e:#}");
            false
        }
    }
}

#[cfg(test)]
fn load(path: &Path) -> Result<GatewayHaRuntimeConfig> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GatewayHaRuntimeConfig::default());
        }
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    if text.trim().is_empty() {
        return Ok(GatewayHaRuntimeConfig::default());
    }
    let value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    Ok(normalize_runtime_config(value))
}

#[cfg(test)]
fn save(path: &Path, value: &GatewayHaRuntimeConfig) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let tmp = path.with_extension("json.tmp");
    let value = normalize_runtime_config(value.clone());
    let text = serde_json::to_string_pretty(&value).context("serializing gateway HA config")?;
    fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))
}

pub fn normalize_runtime_config(mut value: GatewayHaRuntimeConfig) -> GatewayHaRuntimeConfig {
    value.mode = GatewayHaMode::ActiveBackup;
    value.connection_sync = true;
    value.xsync_rpc = XsyncRpc::Grpc;
    value.failover = FailoverMode::BfdAuto;
    value.vip.owner = VipOwner::EdgeLb;
    if !matches!(value.vip.provider, VipProvider::L2) {
        value.vip.private_vip = None;
    }
    if !matches!(value.vip.provider, VipProvider::Hook) {
        value.vip.promote_hook = None;
        value.vip.demote_hook = None;
        value.vip.verify_hook = None;
    }
    value
}

pub fn validate(value: &GatewayHaRuntimeConfig) -> Result<()> {
    let value = normalize_runtime_config(value.clone());
    if value.peers.len() > 1 {
        bail!("active-backup HA supports exactly one peer");
    }
    if value.enabled && value.peers.is_empty() {
        bail!("active-backup HA requires exactly one peer");
    }
    if value.enabled && value.self_index as usize > value.peers.len() {
        bail!("self_index is outside the configured HA cluster range");
    }
    for (idx, peer) in value.peers.iter().enumerate() {
        if peer.name.trim().is_empty() {
            bail!("peers[{idx}].name is required");
        }
        if peer.underlay_ip.trim().is_empty() {
            bail!("peers[{idx}].underlay_ip is required");
        }
        peer.underlay_ip
            .parse::<std::net::IpAddr>()
            .with_context(|| format!("bad peers[{idx}].underlay_ip"))?;
        if let Some(public_ip) = &peer.public_ip {
            public_ip
                .parse::<std::net::IpAddr>()
                .with_context(|| format!("bad peers[{idx}].public_ip"))?;
        }
    }
    validate_garp(&value.vip.garp)?;
    if let Some(device) = value.vip.garp_device.as_deref() {
        let device = device.trim();
        if device.is_empty() {
            bail!("vip.garp_device must be omitted or a non-empty interface name");
        }
        if device.len() >= libc::IFNAMSIZ {
            bail!(
                "vip.garp_device must be shorter than {} bytes",
                libc::IFNAMSIZ
            );
        }
    }
    if value.enabled && matches!(value.vip.provider, VipProvider::Bgp) {
        validate_bgp(&value.bgp)?;
    }
    Ok(())
}

fn validate_garp(value: &GarpConfig) -> Result<()> {
    if value.count == 0 {
        bail!("vip.garp.count must be greater than 0");
    }
    if value.interval_ms == 0 {
        bail!("vip.garp.interval_ms must be greater than 0");
    }
    if value.interval_ms > 60_000 {
        bail!("vip.garp.interval_ms must be <= 60000");
    }
    if value.repeat_after_ms > 60_000 {
        bail!("vip.garp.repeat_after_ms must be <= 60000");
    }
    if value.repeat_count > 10 {
        bail!("vip.garp.repeat_count must be <= 10");
    }
    Ok(())
}

fn validate_bgp(value: &BgpConfig) -> Result<()> {
    let local_as = value.local_as.context("bgp.local_as is required")?;
    if local_as == 0 {
        bail!("bgp.local_as must be greater than 0");
    }
    if value.peers.is_empty() {
        bail!("bgp.peers requires at least one peer");
    }
    for (idx, peer) in value.peers.iter().enumerate() {
        let peer = peer.trim();
        if peer.is_empty() {
            bail!("bgp.peers[{idx}] is empty");
        }
        let Some((addr, asn)) = peer.rsplit_once(':') else {
            bail!("bgp.peers[{idx}] must use <ip>:<asn>");
        };
        addr.parse::<IpAddr>()
            .with_context(|| format!("bad bgp.peers[{idx}] IP"))?;
        let asn = asn
            .parse::<u32>()
            .with_context(|| format!("bad bgp.peers[{idx}] ASN"))?;
        if asn == 0 {
            bail!("bgp.peers[{idx}] ASN must be greater than 0");
        }
    }
    if value.router_id.trim() != "auto" {
        value
            .router_id
            .parse::<Ipv4Addr>()
            .context("bad bgp.router_id")?;
    }
    if value.hold_time_secs == 0 {
        bail!("bgp.hold_time_secs must be greater than 0");
    }
    if value.keepalive_secs == 0 {
        bail!("bgp.keepalive_secs must be greater than 0");
    }
    if value.keepalive_secs >= value.hold_time_secs {
        bail!("bgp.keepalive_secs must be less than bgp.hold_time_secs");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BackendNode, NetworkConfig};

    #[test]
    fn empty_file_loads_as_default() {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-ha-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway-ha.json");
        fs::write(&path, "\n").unwrap();

        let cfg = load(&path).unwrap();

        assert_eq!(cfg, GatewayHaRuntimeConfig::default());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn validate_rejects_enabled_ha_without_peers() {
        let cfg = GatewayHaRuntimeConfig {
            enabled: true,
            connection_sync: true,
            ..GatewayHaRuntimeConfig::default()
        };

        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_more_than_one_peer() {
        let cfg = GatewayHaRuntimeConfig {
            enabled: true,
            peers: vec![
                GatewayHaPeer {
                    name: "gateway-b".to_string(),
                    underlay_ip: "192.168.0.16".to_string(),
                    ..GatewayHaPeer::default()
                },
                GatewayHaPeer {
                    name: "gateway-c".to_string(),
                    underlay_ip: "192.168.0.17".to_string(),
                    ..GatewayHaPeer::default()
                },
            ],
            ..GatewayHaRuntimeConfig::default()
        };

        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_accepts_minimal_connection_sync_peer() {
        let cfg = GatewayHaRuntimeConfig {
            enabled: true,
            connection_sync: true,
            peers: vec![GatewayHaPeer {
                name: "gateway-b".to_string(),
                underlay_ip: "192.168.0.16".to_string(),
                ..GatewayHaPeer::default()
            }],
            ..GatewayHaRuntimeConfig::default()
        };

        validate(&cfg).expect("valid HA peer");
    }

    #[test]
    fn missing_vip_owner_defaults_to_edge_lb() {
        let cfg: GatewayHaRuntimeConfig = serde_json::from_str(
            r#"{
              "enabled": true,
              "mode": "active_backup",
              "self_index": 0,
              "connection_sync": true,
              "xsync_rpc": "grpc",
              "failover": "bfd_auto",
              "peers": [{"name": "gateway-b", "underlay_ip": "192.168.0.16"}],
              "vip": {
                "provider": "l2",
                "private_vip": "192.168.0.6"
              }
            }"#,
        )
        .unwrap();

        assert_eq!(cfg.vip.owner, VipOwner::EdgeLb);
        assert_eq!(cfg.vip.bind_device, VipBindDevice::Loopback);
        assert_eq!(cfg.vip.garp, GarpConfig::default());
    }

    #[test]
    fn validate_rejects_invalid_garp_config() {
        let cfg = GatewayHaRuntimeConfig {
            enabled: true,
            connection_sync: true,
            peers: vec![GatewayHaPeer {
                name: "gateway-b".to_string(),
                underlay_ip: "192.168.0.16".to_string(),
                ..GatewayHaPeer::default()
            }],
            vip: VipConfig {
                garp: GarpConfig {
                    count: 0,
                    ..GarpConfig::default()
                },
                ..VipConfig::default()
            },
            ..GatewayHaRuntimeConfig::default()
        };

        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn validate_identity_pair_rejects_dscp_conflict() {
        let local = test_identity("gateway-a", "192.168.0.12", "10.255.12.0/24", 46);
        let peer = test_identity("gateway-b", "192.168.0.16", "10.255.16.0/24", 46);

        assert!(validate_identity_pair(&local, &peer).is_err());
    }

    #[test]
    fn validate_identity_pair_rejects_overlay_overlap() {
        let local = test_identity("gateway-a", "192.168.0.12", "10.255.12.0/24", 46);
        let peer = test_identity("gateway-b", "192.168.0.16", "10.255.12.128/25", 40);

        assert!(validate_identity_pair(&local, &peer).is_err());
    }

    #[test]
    fn reciprocal_config_flips_self_index_and_keeps_peer_identity() {
        let local = test_identity("gateway-b", "192.168.0.16", "10.255.16.0/24", 40);
        let peer = test_identity("gateway-a", "192.168.0.12", "10.255.12.0/24", 46);
        let input = GatewayHaRuntimeConfig {
            enabled: true,
            self_index: 0,
            connection_sync: true,
            ..GatewayHaRuntimeConfig::default()
        };

        let cfg = reciprocal_config(&input, &local, &peer).unwrap();

        assert_eq!(cfg.self_index, 1);
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].name, "gateway-a");
        assert_eq!(cfg.peers[0].dscp, Some(46));
        assert_eq!(cfg.peers[0].overlay_cidr.as_deref(), Some("10.255.12.0/24"));
    }

    #[test]
    fn pairing_rejects_existing_different_peer() {
        let peer = test_identity("gateway-b", "192.168.0.16", "10.255.16.0/24", 40);
        let cfg = GatewayHaRuntimeConfig {
            peers: vec![GatewayHaPeer {
                name: "gateway-c".to_string(),
                underlay_ip: "192.168.0.17".to_string(),
                ..GatewayHaPeer::default()
            }],
            ..GatewayHaRuntimeConfig::default()
        };

        assert!(ensure_peer_slot_available(&cfg, &peer).is_err());
    }

    #[test]
    fn peer_secret_uses_one_session_token() {
        let peer = test_identity("gateway-b", "192.168.0.16", "10.255.16.0/24", 40);
        let secret = new_session_token_secret(&peer, "ha-session-token".to_string());

        assert_eq!(secret.session_token, "ha-session-token");
        assert_eq!(secret.session_token_id, token_id("ha-session-token"));
    }

    #[test]
    fn session_token_match_uses_shared_token() {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-ha-token-match-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let peer = test_identity("gateway-b", "192.168.0.16", "10.255.16.0/24", 40);
        let secret = new_session_token_secret(&peer, "ha-session-token".to_string());
        save_secrets_for_state_dir(&dir, &secret).unwrap();

        assert!(session_token_matches(&dir, "ha-session-token").unwrap());
        assert!(!session_token_matches(&dir, "wrong").unwrap());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn unpair_clears_peer_and_deletes_secret() {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-ha-unpair-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let cfg = GatewayHaRuntimeConfig {
            enabled: true,
            connection_sync: true,
            peers: vec![GatewayHaPeer {
                name: "gateway-b".to_string(),
                underlay_ip: "192.168.0.16".to_string(),
                ..GatewayHaPeer::default()
            }],
            ..GatewayHaRuntimeConfig::default()
        };
        save(&path_for_state_dir(&dir), &cfg).unwrap();
        let peer = test_identity("gateway-b", "192.168.0.16", "10.255.16.0/24", 40);
        let secret = new_session_token_secret(&peer, "ha-session-token".to_string());
        save_secrets_for_state_dir(&dir, &secret).unwrap();

        let (next, deleted, restart_required) = unpair_for_state_dir(&dir).unwrap();

        assert!(deleted);
        assert!(restart_required);
        assert!(!next.enabled);
        assert!(next.peers.is_empty());
        assert!(!secrets_path_for_state_dir(&dir).exists());
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn merge_gateway_peers_prunes_gateway_underlays_from_backend_nodes() {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-ha-merge-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("gateway-ha.json");
        let cfg = GatewayHaRuntimeConfig {
            enabled: true,
            peers: vec![GatewayHaPeer {
                name: "gateway-b".to_string(),
                underlay_ip: "192.168.0.16".to_string(),
                public_ip: Some("203.0.113.11".to_string()),
                overlay_ip: Some("10.255.16.1/24".to_string()),
                ..GatewayHaPeer::default()
            }],
            ..GatewayHaRuntimeConfig::default()
        };
        save(&path, &cfg).unwrap();
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            public_ip: "203.0.113.10".parse().unwrap(),
            underlay_ip: "192.168.0.12".parse().unwrap(),
            state_dir: dir.clone(),
            network: NetworkConfig {
                underlay_dev: "eth0".to_string(),
                ..NetworkConfig::default()
            },
            backend_nodes: vec![BackendNode {
                name: "old-backend".to_string(),
                public_ip: "203.0.113.11".parse().unwrap(),
                underlay_ip: "192.168.0.16".parse().unwrap(),
                overlay_ip: "10.255.255.3/24".to_string(),
            }],
            ..FileConfig::default()
        };
        file.normalize();

        assert!(merge_gateway_peers(&mut file).unwrap());
        assert!(file.gateway_nodes.iter().any(|gw| gw.name == "gateway-b"
            && gw.underlay_ip.to_string() == "192.168.0.16"
            && gw.overlay_ip == "10.255.16.1/24"));
        assert!(file.backend_nodes.is_empty());
        fs::remove_dir_all(dir).ok();
    }

    fn test_identity(
        name: &str,
        underlay_ip: &str,
        overlay_cidr: &str,
        dscp: u32,
    ) -> GatewayIdentity {
        GatewayIdentity {
            name: name.to_string(),
            underlay_ip: underlay_ip.to_string(),
            public_ip: "198.51.100.1".to_string(),
            api_addr: format!("{underlay_ip}:18080"),
            xds_addr: format!("{underlay_ip}:22222"),
            overlay_cidr: overlay_cidr.to_string(),
            overlay_ip: overlay_cidr.replace(".0/", ".1/"),
            dscp,
            vni: 100,
            vxlan_port: 4789,
            mtu: 1450,
            version: "test".to_string(),
            capabilities: Vec::new(),
        }
    }
}
