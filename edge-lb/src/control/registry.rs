use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{LazyLock, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

use crate::{
    config::{BackendNode, FileConfig},
    control::pb::DiscoveryRequest,
};

#[derive(Debug, Clone, Serialize)]
struct ActiveBackendSubscription {
    public_ip: IpAddr,
    public_ip_mode: String,
    public_ip_source: String,
    underlay_ip: IpAddr,
    underlay_ip_mode: String,
    underlay_ip_source: String,
    peer: Option<SocketAddr>,
    stream_id: String,
    connected_at: u64,
    last_seen: u64,
    last_version: String,
    conflicts: Vec<NodeConflictStatus>,
}

#[derive(Debug, Clone, Serialize)]
struct NodeConflictStatus {
    severity: String,
    kind: String,
    subject: String,
    detail: String,
}

static ACTIVE_BACKEND_SUBSCRIPTIONS: LazyLock<Mutex<BTreeMap<String, ActiveBackendSubscription>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
static KNOWN_BACKEND_NODES: LazyLock<Mutex<BTreeMap<String, BackendNode>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));
const DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS: u64 = 30;

pub fn merge_into(file: &mut FileConfig) -> Result<bool> {
    prune_active_subscriptions(DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS)?;
    let gateway_underlays = gateway_underlays(file);
    let (known, pruned) = prune_known_backend_nodes(&gateway_underlays)?;
    if known.is_empty() {
        if !file.backend_nodes.is_empty() || pruned {
            file.backend_nodes.clear();
            file.normalize();
            return Ok(true);
        }
        return Ok(false);
    }
    let mut desired = file.clone();
    desired.backend_nodes = merge_backend_inventory(&file.backend_nodes, known, &gateway_underlays);
    desired.normalize();
    let backends = desired.backend_nodes;
    if same_backend_inventory(&file.backend_nodes, &backends) {
        return Ok(false);
    }
    file.backend_nodes = backends;
    file.normalize();
    remember_assigned_overlays(&file.backend_nodes)?;
    Ok(true)
}

pub fn upsert(req: &DiscoveryRequest, peer: Option<SocketAddr>, stream_id: &str, state_dir: &Path) {
    if let Err(e) = upsert_inner(req, peer, stream_id, state_dir) {
        tracing::warn!("[control] saving backend inventory skipped: {e:#}");
    }
}

pub fn status() -> Result<serde_json::Value> {
    prune_active_subscriptions(DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS)?;
    let subs = ACTIVE_BACKEND_SUBSCRIPTIONS
        .lock()
        .map_err(|_| anyhow!("active backend subscription lock is poisoned"))?;
    serde_json::to_value(&*subs).context("serializing active backend subscriptions")
}

pub fn active_backend_nodes(file: &FileConfig) -> Result<Vec<BackendNode>> {
    prune_active_subscriptions(DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS)?;
    let known = known_backend_nodes(file)?;
    let gateway_underlays = gateway_underlays(file);
    let subs = ACTIVE_BACKEND_SUBSCRIPTIONS
        .lock()
        .map_err(|_| anyhow!("active backend subscription lock is poisoned"))?
        .clone();
    let nodes = subs
        .into_iter()
        .filter(|(_, sub)| {
            !sub.underlay_ip.is_unspecified() && !gateway_underlays.contains(&sub.underlay_ip)
        })
        .map(|(name, sub)| BackendNode {
            overlay_ip: known
                .get(&name)
                .map(|node| node.overlay_ip.clone())
                .unwrap_or_else(|| "auto".to_string()),
            name,
            public_ip: sub.public_ip,
            underlay_ip: sub.underlay_ip,
        })
        .collect();
    Ok(nodes)
}

fn upsert_inner(
    req: &DiscoveryRequest,
    peer: Option<SocketAddr>,
    stream_id: &str,
    _state_dir: &Path,
) -> Result<()> {
    let Ok(underlay_ip) = req.underlay_ip.parse() else {
        return Ok(());
    };
    let public_ip = req
        .public_ip
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let now = now_secs();
    {
        let mut subs = ACTIVE_BACKEND_SUBSCRIPTIONS
            .lock()
            .map_err(|_| anyhow!("active backend subscription lock is poisoned"))?;
        subs.insert(
            req.node_name.clone(),
            ActiveBackendSubscription {
                public_ip,
                public_ip_mode: non_empty_or(&req.public_ip_mode, "unknown"),
                public_ip_source: non_empty_or(&req.public_ip_source, "unknown"),
                underlay_ip,
                underlay_ip_mode: non_empty_or(&req.underlay_ip_mode, "unknown"),
                underlay_ip_source: non_empty_or(&req.underlay_ip_source, "unknown"),
                peer,
                stream_id: stream_id.to_string(),
                connected_at: now,
                last_seen: now,
                last_version: req.version.clone(),
                conflicts: conflict_statuses(req),
            },
        );
    }
    {
        let mut known = KNOWN_BACKEND_NODES
            .lock()
            .map_err(|_| anyhow!("known backend node lock is poisoned"))?;
        let overlay_ip = known
            .get(&req.node_name)
            .map(|node| node.overlay_ip.clone())
            .unwrap_or_else(|| "auto".to_string());
        known.insert(
            req.node_name.clone(),
            BackendNode {
                name: req.node_name.clone(),
                public_ip,
                underlay_ip,
                overlay_ip,
            },
        );
    }
    Ok(())
}

pub fn touch(node_name: &str, stream_id: &str, req: &DiscoveryRequest) {
    if let Ok(mut subs) = ACTIVE_BACKEND_SUBSCRIPTIONS.lock()
        && let Some(sub) = subs.get_mut(node_name)
        && sub.stream_id == stream_id
    {
        sub.last_seen = now_secs();
        if !req.version.is_empty() {
            sub.last_version = req.version.clone();
        }
        if !req.conflicts.is_empty() {
            sub.conflicts = conflict_statuses(req);
        }
    }
}

pub fn remove(node_name: &str, stream_id: &str) {
    if let Ok(mut subs) = ACTIVE_BACKEND_SUBSCRIPTIONS.lock() {
        let should_remove = subs
            .get(node_name)
            .map(|sub| sub.stream_id == stream_id)
            .unwrap_or(false);
        if should_remove {
            subs.remove(node_name);
        }
    }
    if let Ok(mut known) = KNOWN_BACKEND_NODES.lock() {
        known.remove(node_name);
    }
}

fn prune_known_backend_nodes(
    gateway_underlays: &HashSet<IpAddr>,
) -> Result<(Vec<BackendNode>, bool)> {
    let mut known = KNOWN_BACKEND_NODES
        .lock()
        .map_err(|_| anyhow!("known backend node lock is poisoned"))?;
    let before = known.len();
    known.retain(|_, node| {
        node.underlay_ip.is_unspecified() || !gateway_underlays.contains(&node.underlay_ip)
    });
    Ok((known.values().cloned().collect(), known.len() != before))
}

fn known_backend_nodes(file: &FileConfig) -> Result<BTreeMap<String, BackendNode>> {
    let mut known = file
        .backend_nodes_effective()
        .into_iter()
        .map(|node| (node.name.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let memory = KNOWN_BACKEND_NODES
        .lock()
        .map_err(|_| anyhow!("known backend node lock is poisoned"))?;
    for (name, node) in memory.iter() {
        known.entry(name.clone()).or_insert_with(|| node.clone());
    }
    Ok(known)
}

fn remember_assigned_overlays(nodes: &[BackendNode]) -> Result<()> {
    let mut known = KNOWN_BACKEND_NODES
        .lock()
        .map_err(|_| anyhow!("known backend node lock is poisoned"))?;
    let active = nodes
        .iter()
        .map(|node| node.name.clone())
        .collect::<HashSet<_>>();
    known.retain(|name, _| active.contains(name));
    for node in nodes {
        known.insert(node.name.clone(), node.clone());
    }
    Ok(())
}

fn prune_active_subscriptions(ttl_secs: u64) -> Result<()> {
    let now = now_secs();
    let mut removed = Vec::new();
    {
        let mut subs = ACTIVE_BACKEND_SUBSCRIPTIONS
            .lock()
            .map_err(|_| anyhow!("active backend subscription lock is poisoned"))?;
        subs.retain(|name, sub| {
            let alive = now.saturating_sub(sub.last_seen) <= ttl_secs;
            if !alive {
                removed.push(name.clone());
            }
            alive
        });
    }
    if !removed.is_empty() {
        let mut known = KNOWN_BACKEND_NODES
            .lock()
            .map_err(|_| anyhow!("known backend node lock is poisoned"))?;
        for name in &removed {
            known.remove(name);
        }
    }
    for name in removed {
        tracing::warn!(
            "[control] backend subscription {} expired after {}s without heartbeat",
            name,
            ttl_secs
        );
    }
    Ok(())
}

fn merge_backend_inventory(
    current: &[BackendNode],
    known: Vec<BackendNode>,
    gateway_underlays: &HashSet<IpAddr>,
) -> Vec<BackendNode> {
    let current = current
        .iter()
        .map(|node| (node.name.clone(), node))
        .collect::<BTreeMap<_, _>>();
    let mut by_name = BTreeMap::new();
    for mut node in known {
        if gateway_underlays.contains(&node.underlay_ip) {
            continue;
        }
        if let Some(existing) = current.get(&node.name) {
            node.overlay_ip = existing.overlay_ip.clone();
        }
        by_name.insert(node.name.clone(), node);
    }
    by_name.into_values().collect()
}

fn gateway_underlays(file: &FileConfig) -> HashSet<IpAddr> {
    file.gateway_nodes
        .iter()
        .filter_map(|node| {
            if node.underlay_ip.is_unspecified() {
                None
            } else {
                Some(node.underlay_ip)
            }
        })
        .collect()
}

fn same_backend_inventory(current: &[BackendNode], desired: &[BackendNode]) -> bool {
    current.len() == desired.len()
        && current.iter().zip(desired).all(|(a, b)| {
            a.name == b.name
                && a.public_ip == b.public_ip
                && a.underlay_ip == b.underlay_ip
                && a.overlay_ip == b.overlay_ip
        })
}

fn non_empty_or(value: &str, fallback: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback.to_string()
    } else {
        value.to_string()
    }
}

fn conflict_statuses(req: &DiscoveryRequest) -> Vec<NodeConflictStatus> {
    req.conflicts
        .iter()
        .map(|conflict| NodeConflictStatus {
            severity: non_empty_or(&conflict.severity, "warning"),
            kind: non_empty_or(&conflict.kind, "unknown"),
            subject: conflict.subject.clone(),
            detail: conflict.detail.clone(),
        })
        .collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GatewayNode, NetworkConfig, NodeRole};
    use std::sync::{LazyLock, Mutex};

    static TEST_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn active_inventory_replaces_stale_backend_config() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = temp_state_dir("merge");
        clear_state();
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            state_dir: dir.clone(),
            network: NetworkConfig {
                overlay_cidr: "10.44.0.0/24".to_string(),
                ..NetworkConfig::default()
            },
            backend_nodes: vec![BackendNode {
                name: "stale".to_string(),
                public_ip: "198.51.100.10".parse().unwrap(),
                underlay_ip: "192.0.2.10".parse().unwrap(),
                overlay_ip: "10.44.0.9/24".to_string(),
            }],
            ..FileConfig::default()
        };

        upsert(
            &discovery("backend-1", "198.51.100.20", "192.0.2.20"),
            None,
            "stream-1",
            &dir,
        );
        merge_into(&mut file).expect("active subscriptions merge");

        assert_eq!(file.backend_nodes.len(), 1);
        assert_eq!(file.backend_nodes[0].name, "backend-1");
        assert_eq!(
            file.backend_nodes[0].underlay_ip,
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );
        assert_eq!(file.backend_nodes[0].overlay_ip, "10.44.0.2/24");

        clear_state();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn disconnected_backend_is_removed_from_runtime_inventory() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = temp_state_dir("disconnect");
        clear_state();
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            state_dir: dir.clone(),
            network: NetworkConfig {
                overlay_cidr: "10.44.0.0/24".to_string(),
                ..NetworkConfig::default()
            },
            ..FileConfig::default()
        };

        upsert(
            &discovery("backend-b", "198.51.100.30", "192.0.2.30"),
            None,
            "stream-b",
            &dir,
        );
        upsert(
            &discovery("backend-a", "198.51.100.20", "192.0.2.20"),
            None,
            "stream-a",
            &dir,
        );
        merge_into(&mut file).expect("initial active merge");
        assert_eq!(file.backend_nodes.len(), 2);
        assert_eq!(file.backend_nodes[0].name, "backend-a");
        assert_eq!(file.backend_nodes[0].overlay_ip, "10.44.0.2/24");
        assert_eq!(file.backend_nodes[1].name, "backend-b");
        assert_eq!(file.backend_nodes[1].overlay_ip, "10.44.0.3/24");

        remove("backend-a", "stream-a");
        merge_into(&mut file).expect("active merge after disconnect");
        assert_eq!(file.backend_nodes.len(), 1);
        assert_eq!(file.backend_nodes[0].name, "backend-b");
        assert_eq!(file.backend_nodes[0].overlay_ip, "10.44.0.3/24");

        clear_state();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn active_inventory_excludes_gateway_underlays() {
        let _guard = TEST_LOCK.lock().unwrap();
        let dir = temp_state_dir("exclude-gateway");
        clear_state();
        upsert(
            &discovery("gateway-b", "198.51.100.30", "192.0.2.30"),
            None,
            "stream-gateway",
            &dir,
        );
        upsert(
            &discovery("backend-a", "198.51.100.20", "192.0.2.20"),
            None,
            "stream-backend",
            &dir,
        );

        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            state_dir: dir.clone(),
            network: NetworkConfig {
                overlay_cidr: "10.44.0.0/24".to_string(),
                ..NetworkConfig::default()
            },
            gateway_nodes: vec![GatewayNode {
                name: "gateway-b".to_string(),
                public_ip: "198.51.100.30".parse().unwrap(),
                underlay_ip: "192.0.2.30".parse().unwrap(),
                overlay_ip: "10.44.0.1/24".to_string(),
            }],
            ..FileConfig::default()
        };
        merge_into(&mut file).expect("active inventory merge");

        assert_eq!(file.backend_nodes.len(), 1);
        assert_eq!(file.backend_nodes[0].name, "backend-a");
        assert_eq!(
            file.backend_nodes[0].underlay_ip,
            "192.0.2.20".parse::<IpAddr>().unwrap()
        );

        clear_state();
        std::fs::remove_dir_all(dir).ok();
    }

    fn discovery(name: &str, public_ip: &str, underlay_ip: &str) -> DiscoveryRequest {
        DiscoveryRequest {
            node_name: name.to_string(),
            node_role: "backend".to_string(),
            public_ip: public_ip.to_string(),
            underlay_ip: underlay_ip.to_string(),
            ..DiscoveryRequest::default()
        }
    }

    fn clear_state() {
        ACTIVE_BACKEND_SUBSCRIPTIONS.lock().unwrap().clear();
        KNOWN_BACKEND_NODES.lock().unwrap().clear();
    }

    fn temp_state_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "edge-lb-registry-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}
