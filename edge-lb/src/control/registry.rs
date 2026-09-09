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

#[derive(Default)]
struct BackendRegistry {
    subscriptions: BTreeMap<String, ActiveBackendSubscription>,
    nodes: BTreeMap<String, BackendNode>,
}

// A subscription and its assigned overlay share the same lifetime and lock.
static BACKEND_REGISTRY: LazyLock<Mutex<BackendRegistry>> =
    LazyLock::new(|| Mutex::new(BackendRegistry::default()));
const DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS: u64 = 30;

fn registry() -> Result<std::sync::MutexGuard<'static, BackendRegistry>> {
    BACKEND_REGISTRY
        .lock()
        .map_err(|_| anyhow!("backend registry lock is poisoned"))
}

pub fn merge_into(file: &mut FileConfig) -> Result<bool> {
    prune_active_subscriptions(DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS)?;
    let gateway_underlays = gateway_underlays(file);
    let mut registry = registry()?;
    let before = registry.nodes.len();
    registry.nodes.retain(|_, node| {
        node.underlay_ip.is_unspecified() || !gateway_underlays.contains(&node.underlay_ip)
    });
    let pruned = registry.nodes.len() != before;
    let known = registry.nodes.values().cloned().collect::<Vec<_>>();
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
    let changed = !same_backend_inventory(&file.backend_nodes, &desired.backend_nodes);
    // Publish assignments even when this caller already has the same snapshot.
    // Keep the lock until publication so a disconnected stream cannot be revived.
    for node in &desired.backend_nodes {
        registry.nodes.insert(node.name.clone(), node.clone());
    }
    if changed {
        file.backend_nodes = desired.backend_nodes;
        file.normalize();
    }
    Ok(changed)
}

pub fn upsert(req: &DiscoveryRequest, peer: Option<SocketAddr>, stream_id: &str, state_dir: &Path) {
    if let Err(e) = upsert_inner(req, peer, stream_id, state_dir) {
        tracing::warn!("[control] saving backend inventory skipped: {e:#}");
    }
}

pub fn status() -> Result<serde_json::Value> {
    prune_active_subscriptions(DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS)?;
    let subs = registry()?.subscriptions.clone();
    serde_json::to_value(&subs).context("serializing active backend subscriptions")
}

pub fn active_backend_nodes(file: &FileConfig) -> Result<Vec<BackendNode>> {
    prune_active_subscriptions(DEFAULT_ACTIVE_SUBSCRIPTION_TTL_SECS)?;
    let registry = registry()?;
    let known = known_backend_nodes(file, &registry.nodes);
    let gateway_underlays = gateway_underlays(file);
    let nodes = registry
        .subscriptions
        .iter()
        .filter(|(_, sub)| {
            !sub.underlay_ip.is_unspecified() && !gateway_underlays.contains(&sub.underlay_ip)
        })
        .map(|(name, sub)| BackendNode {
            overlay_ip: known
                .get(name)
                .map(|node| node.overlay_ip.clone())
                .unwrap_or_else(|| "auto".to_string()),
            name: name.clone(),
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
    let mut registry = registry()?;
    registry.subscriptions.insert(
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
    let overlay_ip = registry
        .nodes
        .get(&req.node_name)
        .map(|node| node.overlay_ip.clone())
        .unwrap_or_else(|| "auto".to_string());
    registry.nodes.insert(
        req.node_name.clone(),
        BackendNode {
            name: req.node_name.clone(),
            public_ip,
            underlay_ip,
            overlay_ip,
        },
    );
    Ok(())
}

pub fn touch(node_name: &str, stream_id: &str, req: &DiscoveryRequest) {
    if let Ok(mut registry) = registry()
        && let Some(sub) = registry.subscriptions.get_mut(node_name)
        && sub.stream_id == stream_id
    {
        sub.last_seen = now_secs();
        if !req.version.is_empty() {
            sub.last_version = req.version.clone();
        }
        // Empty-version/nonce heartbeats carry no new conflict observation.
        let full_ack = req.ack && !req.version.is_empty() && !req.response_nonce.is_empty();
        if full_ack || !req.conflicts.is_empty() {
            sub.conflicts = conflict_statuses(req);
        }
    }
}

pub fn remove(node_name: &str, stream_id: &str) {
    if let Ok(mut registry) = registry()
        && registry
            .subscriptions
            .get(node_name)
            .is_some_and(|sub| sub.stream_id == stream_id)
    {
        registry.subscriptions.remove(node_name);
        registry.nodes.remove(node_name);
    }
}

fn known_backend_nodes(
    file: &FileConfig,
    memory: &BTreeMap<String, BackendNode>,
) -> BTreeMap<String, BackendNode> {
    let mut known = file
        .backend_nodes_effective()
        .into_iter()
        .map(|node| (node.name.clone(), node))
        .collect::<BTreeMap<_, _>>();
    for (name, node) in memory {
        known.entry(name.clone()).or_insert_with(|| node.clone());
    }
    known
}

impl BackendRegistry {
    fn prune_expired(&mut self, now: u64, ttl_secs: u64) -> Vec<String> {
        let mut removed = Vec::new();
        self.subscriptions.retain(|name, sub| {
            let alive = now.saturating_sub(sub.last_seen) <= ttl_secs;
            if !alive {
                self.nodes.remove(name);
                removed.push(name.clone());
            }
            alive
        });
        removed
    }
}

fn prune_active_subscriptions(ttl_secs: u64) -> Result<()> {
    let removed = registry()?.prune_expired(now_secs(), ttl_secs);
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

    #[test]
    fn late_disconnect_preserves_reconnected_overlay() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_state();
        let dir = temp_state_dir("reconnect");
        let req = discovery("backend-a", "198.51.100.20", "192.0.2.20");
        upsert(&req, None, "old", &dir);
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            network: NetworkConfig {
                overlay_cidr: "10.44.0.0/24".to_string(),
                ..NetworkConfig::default()
            },
            ..FileConfig::default()
        };
        merge_into(&mut file).unwrap();
        let assigned = file.backend_nodes[0].overlay_ip.clone();

        upsert(&req, None, "new", &dir);
        remove("backend-a", "old");
        let nodes = active_backend_nodes(&FileConfig::default()).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].overlay_ip, assigned);
        assert_eq!(status().unwrap()["backend-a"]["stream_id"], "new");

        remove("backend-a", "new");
        assert!(active_backend_nodes(&file).unwrap().is_empty());
        merge_into(&mut file).unwrap();
        assert!(file.backend_nodes.is_empty());
        clear_state();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn full_ack_clears_conflicts_but_heartbeat_does_not() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_state();
        let dir = temp_state_dir("ack");
        let mut req = discovery("backend-a", "198.51.100.20", "192.0.2.20");
        req.conflicts.push(crate::control::pb::NodeConflict {
            kind: "route_table".to_string(),
            ..Default::default()
        });
        upsert(&req, None, "current", &dir);
        let mut ack = DiscoveryRequest {
            ack: true,
            ..Default::default()
        };
        touch("backend-a", "current", &ack);
        assert_eq!(
            status().unwrap()["backend-a"]["conflicts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );

        ack.version = "v2".to_string();
        ack.response_nonce = "nonce-2".to_string();
        touch("backend-a", "stale", &ack);
        assert_eq!(
            status().unwrap()["backend-a"]["conflicts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        ack.ack = false;
        ack.error_detail = "apply failed".to_string();
        touch("backend-a", "current", &ack);
        assert_eq!(
            status().unwrap()["backend-a"]["conflicts"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        ack.ack = true;
        ack.error_detail.clear();
        touch("backend-a", "current", &ack);
        let snapshot = status().unwrap();
        assert_eq!(snapshot["backend-a"]["last_version"], "v2");
        assert!(
            snapshot["backend-a"]["conflicts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        clear_state();
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn expiry_removes_overlay_and_preserves_fresh_registration() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_state();
        let req = discovery("backend-a", "198.51.100.20", "192.0.2.20");
        let path = Path::new("/unused");
        upsert(&req, None, "old", path);
        {
            let mut registry = registry().unwrap();
            registry
                .subscriptions
                .get_mut("backend-a")
                .unwrap()
                .last_seen = 100;
            assert!(registry.prune_expired(130, 30).is_empty());
            assert_eq!(registry.prune_expired(131, 30), vec!["backend-a"]);
            assert!(registry.nodes.is_empty());
            assert!(registry.subscriptions.is_empty());
        }
        upsert(&req, None, "new", path);
        remove("backend-a", "old");
        prune_active_subscriptions(30).unwrap();
        let registry = registry().unwrap();
        assert_eq!(registry.subscriptions["backend-a"].stream_id, "new");
        assert!(registry.nodes.contains_key("backend-a"));
    }

    #[test]
    fn unchanged_snapshot_still_publishes_overlay_assignment() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_state();
        let req = discovery("backend-a", "198.51.100.20", "192.0.2.20");
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            node_name: "gateway-a".to_string(),
            network: NetworkConfig {
                overlay_cidr: "10.44.0.0/24".to_string(),
                ..NetworkConfig::default()
            },
            ..FileConfig::default()
        };
        upsert(&req, None, "old", Path::new("/unused"));
        merge_into(&mut file).unwrap();
        let overlay = file.backend_nodes[0].overlay_ip.clone();
        remove("backend-a", "old");
        upsert(&req, None, "new", Path::new("/unused"));
        assert!(!merge_into(&mut file).unwrap());
        assert_eq!(
            active_backend_nodes(&FileConfig::default()).unwrap()[0].overlay_ip,
            overlay
        );
        clear_state();
    }

    #[test]
    fn concurrent_registration_and_cleanup_keep_both_indexes_consistent() {
        let _guard = TEST_LOCK.lock().unwrap();
        clear_state();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for _ in 0..200 {
                    upsert(
                        &discovery("backend-a", "198.51.100.20", "192.0.2.20"),
                        None,
                        "current",
                        Path::new("/unused"),
                    );
                }
            });
            scope.spawn(|| {
                for _ in 0..200 {
                    remove("backend-a", "current");
                }
            });
            for _ in 0..200 {
                let registry = registry().unwrap();
                assert_eq!(
                    registry.subscriptions.contains_key("backend-a"),
                    registry.nodes.contains_key("backend-a")
                );
            }
        });
        clear_state();
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
        *registry().unwrap() = BackendRegistry::default();
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
