use std::{
    collections::BTreeSet,
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    config::{
        self, ActiveSource, BackendNode, BackendReturnPort, Config, FileConfig, GatewayNode,
        NetworkConfig, Protocol,
    },
    control::pb::{self, ConfigSnapshot, DiscoveryResponse},
};

pub fn response_for_backend(cfg: &Config, backend_underlay: IpAddr) -> Result<DiscoveryResponse> {
    let snapshot = from_config_for_backend(cfg, backend_underlay)?;
    let version = snapshot_version(&snapshot);
    Ok(DiscoveryResponse {
        nonce: nonce(),
        version,
        snapshot: Some(snapshot),
    })
}

pub fn log_send(node_name: &str, resp: &DiscoveryResponse) {
    let Some(snapshot) = &resp.snapshot else {
        tracing::debug!(
            "[control] sending empty snapshot to {} version {}",
            node_name,
            resp.version
        );
        return;
    };
    let network = snapshot.network.as_ref();
    tracing::debug!(
        "[control] sending snapshot to {} version {} active_gateway={} gateway_vxlan_dev={} overlay_cidr={} vni={} vxlan_port={} mtu={} dscp={} return_ports={} backends={}",
        node_name,
        resp.version,
        snapshot.active_gateway,
        network
            .map(|n| n.gateway_vxlan_dev.as_str())
            .unwrap_or("unknown"),
        network
            .map(|n| n.overlay_cidr.as_str())
            .unwrap_or("unknown"),
        network.map(|n| n.vni).unwrap_or_default(),
        network.map(|n| n.vxlan_port).unwrap_or_default(),
        network.map(|n| n.vxlan_mtu).unwrap_or_default(),
        network.map(|n| n.dscp).unwrap_or_default(),
        snapshot.backend_return_ports.len(),
        snapshot.backend_nodes.len(),
    );
}

pub fn log_recv(cfg: &Config, resp: &DiscoveryResponse) {
    let Some(snapshot) = &resp.snapshot else {
        tracing::debug!(
            "[backend] xDS received empty snapshot version {} nonce {}",
            resp.version,
            resp.nonce
        );
        return;
    };
    let network = snapshot.network.as_ref();
    tracing::debug!(
        "[backend] xDS received snapshot version {} nonce {} active_gateway={} gateway_vxlan_dev={} local_return_dev={} overlay_cidr={} vni={} vxlan_port={} mtu={} dscp={} return_ports={} backends={}",
        resp.version,
        resp.nonce,
        snapshot.active_gateway,
        network
            .map(|n| n.gateway_vxlan_dev.as_str())
            .unwrap_or("unknown"),
        cfg.network().vxlan_dev,
        network
            .map(|n| n.overlay_cidr.as_str())
            .unwrap_or("unknown"),
        network.map(|n| n.vni).unwrap_or_default(),
        network.map(|n| n.vxlan_port).unwrap_or_default(),
        network.map(|n| n.vxlan_mtu).unwrap_or_default(),
        network.map(|n| n.dscp).unwrap_or_default(),
        snapshot.backend_return_ports.len(),
        snapshot.backend_nodes.len(),
    );
}

pub fn apply_managed_reusing(
    base: &Config,
    resp: DiscoveryResponse,
    existing: Option<crate::linux::return_path::ManagedReturnPath>,
) -> Result<crate::linux::return_path::ManagedReturnPath> {
    let snapshot = resp.snapshot.context("empty discovery snapshot")?;
    let file = file_from_snapshot(base, &snapshot)?;
    let cfg = Config {
        path: base.path.clone(),
        file,
    };
    crate::role::backend::apply_managed_reusing(&cfg, existing)
}

pub fn backend_conflicts_for_response(
    base: &Config,
    resp: &DiscoveryResponse,
) -> Result<Vec<crate::linux::conflict::NodeConflict>> {
    let snapshot = resp.snapshot.clone().context("empty discovery snapshot")?;
    let file = file_from_snapshot(base, &snapshot)?;
    let cfg = Config {
        path: base.path.clone(),
        file,
    };
    Ok(crate::linux::conflict::inspect_backend(&cfg))
}

pub fn combine_gateway_responses(responses: Vec<DiscoveryResponse>) -> Result<DiscoveryResponse> {
    let mut responses = responses
        .into_iter()
        .filter(|resp| resp.snapshot.is_some())
        .collect::<Vec<_>>();
    if responses.is_empty() {
        bail!("no xDS snapshots available");
    }
    responses.sort_by(|a, b| {
        snapshot_gateway_key(a)
            .unwrap_or_default()
            .cmp(&snapshot_gateway_key(b).unwrap_or_default())
    });
    // A backend does not elect a gateway. It must install one independent
    // return path for every gateway snapshot so DSCP selects the matching
    // gateway. Active/backup ownership is enforced by the gateways and is
    // deliberately not a prerequisite for backend datapath convergence.
    let mut combined = responses
        .first()
        .and_then(|resp| resp.snapshot.clone())
        .context("missing latest snapshot")?;
    combined.gateway_nodes.clear();
    combined.backend_nodes.clear();
    combined.backend_return_ports.clear();

    let mut gateway_keys = BTreeSet::new();
    let mut backend_keys = BTreeSet::new();
    let mut port_keys = BTreeSet::new();
    let mut versions = Vec::new();
    for resp in responses {
        versions.push(resp.version);
        let Some(snapshot) = resp.snapshot else {
            continue;
        };
        for gateway in snapshot.gateway_nodes {
            let key = (gateway.underlay_ip.clone(), gateway.name.clone());
            if gateway_keys.insert(key) {
                combined.gateway_nodes.push(gateway);
            }
        }
        for backend in snapshot.backend_nodes {
            let key = (backend.underlay_ip.clone(), backend.name.clone());
            if backend_keys.insert(key) {
                combined.backend_nodes.push(backend);
            }
        }
        for port in snapshot.backend_return_ports {
            let key = (
                port.gateway_underlay_ip.clone(),
                port.address.clone(),
                port.protocol.clone(),
                port.port,
                port.dscp,
                port.mark,
                port.route_table_id,
            );
            if port_keys.insert(key) {
                combined.backend_return_ports.push(port);
            }
        }
    }
    versions.sort();
    let mut hasher = Sha256::new();
    for version in versions {
        hasher.update(version.as_bytes());
    }
    Ok(DiscoveryResponse {
        nonce: nonce(),
        version: format!("{:x}", hasher.finalize()),
        snapshot: Some(combined),
    })
}

fn snapshot_gateway_key(resp: &DiscoveryResponse) -> Option<String> {
    resp.snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.network.as_ref())
        .map(|network| network.gateway_ip.clone())
}

fn from_config_for_backend(cfg: &Config, backend_underlay: IpAddr) -> Result<ConfigSnapshot> {
    let n = cfg.network();
    let fallback = GatewayNode {
        name: cfg.node_name.clone(),
        public_ip: cfg.public_ip,
        underlay_ip: cfg.underlay_ip,
        overlay_ip: cfg.gateway_cfg().overlay_ip.clone(),
    };
    let source_gateway = source_gateway(cfg, &fallback);
    let gateway_overlay_ip = overlay_addr(&source_gateway.overlay_ip, "gateway overlay_ip")?;
    // Marks/tables are gateway-slotted so two HA gateways never share one
    // return table.
    let slot = config::gateway_slot(&cfg.gateway_nodes, source_gateway.underlay_ip);
    let backend_return_ports = backend_return_ports_from_config(cfg)
        .into_iter()
        .filter(|p| p.address == backend_underlay)
        .map(|p| pb::BackendReturnPort {
            backend: p.backend.clone().unwrap_or_default(),
            address: p.address.to_string(),
            protocol: p.protocol.as_str().to_string(),
            port: p.port as u32,
            gateway: source_gateway.name.clone(),
            gateway_underlay_ip: source_gateway.underlay_ip.to_string(),
            gateway_overlay_ip: gateway_overlay_ip.to_string(),
            dscp: n.dscp,
            mark: config::return_mark(n.dscp, slot),
            route_table_id: config::return_table_id(n.dscp, slot),
            backend_overlay_ip: p.backend_overlay_ip.unwrap_or_default(),
        })
        .collect();
    let mut snapshot = ConfigSnapshot {
        active_gateway: String::new(),
        network: Some(pb::Network {
            gateway_public_ip: source_gateway.public_ip.to_string(),
            gateway_ip: source_gateway.underlay_ip.to_string(),
            overlay_cidr: n.overlay_cidr.clone(),
            gateway_vxlan_dev: n.vxlan_dev.clone(),
            vni: n.vni,
            vxlan_port: n.vxlan_port as u32,
            vxlan_mtu: n.vxlan_mtu,
            dscp: n.dscp,
        }),
        gateway_nodes: cfg
            .gateway_nodes
            .iter()
            .map(|g| pb::GatewayNode {
                name: g.name.clone(),
                public_ip: g.public_ip.to_string(),
                underlay_ip: g.underlay_ip.to_string(),
                overlay_ip: g.overlay_ip.clone(),
            })
            .collect(),
        backend_nodes: cfg
            .backend_nodes_effective()
            .iter()
            .map(|b| pb::BackendNode {
                name: b.name.clone(),
                public_ip: b.public_ip.to_string(),
                underlay_ip: b.underlay_ip.to_string(),
                overlay_ip: b.overlay_ip.clone(),
            })
            .collect(),
        backend_return_ports,
    };
    snapshot
        .gateway_nodes
        .sort_by(|a, b| a.underlay_ip.cmp(&b.underlay_ip).then(a.name.cmp(&b.name)));
    snapshot
        .backend_nodes
        .sort_by(|a, b| a.underlay_ip.cmp(&b.underlay_ip).then(a.name.cmp(&b.name)));
    Ok(snapshot)
}

fn file_from_snapshot(base: &Config, snapshot: &ConfigSnapshot) -> Result<FileConfig> {
    let network = snapshot
        .network
        .as_ref()
        .context("snapshot missing network")?;
    let mut file = base.file.clone();
    let local_vxlan_dev = file.network.vxlan_dev.clone();
    file.network = NetworkConfig {
        gateway_public_ip: parse_ip(&network.gateway_public_ip, "gateway_public_ip")?,
        gateway_ip: parse_ip(&network.gateway_ip, "gateway_ip")?,
        standby_gateway_ip: None,
        backend_public_ip: file.network.backend_public_ip,
        backend_ip: file.network.backend_ip,
        overlay_cidr: if network.overlay_cidr.trim().is_empty() {
            file.network.overlay_cidr
        } else {
            network.overlay_cidr.clone()
        },
        underlay_dev: file.network.underlay_dev,
        vxlan_dev: local_vxlan_dev,
        vni: network.vni,
        vxlan_port: network.vxlan_port as u16,
        vxlan_mtu: network.vxlan_mtu,
        vxlan_mtu_auto: false,
        dscp: network.dscp,
    };
    file.gateway_nodes = snapshot
        .gateway_nodes
        .iter()
        .map(|g| {
            Ok(GatewayNode {
                name: g.name.clone(),
                public_ip: parse_ip(&g.public_ip, "gateway public_ip")?,
                underlay_ip: parse_ip(&g.underlay_ip, "gateway underlay_ip")?,
                overlay_ip: g.overlay_ip.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    file.backend_nodes = snapshot
        .backend_nodes
        .iter()
        .map(|b| {
            Ok(BackendNode {
                name: b.name.clone(),
                public_ip: parse_ip(&b.public_ip, "backend public_ip")?,
                underlay_ip: parse_ip(&b.underlay_ip, "backend underlay_ip")?,
                overlay_ip: b.overlay_ip.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let local = local_backend_for_snapshot(base, &file)?;
    file.listeners.clear();
    file.target_groups.clear();
    file.backend_return_ports = snapshot
        .backend_return_ports
        .iter()
        .filter_map(|p| backend_return_port_from_proto_for_local(p, local.underlay_ip).transpose())
        .collect::<Result<Vec<_>>>()?;
    file.ha.active_source = ActiveSource::Xds;
    file.normalize();
    file.validate()?;
    Ok(file)
}

fn backend_return_ports_from_config(cfg: &Config) -> Vec<BackendReturnPort> {
    let mut ports = cfg.listener_backend_return_ports();
    if ports.is_empty() {
        ports = cfg.backend_return_ports();
    }
    ports.sort_by(|a, b| {
        (
            a.backend.as_deref().unwrap_or_default(),
            a.address,
            a.protocol.as_str(),
            a.port,
        )
            .cmp(&(
                b.backend.as_deref().unwrap_or_default(),
                b.address,
                b.protocol.as_str(),
                b.port,
            ))
    });
    ports.dedup_by(|a, b| {
        a.backend == b.backend
            && a.address == b.address
            && a.protocol == b.protocol
            && a.port == b.port
            && a.gateway_underlay_ip == b.gateway_underlay_ip
            && a.dscp == b.dscp
            && a.mark == b.mark
            && a.route_table_id == b.route_table_id
    });
    ports
}

fn backend_return_port_from_proto_for_local(
    port: &pb::BackendReturnPort,
    local_underlay: IpAddr,
) -> Result<Option<BackendReturnPort>> {
    let address = parse_ip(&port.address, "backend return port address")?;
    if address != local_underlay {
        return Ok(None);
    }
    let protocol = match port.protocol.as_str() {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => bail!("unknown backend return port protocol {other:?}"),
    };
    Ok(Some(BackendReturnPort {
        backend: (!port.backend.is_empty()).then(|| port.backend.clone()),
        address,
        protocol,
        port: u16::try_from(port.port).context("backend return port out of range")?,
        gateway: (!port.gateway.is_empty()).then(|| port.gateway.clone()),
        gateway_underlay_ip: parse_optional_ip(&port.gateway_underlay_ip, "gateway_underlay_ip")?,
        gateway_overlay_ip: parse_optional_ip(&port.gateway_overlay_ip, "gateway_overlay_ip")?,
        backend_overlay_ip: (!port.backend_overlay_ip.is_empty())
            .then(|| port.backend_overlay_ip.clone()),
        dscp: (port.dscp > 0).then_some(port.dscp),
        mark: (port.mark > 0).then_some(port.mark),
        route_table_id: (port.route_table_id > 0).then_some(port.route_table_id),
    }))
}

fn source_gateway<'a>(cfg: &'a Config, fallback: &'a GatewayNode) -> &'a GatewayNode {
    cfg.gateway_nodes
        .iter()
        .find(|gw| gw.name == cfg.node_name || gw.underlay_ip == cfg.underlay_ip)
        .unwrap_or(fallback)
}

fn overlay_addr(value: &str, name: &str) -> Result<IpAddr> {
    value
        .split('/')
        .next()
        .unwrap_or(value)
        .parse()
        .with_context(|| format!("bad {name} {value:?}"))
}

fn parse_optional_ip(value: &str, name: &str) -> Result<Option<IpAddr>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(parse_ip(value, name)?))
}

fn local_backend_for_snapshot(base: &Config, file: &FileConfig) -> Result<BackendNode> {
    if let Some(backend) = file
        .backend_nodes
        .iter()
        .find(|b| b.name == base.node_name)
        .cloned()
    {
        return Ok(backend);
    }
    if let Ok(local) = base.local_backend()
        && let Some(backend) = file
            .backend_nodes
            .iter()
            .find(|b| b.underlay_ip == local.underlay_ip)
            .cloned()
    {
        return Ok(backend);
    }
    bail!(
        "snapshot does not contain local backend node {}",
        base.node_name
    )
}

fn snapshot_version(snapshot: &ConfigSnapshot) -> String {
    format!("{:x}", Sha256::digest(snapshot.encode_to_vec()))
}

fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}")
}

fn parse_ip(value: &str, name: &str) -> Result<IpAddr> {
    value
        .parse()
        .with_context(|| format!("bad {name} IP {value:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BackendTarget, ControlPlaneMode, HaConfig, LbMode, Listener, NodeRole, TargetGroup,
    };
    use std::{fs, path::PathBuf};

    fn gateway_response(
        name: &str,
        gateway_ip: &str,
        overlay_cidr: &str,
        dscp: u32,
        active_gateway: &str,
    ) -> DiscoveryResponse {
        DiscoveryResponse {
            version: format!("{name}-version"),
            nonce: format!("{name}-nonce"),
            snapshot: Some(ConfigSnapshot {
                active_gateway: active_gateway.to_string(),
                network: Some(pb::Network {
                    gateway_public_ip: "203.0.113.10".to_string(),
                    gateway_ip: gateway_ip.to_string(),
                    gateway_vxlan_dev: "edge-hub".to_string(),
                    vni: 100,
                    vxlan_port: 4789,
                    vxlan_mtu: 1450,
                    dscp,
                    overlay_cidr: overlay_cidr.to_string(),
                }),
                gateway_nodes: vec![
                    pb::GatewayNode {
                        name: "gateway-a".to_string(),
                        public_ip: "203.0.113.10".to_string(),
                        underlay_ip: "192.0.2.11".to_string(),
                        overlay_ip: "10.255.12.1/24".to_string(),
                    },
                    pb::GatewayNode {
                        name: "gateway-b".to_string(),
                        public_ip: "203.0.113.11".to_string(),
                        underlay_ip: "192.0.2.16".to_string(),
                        overlay_ip: "10.255.16.1/24".to_string(),
                    },
                ],
                backend_nodes: vec![pb::BackendNode {
                    name: "backend-1".to_string(),
                    public_ip: "198.51.100.20".to_string(),
                    underlay_ip: "192.0.2.22".to_string(),
                    overlay_ip: "10.255.12.2/24".to_string(),
                }],
                backend_return_ports: vec![{
                    let gateway_underlay = parse_ip(gateway_ip, "gateway underlay").unwrap();
                    let slot = config::gateway_slot(
                        &[
                            GatewayNode {
                                name: "gateway-a".to_string(),
                                public_ip: "203.0.113.10".parse().unwrap(),
                                underlay_ip: "192.0.2.11".parse().unwrap(),
                                overlay_ip: "10.255.12.1/24".to_string(),
                            },
                            GatewayNode {
                                name: "gateway-b".to_string(),
                                public_ip: "203.0.113.11".parse().unwrap(),
                                underlay_ip: "192.0.2.16".parse().unwrap(),
                                overlay_ip: "10.255.16.1/24".to_string(),
                            },
                        ],
                        gateway_underlay,
                    );
                    pb::BackendReturnPort {
                        backend: "backend-1".to_string(),
                        address: "192.0.2.22".to_string(),
                        protocol: "tcp".to_string(),
                        port: 8080,
                        gateway: name.to_string(),
                        gateway_underlay_ip: gateway_ip.to_string(),
                        gateway_overlay_ip: if name == "gateway-a" {
                            "10.255.12.1".to_string()
                        } else {
                            "10.255.16.1".to_string()
                        },
                        dscp,
                        mark: config::return_mark(dscp, slot),
                        route_table_id: config::return_table_id(dscp, slot),
                        backend_overlay_ip: String::new(),
                    }
                }],
            }),
        }
    }

    #[test]
    fn combined_snapshot_uses_deterministic_gateway_network_as_base() {
        let combined = combine_gateway_responses(vec![
            gateway_response("gateway-a", "192.0.2.11", "10.255.12.0/24", 46, "gateway-a"),
            gateway_response("gateway-b", "192.0.2.16", "10.255.16.0/24", 40, "gateway-a"),
        ])
        .expect("snapshots combine");
        let snapshot = combined.snapshot.expect("combined snapshot");
        let network = snapshot.network.expect("combined network");

        assert_eq!(network.gateway_ip, "192.0.2.11");
        assert_eq!(network.overlay_cidr, "10.255.12.0/24");
        assert_eq!(network.dscp, 46);
        assert_eq!(snapshot.backend_return_ports.len(), 2);
    }

    #[test]
    fn combined_snapshot_accepts_multiple_active_gateway_views() {
        let combined = combine_gateway_responses(vec![
            gateway_response("gateway-a", "192.0.2.11", "10.255.12.0/24", 46, "gateway-a"),
            gateway_response("gateway-b", "192.0.2.16", "10.255.16.0/24", 40, "gateway-b"),
        ])
        .expect("snapshots combine");
        let snapshot = combined.snapshot.expect("combined snapshot");
        assert_eq!(snapshot.backend_return_ports.len(), 2);
    }

    #[test]
    fn combined_snapshot_merges_partial_gateway_inventory() {
        let mut gateway_a =
            gateway_response("gateway-a", "192.0.2.11", "10.255.12.0/24", 46, "gateway-a");
        let mut gateway_b =
            gateway_response("gateway-b", "192.0.2.16", "10.255.16.0/24", 40, "gateway-b");
        gateway_a
            .snapshot
            .as_mut()
            .unwrap()
            .gateway_nodes
            .retain(|gateway| gateway.name == "gateway-a");
        gateway_b
            .snapshot
            .as_mut()
            .unwrap()
            .gateway_nodes
            .retain(|gateway| gateway.name == "gateway-b");

        let combined = combine_gateway_responses(vec![gateway_a, gateway_b])
            .expect("partial gateway inventories combine");
        let snapshot = combined.snapshot.expect("combined snapshot");
        let mut underlays = snapshot
            .gateway_nodes
            .iter()
            .map(|gateway| gateway.underlay_ip.as_str())
            .collect::<Vec<_>>();
        underlays.sort_unstable();

        assert_eq!(underlays, vec!["192.0.2.11", "192.0.2.16"]);
        assert_eq!(snapshot.backend_return_ports.len(), 2);
    }

    #[test]
    fn backend_config_accepts_gateway_inventory_from_multiple_overlay_cidrs() {
        let combined = combine_gateway_responses(vec![
            gateway_response("gateway-a", "192.0.2.11", "10.255.12.0/24", 46, "gateway-a"),
            gateway_response("gateway-b", "192.0.2.16", "10.255.16.0/24", 40, "gateway-b"),
        ])
        .expect("snapshots combine");
        let snapshot = combined.snapshot.expect("combined snapshot");
        let mut base_file = FileConfig {
            node_role: crate::config::NodeRole::Backend,
            node_name: "backend-1".to_string(),
            ..FileConfig::default()
        };
        base_file.ha.active_source = ActiveSource::Xds;
        base_file.control_plane.enabled = true;
        base_file.control_plane.mode = crate::config::ControlPlaneMode::Xds;
        base_file.backend_nodes = vec![BackendNode {
            name: "backend-1".to_string(),
            public_ip: "198.51.100.20".parse().unwrap(),
            underlay_ip: "192.0.2.22".parse().unwrap(),
            overlay_ip: "10.255.12.2/24".to_string(),
        }];
        let base = Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: base_file,
        };

        let file = file_from_snapshot(&base, &snapshot)
            .expect("backend xDS config accepts multi-overlay gateway inventory");

        assert_eq!(file.gateway_nodes.len(), 2);
        assert!(file.backend_return_ports.len() >= 2);
    }

    #[test]
    fn snapshot_to_backend_config_keeps_only_return_path_contract() {
        let mut base_file = FileConfig {
            node_name: "backend-2".to_string(),
            ha: HaConfig {
                active_source: ActiveSource::Xds,
                ..HaConfig::default()
            },
            ..FileConfig::default()
        };
        base_file.control_plane.enabled = true;
        base_file.control_plane.mode = ControlPlaneMode::Xds;
        base_file.control_plane.listen = "127.0.0.1:22222".to_string();
        base_file.backend_nodes = vec![BackendNode {
            name: "backend-2".to_string(),
            public_ip: "198.51.100.21".parse().unwrap(),
            underlay_ip: "192.0.2.23".parse().unwrap(),
            overlay_ip: "10.255.255.3/24".to_string(),
        }];
        let base = Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: base_file,
        };

        let snapshot = ConfigSnapshot {
            active_gateway: "gateway-a".to_string(),
            network: Some(pb::Network {
                gateway_public_ip: "203.0.113.10".to_string(),
                gateway_ip: "192.0.2.11".to_string(),
                overlay_cidr: "10.255.255.0/24".to_string(),
                gateway_vxlan_dev: "edge-hub".to_string(),
                vni: 100,
                vxlan_port: 4789,
                vxlan_mtu: 1450,
                dscp: 46,
            }),
            gateway_nodes: vec![pb::GatewayNode {
                name: "gateway-a".to_string(),
                public_ip: "203.0.113.10".to_string(),
                underlay_ip: "192.0.2.11".to_string(),
                overlay_ip: "10.255.255.1/24".to_string(),
            }],
            backend_nodes: vec![
                pb::BackendNode {
                    name: "backend-1".to_string(),
                    public_ip: "198.51.100.20".to_string(),
                    underlay_ip: "192.0.2.22".to_string(),
                    overlay_ip: "10.255.255.2/24".to_string(),
                },
                pb::BackendNode {
                    name: "backend-2".to_string(),
                    public_ip: "198.51.100.21".to_string(),
                    underlay_ip: "192.0.2.23".to_string(),
                    overlay_ip: "10.255.255.3/24".to_string(),
                },
            ],
            backend_return_ports: vec![
                pb::BackendReturnPort {
                    backend: "backend-2".to_string(),
                    address: "192.0.2.23".to_string(),
                    protocol: "tcp".to_string(),
                    port: 8080,
                    ..Default::default()
                },
                pb::BackendReturnPort {
                    backend: "backend-2".to_string(),
                    address: "192.0.2.23".to_string(),
                    protocol: "udp".to_string(),
                    port: 8080,
                    ..Default::default()
                },
                pb::BackendReturnPort {
                    backend: "backend-1".to_string(),
                    address: "192.0.2.22".to_string(),
                    protocol: "tcp".to_string(),
                    port: 8081,
                    ..Default::default()
                },
            ],
        };

        let file = file_from_snapshot(&base, &snapshot).expect("snapshot converts");

        assert!(file.listeners.is_empty());
        assert!(file.target_groups.is_empty());
        assert_eq!(file.backend_return_ports.len(), 2);
        assert_eq!(file.backend_return_ports[0].address, local_ip("192.0.2.23"));
        assert_eq!(file.backend_return_ports[0].port, 8080);
    }

    #[test]
    fn backend_snapshot_excludes_business_listener_resources() {
        let backend_ip = local_ip("192.0.2.23");
        let cfg = Config {
            file: FileConfig {
                gateway_nodes: vec![GatewayNode {
                    name: "gateway-a".to_string(),
                    public_ip: "203.0.113.10".parse().unwrap(),
                    underlay_ip: "192.0.2.11".parse().unwrap(),
                    overlay_ip: "10.255.255.1/24".to_string(),
                }],
                backend_nodes: vec![BackendNode {
                    name: "backend-1".to_string(),
                    public_ip: "198.51.100.20".parse().unwrap(),
                    underlay_ip: backend_ip,
                    overlay_ip: "10.255.255.2/24".to_string(),
                }],
                target_groups: vec![TargetGroup {
                    name: "targets".to_string(),
                    targets: vec![BackendTarget {
                        backend: Some("backend-1".to_string()),
                        address: backend_ip,
                        weight: 1,
                    }],
                    ..TargetGroup::default()
                }],
                listeners: vec![Listener {
                    name: "tcp-80".to_string(),
                    port: 80,
                    target_port: 8080,
                    target_group: "targets".to_string(),
                    protocols: vec![Protocol::Tcp],
                    mode: LbMode::Default,
                    ..Listener::default()
                }],
                ..FileConfig::default()
            },
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
        };

        let snapshot = from_config_for_backend(&cfg, backend_ip).unwrap();

        assert_eq!(snapshot.backend_return_ports.len(), 1);
    }

    #[test]
    fn snapshot_return_ports_include_all_native_listeners() {
        let cfg = Config {
            file: FileConfig {
                target_groups: vec![
                    TargetGroup {
                        name: "default-targets".to_string(),
                        targets: vec![BackendTarget {
                            address: "192.0.2.23".parse().unwrap(),
                            weight: 1,
                            ..BackendTarget::default()
                        }],
                        ..TargetGroup::default()
                    },
                    TargetGroup {
                        name: "secondary-targets".to_string(),
                        targets: vec![BackendTarget {
                            address: "192.0.2.23".parse().unwrap(),
                            weight: 1,
                            ..BackendTarget::default()
                        }],
                        ..TargetGroup::default()
                    },
                ],
                listeners: vec![
                    Listener {
                        name: "default".to_string(),
                        port: 80,
                        target_port: 8080,
                        target_group: "default-targets".to_string(),
                        protocols: vec![Protocol::Tcp],
                        mode: LbMode::Default,
                        ..Listener::default()
                    },
                    Listener {
                        name: "secondary".to_string(),
                        port: 81,
                        target_port: 8081,
                        target_group: "secondary-targets".to_string(),
                        protocols: vec![Protocol::Tcp],
                        mode: LbMode::Default,
                        ..Listener::default()
                    },
                ],
                ..FileConfig::default()
            },
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
        };

        let ports = backend_return_ports_from_config(&cfg);

        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0].port, 8080);
        assert_eq!(ports[0].address, local_ip("192.0.2.23"));
        assert_eq!(ports[1].port, 8081);
        assert_eq!(ports[1].address, local_ip("192.0.2.23"));
    }

    #[test]
    fn backend_snapshot_contains_only_that_backend_ports() {
        let cfg = Config {
            file: FileConfig {
                gateway_nodes: vec![GatewayNode {
                    name: "gateway-a".to_string(),
                    public_ip: "203.0.113.10".parse().unwrap(),
                    underlay_ip: "192.0.2.11".parse().unwrap(),
                    overlay_ip: "10.255.255.1/24".to_string(),
                }],
                backend_nodes: vec![
                    BackendNode {
                        name: "backend-1".to_string(),
                        public_ip: "198.51.100.20".parse().unwrap(),
                        underlay_ip: "192.0.2.20".parse().unwrap(),
                        overlay_ip: "10.255.255.2/24".to_string(),
                    },
                    BackendNode {
                        name: "backend-2".to_string(),
                        public_ip: "198.51.100.21".parse().unwrap(),
                        underlay_ip: "192.0.2.21".parse().unwrap(),
                        overlay_ip: "10.255.255.3/24".to_string(),
                    },
                ],
                target_groups: vec![TargetGroup {
                    name: "targets".to_string(),
                    targets: vec![
                        BackendTarget {
                            backend: Some("backend-1".to_string()),
                            address: "192.0.2.20".parse().unwrap(),
                            weight: 1,
                        },
                        BackendTarget {
                            backend: Some("backend-2".to_string()),
                            address: "192.0.2.21".parse().unwrap(),
                            weight: 2,
                        },
                    ],
                    ..TargetGroup::default()
                }],
                listeners: vec![Listener {
                    name: "multi-backend".to_string(),
                    port: 80,
                    target_port: 8081,
                    target_group: "targets".to_string(),
                    protocols: vec![Protocol::Tcp],
                    mode: LbMode::Default,
                    ..Listener::default()
                }],
                ..FileConfig::default()
            },
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
        };

        let snapshot = from_config_for_backend(&cfg, local_ip("192.0.2.21")).unwrap();

        assert_eq!(snapshot.backend_nodes.len(), 2);
        assert_eq!(snapshot.backend_return_ports.len(), 1);
        assert_eq!(snapshot.backend_return_ports[0].address, "192.0.2.21");
        assert_eq!(snapshot.backend_return_ports[0].port, 8081);
    }

    #[test]
    fn snapshot_version_changes_when_return_path_changes() {
        let mut file = FileConfig {
            node_role: NodeRole::Gateway,
            target_groups: vec![TargetGroup {
                name: "listener-targets".to_string(),
                targets: vec![BackendTarget {
                    address: "192.0.2.23".parse().unwrap(),
                    weight: 1,
                    ..BackendTarget::default()
                }],
                ..TargetGroup::default()
            }],
            listeners: vec![Listener {
                name: "listener".to_string(),
                port: 80,
                target_port: 8080,
                target_group: "listener-targets".to_string(),
                protocols: vec![Protocol::Tcp],
                mode: LbMode::Default,
                ..Listener::default()
            }],
            ..FileConfig::default()
        };
        file.normalize();
        let default_cfg = Config {
            file: file.clone(),
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
        };
        let default_version = response_for_backend(&default_cfg, local_ip("192.0.2.23"))
            .unwrap()
            .version;
        assert_eq!(backend_return_ports_from_config(&default_cfg).len(), 1);

        file.listeners[0].target_port = 8081;
        file.normalize();
        let changed_cfg = Config {
            file,
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
        };
        let changed_version = response_for_backend(&changed_cfg, local_ip("192.0.2.23"))
            .unwrap()
            .version;
        assert_eq!(backend_return_ports_from_config(&changed_cfg).len(), 1);
        assert_ne!(default_version, changed_version);
    }

    #[test]
    fn snapshot_version_ignores_active_gateway_changes() {
        let dir = std::env::temp_dir().join(format!("edge-lb-active-version-{}", nonce()));
        fs::create_dir_all(&dir).unwrap();
        let active_file = dir.join("active-gateway");
        let file = FileConfig {
            ha: HaConfig {
                active_state_file: active_file.clone(),
                ..HaConfig::default()
            },
            gateway_nodes: vec![
                GatewayNode {
                    name: "gateway-a".to_string(),
                    public_ip: "203.0.113.10".parse().unwrap(),
                    underlay_ip: "192.0.2.10".parse().unwrap(),
                    overlay_ip: "10.255.255.1/24".to_string(),
                },
                GatewayNode {
                    name: "gateway-b".to_string(),
                    public_ip: "203.0.113.11".parse().unwrap(),
                    underlay_ip: "192.0.2.11".parse().unwrap(),
                    overlay_ip: "10.255.255.1/24".to_string(),
                },
            ],
            ..FileConfig::default()
        };
        let cfg = Config {
            file,
            path: dir.join("config.toml"),
        };

        fs::write(&active_file, "gateway-a\n").unwrap();
        let gateway_a_version = response_for_backend(&cfg, local_ip("192.0.2.23"))
            .unwrap()
            .version;
        fs::write(&active_file, "gateway-b\n").unwrap();
        let gateway_b_version = response_for_backend(&cfg, local_ip("192.0.2.23"))
            .unwrap()
            .version;

        assert_eq!(gateway_a_version, gateway_b_version);
        let _ = fs::remove_dir_all(dir);
    }

    fn local_ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }
}
