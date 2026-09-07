use std::collections::{HashMap, HashSet};

use super::{
    ActiveSource, BackendNode, ControlPlaneMode, DEFAULT_BACKEND_VXLAN_DEV,
    DEFAULT_GATEWAY_VXLAN_DEV, FileConfig, GatewayNode, NodeRole, Protocol, Service,
    TargetEndpoint,
    defaults::{
        default_auto_ip, default_backend_overlay, default_gateway_ip, default_gateway_overlay,
        default_gateway_public_ip, is_auto_ip,
    },
    overlay::{overlay_host, overlay_needs_assignment, underlay_dev_is_auto},
};

pub(super) fn normalize_config(file: &mut FileConfig) {
    normalize_discovery(file);
    apply_role_sections(file);
    mark_vxlan_mtu_auto(file);
    apply_role_defaults(file);
    if file.control_plane.enabled
        && file.control_plane.mode == ControlPlaneMode::File
        && (file.ha.active_source == ActiveSource::Xds
            || matches!(file.node_role, NodeRole::Gateway))
    {
        file.control_plane.mode = ControlPlaneMode::Xds;
    }
    ensure_local_node(file);
    apply_top_level_local_ips(file);
    if file.backend_nodes.is_empty()
        && let (Some(public_ip), Some(underlay_ip)) =
            (file.network.backend_public_ip, file.network.backend_ip)
    {
        file.backend_nodes.push(BackendNode {
            name: "backend-1".to_string(),
            public_ip,
            underlay_ip,
            overlay_ip: file.backend.overlay_ip.clone(),
        });
    }
    assign_overlay_ips(file);
    synthesize_services_from_listeners(file);
    if let Some(gw) = file
        .gateway_nodes
        .iter()
        .find(|g| g.name == file.node_name)
        .or_else(|| file.gateway_nodes.first())
    {
        if file.network.gateway_public_ip == default_gateway_public_ip() {
            file.network.gateway_public_ip = gw.public_ip;
        }
        if file.network.gateway_ip == default_gateway_ip() {
            file.network.gateway_ip = gw.underlay_ip;
        }
        if matches!(file.node_role, NodeRole::Gateway)
            && overlay_needs_assignment(&file.gateway.overlay_ip)
        {
            file.gateway.overlay_ip = gw.overlay_ip.clone();
        }
    }
    let backends = file.backend_nodes_effective();
    for svc in &mut file.services {
        if let Some(name) = &svc.backend {
            if let Some(backend) = backends.iter().find(|b| &b.name == name) {
                svc.backend_ip = backend.underlay_ip;
            }
        } else if is_auto_ip(svc.backend_ip) && backends.len() == 1 {
            svc.backend = Some(backends[0].name.clone());
            svc.backend_ip = backends[0].underlay_ip;
        }
        if svc.protocols.is_empty() {
            svc.protocols.push(svc.protocol.unwrap_or(Protocol::Tcp));
        }
        svc.protocol = None;
    }
}

fn normalize_discovery(file: &mut FileConfig) {
    file.discovery
        .stun_servers
        .iter_mut()
        .for_each(|server| *server = server.trim().to_string());
    file.discovery
        .stun_servers
        .retain(|server| !server.is_empty());
    if file.discovery.stun_servers.is_empty() {
        file.discovery
            .stun_servers
            .push("stun.l.google.com:19302".to_string());
    }
}

fn mark_vxlan_mtu_auto(file: &mut FileConfig) {
    if file.network.vxlan_mtu == 0 {
        file.network.vxlan_mtu_auto = true;
    }
}

fn apply_role_sections(file: &mut FileConfig) {
    match file.node_role {
        NodeRole::Gateway => {
            if let Some(value) = file.gateway.xds.clone() {
                file.control_plane.enabled = true;
                file.control_plane.mode = ControlPlaneMode::Xds;
                file.control_plane.listen = value.listen;
                file.control_plane.gateway_port = None;
                file.control_plane.token = value.token;
                file.control_plane.trusted_source_cidrs = value.trusted_source_cidrs;
            }
            if let Some(value) = file.gateway.reconcile.clone() {
                file.ha.watch_interval_secs = value.interval_secs;
            }
            if let Some(value) = file.gateway.control_plane.clone() {
                file.control_plane = value;
            }
            if let Some(value) = file.gateway.network.clone() {
                let resolved_underlay_dev = file.network.underlay_dev.clone();
                file.network = value;
                if underlay_dev_is_auto(&file.network.underlay_dev)
                    && !underlay_dev_is_auto(&resolved_underlay_dev)
                {
                    file.network.underlay_dev = resolved_underlay_dev;
                }
            }
            if let Some(value) = file.gateway.api.clone() {
                file.api = value;
            }
        }
        NodeRole::Backend => {
            if let Some(value) = file.backend.xds.clone() {
                file.ha.active_source = ActiveSource::Xds;
                file.ha.watch_interval_secs = value.reconnect_interval_secs;
                file.control_plane.enabled = true;
                file.control_plane.mode = ControlPlaneMode::Xds;
                file.control_plane.token = value.token;
                let gateways = if !value.gateways.is_empty() {
                    value.gateways.clone()
                } else if !value.gateway.trim().is_empty() {
                    vec![value.gateway.clone()]
                } else {
                    Vec::new()
                };
                if !gateways.is_empty() && file.gateway_nodes.is_empty() {
                    let mut gateway_port = file.control_plane.gateway_port;
                    let nodes = gateways
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, gateway)| {
                            let (host, port) = split_host_port(gateway)?;
                            if gateway_port.is_none() {
                                gateway_port = Some(port);
                            }
                            Some(GatewayNode {
                                name: format!("gateway-{}", idx + 1),
                                public_ip: default_auto_ip(),
                                underlay_ip: host.parse().ok()?,
                                overlay_ip: default_gateway_overlay(),
                            })
                        })
                        .collect();
                    file.control_plane.gateway_port = gateway_port;
                    file.gateway_nodes = nodes;
                }
            }
            if let Some(value) = file.backend.return_path.clone() {
                file.network.vxlan_dev = value.vxlan_dev;
                file.backend.ct_mark = value.ct_mark;
                file.backend.fwmark = value.fwmark;
                file.backend.route_table = value.route_table;
                file.backend.route_table_id = value.route_table_id;
                file.backend.rule_priority = value.rule_priority;
                file.backend.nft_table = value.nft_table;
                file.backend.mss = value.mss;
            }
            if let Some(value) = file.backend.control.clone() {
                file.ha.active_source = value.source;
                file.ha.watch_interval_secs = value.reconnect_interval_secs;
            }
            if let Some(value) = file.backend.control_plane.clone() {
                file.control_plane = value;
            }
            if let Some(value) = file.backend.network.clone() {
                let resolved_underlay_dev = file.network.underlay_dev.clone();
                file.network = value;
                if underlay_dev_is_auto(&file.network.underlay_dev)
                    && !underlay_dev_is_auto(&resolved_underlay_dev)
                {
                    file.network.underlay_dev = resolved_underlay_dev;
                }
            }
            if let Some(value) = file.backend.api.clone() {
                file.api = value;
            }
        }
    }
}

fn split_host_port(value: &str) -> Option<(&str, u16)> {
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse().ok()?;
    Some((host, port))
}

fn apply_role_defaults(file: &mut FileConfig) {
    let configured = file.network.vxlan_dev.trim();
    if !configured.eq_ignore_ascii_case("auto") && !configured.is_empty() {
        return;
    }
    file.network.vxlan_dev = match file.node_role {
        NodeRole::Gateway => DEFAULT_GATEWAY_VXLAN_DEV,
        NodeRole::Backend => DEFAULT_BACKEND_VXLAN_DEV,
    }
    .to_string();
}

fn ensure_local_node(file: &mut FileConfig) {
    match file.node_role {
        NodeRole::Gateway => {
            if !file.gateway_nodes.iter().any(|g| g.name == file.node_name) {
                file.gateway_nodes.push(GatewayNode {
                    name: file.node_name.clone(),
                    public_ip: file.public_ip,
                    underlay_ip: file.underlay_ip,
                    overlay_ip: default_gateway_overlay(),
                });
            }
        }
        NodeRole::Backend => {
            if !file.backend_nodes.iter().any(|b| b.name == file.node_name) {
                file.backend_nodes.push(BackendNode {
                    name: file.node_name.clone(),
                    public_ip: file.public_ip,
                    underlay_ip: file.underlay_ip,
                    overlay_ip: default_backend_overlay(),
                });
            }
        }
    }
}

fn apply_top_level_local_ips(file: &mut FileConfig) {
    match file.node_role {
        NodeRole::Gateway => {
            if let Some(gw) = file
                .gateway_nodes
                .iter_mut()
                .find(|g| g.name == file.node_name)
            {
                if !file.public_ip.is_unspecified() {
                    gw.public_ip = file.public_ip;
                } else {
                    file.public_ip = gw.public_ip;
                }
                if !file.underlay_ip.is_unspecified() {
                    gw.underlay_ip = file.underlay_ip;
                } else {
                    file.underlay_ip = gw.underlay_ip;
                }
            }
        }
        NodeRole::Backend => {
            if let Some(backend) = file
                .backend_nodes
                .iter_mut()
                .find(|b| b.name == file.node_name)
            {
                if !file.public_ip.is_unspecified() {
                    backend.public_ip = file.public_ip;
                } else {
                    file.public_ip = backend.public_ip;
                }
                if !file.underlay_ip.is_unspecified() {
                    backend.underlay_ip = file.underlay_ip;
                } else {
                    file.underlay_ip = backend.underlay_ip;
                }
            }
        }
    }
}

fn synthesize_services_from_listeners(file: &mut FileConfig) {
    if !matches!(file.node_role, NodeRole::Gateway) {
        return;
    }
    let listener_names = file
        .listeners
        .iter()
        .map(|listener| listener.name.as_str())
        .collect::<HashSet<_>>();
    let mut services = file
        .services
        .iter()
        .filter(|svc| svc.target_group.is_none() && !listener_names.contains(svc.name.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    if file.listeners.is_empty() {
        file.services = services;
        return;
    }
    let backends = file.backend_nodes_effective();
    let groups = file
        .target_groups
        .iter()
        .map(|group| (group.name.as_str(), group))
        .collect::<HashMap<_, _>>();
    for listener in &file.listeners {
        let Some(group) = groups.get(listener.target_group.as_str()) else {
            continue;
        };
        if group.targets.is_empty() {
            continue;
        }
        let first = &group.targets[0];
        let first_address = file.resolve_backend_target_address(first);
        let backend = first.backend.clone().or_else(|| {
            backends
                .iter()
                .find(|b| b.underlay_ip == first_address)
                .map(|b| b.name.clone())
        });
        let backend_ip = backend
            .as_ref()
            .and_then(|name| backends.iter().find(|b| &b.name == name))
            .map(|b| b.underlay_ip)
            .unwrap_or(first_address);
        services.push(Service {
            name: listener.name.clone(),
            vip_port: listener.port,
            target_group: Some(group.name.clone()),
            backend,
            backend_ip,
            backend_port: listener.target_port,
            backend_weight: first.weight,
            select: listener.select,
            mode: listener.mode,
            bgp: listener.bgp,
            monitor: group.monitor,
            probe_type: group.probe_type.clone(),
            probe_port: group.probe_port,
            probe_req: group.probe_req.clone(),
            probe_resp: group.probe_resp.clone(),
            probe_status: group.probe_status,
            probe_skip_tls_verify: group.probe_skip_tls_verify,
            period_secs: group.period_secs,
            retries: group.retries,
            inactive_timeout: listener.inactive_timeout,
            mark: listener.mark,
            security: listener.security,
            host: listener.host.clone(),
            proxy_protocol_v2: listener.proxy_protocol_v2,
            egress: listener.egress,
            protocol: None,
            protocols: listener.protocols.clone(),
            endpoints: group
                .targets
                .iter()
                .map(|target| TargetEndpoint {
                    backend: target.backend.clone(),
                    address: file.resolve_backend_target_address(target),
                    port: listener.target_port,
                    weight: target.weight,
                })
                .collect(),
        });
    }
    file.services = services;
}

fn assign_overlay_ips(file: &mut FileConfig) {
    let mut used = HashSet::new();
    if let Ok(gateway_overlay) = overlay_host(&file.network.overlay_cidr, 1) {
        for gw in &mut file.gateway_nodes {
            if overlay_needs_assignment(&gw.overlay_ip) {
                gw.overlay_ip = gateway_overlay.clone();
            }
            used.insert(gw.overlay_ip.clone());
        }
        if overlay_needs_assignment(&file.gateway.overlay_ip) {
            file.gateway.overlay_ip = gateway_overlay;
        }
        used.insert(file.gateway.overlay_ip.clone());
    } else {
        for gw in &file.gateway_nodes {
            used.insert(gw.overlay_ip.clone());
        }
        used.insert(file.gateway.overlay_ip.clone());
    }

    for backend in &mut file.backend_nodes {
        if !overlay_needs_assignment(&backend.overlay_ip)
            && !used.insert(backend.overlay_ip.clone())
        {
            backend.overlay_ip = default_backend_overlay();
        }
    }

    let max_host_index = file.backend_nodes.len() as u32 + file.gateway_nodes.len() as u32 + 256;
    for backend in &mut file.backend_nodes {
        if !overlay_needs_assignment(&backend.overlay_ip) {
            continue;
        }
        for host_index in 2..=max_host_index {
            let Ok(overlay) = overlay_host(&file.network.overlay_cidr, host_index) else {
                break;
            };
            if used.insert(overlay.clone()) {
                backend.overlay_ip = overlay;
                break;
            }
        }
    }
}
