//! Host-side preflight checks for backend VXLAN and return routing.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use serde::Serialize;

use crate::config::{
    Config, EDGE_CURRENT_MARK_BASE, EDGE_CURRENT_TABLE_BASE, EDGE_MARK_LIMIT, EDGE_TABLE_LIMIT,
    gateway_slot, return_mark, return_table_id,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeConflict {
    pub severity: String,
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

impl NodeConflict {
    fn warning(
        kind: impl Into<String>,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            severity: "warning".to_string(),
            kind: kind.into(),
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InterfaceAddr {
    dev: String,
    network: Ipv4Net,
    raw: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Ipv4Net {
    network: u32,
    prefix: u8,
}

impl Ipv4Net {
    fn parse(value: &str) -> Option<Self> {
        let (ip, prefix) = value.split_once('/')?;
        let ip = ip.parse::<Ipv4Addr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = mask(prefix);
        Some(Self {
            network: u32::from(ip) & mask,
            prefix,
        })
    }

    fn contains_ip(self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & mask(self.prefix)) == self.network
    }

    fn overlaps(self, other: Self) -> bool {
        let prefix = self.prefix.min(other.prefix);
        (self.network & mask(prefix)) == (other.network & mask(prefix))
    }
}

pub fn inspect_backend(cfg: &Config) -> Vec<NodeConflict> {
    let mut out = Vec::new();
    check_overlay_conflicts(cfg, &mut out);
    check_overlay_route_conflicts(cfg, &mut out);
    check_rule_conflicts(cfg, &mut out);
    check_route_table_conflicts(cfg, &mut out);
    out
}

fn check_overlay_conflicts(cfg: &Config, out: &mut Vec<NodeConflict>) {
    let n = cfg.network();
    let planned = planned_overlay_networks(cfg);
    if planned.is_empty() {
        return;
    }
    let existing = host_ipv4_addrs();
    for iface in &existing {
        if iface.dev == n.vxlan_dev {
            continue;
        }
        for net in &planned {
            if iface.network.overlaps(*net) {
                out.push(NodeConflict::warning(
                    "overlay_cidr",
                    iface.raw.clone(),
                    format!(
                        "planned overlay network overlaps interface {} address {}",
                        iface.dev, iface.raw
                    ),
                ));
            }
        }
    }

    for addr in planned_overlay_ips(cfg) {
        let Ok(ip) = addr.parse::<Ipv4Addr>() else {
            continue;
        };
        for iface in &existing {
            if iface.dev == n.vxlan_dev {
                continue;
            }
            if iface.network.contains_ip(ip) {
                out.push(NodeConflict::warning(
                    "overlay_ip",
                    addr.clone(),
                    format!(
                        "planned overlay IP belongs to interface {} address {}",
                        iface.dev, iface.raw
                    ),
                ));
            }
        }
    }
}

fn check_overlay_route_conflicts(cfg: &Config, out: &mut Vec<NodeConflict>) {
    let planned = planned_overlay_networks(cfg);
    if planned.is_empty() {
        return;
    }
    let routes = crate::linux::route::route_descriptions(cfg, libc::RT_TABLE_MAIN as u32)
        .unwrap_or_default();
    for line in routes.iter().map(String::as_str) {
        // The overlay address on the backend return VXLAN creates a connected
        // route in the main table. It is managed by edge-lb just like the
        // gateway VXLAN device and must not be reported as an external clash.
        if is_edge_lb_overlay_device(cfg, line) {
            continue;
        }
        let Some(route) = route_destination_network(line) else {
            continue;
        };
        if planned.iter().any(|net| net.overlaps(route)) {
            out.push(NodeConflict::warning(
                "overlay_route",
                route_destination(line).unwrap_or_default(),
                format!("main route overlaps planned overlay network: {line}"),
            ));
        }
    }
}

fn is_edge_lb_overlay_device(cfg: &Config, line: &str) -> bool {
    if has_dev(line, &cfg.network().vxlan_dev) {
        return true;
    }
    cfg.backend
        .return_path
        .as_ref()
        .map(|return_path| return_path.vxlan_dev.trim())
        .filter(|dev| !dev.is_empty() && *dev != "auto")
        .is_some_and(|dev| has_dev(line, dev))
}

fn check_rule_conflicts(cfg: &Config, out: &mut Vec<NodeConflict>) {
    let rules = crate::linux::route::policy_rule_descriptions().unwrap_or_default();
    let wanted = wanted_policy_rules(cfg);
    for line in rules.iter().map(String::as_str) {
        if policy_rule_is_edge_lb_managed(line) {
            continue;
        }
        let Some(mark) = parse_policy_rule_mark(line) else {
            continue;
        };
        if wanted
            .iter()
            .any(|(_, wanted_mark, _)| *wanted_mark == mark)
            && !wanted
                .iter()
                .any(|wanted| policy_rule_matches(line, *wanted))
        {
            out.push(NodeConflict::warning(
                "route_rule",
                format!("fwmark 0x{mark:x}"),
                format!("policy rule fwmark is already used by: {line}"),
            ));
        }
    }
}

fn check_route_table_conflicts(cfg: &Config, out: &mut Vec<NodeConflict>) {
    let n = cfg.network();
    let expected = expected_routes(cfg);
    let gateway_underlays = known_gateway_underlays(cfg);
    for table in planned_route_tables(cfg) {
        let routes = crate::linux::route::route_descriptions(cfg, table).unwrap_or_default();
        for line in routes.iter().map(String::as_str) {
            if expected
                .iter()
                .any(|route| route.table == table && route.matches(line, n))
                || is_managed_gateway_host_route(line, n, &gateway_underlays)
            {
                continue;
            }
            out.push(NodeConflict::warning(
                "route_table",
                format!("table {table}"),
                format!("route table contains non edge-lb route: {line}"),
            ));
        }
    }
}

fn known_gateway_underlays(cfg: &Config) -> Vec<IpAddr> {
    let mut addresses = cfg
        .gateway_nodes
        .iter()
        .map(|gateway| gateway.underlay_ip)
        .collect::<Vec<_>>();
    // Backend return ports are populated from the xDS snapshot. During the
    // first few reconciliation rounds they can be newer than gateway_nodes,
    // so include their explicit gateway references in the ownership check.
    addresses.extend(
        cfg.backend_return_ports()
            .iter()
            .filter_map(|port| port.gateway_underlay_ip),
    );
    // The backend preflight config is reconstructed from each xDS response.
    // That response may not carry the complete gateway inventory, while the
    // subscription endpoints still identify every gateway that owns a return
    // table. Include those endpoint addresses for precise host-route ownership.
    if let Some(xds) = cfg.backend.xds.as_ref() {
        for endpoint in xds
            .gateways
            .iter()
            .chain((!xds.gateway.trim().is_empty()).then_some(&xds.gateway))
        {
            if let Ok(address) = endpoint.parse::<SocketAddr>() {
                addresses.push(address.ip());
            }
        }
    }
    addresses.push(cfg.network().gateway_ip);
    if let Some(standby) = cfg.network().standby_gateway_ip {
        addresses.push(standby);
    }
    if let Ok(ha) = crate::runtime::ha::load_for_state_dir(&cfg.state_dir) {
        for peer in ha.peers {
            if let Ok(address) = peer.underlay_ip.parse() {
                addresses.push(address);
            }
        }
    }
    addresses.sort_by_key(|address| match address {
        IpAddr::V4(value) => (4u8, u128::from(u32::from(*value))),
        IpAddr::V6(value) => (6u8, u128::from(*value)),
    });
    addresses.dedup();
    addresses
}

fn is_managed_gateway_host_route(
    line: &str,
    network: &crate::config::NetworkConfig,
    gateway_underlays: &[IpAddr],
) -> bool {
    let destination = line.split_whitespace().next().unwrap_or_default();
    let destination = destination.strip_suffix("/32").unwrap_or(destination);
    let Ok(destination) = destination.parse::<IpAddr>() else {
        return false;
    };
    if !line.contains(" src ") {
        return false;
    }
    // Backend xDS can temporarily have only one gateway snapshot while the
    // return table still contains the other gateway's underlay host route.
    // The shape itself is managed by edge-lb: a /32 route via underlay to keep
    // VXLAN outer traffic out of the marked default route.
    if gateway_underlays.contains(&destination) && is_underlay_host_route(destination, line) {
        return true;
    }
    has_dev(line, &network.underlay_dev) && is_underlay_host_route(destination, line)
}

fn is_underlay_host_route(_destination: IpAddr, line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or_default();
    first.ends_with("/32") || first.parse::<IpAddr>().is_ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedRoute {
    table: u32,
    kind: ExpectedRouteKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedRouteKind {
    DefaultVia(IpAddr),
    HostViaUnderlay(IpAddr),
}

impl ExpectedRoute {
    fn matches(&self, line: &str, cfg: &crate::config::NetworkConfig) -> bool {
        match self.kind {
            ExpectedRouteKind::DefaultVia(gw) => {
                line.starts_with(&format!("default via {gw} ")) && has_dev(line, &cfg.vxlan_dev)
            }
            ExpectedRouteKind::HostViaUnderlay(dst) => {
                (line.starts_with(&format!("{dst} ")) || line.starts_with(&format!("{dst}/32 ")))
                    && has_dev(line, &cfg.underlay_dev)
            }
        }
    }
}

fn expected_routes(cfg: &Config) -> Vec<ExpectedRoute> {
    let ports = cfg.backend_return_ports();
    let mut routes = Vec::new();
    if ports.is_empty() {
        return routes;
    }
    for (gateway_overlay, table) in planned_gateway_tables(cfg) {
        routes.push(ExpectedRoute {
            table,
            kind: ExpectedRouteKind::DefaultVia(gateway_overlay),
        });
        for gateway in &cfg.gateway_nodes {
            routes.push(ExpectedRoute {
                table,
                kind: ExpectedRouteKind::HostViaUnderlay(gateway.underlay_ip),
            });
        }
    }
    routes
}

fn planned_gateway_tables(cfg: &Config) -> Vec<(IpAddr, u32)> {
    let fallback_gateway = cfg.active_gateway().ok();
    let fallback_gateway_overlay = cfg.gateway_overlay_ip().ok();
    let mut routes = Vec::new();
    for port in cfg.backend_return_ports() {
        let dscp = port.dscp.unwrap_or(cfg.network().dscp);
        let Some(gateway_overlay) = port.gateway_overlay_ip.or(fallback_gateway_overlay) else {
            continue;
        };
        let gateway_underlay = port
            .gateway_underlay_ip
            .or_else(|| fallback_gateway.as_ref().map(|gateway| gateway.underlay_ip));
        let slot = gateway_underlay
            .map(|underlay| gateway_slot(&cfg.gateway_nodes, underlay))
            .unwrap_or(0);
        let table = port
            .route_table_id
            .unwrap_or_else(|| return_table_id(dscp, slot));
        routes.push((gateway_overlay, table));
    }
    if cfg.backend_return_ports().is_empty()
        || (fallback_gateway.is_none() && fallback_gateway_overlay.is_none())
    {
        return routes;
    }
    routes.sort_by_key(|(gateway_overlay, table)| (ip_sort_key(*gateway_overlay), *table));
    routes.dedup();
    routes
}

fn planned_policy_routes(cfg: &Config) -> Vec<(u32, u32)> {
    let fallback_gateway = cfg.active_gateway().ok();
    let fallback_gateway_overlay = cfg.gateway_overlay_ip().ok();
    let mut routes = Vec::new();
    for port in cfg.backend_return_ports() {
        let dscp = port.dscp.unwrap_or(cfg.network().dscp);
        let Some(gateway_underlay) = port
            .gateway_underlay_ip
            .or_else(|| fallback_gateway.as_ref().map(|gateway| gateway.underlay_ip))
        else {
            continue;
        };
        let Some(gateway_overlay) = port.gateway_overlay_ip.or(fallback_gateway_overlay) else {
            continue;
        };
        let slot = gateway_slot(&cfg.gateway_nodes, gateway_underlay);
        routes.push((
            gateway_underlay,
            gateway_overlay,
            port.mark.unwrap_or_else(|| return_mark(dscp, slot)),
            port.route_table_id
                .unwrap_or_else(|| return_table_id(dscp, slot)),
        ));
    }
    routes.sort_by_key(|(gateway_underlay, gateway_overlay, mark, table)| {
        (
            ip_sort_key(*gateway_underlay),
            ip_sort_key(*gateway_overlay),
            *mark,
            *table,
        )
    });
    routes.dedup();
    routes
        .into_iter()
        .map(|(_, _, mark, table)| (mark, table))
        .collect()
}

fn ip_sort_key(ip: IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(ip) => (4, u32::from_be_bytes(ip.octets()) as u128),
        IpAddr::V6(ip) => (6, u128::from(ip)),
    }
}

fn has_dev(line: &str, dev: &str) -> bool {
    line.split_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|pair| {
            pair[0] == "dev" && pair[1].split_once('(').map_or(pair[1], |(name, _)| name) == dev
        })
}

fn route_destination_network(line: &str) -> Option<Ipv4Net> {
    let dst = route_destination(line)?;
    if dst == "default" {
        return None;
    }
    if dst.contains('/') {
        Ipv4Net::parse(&dst)
    } else {
        Ipv4Net::parse(&format!("{dst}/32"))
    }
}

fn route_destination(line: &str) -> Option<String> {
    line.split_whitespace().next().map(str::to_string)
}

fn planned_overlay_networks(cfg: &Config) -> Vec<Ipv4Net> {
    let mut nets = Vec::new();
    if let Some(net) = Ipv4Net::parse(&cfg.network().overlay_cidr) {
        nets.push(net);
    }
    for addr in planned_overlay_addrs(cfg) {
        if let Some(net) = Ipv4Net::parse(&addr) {
            nets.push(net);
        }
    }
    nets.sort_by_key(|net| (net.network, net.prefix));
    nets.dedup();
    nets
}

fn planned_overlay_ips(cfg: &Config) -> Vec<String> {
    planned_overlay_addrs(cfg)
        .into_iter()
        .filter_map(|addr| addr.split('/').next().map(str::to_string))
        .collect()
}

fn planned_overlay_addrs(cfg: &Config) -> Vec<String> {
    let mut addrs = Vec::new();
    if let Ok(local) = cfg.local_backend() {
        addrs.push(local.overlay_ip);
    }
    for port in cfg.backend_return_ports() {
        if let Some(addr) = port.backend_overlay_ip {
            addrs.push(addr);
        }
    }
    addrs.sort();
    addrs.dedup();
    addrs
}

fn wanted_policy_rules(cfg: &Config) -> Vec<(u32, u32, u32)> {
    let b = cfg.backend_cfg();
    let mut routes = planned_policy_routes(cfg);
    routes.dedup();
    if routes.is_empty() {
        return Vec::new();
    }
    routes
        .into_iter()
        .enumerate()
        .map(|(idx, (mark, table))| (b.rule_priority + idx as u32, mark, table))
        .collect()
}

fn planned_route_tables(cfg: &Config) -> BTreeSet<u32> {
    planned_gateway_tables(cfg)
        .into_iter()
        .map(|(_, table)| table)
        .collect::<BTreeSet<_>>()
}

fn policy_rule_matches(line: &str, wanted: (u32, u32, u32)) -> bool {
    let (priority, mark, table) = wanted;
    line.trim_start().starts_with(&format!("{priority}:"))
        && line.contains(&format!("fwmark 0x{mark:x}"))
        && line.contains(&format!("lookup {table}"))
}

fn policy_rule_is_edge_lb_managed(line: &str) -> bool {
    if parse_policy_rule_mark(line)
        .is_some_and(|mark| (EDGE_CURRENT_MARK_BASE..EDGE_MARK_LIMIT).contains(&mark))
    {
        return true;
    }
    if parse_policy_rule_table(line)
        .is_some_and(|table| (EDGE_CURRENT_TABLE_BASE..EDGE_TABLE_LIMIT).contains(&table))
    {
        return true;
    }
    false
}

fn parse_policy_rule_mark(line: &str) -> Option<u32> {
    let token = line
        .split_whitespace()
        .skip_while(|token| *token != "fwmark")
        .nth(1)?;
    parse_u32_token(token.split_once('/').map_or(token, |(mark, _)| mark))
}

fn parse_policy_rule_table(line: &str) -> Option<u32> {
    let token = line
        .split_whitespace()
        .skip_while(|token| *token != "lookup")
        .nth(1)?;
    parse_u32_token(token)
}

fn parse_u32_token(value: &str) -> Option<u32> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

fn host_ipv4_addrs() -> Vec<InterfaceAddr> {
    crate::linux::net::ipv4_addresses()
        .into_iter()
        .filter_map(|(dev, raw)| {
            Some(InterfaceAddr {
                dev,
                network: Ipv4Net::parse(&raw)?,
                raw,
            })
        })
        .collect()
}

#[cfg(test)]
fn parse_ip_addr_show(output: &str) -> Vec<InterfaceAddr> {
    let mut out = Vec::new();
    for line in output.lines() {
        let tokens = line.split_whitespace().collect::<Vec<_>>();
        let Some(dev) = tokens.get(1) else {
            continue;
        };
        let Some(pos) = tokens.iter().position(|token| *token == "inet") else {
            continue;
        };
        let Some(raw) = tokens.get(pos + 1) else {
            continue;
        };
        let Some(network) = Ipv4Net::parse(raw) else {
            continue;
        };
        out.push(InterfaceAddr {
            dev: dev.trim_end_matches(':').to_string(),
            network,
            raw: (*raw).to_string(),
        });
    }
    out
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BackendReturnPort, FileConfig, GatewayNode, Protocol};
    use std::path::PathBuf;

    #[test]
    fn ipv4_overlap_detects_nested_networks() {
        let a = Ipv4Net::parse("10.255.0.0/16").unwrap();
        let b = Ipv4Net::parse("10.255.12.2/24").unwrap();
        let c = Ipv4Net::parse("192.168.0.1/24").unwrap();
        assert!(a.overlaps(b));
        assert!(!a.overlaps(c));
    }

    #[test]
    fn parses_ip_addr_show_lines() {
        let addrs = parse_ip_addr_show(
            "2: eth0    inet 192.168.0.14/24 brd 192.168.0.255 scope global eth0\n\
             8: edge-return    inet 10.255.12.2/24 scope global edge-return\n",
        );
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0].dev, "eth0");
        assert!(
            addrs[0]
                .network
                .contains_ip("192.168.0.20".parse().unwrap())
        );
    }

    #[test]
    fn parses_route_destination_networks() {
        assert_eq!(
            route_destination_network("10.255.12.0/24 dev eth1 proto kernel")
                .unwrap()
                .prefix,
            24
        );
        assert_eq!(
            route_destination_network("10.255.12.9 dev eth1 scope link")
                .unwrap()
                .prefix,
            32
        );
        assert!(route_destination_network("default via 192.0.2.1 dev eth0").is_none());
    }

    #[test]
    fn managed_backend_return_device_is_not_an_overlay_conflict() {
        let cfg = Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig {
                backend: crate::config::BackendConfig {
                    return_path: Some(crate::config::BackendReturnPathConfig {
                        vxlan_dev: "edge-return".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        assert!(is_edge_lb_overlay_device(
            &cfg,
            "10.255.16.0/24 dev edge-return proto kernel scope link src 10.255.16.2"
        ));
        assert!(!is_edge_lb_overlay_device(
            &cfg,
            "10.255.16.0/24 dev eth0 proto static"
        ));
        assert!(is_edge_lb_overlay_device(
            &cfg,
            "10.255.16.0/24 dev edge-return(3) src 10.255.16.2 table 254"
        ));
    }

    #[test]
    fn managed_underlay_host_routes_are_not_route_table_conflicts() {
        let network = crate::config::NetworkConfig {
            underlay_dev: "eth0".to_string(),
            ..Default::default()
        };
        let known = [
            "192.168.0.12".parse().unwrap(),
            "192.168.0.16".parse().unwrap(),
        ];

        assert!(is_managed_gateway_host_route(
            "192.168.0.12/32 dev eth0(2) proto static scope link src 192.168.0.13 table 1104",
            &network,
            &known
        ));
        assert!(is_managed_gateway_host_route(
            "192.168.0.12/32 dev ens5 proto static scope link src 192.168.0.13 table 1104",
            &network,
            &known
        ));
        assert!(!is_managed_gateway_host_route(
            "192.168.0.99/32 dev eth1 proto static scope link src 192.168.0.13 table 1104",
            &network,
            &known
        ));
        assert!(!is_managed_gateway_host_route(
            "192.168.0.0/24 dev eth0 proto static scope link src 192.168.0.13 table 1104",
            &network,
            &known
        ));
    }

    #[test]
    fn policy_rule_match_accepts_only_expected_mark_and_table() {
        let wanted = (100, 0x102e, 1046);

        assert!(policy_rule_matches(
            "100: from all fwmark 0x102e lookup 1046",
            wanted
        ));
        assert!(!policy_rule_matches(
            "100: from all fwmark 0x1028 lookup 1040",
            wanted
        ));
        assert!(!policy_rule_matches(
            "100: from all fwmark 0x1/0xff lookup custom-return",
            wanted
        ));
    }

    #[test]
    fn edge_lb_owned_policy_rules_are_not_external_conflicts() {
        assert!(policy_rule_is_edge_lb_managed(
            "100: from all fwmark 0x106e lookup 1110"
        ));
        assert!(!policy_rule_is_edge_lb_managed(
            "100: from all fwmark 0x102e lookup 1046"
        ));
        assert!(!policy_rule_is_edge_lb_managed(
            "100: from all fwmark 0x1/0xff lookup custom-return"
        ));
        assert!(!policy_rule_is_edge_lb_managed(
            "100: from all fwmark 0x1/0xff lookup 100"
        ));
        assert!(!policy_rule_is_edge_lb_managed(
            "100: from all fwmark 0x9 lookup 999"
        ));
        assert!(!policy_rule_is_edge_lb_managed(
            "100: from all lookup local"
        ));
    }

    #[test]
    fn policy_rule_parser_ignores_unmarked_and_unrelated_rules() {
        assert_eq!(parse_policy_rule_mark("100: from all lookup local"), None);
        assert_eq!(
            parse_policy_rule_mark("9: from all fwmark 0x200/0xf00 lookup 2004"),
            Some(0x200)
        );
        assert_eq!(
            parse_policy_rule_table("9: from all fwmark 0x200/0xf00 lookup 2004"),
            Some(2004)
        );
    }

    #[test]
    fn wanted_policy_rules_derive_gateway_slotted_mark_and_table() {
        let cfg = Config {
            path: PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig {
                gateway_nodes: vec![
                    GatewayNode {
                        name: "gateway-a".to_string(),
                        public_ip: "203.0.113.10".parse().unwrap(),
                        underlay_ip: "192.168.0.12".parse().unwrap(),
                        overlay_ip: "10.255.12.1/24".to_string(),
                    },
                    GatewayNode {
                        name: "gateway-b".to_string(),
                        public_ip: "203.0.113.11".parse().unwrap(),
                        underlay_ip: "192.168.0.16".parse().unwrap(),
                        overlay_ip: "10.255.16.1/24".to_string(),
                    },
                ],
                backend_return_ports: vec![
                    BackendReturnPort {
                        backend: None,
                        address: "192.168.0.14".parse().unwrap(),
                        protocol: Protocol::Tcp,
                        port: 8080,
                        gateway: None,
                        gateway_underlay_ip: Some("192.168.0.16".parse().unwrap()),
                        gateway_overlay_ip: Some("10.255.16.1".parse().unwrap()),
                        backend_overlay_ip: None,
                        dscp: Some(40),
                        mark: None,
                        route_table_id: None,
                    },
                    BackendReturnPort {
                        backend: None,
                        address: "192.168.0.14".parse().unwrap(),
                        protocol: Protocol::Tcp,
                        port: 8080,
                        gateway: None,
                        gateway_underlay_ip: Some("192.168.0.12".parse().unwrap()),
                        gateway_overlay_ip: Some("10.255.12.1".parse().unwrap()),
                        backend_overlay_ip: None,
                        dscp: Some(46),
                        mark: None,
                        route_table_id: None,
                    },
                ],
                ..FileConfig::default()
            },
        };

        assert_eq!(
            wanted_policy_rules(&cfg),
            vec![(100, 0x106e, 1110), (101, 0x10a8, 1168)]
        );
    }
}
