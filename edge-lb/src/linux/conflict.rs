//! Host-side preflight checks for backend VXLAN and return routing.

use std::net::Ipv4Addr;

use serde::Serialize;

use crate::config::Config;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeConflict {
    pub severity: String,
    pub kind: String,
    pub subject: String,
    pub detail: String,
}

impl NodeConflict {
    pub(super) fn warning(
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
    match crate::linux::route::ownership_conflicts(cfg) {
        Ok(conflicts) => out.extend(conflicts),
        Err(error) => out.push(NodeConflict::warning(
            "route_ownership",
            "inspection",
            format!("cannot verify route ownership: {error:#}"),
        )),
    }
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
    for path in cfg.backend_return_paths() {
        if let Some(addr) = path.backend_overlay_ip {
            addrs.push(addr);
        }
    }
    addrs.sort();
    addrs.dedup();
    addrs
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
    use crate::config::FileConfig;
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
}
