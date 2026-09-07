//! Local IP discovery used by config fields set to `auto`.

use std::{
    collections::HashSet,
    env,
    net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket},
    os::fd::AsRawFd,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail};

use crate::config::{
    DeviceDiscoveryRuntime, FileConfig, IpDiscoveryRuntime, NodeRole, RuntimeDiscovery,
};

const DEFAULT_VXLAN_MTU: u32 = 1450;
const MIN_VXLAN_MTU: u32 = 576;
const VXLAN_IPV4_OVERHEAD: u32 = 50;
const IPV4_PING_OVERHEAD: u32 = 28;

#[derive(Debug, Clone, Copy)]
struct ResolvedIp {
    value: IpAddr,
    source: &'static str,
}

#[derive(Debug, Clone)]
struct ResolvedDevice {
    value: String,
    source: &'static str,
}

pub fn resolve_auto_ips(file: &mut FileConfig) -> Result<()> {
    let public_was_auto = file.public_ip.is_unspecified();
    let underlay_was_auto = file.underlay_ip.is_unspecified();
    let underlay_dev_was_auto = file
        .network
        .underlay_dev
        .trim()
        .eq_ignore_ascii_case("auto")
        || file.network.underlay_dev.trim().is_empty();
    let need_underlay = needs_local_underlay_ip(file) || needs_local_public_ip(file);
    let underlay = if need_underlay {
        Some(local_underlay_ip(file)?)
    } else {
        None
    };
    let public = if needs_local_public_ip(file) {
        local_public_ip(file).ok()
    } else {
        None
    };
    if file.underlay_ip.is_unspecified()
        && let Some(underlay) = underlay
    {
        file.underlay_ip = underlay.value;
    }
    if file.public_ip.is_unspecified() {
        if let Some(public) = public {
            file.public_ip = public.value;
        } else if let Some(underlay) = underlay {
            file.public_ip = underlay.value;
        }
    }
    let underlay_dev = if underlay_dev_was_auto {
        let dev = local_underlay_dev(file)?;
        file.network.underlay_dev = dev.value.clone();
        Some(dev)
    } else {
        None
    };
    file.runtime_discovery = RuntimeDiscovery {
        public_ip: IpDiscoveryRuntime {
            value: (!file.public_ip.is_unspecified()).then_some(file.public_ip),
            mode: discovery_mode(public_was_auto).to_string(),
            source: if public_was_auto {
                public
                    .map(|ip| ip.source)
                    .or_else(|| underlay.map(|_| "underlay_fallback"))
                    .unwrap_or("unresolved")
                    .to_string()
            } else {
                "config".to_string()
            },
        },
        underlay_ip: IpDiscoveryRuntime {
            value: (!file.underlay_ip.is_unspecified()).then_some(file.underlay_ip),
            mode: discovery_mode(underlay_was_auto).to_string(),
            source: if underlay_was_auto {
                underlay
                    .map(|ip| ip.source)
                    .unwrap_or("unresolved")
                    .to_string()
            } else {
                "config".to_string()
            },
        },
        underlay_dev: DeviceDiscoveryRuntime {
            value: (!file.network.underlay_dev.trim().is_empty())
                .then(|| file.network.underlay_dev.clone()),
            mode: discovery_mode(underlay_dev_was_auto).to_string(),
            source: if underlay_dev_was_auto {
                underlay_dev
                    .as_ref()
                    .map(|dev| dev.source)
                    .unwrap_or("unresolved")
                    .to_string()
            } else {
                "config".to_string()
            },
        },
    };

    match file.node_role {
        NodeRole::Gateway => {
            if file.network.gateway_ip.is_unspecified() {
                file.network.gateway_ip = underlay
                    .context("local underlay IP was not discovered")?
                    .value;
            }
            if file.network.gateway_public_ip.is_unspecified() {
                file.network.gateway_public_ip = public
                    .unwrap_or(underlay.context("local public IP fallback unavailable")?)
                    .value;
            }
            for gw in &mut file.gateway_nodes {
                if gw.name == file.node_name {
                    if gw.underlay_ip.is_unspecified() {
                        gw.underlay_ip = underlay
                            .context("local underlay IP was not discovered")?
                            .value;
                    }
                    if gw.public_ip.is_unspecified() {
                        gw.public_ip = public
                            .unwrap_or(underlay.context("local public IP fallback unavailable")?)
                            .value;
                    }
                } else {
                    resolve_remote_node_ips(
                        "GATEWAY",
                        &gw.name,
                        &mut gw.public_ip,
                        &mut gw.underlay_ip,
                    )?;
                }
            }
            for backend in &mut file.backend_nodes {
                resolve_remote_node_ips(
                    "BACKEND",
                    &backend.name,
                    &mut backend.public_ip,
                    &mut backend.underlay_ip,
                )?;
            }
        }
        NodeRole::Backend => {
            let mut resolved_backend = None;
            for gw in &mut file.gateway_nodes {
                resolve_remote_node_ips(
                    "GATEWAY",
                    &gw.name,
                    &mut gw.public_ip,
                    &mut gw.underlay_ip,
                )?;
            }
            for backend in &mut file.backend_nodes {
                if backend.name == file.node_name {
                    if backend.underlay_ip.is_unspecified() {
                        backend.underlay_ip = underlay
                            .context("local underlay IP was not discovered")?
                            .value;
                    }
                    if backend.public_ip.is_unspecified() {
                        backend.public_ip = public
                            .unwrap_or(underlay.context("local public IP fallback unavailable")?)
                            .value;
                    }
                    resolved_backend = Some(backend.underlay_ip);
                } else {
                    resolve_remote_node_ips(
                        "BACKEND",
                        &backend.name,
                        &mut backend.public_ip,
                        &mut backend.underlay_ip,
                    )?;
                }
            }
            if let Some(ip) = file
                .network
                .backend_ip
                .as_mut()
                .filter(|ip| ip.is_unspecified())
            {
                *ip = underlay
                    .context("local underlay IP was not discovered")?
                    .value;
            }
            if let Some(ip) = file
                .network
                .backend_public_ip
                .as_mut()
                .filter(|ip| ip.is_unspecified())
            {
                *ip = public
                    .unwrap_or(underlay.context("local public IP fallback unavailable")?)
                    .value;
            }
            if let Some(local_backend) = resolved_backend {
                for svc in &mut file.services {
                    if svc.backend_ip.is_unspecified() {
                        svc.backend_ip = local_backend;
                    }
                }
            }
        }
    }
    resolve_auto_vxlan_mtu(file);
    file.normalize();
    Ok(())
}

fn discovery_mode(auto: bool) -> &'static str {
    if auto { "auto" } else { "static" }
}

fn needs_local_underlay_ip(file: &FileConfig) -> bool {
    if file.underlay_ip.is_unspecified() {
        return true;
    }
    match file.node_role {
        NodeRole::Gateway => {
            file.network.gateway_ip.is_unspecified()
                || file
                    .gateway_nodes
                    .iter()
                    .any(|gw| gw.name == file.node_name && gw.underlay_ip.is_unspecified())
        }
        NodeRole::Backend => {
            file.network
                .backend_ip
                .is_some_and(|ip| ip.is_unspecified())
                || file.backend_nodes.iter().any(|backend| {
                    backend.name == file.node_name && backend.underlay_ip.is_unspecified()
                })
        }
    }
}

fn needs_local_public_ip(file: &FileConfig) -> bool {
    if file.public_ip.is_unspecified() {
        return true;
    }
    match file.node_role {
        NodeRole::Gateway => {
            file.network.gateway_public_ip.is_unspecified()
                || file
                    .gateway_nodes
                    .iter()
                    .any(|gw| gw.name == file.node_name && gw.public_ip.is_unspecified())
        }
        NodeRole::Backend => {
            file.network
                .backend_public_ip
                .is_some_and(|ip| ip.is_unspecified())
                || file.backend_nodes.iter().any(|backend| {
                    backend.name == file.node_name && backend.public_ip.is_unspecified()
                })
        }
    }
}

fn resolve_remote_node_ips(
    kind: &str,
    name: &str,
    public_ip: &mut IpAddr,
    underlay_ip: &mut IpAddr,
) -> Result<()> {
    let key = env_key(name);
    if public_ip.is_unspecified()
        && let Some(ip) = env_ip_any(&[
            format!("EDGE_LB_{kind}_{key}_PUBLIC_IP"),
            format!("EDGE_LB_{kind}_PUBLIC_IP"),
        ])?
    {
        *public_ip = ip;
    }
    if underlay_ip.is_unspecified()
        && let Some(ip) = env_ip_any(&[
            format!("EDGE_LB_{kind}_{key}_UNDERLAY_IP"),
            format!("EDGE_LB_{kind}_UNDERLAY_IP"),
        ])?
    {
        *underlay_ip = ip;
    }
    Ok(())
}

fn local_underlay_ip(file: &FileConfig) -> Result<ResolvedIp> {
    if let Some(ip) = env_ip(
        file.discovery.underlay_ip_env.as_deref(),
        "EDGE_LB_UNDERLAY_IP",
    )? {
        return Ok(ResolvedIp {
            value: ip,
            source: "env",
        });
    }
    Ok(ResolvedIp {
        value: udp_source_ip(&file.discovery.udp_probe_addr)?,
        source: "udp_source",
    })
}

fn local_public_ip(file: &FileConfig) -> Result<ResolvedIp> {
    if let Some(ip) = env_ip(file.discovery.public_ip_env.as_deref(), "EDGE_LB_PUBLIC_IP")? {
        return Ok(ResolvedIp {
            value: ip,
            source: "env",
        });
    }
    let servers = if file.discovery.stun_servers.is_empty() {
        vec!["stun.l.google.com:19302".to_string()]
    } else {
        file.discovery.stun_servers.clone()
    };
    let mut errors = Vec::new();
    for server in servers.iter().map(String::as_str).map(str::trim) {
        if server.is_empty() {
            continue;
        }
        match stun_public_ip(server) {
            Ok(value) => {
                return Ok(ResolvedIp {
                    value,
                    source: "stun",
                });
            }
            Err(error) => errors.push(format!("{server}: {error:#}")),
        }
    }
    if errors.is_empty() {
        bail!("no valid STUN servers configured")
    }
    bail!("all STUN servers failed: {}", errors.join("; "))
}

fn local_underlay_dev(file: &FileConfig) -> Result<ResolvedDevice> {
    if let Some(dev) = env_text(
        file.discovery.underlay_dev_env.as_deref(),
        "EDGE_LB_UNDERLAY_DEV",
    ) {
        return Ok(ResolvedDevice {
            value: dev,
            source: "env",
        });
    }
    Ok(ResolvedDevice {
        value: route_dev_for(&file.discovery.udp_probe_addr)?,
        source: "route",
    })
}

fn resolve_auto_vxlan_mtu(file: &mut FileConfig) {
    if !file.network.vxlan_mtu_auto && file.network.vxlan_mtu != 0 {
        return;
    }
    let dev = file.network.underlay_dev.clone();
    let dev_mtu = crate::linux::net::link_mtu(&dev).unwrap_or_else(|e| {
        tracing::warn!(
            "[discovery] failed to read underlay MTU from {dev}; falling back to {DEFAULT_VXLAN_MTU}: {e:#}"
        );
        DEFAULT_VXLAN_MTU + VXLAN_IPV4_OVERHEAD
    });
    let peers = vxlan_pmtu_peers(file);
    let mut outer_mtu = dev_mtu;
    let mut probed = Vec::new();
    for peer in peers {
        match peer {
            IpAddr::V4(addr) => match probe_ipv4_pmtu(addr, dev_mtu) {
                Some(pmtu) => {
                    outer_mtu = outer_mtu.min(pmtu);
                    probed.push(format!("{addr}:{pmtu}"));
                }
                None => tracing::warn!(
                    "[discovery] PMTU probe to {addr} failed; keeping underlay device MTU fallback"
                ),
            },
            IpAddr::V6(addr) => tracing::warn!(
                "[discovery] PMTU auto currently skips IPv6 underlay peer {addr}; using device MTU fallback"
            ),
        }
    }
    let candidate = outer_mtu.saturating_sub(VXLAN_IPV4_OVERHEAD);
    let resolved = if candidate >= MIN_VXLAN_MTU {
        candidate
    } else {
        DEFAULT_VXLAN_MTU
    };
    file.network.vxlan_mtu = resolved;
    file.network.vxlan_mtu_auto = true;
    clamp_backend_mss(file, resolved);
    tracing::info!(
        "[discovery] resolved vxlan_mtu=auto to {resolved} from underlay_dev={dev} dev_mtu={dev_mtu} peer_pmtu=[{}]",
        probed.join(",")
    );
}

fn clamp_backend_mss(file: &mut FileConfig, vxlan_mtu: u32) {
    let max_mss = vxlan_mtu.saturating_sub(40);
    if file.backend.mss > max_mss && max_mss > 0 {
        tracing::warn!(
            "[discovery] backend MSS {} exceeds vxlan_mtu {vxlan_mtu}; clamping to {max_mss}",
            file.backend.mss
        );
        file.backend.mss = max_mss;
    }
}

fn vxlan_pmtu_peers(file: &FileConfig) -> Vec<IpAddr> {
    let mut seen = HashSet::new();
    let mut peers = Vec::new();
    let local = file.underlay_ip;
    match file.node_role {
        NodeRole::Gateway => {
            for backend in file.backend_nodes_effective() {
                push_peer(&mut peers, &mut seen, local, backend.underlay_ip);
            }
        }
        NodeRole::Backend => {
            for gateway in &file.gateway_nodes {
                push_peer(&mut peers, &mut seen, local, gateway.underlay_ip);
            }
        }
    }
    peers
}

fn push_peer(peers: &mut Vec<IpAddr>, seen: &mut HashSet<IpAddr>, local: IpAddr, peer: IpAddr) {
    if peer.is_unspecified() || peer == local || !seen.insert(peer) {
        return;
    }
    peers.push(peer);
}

fn probe_ipv4_pmtu(peer: std::net::Ipv4Addr, max_outer_mtu: u32) -> Option<u32> {
    let mut low = MIN_VXLAN_MTU + VXLAN_IPV4_OVERHEAD;
    let mut high = max_outer_mtu;
    let mut best = None;
    while low <= high {
        let mid = low + (high - low) / 2;
        if ping_ipv4_no_fragment(peer, mid.saturating_sub(IPV4_PING_OVERHEAD)) {
            best = Some(mid);
            low = mid.saturating_add(1);
        } else {
            high = mid.saturating_sub(1);
        }
    }
    best
}

fn ping_ipv4_no_fragment(peer: std::net::Ipv4Addr, payload_size: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(socket) = UdpSocket::bind("0.0.0.0:0") else {
            return false;
        };
        let value: libc::c_int = libc::IP_PMTUDISC_DO;
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_MTU_DISCOVER,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result != 0 {
            return false;
        }
        if socket.connect(SocketAddr::new(peer.into(), 33434)).is_err() {
            return false;
        }
        socket.send(&vec![0_u8; payload_size as usize]).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (peer, payload_size);
        false
    }
}

fn env_ip(primary: Option<&str>, fallback: &str) -> Result<Option<IpAddr>> {
    for name in primary.into_iter().chain(std::iter::once(fallback)) {
        if let Ok(value) = env::var(name) {
            let value = value.trim();
            if !value.is_empty() {
                return value
                    .parse()
                    .map(Some)
                    .with_context(|| format!("invalid IP in ${name}: {value}"));
            }
        }
    }
    Ok(None)
}

fn env_ip_any(names: &[String]) -> Result<Option<IpAddr>> {
    for name in names {
        if let Ok(value) = env::var(name) {
            let value = value.trim();
            if !value.is_empty() {
                return value
                    .parse()
                    .map(Some)
                    .with_context(|| format!("invalid IP in ${name}: {value}"));
            }
        }
    }
    Ok(None)
}

fn env_key(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn env_text(primary: Option<&str>, fallback: &str) -> Option<String> {
    for name in primary.into_iter().chain(std::iter::once(fallback)) {
        if let Ok(value) = env::var(name) {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn route_dev_for(target: &str) -> Result<String> {
    let target = target
        .to_socket_addrs()
        .with_context(|| format!("resolving UDP probe target {target}"))?
        .next()
        .ok_or_else(|| anyhow!("UDP probe target {target} resolved no addresses"))?;
    let bind = match target {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket =
        UdpSocket::bind(bind).with_context(|| format!("binding route probe socket {bind}"))?;
    socket
        .connect(target)
        .with_context(|| format!("connecting route probe socket to {target}"))?;
    let source = socket.local_addr()?.ip();
    crate::linux::net::interface_for_ipv4(source)
        .ok_or_else(|| anyhow!("cannot resolve interface for UDP source {source}"))
}

fn udp_source_ip(target: &str) -> Result<IpAddr> {
    let target = target
        .to_socket_addrs()
        .with_context(|| format!("resolving UDP probe target {target}"))?
        .next()
        .ok_or_else(|| anyhow!("UDP probe target {target} resolved no addresses"))?;
    let bind = match target {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket =
        UdpSocket::bind(bind).with_context(|| format!("binding UDP probe socket {bind}"))?;
    socket
        .connect(target)
        .with_context(|| format!("connecting UDP probe socket to {target}"))?;
    Ok(socket.local_addr()?.ip())
}

fn stun_public_ip(server: &str) -> Result<IpAddr> {
    let server = server
        .to_socket_addrs()
        .with_context(|| format!("resolving STUN server {server}"))?
        .next()
        .ok_or_else(|| anyhow!("STUN server {server} resolved no addresses"))?;
    let bind = match server {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    };
    let socket = UdpSocket::bind(bind).with_context(|| format!("binding STUN socket {bind}"))?;
    let mut client = stunclient::StunClient::new(server);
    client.set_timeout(Duration::from_secs(3));
    client.set_retry_interval(Duration::from_millis(500));
    let external = client
        .query_external_address(&socket)
        .map_err(|error| anyhow!("STUN binding request failed: {error}"))?;
    Ok(external.ip())
}
