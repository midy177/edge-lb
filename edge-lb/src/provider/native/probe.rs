//! Native target health probe worker.
//!
//! Runs probes independently of the API read path: the scheduler below owns
//! health evaluation, writes observed `currState` back into the native proxy
//! state, and refreshes the eBPF health map when a transition happens.
//! The API stays a pure reader of observed state. Desired target-group
//! configuration is never modified here.

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

use anyhow::Result;

use crate::config::{Config, Listener, TargetGroup};

/// Default probe period when the target group does not configure one.
pub const DEFAULT_PERIOD_SECS: u64 = 5;
/// Default consecutive failures before a target is marked unhealthy.
pub const DEFAULT_RETRIES: u32 = 2;
/// Probe types supported by the native worker. `none` disables probing.
const EXECUTABLE_PROBES: [&str; 5] = ["ping", "tcp", "udp", "http", "https"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Ok,
    Fail,
}

/// One scheduled probe target: a target-group target observed under every
/// listener protocol that references its group. The probe uses `port`, while
/// `names` use each listener's forwarding target port because that is the
/// runtime identity stored by the native datapath.
#[derive(Debug, Clone)]
pub struct ProbeTarget {
    pub names: Vec<String>,
    pub address: IpAddr,
    pub port: u16,
    pub probe_type: String,
    pub probe_req: Option<String>,
    pub probe_resp: Option<String>,
    pub expected_status: Option<u16>,
    pub skip_tls_verify: bool,
    pub timeout: Duration,
    pub period: Duration,
    pub retries: u32,
}

/// Runtime probe state per backend target (worker memory only).
#[derive(Debug, Default)]
struct ProbeRuntime {
    consecutive_failures: u32,
}

pub fn run_worker(cfg: Config) {
    let mut runtimes: HashMap<String, ProbeRuntime> = HashMap::new();
    let mut next_due = Instant::now();
    tracing::info!("[probe] native target probe worker started");
    loop {
        if crate::runtime::shutdown::requested() {
            tracing::info!("[probe] shutdown requested");
            return;
        }
        let now = Instant::now();
        if now < next_due {
            std::thread::sleep(Duration::from_millis(250).min(next_due - now));
            continue;
        }
        let period = probe_round(&cfg, &mut runtimes);
        next_due = Instant::now() + period;
    }
}

/// Probe every monitored backend target once and apply state transitions.
/// Returns the shortest configured period (the wait before the next round).
fn probe_round(cfg: &Config, runtimes: &mut HashMap<String, ProbeRuntime>) -> Duration {
    let mut effective = cfg.clone();
    if let Err(error) = super::hydrate_proxy_config_from_api(&mut effective) {
        tracing::warn!("[probe] native proxy state refresh failed: {error:#}");
    }
    let targets = scheduled_targets(&effective);
    if targets.is_empty() {
        return Duration::from_secs(DEFAULT_PERIOD_SECS);
    }
    let mut shortest = Duration::from_secs(DEFAULT_PERIOD_SECS);
    let clients = ProbeClients::new();
    let mut outcomes: Vec<(&ProbeTarget, ProbeOutcome)> = Vec::new();
    for target in &targets {
        shortest = shortest.min(target.period);
        let outcome = probe_target_with_clients(target, &clients);
        outcomes.push((target, outcome));
    }
    let transitions = apply_results(cfg, &outcomes, runtimes);
    if transitions > 0
        && let Err(e) = crate::linux::native_dnat::refresh_target_health(cfg)
    {
        tracing::warn!("[probe] native health map refresh failed: {e:#}");
    }
    shortest
}

/// Expand monitored target groups into probe targets. Backend target addresses are
/// resolved through the backend inventory so `backend = name` targets probe
/// the live underlay address even when the stored record was created while
/// the backend was offline.
pub fn scheduled_targets(cfg: &Config) -> Vec<ProbeTarget> {
    let mut out = Vec::new();
    for group in monitored_groups(cfg) {
        let probe_type = normalized_probe_type(group);
        if !EXECUTABLE_PROBES.contains(&probe_type.as_str()) {
            continue;
        }
        let probe_port = if probe_type == "ping" {
            0
        } else {
            group
                .probe_port
                .or_else(|| {
                    cfg.listeners
                        .iter()
                        .find(|listener| listener.target_group == group.name)
                        .map(|listener| listener.target_port)
                        .filter(|port| *port != 0)
                })
                .unwrap_or(0)
        };
        let period_secs = u64::from(group.period_secs.unwrap_or(DEFAULT_PERIOD_SECS as u32)).max(1);
        let timeout = Duration::from_secs(period_secs.min(3)).max(Duration::from_millis(500));
        let retries = group.retries.unwrap_or(DEFAULT_RETRIES).max(1);
        for target in &group.targets {
            let address = cfg.resolve_backend_target_address(target);
            if address.is_unspecified() || address.is_loopback() {
                continue;
            }
            let listener_identities = listener_identities(cfg, &group.name);
            if listener_identities.is_empty() {
                continue;
            }
            let names = listener_identities
                .iter()
                .map(|(protocol, target_port)| {
                    target_health_identity(address, protocol, *target_port)
                })
                .collect::<Vec<_>>();
            out.push(ProbeTarget {
                names,
                address,
                port: probe_port,
                probe_type: probe_type.clone(),
                probe_req: group.probe_req.clone(),
                probe_resp: group.probe_resp.clone(),
                expected_status: group.probe_status,
                skip_tls_verify: group.probe_skip_tls_verify,
                timeout,
                period: Duration::from_secs(period_secs),
                retries,
            });
        }
    }
    out
}

fn monitored_groups(cfg: &Config) -> Vec<&TargetGroup> {
    let bound_groups = cfg
        .listeners
        .iter()
        .map(|listener| listener.target_group.as_str())
        .collect::<std::collections::HashSet<_>>();
    cfg.target_groups
        .iter()
        .filter(|group| bound_groups.contains(group.name.as_str()))
        .filter(|group| group.monitor)
        .filter(|group| {
            group
                .probe_type
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty() && !value.eq_ignore_ascii_case("none"))
        })
        .collect()
}

fn normalized_probe_type(group: &TargetGroup) -> String {
    group
        .probe_type
        .clone()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Runtime identities of every listener bound to this group. The target port
/// is deliberately kept separate from the health probe port.
fn listener_identities(cfg: &Config, group: &str) -> BTreeSet<(String, u16)> {
    cfg.listeners
        .iter()
        .filter(|listener: &&Listener| listener.target_group == group)
        .flat_map(|listener| {
            listener
                .protocols
                .iter()
                .map(|protocol| (protocol.as_str().to_string(), listener.target_port))
        })
        .collect()
}

pub fn target_health_identity(address: IpAddr, protocol: &str, service_port: u16) -> String {
    format!(
        "{}_{}_{}",
        address,
        protocol.trim().to_ascii_lowercase(),
        service_port
    )
}

/// Execute one probe.
pub fn probe_target(target: &ProbeTarget) -> ProbeOutcome {
    probe_target_with_clients(target, &ProbeClients::new())
}

struct ProbeClients {
    secure: Option<reqwest::blocking::Client>,
    insecure: Option<reqwest::blocking::Client>,
}

impl ProbeClients {
    fn new() -> Self {
        let build = |accept_invalid_certs| {
            reqwest::blocking::Client::builder()
                .pool_idle_timeout(Duration::from_secs(30))
                .danger_accept_invalid_certs(accept_invalid_certs)
                .build()
                .ok()
        };
        Self {
            secure: build(false),
            insecure: build(true),
        }
    }
}

fn probe_target_with_clients(target: &ProbeTarget, clients: &ProbeClients) -> ProbeOutcome {
    match target.probe_type.as_str() {
        "ping" => probe_ping(target),
        "tcp" => probe_tcp(target),
        "udp" => probe_udp(target),
        "http" => probe_http(target, clients, false),
        "https" => probe_http(target, clients, true),
        other => {
            tracing::debug!("[probe] probe type {other:?} not executable; skipping");
            ProbeOutcome::Ok
        }
    }
}

fn probe_ping(target: &ProbeTarget) -> ProbeOutcome {
    let IpAddr::V4(address) = target.address else {
        return ProbeOutcome::Fail;
    };

    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
    if fd < 0 {
        tracing::debug!("[probe] ping socket creation failed for {address}");
        return ProbeOutcome::Fail;
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: target.timeout.as_secs().try_into().unwrap_or(i64::MAX),
        tv_usec: i64::from(target.timeout.subsec_micros()),
    };
    let timeout_len = std::mem::size_of_val(&timeout) as libc::socklen_t;
    let timeout_result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            timeout_len,
        )
    };
    if timeout_result < 0 {
        return ProbeOutcome::Fail;
    }

    let identifier = std::process::id() as u16;
    let sequence = (Instant::now().elapsed().subsec_nanos() as u16).wrapping_add(identifier);
    let mut packet = [0u8; 8];
    packet[0] = 8;
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&sequence.to_be_bytes());
    let checksum = icmp_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());

    let destination = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    };
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            0,
            (&destination as *const libc::sockaddr_in).cast(),
            std::mem::size_of_val(&destination) as libc::socklen_t,
        )
    };
    if sent != packet.len() as libc::ssize_t {
        return ProbeOutcome::Fail;
    }

    let mut response = [0u8; 1500];
    let received = unsafe {
        libc::recv(
            socket.as_raw_fd(),
            response.as_mut_ptr().cast(),
            response.len(),
            0,
        )
    };
    if received < 8 {
        return ProbeOutcome::Fail;
    }
    let bytes = &response[..received as usize];
    let offset = if bytes[0] >> 4 == 4 {
        usize::from(bytes[0] & 0x0f) * 4
    } else {
        0
    };
    if bytes.len() < offset + 8 {
        return ProbeOutcome::Fail;
    }
    let icmp = &bytes[offset..offset + 8];
    if icmp[0] == 0
        && icmp[1] == 0
        && u16::from_be_bytes([icmp[4], icmp[5]]) == identifier
        && u16::from_be_bytes([icmp[6], icmp[7]]) == sequence
    {
        ProbeOutcome::Ok
    } else {
        ProbeOutcome::Fail
    }
}

fn icmp_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < packet.len() {
        sum += u32::from(u16::from_be_bytes([packet[index], packet[index + 1]]));
        index += 2;
    }
    if let Some(&byte) = packet.get(index) {
        sum += u32::from(byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn probe_tcp(target: &ProbeTarget) -> ProbeOutcome {
    match tcp_connect(target.address, target.port, target.timeout) {
        Ok(mut stream) => {
            if let Some(request) = target.probe_req.as_deref().filter(|v| !v.is_empty())
                && std::io::Write::write_all(&mut stream, request.as_bytes()).is_err()
            {
                return ProbeOutcome::Fail;
            }
            if let Some(expected) = target.probe_resp.as_deref().filter(|v| !v.is_empty()) {
                let _ = stream.set_read_timeout(Some(target.timeout));
                let mut buf = [0u8; 1024];
                return match std::io::Read::read(&mut stream, &mut buf) {
                    Ok(size) if String::from_utf8_lossy(&buf[..size]).contains(expected) => {
                        ProbeOutcome::Ok
                    }
                    _ => ProbeOutcome::Fail,
                };
            }
            ProbeOutcome::Ok
        }
        Err(e) => {
            tracing::debug!("[probe] tcp {}:{} failed: {e}", target.address, target.port);
            ProbeOutcome::Fail
        }
    }
}

fn probe_udp(target: &ProbeTarget) -> ProbeOutcome {
    use std::net::UdpSocket;
    let addr = SocketAddr::new(target.address, target.port);
    let bind = if target.address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(bind) else {
        return ProbeOutcome::Fail;
    };
    if socket.connect(addr).is_err() {
        return ProbeOutcome::Fail;
    }
    let payload = target.probe_req.clone().unwrap_or_default();
    if socket.send(payload.as_bytes()).is_err() {
        return ProbeOutcome::Fail;
    }
    // Best-effort UDP probe: an ICMP port-unreachable surfaces as a read
    // error on the connected socket; silence within the window counts as ok.
    let _ = socket.set_read_timeout(Some(target.timeout));
    let mut buf = [0u8; 512];
    match socket.recv(&mut buf) {
        Ok(_size)
            if target
                .probe_resp
                .as_deref()
                .is_none_or(|expected| expected.is_empty()) =>
        {
            ProbeOutcome::Ok
        }
        Ok(size)
            if String::from_utf8_lossy(&buf[..size])
                .contains(target.probe_resp.as_deref().unwrap_or_default()) =>
        {
            ProbeOutcome::Ok
        }
        Ok(_) => ProbeOutcome::Fail,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            ProbeOutcome::Fail
        }
        Err(_) => ProbeOutcome::Ok,
    }
}

fn probe_http(target: &ProbeTarget, clients: &ProbeClients, tls: bool) -> ProbeOutcome {
    let scheme = if tls { "https" } else { "http" };
    let host = target.address.to_string();
    let path = target
        .probe_req
        .clone()
        .filter(|req| req.starts_with('/'))
        .unwrap_or_else(|| "/".to_string());
    let url = format!("{scheme}://{host}:{}/{path}", target.port);
    let client = if tls && target.skip_tls_verify {
        clients.insecure.as_ref()
    } else {
        clients.secure.as_ref()
    };
    let Some(client) = client else {
        return ProbeOutcome::Fail;
    };
    match client.get(&url).timeout(target.timeout).send() {
        Ok(response) => {
            let status = response.status().as_u16();
            if http_status_is_healthy(status, target.expected_status) {
                ProbeOutcome::Ok
            } else {
                tracing::debug!("[probe] {url} returned status {status}");
                ProbeOutcome::Fail
            }
        }
        Err(e) => {
            tracing::debug!("[probe] {url} failed: {e}");
            ProbeOutcome::Fail
        }
    }
}

fn http_status_is_healthy(status: u16, expected: Option<u16>) -> bool {
    expected.map_or((200..400).contains(&status), |value| value == status)
}

fn tcp_connect(address: IpAddr, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addr = SocketAddr::new(address, port);
    let mut last_err = None;
    for resolved in addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("resolving {addr}: {e}"))?
    {
        match TcpStream::connect_timeout(&resolved, timeout) {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(anyhow::anyhow!(
        "tcp connect to {addr} failed: {}",
        last_err
            .map(|e| e.to_string())
            .unwrap_or_else(|| "no address".into())
    ))
}

/// Fold probe outcomes into observed target health and report how many
/// records transitioned (each record name counts once).
fn apply_results(
    cfg: &Config,
    outcomes: &[(&ProbeTarget, ProbeOutcome)],
    runtimes: &mut HashMap<String, ProbeRuntime>,
) -> usize {
    // One decision per probe target, applied to every protocol identity.
    let mut transitions = 0usize;
    let mut updates: Vec<(String, &'static str, u32)> = Vec::new();
    for (target, outcome) in outcomes {
        let runtime = runtimes.entry(names_key(&target.names)).or_default();
        let (next_state, failures) = match outcome {
            ProbeOutcome::Ok => {
                runtime.consecutive_failures = 0;
                ("ok", 0)
            }
            ProbeOutcome::Fail => {
                runtime.consecutive_failures += 1;
                ("nok", runtime.consecutive_failures)
            }
        };
        for name in &target.names {
            updates.push((name.clone(), next_state, failures));
        }
    }
    let result = crate::provider::native::store::mutate_target_health(cfg, |targets| {
        for (name, next_state, failures) in &updates {
            let Some(entry) = targets.iter_mut().find(|entry| &entry.name == name) else {
                continue;
            };
            if entry.current_state.as_deref() == Some(next_state) {
                continue;
            }
            // Unhealthy only after the configured retry threshold; recovery
            // is immediate on the first success.
            if next_state == &"nok" {
                let retries = entry.inactive_retries.unwrap_or(DEFAULT_RETRIES).max(1);
                if *failures < retries {
                    continue;
                }
            }
            tracing::info!(
                "[probe] target {name}: {} -> {next_state}",
                entry.current_state.as_deref().unwrap_or("unknown")
            );
            entry.current_state = Some(next_state.to_string());
            transitions += 1;
        }
    });
    if let Err(e) = result {
        tracing::warn!("[probe] persisting observed target health failed: {e:#}");
        return 0;
    }
    transitions
}

fn names_key(names: &[String]) -> String {
    names.first().cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BackendTarget, Config, FileConfig, Listener, Protocol, TargetGroup};
    use std::path::PathBuf;

    fn cfg_with_group(monitor: bool, probe_type: Option<&str>) -> Config {
        let group = TargetGroup {
            name: "web".to_string(),
            monitor,
            probe_type: probe_type.map(str::to_string),
            probe_port: None,
            probe_req: None,
            probe_resp: None,
            probe_status: None,
            probe_skip_tls_verify: false,
            period_secs: Some(5),
            retries: Some(2),
            targets: vec![BackendTarget {
                backend: None,
                address: "192.0.2.10".parse().unwrap(),
                weight: 1,
            }],
        };
        let listener = Listener {
            name: "web".to_string(),
            port: 80,
            target_port: 8080,
            target_group: "web".to_string(),
            protocols: vec![Protocol::Tcp],
            ..Listener::default()
        };
        let mut file = FileConfig::default();
        file.target_groups = vec![group];
        file.listeners = vec![listener];
        Config {
            path: PathBuf::from("/tmp/edge-lb-probe-test.toml"),
            file,
        }
    }

    #[test]
    fn unsupported_probe_types_are_not_scheduled() {
        for probe in ["none", ""] {
            let cfg = cfg_with_group(true, if probe.is_empty() { None } else { Some(probe) });
            assert!(scheduled_targets(&cfg).is_empty(), "probe {probe:?}");
        }
    }

    #[test]
    fn ping_probe_is_scheduled_without_a_port() {
        let cfg = cfg_with_group(true, Some("ping"));
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].port, 0);
        assert_eq!(targets[0].probe_type, "ping");
    }

    #[test]
    fn unmonitored_groups_are_not_scheduled() {
        let cfg = cfg_with_group(false, Some("tcp"));
        assert!(scheduled_targets(&cfg).is_empty());
    }

    #[test]
    fn executable_target_uses_listener_protocol_identity() {
        let cfg = cfg_with_group(true, Some("http"));
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 1);
        let target = &targets[0];
        assert_eq!(target.probe_type, "http");
        assert_eq!(target.port, 8080, "probe port falls back to service port");
        assert_eq!(target.retries, 2);
        assert_eq!(target.period, Duration::from_secs(5));
        assert_eq!(
            target.names,
            vec![target_health_identity(
                "192.0.2.10".parse().unwrap(),
                "tcp",
                8080
            )]
        );
    }

    #[test]
    fn probe_port_does_not_change_listener_target_identity() {
        let mut cfg = cfg_with_group(true, Some("http"));
        cfg.file.target_groups[0].probe_port = Some(9090);
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets[0].port, 9090);
        assert_eq!(
            targets[0].names,
            vec![target_health_identity(
                "192.0.2.10".parse().unwrap(),
                "tcp",
                8080
            )]
        );
    }

    #[test]
    fn multiple_listener_protocols_expand_to_one_name_each() {
        let mut cfg = cfg_with_group(true, Some("tcp"));
        cfg.file.listeners[0].protocols = vec![Protocol::Tcp, Protocol::Udp];
        let targets = scheduled_targets(&cfg);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].names.len(), 2);
    }

    #[test]
    fn unresolvable_auto_addresses_are_skipped() {
        let mut cfg = cfg_with_group(true, Some("tcp"));
        cfg.file.target_groups[0].targets[0].address = "0.0.0.0".parse().unwrap();
        assert!(scheduled_targets(&cfg).is_empty());
    }

    #[test]
    fn target_health_identity_matches_store_convention() {
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        assert_eq!(
            target_health_identity(ip, "TCP", 8080),
            "192.0.2.10_tcp_8080"
        );
    }

    #[test]
    fn http_status_rule_accepts_success_redirects_by_default() {
        assert!(http_status_is_healthy(200, None));
        assert!(http_status_is_healthy(302, None));
        assert!(!http_status_is_healthy(199, None));
        assert!(!http_status_is_healthy(400, None));
    }

    #[test]
    fn http_status_rule_supports_exact_expected_status() {
        assert!(http_status_is_healthy(204, Some(204)));
        assert!(!http_status_is_healthy(200, Some(204)));
    }
}
