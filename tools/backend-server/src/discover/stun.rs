//! STUN (RFC 5389) client used for public IP discovery.
//!
//! Transport and message encoding are delegated to the `stunclient` crate
//! (synchronous mode, no tokio): classic Binding requests over UDP, no
//! credentials. This module owns the policy around it — server-list
//! normalization, per-family DNS filtering and result validation.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;
use stunclient::StunClient;

/// Default STUN port applied when a server is configured without one.
pub const DEFAULT_STUN_PORT: u16 = 3478;

/// End-to-end budget per server address; `stunclient` re-sends the request
/// every `retry_interval` (default 1s) until this deadline.
const QUERY_TIMEOUT: Duration = Duration::from_secs(6);
const MAX_SERVER_ADDRS: usize = 3;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Family {
    IPv4,
    IPv6,
}

/// Append the default STUN port when the input carries none.
pub fn normalize_server(input: &str) -> String {
    let s = input.trim();
    if s.is_empty() {
        return s.to_string();
    }
    let colons = s.matches(':').count();
    if colons == 0 {
        format!("{s}:{DEFAULT_STUN_PORT}")
    } else if colons == 1 || s.starts_with('[') {
        s.to_string()
    } else {
        // Bare IPv6 literal.
        format!("[{s}]:{DEFAULT_STUN_PORT}")
    }
}

/// Query the servers in order; the first success wins.
pub fn discover(
    servers: &[String],
    family: Family,
    debug_log: impl Fn(&str),
) -> Result<IpAddr, String> {
    let mut errors: Vec<String> = Vec::new();
    for server in servers {
        debug_log(&format!("stun: trying {server}"));
        match query_server(server, family) {
            Ok(ip) => {
                debug_log(&format!("stun: {server} returned {ip}"));
                return Ok(ip);
            }
            Err(e) => errors.push(format!("{server}: {e}")),
        }
    }
    Err(format!("all STUN servers failed: {}", errors.join("; ")))
}

fn query_server(server: &str, family: Family) -> Result<IpAddr, String> {
    // Only addresses of the queried family can reflect an address of that
    // family, so anything else the resolver returns is useless here.
    let addrs: Vec<SocketAddr> = server
        .to_socket_addrs()
        .map_err(|e| format!("failed to resolve: {e}"))?
        .filter(|a| match family {
            Family::IPv4 => a.is_ipv4(),
            Family::IPv6 => a.is_ipv6(),
        })
        .take(MAX_SERVER_ADDRS)
        .collect();
    if addrs.is_empty() {
        return Err(format!("no {family:?} address records"));
    }
    let mut last = "no response".to_string();
    for addr in addrs {
        match query_addr(addr, family) {
            Ok(ip) => return Ok(ip),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn query_addr(addr: SocketAddr, family: Family) -> Result<IpAddr, String> {
    let bind_addr = match family {
        Family::IPv4 => "0.0.0.0:0",
        Family::IPv6 => "[::]:0",
    };
    let sock = UdpSocket::bind(bind_addr).map_err(|e| format!("bind failed: {e}"))?;
    let mut client = StunClient::new(addr);
    client.set_timeout(QUERY_TIMEOUT);

    match client.query_external_address(&sock) {
        Ok(sa) => {
            let ip = sa.ip();
            match (family, ip) {
                (Family::IPv4, IpAddr::V4(_)) | (Family::IPv6, IpAddr::V6(_)) => Ok(ip),
                (want, ip) => Err(format!(
                    "mapped address family does not match {want:?} query: {ip}"
                )),
            }
        }
        Err(stunclient::Error::Timeout(())) => Err("timed out".into()),
        Err(stunclient::Error::Socket(e)) => Err(format!("socket error: {e}")),
        Err(e) => Err(format!("stun query failed: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_server_forms() {
        assert_eq!(
            normalize_server("stun.example.com"),
            "stun.example.com:3478"
        );
        assert_eq!(
            normalize_server("stun.example.com:19302"),
            "stun.example.com:19302"
        );
        assert_eq!(normalize_server("2001:db8::1"), "[2001:db8::1]:3478");
        assert_eq!(normalize_server("[2001:db8::1]:9999"), "[2001:db8::1]:9999");
        assert_eq!(normalize_server("  host  "), "host:3478");
    }
}
