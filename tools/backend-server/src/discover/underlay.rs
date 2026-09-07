//! Underlay IP discovery (fills the Go version's `privatev4` field).
//!
//! Precedence:
//!   1. `UNDERLAY_IP` environment variable
//!   2. UDP probe — connect an unconnected UDP socket to a public target. No
//!      packet is sent; the kernel runs the routing table (the default route,
//!      i.e. the underlay device) and reports the source address it chose.
//!   3. First global-unicast IPv4 of the default-route device (`underlay_dev`)
//!   4. First global-unicast IPv4 of any non-docker, non-loopback interface
//!      (same heuristic as the Go version's default discovery).

use super::env_nonempty;
use crate::log::debug_if;
use crate::system::ifaddr::IfaceAddr;
use crate::system::{ifaddr, route};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Public anycast targets used to steer the UDP probe along the default route.
const UDP_PROBE_TARGETS: &[&str] = &["8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53", "9.9.9.9:53"];

pub fn discover(debug: bool) -> Result<Ipv4Addr, String> {
    if let Some(v) = env_nonempty("UNDERLAY_IP") {
        if let Ok(ip) = v.parse::<Ipv4Addr>() {
            return Ok(ip);
        }
        debug_if(
            debug,
            &format!("underlay: invalid UNDERLAY_IP value {v:?}; discovering instead"),
        );
    }

    let dev = route::default_interface();
    match &dev {
        Some(d) => debug_if(debug, &format!("underlay: default route device is {d}")),
        None => debug_if(debug, "underlay: failed to determine default route device"),
    }

    if let Some(ip) = udp_source_address() {
        debug_if(
            debug,
            &format!("underlay: UDP probe selected source address {ip}"),
        );
        return Ok(ip);
    }
    debug_if(
        debug,
        "underlay: UDP probe failed; falling back to interface scan",
    );

    let addrs = ifaddr::list();
    if let Some(dev) = &dev {
        if let Some(ip) = interface_ipv4(&addrs, dev) {
            debug_if(
                debug,
                &format!("underlay: using first address of {dev}: {ip}"),
            );
            return Ok(ip);
        }
    }
    if let Some((ip, name)) = any_interface_ipv4(&addrs) {
        debug_if(debug, &format!("underlay: using address of {name}: {ip}"));
        return Ok(ip);
    }

    Err("valid address not found".to_string())
}

/// Source address the kernel would use towards a public target. Connecting a
/// UDP socket performs only a local routing-table lookup; nothing is sent.
fn udp_source_address() -> Option<Ipv4Addr> {
    for target in UDP_PROBE_TARGETS {
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
            continue;
        };
        if sock.connect(target).is_err() {
            continue;
        }
        if let Ok(local) = sock.local_addr() {
            if let IpAddr::V4(ip) = local.ip() {
                if !ip.is_unspecified() && !ip.is_loopback() {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Go-parity `IsGlobalUnicast` check for IPv4 (private ranges included).
pub fn is_global_unicast_v4(ip: Ipv4Addr) -> bool {
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_link_local())
}

/// First usable IPv4 address of the named device.
fn interface_ipv4(addrs: &[IfaceAddr], dev: &str) -> Option<Ipv4Addr> {
    addrs
        .iter()
        .filter(|a| a.name == dev && !a.is_loopback)
        .filter_map(|a| match a.ip {
            IpAddr::V4(v) => Some(v),
            IpAddr::V6(_) => None,
        })
        .find(|ip| is_global_unicast_v4(*ip))
}

/// First usable IPv4 of any interface, skipping `docker*` (Go-version parity).
fn any_interface_ipv4(addrs: &[IfaceAddr]) -> Option<(Ipv4Addr, String)> {
    addrs
        .iter()
        .filter(|a| !a.is_loopback && !a.name.starts_with("docker"))
        .find_map(|a| match a.ip {
            IpAddr::V4(v) if is_global_unicast_v4(v) => Some((v, a.name.clone())),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: IpAddr, lo: bool) -> IfaceAddr {
        IfaceAddr {
            name: name.into(),
            ip,
            is_loopback: lo,
        }
    }

    #[test]
    fn global_unicast_classification() {
        assert!(is_global_unicast_v4("192.168.1.10".parse().unwrap()));
        assert!(is_global_unicast_v4("10.0.0.5".parse().unwrap()));
        assert!(is_global_unicast_v4("203.0.113.7".parse().unwrap()));
        assert!(!is_global_unicast_v4("127.0.0.1".parse().unwrap()));
        assert!(!is_global_unicast_v4("0.0.0.0".parse().unwrap()));
        assert!(!is_global_unicast_v4("169.254.1.1".parse().unwrap()));
        assert!(!is_global_unicast_v4("224.0.0.1".parse().unwrap()));
        assert!(!is_global_unicast_v4("255.255.255.255".parse().unwrap()));
    }

    #[test]
    fn interface_pick_prefers_named_device() {
        let addrs = vec![
            iface("lo0", "127.0.0.1".parse().unwrap(), true),
            iface("en0", "192.168.1.10".parse().unwrap(), false),
            iface("en1", "10.1.2.3".parse().unwrap(), false),
        ];
        assert_eq!(
            interface_ipv4(&addrs, "en1"),
            Some("10.1.2.3".parse().unwrap())
        );
        assert_eq!(interface_ipv4(&addrs, "missing"), None);
    }

    #[test]
    fn any_interface_skips_docker_and_bad_ranges() {
        let addrs = vec![
            iface("lo0", "127.0.0.1".parse().unwrap(), true),
            iface("docker0", "172.17.0.1".parse().unwrap(), false),
            iface("en0", "169.254.9.9".parse().unwrap(), false), // link-local
            iface("en0", "192.168.1.10".parse().unwrap(), false),
        ];
        assert_eq!(
            any_interface_ipv4(&addrs),
            Some(("192.168.1.10".parse().unwrap(), "en0".to_string()))
        );
    }
}
