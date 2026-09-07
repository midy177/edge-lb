//! Network interface address enumeration via getifaddrs(3).

use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One address of one network interface.
pub struct IfaceAddr {
    pub name: String,
    pub ip: IpAddr,
    pub is_loopback: bool,
}

/// Enumerate all interface addresses; empty on failure.
pub fn list() -> Vec<IfaceAddr> {
    let mut out = Vec::new();
    // SAFETY: standard getifaddrs(3) usage — the list is owned by us and
    // released with freeifaddrs below; each node is read-only.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return out;
        }
        let mut cur = ifap;
        while !cur.is_null() {
            let ifa: &libc::ifaddrs = &*cur;
            if !ifa.ifa_addr.is_null() {
                let family = (*ifa.ifa_addr).sa_family as libc::c_int;
                let ip = match family {
                    libc::AF_INET => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr))))
                    }
                    libc::AF_INET6 => {
                        let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                        Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)))
                    }
                    _ => None,
                };
                if let Some(ip) = ip {
                    let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();
                    let is_loopback = (ifa.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint) != 0;
                    out.push(IfaceAddr {
                        name,
                        ip,
                        is_loopback,
                    });
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(ifap);
    }
    out
}
