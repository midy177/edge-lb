//! Minimal ARP helpers used by cloud HAVIP failover.

use std::{
    ffi::CString,
    io,
    mem::{size_of, zeroed},
    net::Ipv4Addr,
    os::fd::RawFd,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, anyhow};

const ETH_P_ARP: u16 = 0x0806;
const ETH_P_IP: u16 = 0x0800;
const ARPHRD_ETHER: u16 = 1;
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
const ZERO_MAC: [u8; 6] = [0; 6];

pub fn announce_gratuitous_ipv4(
    dev: &str,
    vip: Ipv4Addr,
    count: u32,
    interval: Duration,
    repeat_after: Duration,
    repeat_count: u32,
) -> Result<()> {
    let ifindex = ifindex(dev)?;
    let mac = interface_mac(dev)?;
    let fd = open_packet_socket()?;
    let _guard = FdGuard(fd);
    let request = arp_frame(BROADCAST_MAC, mac, ARP_REQUEST, mac, vip, ZERO_MAC, vip);
    let reply = arp_frame(BROADCAST_MAC, mac, ARP_REPLY, mac, vip, BROADCAST_MAC, vip);
    let rounds = count.max(1);
    for batch in 0..=repeat_count {
        for idx in 0..rounds {
            send_frame(fd, ifindex, &request)
                .with_context(|| format!("sending GARP request on {dev}"))?;
            send_frame(fd, ifindex, &reply)
                .with_context(|| format!("sending GARP reply on {dev}"))?;
            if idx + 1 < rounds {
                thread::sleep(interval);
            }
        }
        if batch < repeat_count {
            thread::sleep(repeat_after);
        }
    }
    Ok(())
}

fn interface_mac(dev: &str) -> Result<[u8; 6]> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{dev}/address"))
        .with_context(|| format!("reading MAC address for {dev}"))?;
    parse_mac(text.trim())
}

fn parse_mac(value: &str) -> Result<[u8; 6]> {
    let mut out = [0u8; 6];
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 6 {
        return Err(anyhow!("bad MAC address {value:?}"));
    }
    for (idx, part) in parts.iter().enumerate() {
        out[idx] =
            u8::from_str_radix(part, 16).with_context(|| format!("bad MAC address {value:?}"))?;
    }
    Ok(out)
}

fn ifindex(dev: &str) -> Result<i32> {
    let dev = CString::new(dev).context("interface name contains NUL")?;
    let index = unsafe { libc::if_nametoindex(dev.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error()).context("resolving interface ifindex");
    }
    Ok(index as i32)
}

fn open_packet_socket() -> Result<RawFd> {
    let fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            i32::from(ETH_P_ARP.to_be()),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("opening ARP packet socket");
    }
    Ok(fd)
}

fn send_frame(fd: RawFd, ifindex: i32, frame: &[u8]) -> Result<()> {
    let mut addr: libc::sockaddr_ll = unsafe { zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::sa_family_t;
    addr.sll_protocol = ETH_P_ARP.to_be();
    addr.sll_ifindex = ifindex;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&BROADCAST_MAC);
    let ret = unsafe {
        libc::sendto(
            fd,
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&addr as *const libc::sockaddr_ll).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error()).context("sending ARP packet");
    }
    Ok(())
}

fn arp_frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    op: u16,
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    target_mac: [u8; 6],
    target_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(42);
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETH_P_ARP.to_be_bytes());
    frame.extend_from_slice(&ARPHRD_ETHER.to_be_bytes());
    frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
    frame.push(6);
    frame.push(4);
    frame.extend_from_slice(&op.to_be_bytes());
    frame.extend_from_slice(&sender_mac);
    frame.extend_from_slice(&sender_ip.octets());
    frame.extend_from_slice(&target_mac);
    frame.extend_from_slice(&target_ip.octets());
    frame
}

struct FdGuard(RawFd);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn garp_request_and_reply_frames_are_well_formed() {
        let mac = [0x52, 0x54, 0, 3, 0x41, 0x42];
        let vip = Ipv4Addr::new(192, 168, 0, 6);
        let request = arp_frame(BROADCAST_MAC, mac, ARP_REQUEST, mac, vip, ZERO_MAC, vip);
        let reply = arp_frame(BROADCAST_MAC, mac, ARP_REPLY, mac, vip, BROADCAST_MAC, vip);

        assert_eq!(request.len(), 42);
        assert_eq!(&request[0..6], &BROADCAST_MAC);
        assert_eq!(&request[6..12], &mac);
        assert_eq!(&request[20..22], &ARP_REQUEST.to_be_bytes());
        assert_eq!(&request[22..28], &mac);
        assert_eq!(&request[28..32], &vip.octets());
        assert_eq!(&request[32..38], &ZERO_MAC);
        assert_eq!(&request[38..42], &vip.octets());

        assert_eq!(reply.len(), 42);
        assert_eq!(&reply[20..22], &ARP_REPLY.to_be_bytes());
        assert_eq!(&reply[32..38], &BROADCAST_MAC);
    }
}
