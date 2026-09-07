//! VIP address management through the Linux rtnetlink address API.

use crate::config::Config;
use anyhow::{Context, Result};

#[cfg(target_os = "linux")]
mod linux {
    use anyhow::{Context, Result, bail};
    use std::{ffi::CString, io, mem::size_of, os::fd::RawFd};

    const NLM_F_REQUEST: u16 = 0x01;
    const NLM_F_ACK: u16 = 0x04;
    const NLM_F_ROOT: u16 = 0x100;
    const NLM_F_MATCH: u16 = 0x200;
    const NLM_F_REPLACE: u16 = 0x100;
    const NLM_F_CREATE: u16 = 0x400;
    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const RTM_NEWADDR: u16 = 20;
    const RTM_DELADDR: u16 = 21;
    const RTM_GETADDR: u16 = 22;
    const IFA_ADDRESS: u16 = 1;
    const IFA_LOCAL: u16 = 2;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Header {
        len: u32,
        kind: u16,
        flags: u16,
        seq: u32,
        pid: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfAddr {
        family: u8,
        prefix_len: u8,
        flags: u8,
        scope: u8,
        index: u32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Attr {
        len: u16,
        kind: u16,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MsgError {
        error: i32,
        _header: Header,
    }

    fn align(value: usize) -> usize {
        (value + 3) & !3
    }

    fn attr(body: &mut Vec<u8>, kind: u16, value: &[u8]) {
        let len = size_of::<Attr>() + value.len();
        let start = body.len();
        body.resize(start + align(len), 0);
        body[start..start + 2].copy_from_slice(&(len as u16).to_ne_bytes());
        body[start + 2..start + 4].copy_from_slice(&kind.to_ne_bytes());
        body[start + 4..start + 4 + value.len()].copy_from_slice(value);
    }

    fn ifindex(dev: &str) -> Result<u32> {
        let name = CString::new(dev).context("interface name contains NUL")?;
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index == 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("looking up {dev}"));
        }
        Ok(index)
    }

    fn socket() -> Result<RawFd> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("opening address rtnetlink socket");
        }
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let result = unsafe {
            libc::bind(
                fd,
                (&address as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(error).context("binding address rtnetlink socket");
        }
        Ok(fd)
    }

    fn send(fd: RawFd, message: &[u8]) -> Result<()> {
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        let sent = unsafe {
            libc::sendto(
                fd,
                message.as_ptr().cast(),
                message.len(),
                0,
                (&address as *const libc::sockaddr_nl).cast(),
                size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error()).context("sending address rtnetlink request");
        }
        if sent as usize != message.len() {
            bail!("short address rtnetlink write: {sent}/{}", message.len());
        }
        Ok(())
    }

    fn addr_message(kind: u16, flags: u16, index: u32, vip: std::net::Ipv4Addr) -> Vec<u8> {
        let header = Header {
            len: (size_of::<Header>() + size_of::<IfAddr>()) as u32,
            kind,
            flags,
            seq: 1,
            pid: 0,
        };
        let address = IfAddr {
            family: libc::AF_INET as u8,
            prefix_len: 32,
            flags: 0,
            scope: 0,
            index,
        };
        let mut message = Vec::new();
        message.extend_from_slice(unsafe {
            std::slice::from_raw_parts((&header as *const Header).cast(), size_of::<Header>())
        });
        message.extend_from_slice(unsafe {
            std::slice::from_raw_parts((&address as *const IfAddr).cast(), size_of::<IfAddr>())
        });
        attr(&mut message, IFA_LOCAL, &vip.octets());
        attr(&mut message, IFA_ADDRESS, &vip.octets());
        let message_len = message.len() as u32;
        message[..4].copy_from_slice(&message_len.to_ne_bytes());
        message
    }

    fn update(kind: u16, flags: u16, index: u32, vip: std::net::Ipv4Addr) -> Result<()> {
        let fd = socket()?;
        let result = (|| {
            send(fd, &addr_message(kind, flags, index, vip))?;
            let mut buffer = [0_u8; 8192];
            loop {
                let size = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
                if size < 0 {
                    return Err(io::Error::last_os_error())
                        .context("reading address rtnetlink ack");
                }
                let mut offset = 0;
                while offset + size_of::<Header>() <= size as usize {
                    let header = unsafe {
                        std::ptr::read_unaligned(buffer[offset..].as_ptr().cast::<Header>())
                    };
                    let length = header.len as usize;
                    if length < size_of::<Header>() || offset + length > size as usize {
                        bail!("truncated address rtnetlink response");
                    }
                    if header.kind == NLMSG_ERROR {
                        if length < size_of::<Header>() + size_of::<MsgError>() {
                            bail!("truncated address rtnetlink error response");
                        }
                        let error = unsafe {
                            std::ptr::read_unaligned(
                                buffer[offset + size_of::<Header>()..]
                                    .as_ptr()
                                    .cast::<MsgError>(),
                            )
                        };
                        if error.error != 0 {
                            return Err(io::Error::from_raw_os_error(-error.error))
                                .context("address rtnetlink request failed");
                        }
                        return Ok(());
                    }
                    offset += align(length);
                }
            }
        })();
        unsafe { libc::close(fd) };
        result
    }

    pub fn bind(dev: &str, vip: std::net::Ipv4Addr) -> Result<()> {
        update(
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
            ifindex(dev)?,
            vip,
        )
    }

    pub fn release(dev: &str, vip: std::net::Ipv4Addr) -> Result<()> {
        update(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, ifindex(dev)?, vip)
    }

    pub fn bound(dev: &str, vip: std::net::Ipv4Addr) -> Result<bool> {
        let index = ifindex(dev)?;
        let fd = socket()?;
        let result = (|| {
            let header = Header {
                len: (size_of::<Header>() + size_of::<IfAddr>()) as u32,
                kind: RTM_GETADDR,
                flags: NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH,
                seq: 1,
                pid: 0,
            };
            let address = IfAddr {
                family: libc::AF_INET as u8,
                prefix_len: 0,
                flags: 0,
                scope: 0,
                index,
            };
            let mut message = Vec::new();
            message.extend_from_slice(unsafe {
                std::slice::from_raw_parts((&header as *const Header).cast(), size_of::<Header>())
            });
            message.extend_from_slice(unsafe {
                std::slice::from_raw_parts((&address as *const IfAddr).cast(), size_of::<IfAddr>())
            });
            send(fd, &message)?;
            let mut buffer = [0_u8; 32768];
            let mut found = false;
            loop {
                let size = unsafe { libc::recv(fd, buffer.as_mut_ptr().cast(), buffer.len(), 0) };
                if size < 0 {
                    return Err(io::Error::last_os_error()).context("reading address dump");
                }
                let mut offset = 0;
                while offset + size_of::<Header>() <= size as usize {
                    let header = unsafe {
                        std::ptr::read_unaligned(buffer[offset..].as_ptr().cast::<Header>())
                    };
                    let length = header.len as usize;
                    if length < size_of::<Header>() || offset + length > size as usize {
                        bail!("truncated address dump");
                    }
                    if header.kind == NLMSG_DONE {
                        return Ok(found);
                    }
                    if header.kind == NLMSG_ERROR {
                        if length < size_of::<Header>() + size_of::<MsgError>() {
                            bail!("truncated address dump error");
                        }
                        let error = unsafe {
                            std::ptr::read_unaligned(
                                buffer[offset + size_of::<Header>()..]
                                    .as_ptr()
                                    .cast::<MsgError>(),
                            )
                        };
                        if error.error != 0 {
                            return Err(io::Error::from_raw_os_error(-error.error))
                                .context("address dump failed");
                        }
                        return Ok(found);
                    }
                    let end = offset + length;
                    if header.kind == RTM_NEWADDR
                        && length >= size_of::<Header>() + size_of::<IfAddr>()
                    {
                        let info = unsafe {
                            std::ptr::read_unaligned(
                                buffer[offset + size_of::<Header>()..]
                                    .as_ptr()
                                    .cast::<IfAddr>(),
                            )
                        };
                        let mut pos = offset + size_of::<Header>() + size_of::<IfAddr>();
                        while pos + size_of::<Attr>() <= end {
                            let item = unsafe {
                                std::ptr::read_unaligned(buffer[pos..].as_ptr().cast::<Attr>())
                            };
                            let item_len = item.len as usize;
                            let item_end = pos + item_len;
                            if item_len < size_of::<Attr>() || item_end > end {
                                break;
                            }
                            let attr_kind = item.kind & 0x3fff;
                            if info.family == libc::AF_INET as u8
                                && info.index == index
                                && (attr_kind == IFA_LOCAL || attr_kind == IFA_ADDRESS)
                                && item_len >= size_of::<Attr>() + 4
                                && buffer[pos + size_of::<Attr>()..pos + size_of::<Attr>() + 4]
                                    == vip.octets()
                            {
                                found = true;
                            }
                            pos += align(item.len as usize);
                        }
                    }
                    offset += align(length);
                }
            }
        })();
        unsafe { libc::close(fd) };
        result
    }
}

pub fn bind_vip_on_device(_cfg: &Config, vip: std::net::Ipv4Addr, dev: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::bind(dev, vip).with_context(|| format!("binding VIP {vip}/32 to {dev}"));
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dev, vip);
        anyhow::bail!("VIP address management requires Linux rtnetlink");
    }
}

pub fn release_vip_on_device(_cfg: &Config, vip: std::net::Ipv4Addr, dev: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !linux::bound(dev, vip)? {
            return Ok(());
        }
        linux::release(dev, vip).with_context(|| format!("releasing VIP {vip}/32 from {dev}"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dev, vip);
        anyhow::bail!("VIP address management requires Linux rtnetlink");
    }
}

pub fn vip_bound_on_device(_cfg: &Config, vip: std::net::Ipv4Addr, dev: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        linux::bound(dev, vip).unwrap_or(false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (dev, vip);
        false
    }
}
