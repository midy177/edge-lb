//! Backend policy routing via rtnetlink.

use std::{
    ffi::CString,
    io,
    mem::size_of,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::RawFd,
};

use anyhow::{Context, Result, anyhow, bail};

use crate::config::{
    BackendConfig, Config, EDGE_CURRENT_MARK_BASE, EDGE_CURRENT_TABLE_BASE, EDGE_MARK_LIMIT,
    EDGE_TABLE_LIMIT, gateway_slot, return_mark, return_table_id,
};

const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_REPLACE: u16 = 0x100;

const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const RTM_GETROUTE: u16 = 26;
const RTM_NEWRULE: u16 = 32;
const RTM_DELRULE: u16 = 33;
const RTM_GETRULE: u16 = 34;

const RTN_UNICAST: u8 = 1;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_UNIVERSE: u8 = 0;
const RT_SCOPE_LINK: u8 = 253;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PREFSRC: u16 = 7;
const RTA_TABLE: u16 = 15;

const FR_ACT_TO_TBL: u8 = 1;
const FRA_PRIORITY: u16 = 6;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;

const EDGE_DSCP_LIMIT: u32 = 63;
const RULE_BAND: u32 = 64;

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FibRuleHdr {
    family: u8,
    dst_len: u8,
    src_len: u8,
    tos: u8,
    table: u8,
    res1: u8,
    res2: u8,
    action: u8,
    flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RtAttr {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct NlMsgErr {
    error: i32,
}

pub fn ensure_policy_routing(cfg: &Config) -> Result<()> {
    let b = cfg.backend_cfg();
    let local = cfg.local_backend()?;
    let vxlan_ifindex = ifindex(&cfg.network().vxlan_dev)?;
    let underlay_ifindex = ifindex(&cfg.network().underlay_dev)?;

    let routes = return_routes(cfg)?;
    let fd = socket()?;
    let result = reconcile_on_socket(
        fd,
        cfg,
        &routes,
        b,
        vxlan_ifindex,
        underlay_ifindex,
        local.underlay_ip,
    );
    unsafe {
        libc::close(fd);
    }
    result
}

pub fn policy_rule_present(cfg: &Config) -> bool {
    let Ok((mark, mask)) = parse_fwmark(&cfg.backend_cfg().fwmark) else {
        return false;
    };
    let Ok(fd) = socket() else {
        return false;
    };
    let present = dump_policy_rules_on_socket(fd).is_ok_and(|rules| {
        rules.iter().any(|rule| {
            rule.mark == Some(mark)
                && rule.mask == Some(mask)
                && rule.table == cfg.backend_cfg().route_table_id
        })
    });
    unsafe { libc::close(fd) };
    present
}

/// Human-readable snapshots for diagnostics and preflight checks. The data is
/// obtained from the same rtnetlink dumps used by reconciliation.
pub fn route_descriptions(cfg: &Config, table: u32) -> Result<Vec<String>> {
    let fd = socket()?;
    let result = dump_routes_in_table_on_socket(fd, table).map(|routes| {
        routes
            .iter()
            .map(|route| route.describe(&cfg.network().vxlan_dev, &cfg.network().underlay_dev))
            .collect()
    });
    unsafe { libc::close(fd) };
    result
}

pub fn policy_rule_descriptions() -> Result<Vec<String>> {
    let fd = socket()?;
    let result = dump_policy_rules_on_socket(fd).map(|rules| {
        rules
            .iter()
            .map(|rule| {
                let mark = rule
                    .mark
                    .map(|value| {
                        let mask = rule
                            .mask
                            .map(|mask| format!("/0x{mask:x}"))
                            .unwrap_or_default();
                        format!(" fwmark 0x{value:x}{mask}")
                    })
                    .unwrap_or_default();
                format!("{}: from all{} lookup {}", rule.priority, mark, rule.table)
            })
            .collect()
    });
    unsafe { libc::close(fd) };
    result
}

/// Dump-driven convergence: one RTM_GETRULE dump decides which rules are
/// ours and stale, one RTM_GETROUTE dump per table decides which routes are
/// ours and stale. Anything unexpected inside an edge-lb table is *deleted*
/// (self-heal), never bailed on.
#[allow(clippy::too_many_arguments)]
fn reconcile_on_socket(
    fd: RawFd,
    cfg: &Config,
    routes: &[ReturnRoute],
    b: &BackendConfig,
    vxlan_ifindex: u32,
    underlay_ifindex: u32,
    local_underlay: IpAddr,
) -> Result<()> {
    let rules = dump_policy_rules_on_socket(fd).context("dumping policy rules")?;
    let mut desired: Vec<(u32, u32)> = routes.iter().map(|r| (r.mark, r.table)).collect();
    desired.sort_unstable();
    desired.dedup();
    let mut stale_tables = Vec::new();

    for rule in &rules {
        if rule_is_stale_ours(rule, &desired) {
            if !stale_tables.contains(&rule.table) {
                stale_tables.push(rule.table);
            }
            delete_policy_rule_on_socket(fd, rule);
        }
    }

    if routes.is_empty() {
        for table in stale_tables {
            reconcile_table_on_socket(
                fd,
                table,
                &[],
                !(EDGE_CURRENT_TABLE_BASE..EDGE_TABLE_LIMIT).contains(&table),
                vxlan_ifindex,
                underlay_ifindex,
                local_underlay,
            )
            .with_context(|| format!("clearing return route table {table}"))?;
        }
        return Ok(());
    }

    for route in routes {
        reconcile_table_on_socket(
            fd,
            route.table,
            &expected_table_entries(cfg, route, vxlan_ifindex, underlay_ifindex, local_underlay),
            false,
            vxlan_ifindex,
            underlay_ifindex,
            local_underlay,
        )
        .with_context(|| format!("converging return route table {}", route.table))?;
    }

    for (idx, route) in routes.iter().enumerate() {
        // Rules for desired keys were kept by the sweep; only add missing ones.
        if rules
            .iter()
            .any(|r| r.mark == Some(route.mark) && r.table == route.table)
        {
            continue;
        }
        ensure_rule_at_or_after_on_socket(
            fd,
            b.rule_priority + idx as u32,
            route.mark,
            u32::MAX,
            route.table,
        )
        .with_context(|| format!("adding fwmark rule for {}", route.gateway_underlay))?;
    }
    Ok(())
}

pub fn cleanup_policy_routing(cfg: &Config) {
    let Ok(fd) = socket() else {
        return;
    };
    let result: Result<()> = (|| {
        let rules = dump_policy_rules_on_socket(fd)?;
        let mut tables: Vec<u32> = Vec::new();
        for rule in &rules {
            if rule_is_stale_ours(rule, &[]) {
                delete_policy_rule_on_socket(fd, rule);
            }
            if rule_is_ours_family(rule) && !tables.contains(&rule.table) {
                tables.push(rule.table);
            }
        }
        let vxlan_ifindex = ifindex(&cfg.network().vxlan_dev)?;
        let underlay_ifindex = ifindex(&cfg.network().underlay_dev)?;
        let local = cfg.local_backend()?;
        for table in tables {
            // Shape-guarded on teardown too: a user table (e.g. 100) may hold
            // foreign routes that must survive edge-lb removal.
            reconcile_table_on_socket(
                fd,
                table,
                &[],
                true,
                vxlan_ifindex,
                underlay_ifindex,
                local.underlay_ip,
            )
            .ok();
        }
        Ok(())
    })();
    if let Err(e) = result {
        tracing::warn!("[route] policy routing cleanup incomplete: {e:#}");
    }
    unsafe {
        libc::close(fd);
    }
}

/// A rule belongs to edge-lb if its mark or table falls in the derived
/// ranges.
fn rule_is_ours_family(rule: &PolicyRule) -> bool {
    if rule
        .mark
        .is_some_and(|m| (EDGE_CURRENT_MARK_BASE..EDGE_MARK_LIMIT).contains(&m))
    {
        return true;
    }
    if (EDGE_CURRENT_TABLE_BASE..EDGE_TABLE_LIMIT).contains(&rule.table) {
        return true;
    }
    false
}

fn rule_is_stale_ours(rule: &PolicyRule, desired: &[(u32, u32)]) -> bool {
    if !rule_is_ours_family(rule) {
        return false;
    }
    let key = (rule.mark.unwrap_or(0), rule.table);
    if desired.contains(&key) {
        return false;
    }
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReturnRoute {
    gateway_underlay: IpAddr,
    gateway_overlay: IpAddr,
    mark: u32,
    table: u32,
}

fn return_routes(cfg: &Config) -> Result<Vec<ReturnRoute>> {
    let mut routes = Vec::new();
    let fallback_gateway = cfg.active_gateway().ok();
    let fallback_gateway_overlay = cfg.gateway_overlay_ip().ok();
    for port in cfg.backend_return_ports() {
        let dscp = port.dscp.unwrap_or(cfg.network().dscp);
        if dscp > EDGE_DSCP_LIMIT {
            bail!(
                "backend return port {} has dscp {dscp} outside 0..=63; \
                 the nft match would silently degrade",
                port.port
            );
        }
        let gateway_underlay = port
            .gateway_underlay_ip
            .or_else(|| fallback_gateway.as_ref().map(|gateway| gateway.underlay_ip));
        let gateway_overlay = port.gateway_overlay_ip.or(fallback_gateway_overlay);
        let (Some(gateway_underlay), Some(gateway_overlay)) = (gateway_underlay, gateway_overlay)
        else {
            continue;
        };
        let slot = gateway_slot(&cfg.gateway_nodes, gateway_underlay);
        let mark = port.mark.unwrap_or_else(|| return_mark(dscp, slot));
        let table = port
            .route_table_id
            .unwrap_or_else(|| return_table_id(dscp, slot));
        routes.push(ReturnRoute {
            gateway_underlay,
            gateway_overlay,
            mark,
            table,
        });
    }
    routes.sort_by_key(|route| {
        (
            ip_sort_key(route.gateway_underlay),
            ip_sort_key(route.gateway_overlay),
            route.mark,
            route.table,
        )
    });
    routes.dedup();
    Ok(routes)
}

fn ip_sort_key(ip: IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(ip) => (4, u32::from_be_bytes(ip.octets()) as u128),
        IpAddr::V6(ip) => (6, u128::from(ip)),
    }
}

/// Entries a converged return table must hold: one default via the owning
/// gateway's overlay plus a host route per gateway underlay (so VXLAN outer
/// packets never recurse into the tunnel).
fn expected_table_entries(
    cfg: &Config,
    route: &ReturnRoute,
    vxlan_ifindex: u32,
    underlay_ifindex: u32,
    local_underlay: IpAddr,
) -> Vec<RouteEntry> {
    let mut entries = vec![default_entry(
        route.table,
        route.gateway_overlay,
        vxlan_ifindex,
    )];
    for gw in &cfg.gateway_nodes {
        entries.push(host_entry(
            route.table,
            gw.underlay_ip,
            underlay_ifindex,
            local_underlay,
        ));
    }
    entries
}

fn default_entry(table: u32, gateway_overlay: IpAddr, oif: u32) -> RouteEntry {
    RouteEntry {
        family: family(gateway_overlay),
        table,
        dst_len: 0,
        dst: None,
        gateway: Some(gateway_overlay),
        oif: Some(oif),
        prefsrc: None,
    }
}

fn host_entry(table: u32, dst: IpAddr, oif: u32, preferred_src: IpAddr) -> RouteEntry {
    RouteEntry {
        family: family(dst),
        table,
        dst_len: prefix_len(dst),
        dst: Some(dst),
        gateway: None,
        oif: Some(oif),
        prefsrc: Some(preferred_src),
    }
}

/// Converge one table toward `expected`.
///
/// Current derived tables are wholly owned by edge-lb:
/// anything not expected is deleted — this is what heals stale routes after
/// a failover, gateway re-IP or local underlay change. Other tables are only
/// touched where an entry matches the edge-lb route *shape*
/// (`shape_guard = true`).
#[allow(clippy::too_many_arguments)]
fn reconcile_table_on_socket(
    fd: RawFd,
    table: u32,
    expected: &[RouteEntry],
    shape_guard: bool,
    vxlan_ifindex: u32,
    underlay_ifindex: u32,
    local_underlay: IpAddr,
) -> Result<()> {
    let current = dump_routes_in_table_on_socket(fd, table)?;
    let fully_owned = !shape_guard && (EDGE_CURRENT_TABLE_BASE..EDGE_TABLE_LIMIT).contains(&table);
    for entry in &current {
        let stale = if expected.contains(entry) {
            false
        } else if fully_owned {
            true
        } else {
            entry_is_ours_by_shape(entry, vxlan_ifindex, underlay_ifindex, local_underlay)
        };
        if stale && let Err(error) = delete_route_entry_on_socket(fd, entry) {
            if is_absent_route_error(&error) {
                tracing::debug!(
                    "stale route {} from table {table} already absent",
                    entry.describe("", "")
                );
            } else {
                return Err(error).with_context(|| {
                    format!(
                        "deleting stale route {} from table {table}",
                        entry.describe("", "")
                    )
                });
            }
        }
    }
    for want in expected {
        if !current.contains(want) {
            add_route_replace_on_socket(fd, want).with_context(|| {
                format!(
                    "installing route {} in table {table}",
                    want.describe("", "")
                )
            })?;
        }
    }
    Ok(())
}

/// Shape of routes edge-lb creates: a default via the VXLAN device, or a
/// host route to a gateway underlay via the underlay device with the local
/// underlay as preferred source.
fn entry_is_ours_by_shape(
    entry: &RouteEntry,
    vxlan_ifindex: u32,
    underlay_ifindex: u32,
    local_underlay: IpAddr,
) -> bool {
    (entry.dst_len == 0 && entry.dst.is_none() && entry.oif == Some(vxlan_ifindex))
        || (entry.oif == Some(underlay_ifindex)
            && entry.dst_len == prefix_len(entry.dst.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)))
            && entry.prefsrc == Some(local_underlay))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RouteEntry {
    family: u8,
    table: u32,
    dst_len: u8,
    dst: Option<IpAddr>,
    gateway: Option<IpAddr>,
    oif: Option<u32>,
    prefsrc: Option<IpAddr>,
}

impl RouteEntry {
    fn describe(&self, vxlan_dev: &str, underlay_dev: &str) -> String {
        let dst = self
            .dst
            .map(|ip| format!("{ip}/{}", self.dst_len))
            .unwrap_or_else(|| "default".to_string());
        let gateway = self
            .gateway
            .map(|ip| format!(" via {ip}"))
            .unwrap_or_default();
        let oif = self.oif.map(|index| {
            let dev = if Some(index) == ifindex(vxlan_dev).ok() {
                vxlan_dev
            } else if Some(index) == ifindex(underlay_dev).ok() {
                underlay_dev
            } else {
                "ifindex"
            };
            format!(" dev {dev}({index})")
        });
        let prefsrc = self
            .prefsrc
            .map(|ip| format!(" src {ip}"))
            .unwrap_or_default();
        format!(
            "{dst}{gateway}{}{} table {}",
            oif.unwrap_or_default(),
            prefsrc,
            self.table
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicyRule {
    priority: u32,
    mark: Option<u32>,
    mask: Option<u32>,
    table: u32,
}

fn ensure_rule_at_or_after_on_socket(
    fd: RawFd,
    start: u32,
    mark: u32,
    mask: u32,
    table: u32,
) -> Result<()> {
    let mut priority = start;
    for _ in 0..RULE_BAND {
        match send_ack_on_socket(
            fd,
            RTM_NEWRULE,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            rule_body(mark, mask, priority, table),
        ) {
            Ok(()) => return Ok(()),
            Err(e) if is_errno(&e, libc::EEXIST) => priority += 1,
            Err(e) => return Err(e),
        }
    }
    bail!("no free policy-rule priority within {RULE_BAND} slots after {start}");
}

fn delete_policy_rule_on_socket(fd: RawFd, rule: &PolicyRule) {
    let mut body = bytes_of(&FibRuleHdr {
        family: libc::AF_INET as u8,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: table_field(rule.table),
        res1: 0,
        res2: 0,
        action: FR_ACT_TO_TBL,
        flags: 0,
    });
    push_attr_u32(&mut body, FRA_PRIORITY, rule.priority);
    push_attr_u32(&mut body, FRA_TABLE, rule.table);
    if let Some(mark) = rule.mark {
        push_attr_u32(&mut body, FRA_FWMARK, mark);
    }
    if let Some(mask) = rule.mask {
        push_attr_u32(&mut body, FRA_FWMASK, mask);
    }
    let _ = send_ack_on_socket(fd, RTM_DELRULE, NLM_F_REQUEST | NLM_F_ACK, body);
}

fn rule_body(mark: u32, mask: u32, priority: u32, table: u32) -> Vec<u8> {
    let mut body = bytes_of(&FibRuleHdr {
        family: libc::AF_INET as u8,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: table_field(table),
        res1: 0,
        res2: 0,
        action: FR_ACT_TO_TBL,
        flags: 0,
    });
    push_attr_u32(&mut body, FRA_PRIORITY, priority);
    push_attr_u32(&mut body, FRA_FWMARK, mark);
    push_attr_u32(&mut body, FRA_FWMASK, mask);
    push_attr_u32(&mut body, FRA_TABLE, table);
    body
}

fn add_route_replace_on_socket(fd: RawFd, entry: &RouteEntry) -> Result<()> {
    let scope = if entry.dst_len == 0 {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    let mut body = route_body(entry.table, entry.family, entry.dst_len, scope);
    if let Some(dst) = entry.dst {
        push_attr_ip(&mut body, RTA_DST, dst);
    }
    if let Some(oif) = entry.oif {
        push_attr_u32(&mut body, RTA_OIF, oif);
    }
    if let Some(gateway) = entry.gateway {
        push_attr_ip(&mut body, RTA_GATEWAY, gateway);
    }
    if let Some(prefsrc) = entry.prefsrc {
        push_attr_ip(&mut body, RTA_PREFSRC, prefsrc);
    }
    push_attr_u32(&mut body, RTA_TABLE, entry.table);
    // CREATE|REPLACE keeps the write atomic: a converged route is never
    // briefly removed, and a failure leaves the previous route in place.
    send_ack_on_socket(
        fd,
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        body,
    )
}

fn delete_route_entry_on_socket(fd: RawFd, entry: &RouteEntry) -> Result<()> {
    let scope = if entry.dst_len == 0 {
        RT_SCOPE_UNIVERSE
    } else {
        RT_SCOPE_LINK
    };
    let mut body = route_body(entry.table, entry.family, entry.dst_len, scope);
    if let Some(dst) = entry.dst {
        push_attr_ip(&mut body, RTA_DST, dst);
    }
    if let Some(oif) = entry.oif {
        push_attr_u32(&mut body, RTA_OIF, oif);
    }
    if let Some(gateway) = entry.gateway {
        push_attr_ip(&mut body, RTA_GATEWAY, gateway);
    }
    if let Some(prefsrc) = entry.prefsrc {
        push_attr_ip(&mut body, RTA_PREFSRC, prefsrc);
    }
    push_attr_u32(&mut body, RTA_TABLE, entry.table);
    send_ack_on_socket(fd, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, body)
}

fn dump_policy_rules_on_socket(fd: RawFd) -> Result<Vec<PolicyRule>> {
    let seq = 1;
    let body = bytes_of(&FibRuleHdr {
        family: libc::AF_UNSPEC as u8,
        dst_len: 0,
        src_len: 0,
        tos: 0,
        table: 0,
        res1: 0,
        res2: 0,
        action: FR_ACT_TO_TBL,
        flags: 0,
    });
    send_netlink_on_socket(fd, RTM_GETRULE, NLM_F_REQUEST | NLM_F_DUMP, body, seq)?;
    read_rule_dump(fd, seq)
}

fn read_rule_dump(fd: RawFd, seq: u32) -> Result<Vec<PolicyRule>> {
    let mut rules = Vec::new();
    let mut buf = vec![0u8; 32768];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("reading rtnetlink rule dump");
        }
        let mut offset = 0usize;
        let n = n as usize;
        while offset + size_of::<NlMsghdr>() <= n {
            let hdr = read_struct::<NlMsghdr>(&buf[offset..])?;
            if (hdr.nlmsg_len as usize) < size_of::<NlMsghdr>()
                || offset + hdr.nlmsg_len as usize > n
            {
                bail!("short rtnetlink rule dump");
            }
            if hdr.nlmsg_seq != seq {
                offset += align(hdr.nlmsg_len as usize);
                continue;
            }
            let start = offset + size_of::<NlMsghdr>();
            let end = offset + hdr.nlmsg_len as usize;
            match hdr.nlmsg_type {
                NLMSG_DONE => return Ok(rules),
                NLMSG_ERROR => {
                    let err = read_struct::<NlMsgErr>(&buf[start..])?.error;
                    if err == 0 {
                        return Ok(rules);
                    }
                    return Err(io::Error::from_raw_os_error(-err))
                        .context("rtnetlink rule dump failed");
                }
                RTM_NEWRULE => {
                    if let Some(rule) = parse_policy_rule(&buf[start..end]) {
                        rules.push(rule);
                    }
                }
                _ => {}
            }
            offset += align(hdr.nlmsg_len as usize);
        }
    }
}

fn parse_policy_rule(data: &[u8]) -> Option<PolicyRule> {
    if data.len() < size_of::<FibRuleHdr>() {
        return None;
    }
    let msg = read_struct::<FibRuleHdr>(data).ok()?;
    if msg.action != FR_ACT_TO_TBL || msg.family != libc::AF_INET as u8 {
        return None;
    }
    let mut rule = PolicyRule {
        priority: 0,
        mark: None,
        mask: None,
        table: msg.table as u32,
    };
    let mut offset = align(size_of::<FibRuleHdr>());
    while offset + size_of::<RtAttr>() <= data.len() {
        let Ok(attr) = read_struct::<RtAttr>(&data[offset..]) else {
            return None;
        };
        let len = attr.rta_len as usize;
        if len < size_of::<RtAttr>() || offset + len > data.len() {
            return None;
        }
        let payload = &data[offset + size_of::<RtAttr>()..offset + len];
        match attr.rta_type {
            FRA_PRIORITY => rule.priority = parse_u32_attr(payload)?,
            FRA_FWMARK => rule.mark = parse_u32_attr(payload),
            FRA_FWMASK => rule.mask = parse_u32_attr(payload),
            FRA_TABLE => {
                if let Some(table) = parse_u32_attr(payload) {
                    rule.table = table;
                }
            }
            _ => {}
        }
        offset += align(len);
    }
    Some(rule)
}

fn dump_routes_in_table_on_socket(fd: RawFd, table: u32) -> Result<Vec<RouteEntry>> {
    let seq = 1;
    let mut body = bytes_of(&RtMsg {
        rtm_family: libc::AF_UNSPEC as u8,
        rtm_dst_len: 0,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: table_field(table),
        rtm_protocol: 0,
        rtm_scope: 0,
        rtm_type: 0,
        rtm_flags: 0,
    });
    push_attr_u32(&mut body, RTA_TABLE, table);
    send_netlink_on_socket(fd, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, body, seq)?;
    read_route_dump(fd, seq, table)
}

fn route_body(table: u32, family: u8, dst_len: u8, scope: u8) -> Vec<u8> {
    bytes_of(&RtMsg {
        rtm_family: family,
        rtm_dst_len: dst_len,
        rtm_src_len: 0,
        rtm_tos: 0,
        rtm_table: table_field(table),
        rtm_protocol: RTPROT_STATIC,
        rtm_scope: scope,
        rtm_type: RTN_UNICAST,
        rtm_flags: 0,
    })
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
        return Err(io::Error::last_os_error()).context("opening rtnetlink socket");
    }
    let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    addr.nl_pid = 0;
    addr.nl_groups = 0;
    let rc = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        let err = io::Error::last_os_error();
        unsafe {
            libc::close(fd);
        }
        return Err(err).context("binding rtnetlink socket");
    }
    Ok(fd)
}

fn send_ack_on_socket(fd: RawFd, kind: u16, flags: u16, body: Vec<u8>) -> Result<()> {
    let seq = 1;
    send_netlink_on_socket(fd, kind, flags, body, seq)?;
    read_ack(fd, seq)
}

fn send_netlink_on_socket(fd: RawFd, kind: u16, flags: u16, body: Vec<u8>, seq: u32) -> Result<()> {
    let mut msg = bytes_of(&NlMsghdr {
        nlmsg_len: (size_of::<NlMsghdr>() + body.len()) as u32,
        nlmsg_type: kind,
        nlmsg_flags: flags,
        nlmsg_seq: seq,
        nlmsg_pid: 0,
    });
    msg.extend_from_slice(&body);

    let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    kernel.nl_pid = 0;
    kernel.nl_groups = 0;
    let sent = unsafe {
        libc::sendto(
            fd,
            msg.as_ptr().cast(),
            msg.len(),
            0,
            (&kernel as *const libc::sockaddr_nl).cast::<libc::sockaddr>(),
            size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error()).context("sending rtnetlink request");
    }
    Ok(())
}

fn read_ack(fd: RawFd, seq: u32) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("reading rtnetlink ack");
        }
        let mut offset = 0usize;
        let n = n as usize;
        while offset + size_of::<NlMsghdr>() <= n {
            let hdr = read_struct::<NlMsghdr>(&buf[offset..])?;
            if hdr.nlmsg_len as usize <= size_of::<NlMsghdr>()
                || offset + hdr.nlmsg_len as usize > n
            {
                bail!("short rtnetlink ack");
            }
            if hdr.nlmsg_seq == seq && hdr.nlmsg_type == NLMSG_ERROR {
                let start = offset + size_of::<NlMsghdr>();
                let err = read_struct::<NlMsgErr>(&buf[start..])?.error;
                if err == 0 {
                    return Ok(());
                }
                return Err(io::Error::from_raw_os_error(-err)).context("rtnetlink request failed");
            }
            offset += align(hdr.nlmsg_len as usize);
        }
    }
}

fn read_route_dump(fd: RawFd, seq: u32, table: u32) -> Result<Vec<RouteEntry>> {
    let mut routes = Vec::new();
    let mut buf = vec![0u8; 32768];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error()).context("reading rtnetlink route dump");
        }
        let mut offset = 0usize;
        let n = n as usize;
        while offset + size_of::<NlMsghdr>() <= n {
            let hdr = read_struct::<NlMsghdr>(&buf[offset..])?;
            if (hdr.nlmsg_len as usize) < size_of::<NlMsghdr>()
                || offset + hdr.nlmsg_len as usize > n
            {
                bail!("short rtnetlink route dump");
            }
            if hdr.nlmsg_seq != seq {
                offset += align(hdr.nlmsg_len as usize);
                continue;
            }
            let start = offset + size_of::<NlMsghdr>();
            let end = offset + hdr.nlmsg_len as usize;
            match hdr.nlmsg_type {
                NLMSG_DONE => return Ok(routes),
                NLMSG_ERROR => {
                    let err = read_struct::<NlMsgErr>(&buf[start..])?.error;
                    if err == 0 {
                        return Ok(routes);
                    }
                    return Err(io::Error::from_raw_os_error(-err))
                        .context("rtnetlink route dump failed");
                }
                RTM_NEWROUTE => {
                    let route = parse_route_entry(&buf[start..end])?;
                    if route.table == table {
                        routes.push(route);
                    }
                }
                _ => {}
            }
            offset += align(hdr.nlmsg_len as usize);
        }
    }
}

fn parse_route_entry(data: &[u8]) -> Result<RouteEntry> {
    if data.len() < size_of::<RtMsg>() {
        bail!("short rtnetlink route entry");
    }
    let msg = read_struct::<RtMsg>(data)?;
    let mut route = RouteEntry {
        family: msg.rtm_family,
        table: msg.rtm_table as u32,
        dst_len: msg.rtm_dst_len,
        dst: None,
        gateway: None,
        oif: None,
        prefsrc: None,
    };
    let mut offset = align(size_of::<RtMsg>());
    while offset + size_of::<RtAttr>() <= data.len() {
        let attr = read_struct::<RtAttr>(&data[offset..])?;
        let len = attr.rta_len as usize;
        if len < size_of::<RtAttr>() || offset + len > data.len() {
            bail!("short rtnetlink route attribute");
        }
        let payload_start = offset + size_of::<RtAttr>();
        let payload = &data[payload_start..offset + len];
        match attr.rta_type {
            RTA_DST => route.dst = parse_ip_attr(route.family, payload),
            RTA_GATEWAY => route.gateway = parse_ip_attr(route.family, payload),
            RTA_PREFSRC => route.prefsrc = parse_ip_attr(route.family, payload),
            RTA_OIF => route.oif = parse_u32_attr(payload),
            RTA_TABLE => {
                if let Some(table) = parse_u32_attr(payload) {
                    route.table = table;
                }
            }
            _ => {}
        }
        offset += align(len);
    }
    Ok(route)
}

fn parse_ip_attr(family: u8, payload: &[u8]) -> Option<IpAddr> {
    match family as i32 {
        libc::AF_INET if payload.len() >= 4 => Some(IpAddr::V4(Ipv4Addr::new(
            payload[0], payload[1], payload[2], payload[3],
        ))),
        libc::AF_INET6 if payload.len() >= 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[..16]);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn parse_u32_attr(payload: &[u8]) -> Option<u32> {
    let bytes = payload.get(..4)?;
    Some(u32::from_ne_bytes(bytes.try_into().ok()?))
}

fn ifindex(dev: &str) -> Result<u32> {
    let dev = CString::new(dev).context("interface name contains NUL")?;
    let index = unsafe { libc::if_nametoindex(dev.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error()).context("resolving interface ifindex");
    }
    Ok(index)
}

fn parse_fwmark(value: &str) -> Result<(u32, u32)> {
    let (mark, mask) = value
        .split_once('/')
        .ok_or_else(|| anyhow!("fwmark must look like 0x1/0xff, got {value}"))?;
    Ok((parse_u32(mark)?, parse_u32(mask)?))
}

fn parse_u32(value: &str) -> Result<u32> {
    let value = value.trim();
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).with_context(|| format!("parsing {value}"))
    } else {
        value
            .parse::<u32>()
            .with_context(|| format!("parsing {value}"))
    }
}

fn table_field(table: u32) -> u8 {
    u8::try_from(table).unwrap_or(0)
}

fn family(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => libc::AF_INET as u8,
        IpAddr::V6(_) => libc::AF_INET6 as u8,
    }
}

fn prefix_len(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn push_attr_u32(buf: &mut Vec<u8>, kind: u16, value: u32) {
    push_attr(buf, kind, &value.to_ne_bytes());
}

fn push_attr_ip(buf: &mut Vec<u8>, kind: u16, value: IpAddr) {
    match value {
        IpAddr::V4(ip) => push_attr(buf, kind, &ipv4_bytes(ip)),
        IpAddr::V6(ip) => push_attr(buf, kind, &ipv6_bytes(ip)),
    }
}

fn ipv4_bytes(ip: Ipv4Addr) -> [u8; 4] {
    ip.octets()
}

fn ipv6_bytes(ip: Ipv6Addr) -> [u8; 16] {
    ip.octets()
}

fn push_attr(buf: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = size_of::<RtAttr>() + payload.len();
    buf.extend_from_slice(&bytes_of(&RtAttr {
        rta_len: len as u16,
        rta_type: kind,
    }));
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn bytes_of<T: Copy>(value: &T) -> Vec<u8> {
    unsafe { std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>()).to_vec() }
}

fn read_struct<T: Copy>(bytes: &[u8]) -> Result<T> {
    if bytes.len() < size_of::<T>() {
        bail!("short rtnetlink message");
    }
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            out.as_mut_ptr().cast::<u8>(),
            size_of::<T>(),
        );
        Ok(out.assume_init())
    }
}

fn align(len: usize) -> usize {
    let align = 4;
    (len + align - 1) & !(align - 1)
}

fn is_errno(err: &anyhow::Error, code: i32) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
            == Some(code)
    })
}

fn is_absent_route_error(err: &anyhow::Error) -> bool {
    is_errno(err, libc::ESRCH) || is_errno(err, libc::ENOENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_fwmark_and_mask() {
        assert_eq!(parse_fwmark("0x1/0xff").unwrap(), (1, 255));
    }

    #[test]
    fn parses_decimal_fwmark_and_mask() {
        assert_eq!(parse_fwmark("1/255").unwrap(), (1, 255));
    }

    fn v4(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn shape_predicate_recognizes_only_edge_lb_routes() {
        let local = v4("192.168.0.14");
        assert!(entry_is_ours_by_shape(
            &default_entry(1064, v4("10.255.16.1"), 11),
            11,
            2,
            local
        ));
        assert!(entry_is_ours_by_shape(
            &host_entry(1064, v4("192.168.0.12"), 2, local),
            11,
            2,
            local
        ));
        // A default route on the underlay device is not edge-lb-owned.
        assert!(!entry_is_ours_by_shape(
            &RouteEntry {
                family: libc::AF_INET as u8,
                table: 100,
                dst_len: 0,
                dst: None,
                gateway: Some(v4("192.168.0.1")),
                oif: Some(2),
                prefsrc: None,
            },
            11,
            2,
            local
        ));
        // A stale default route on the VXLAN device is still edge-lb-owned.
        assert!(entry_is_ours_by_shape(
            &RouteEntry {
                family: libc::AF_INET as u8,
                table: 1064,
                dst_len: 0,
                dst: None,
                gateway: Some(v4("10.255.20.1")),
                oif: Some(11),
                prefsrc: None,
            },
            11,
            2,
            local
        ));
    }

    #[test]
    fn stale_rule_detection_only_touches_edge_lb_ranges() {
        let current_mark = return_mark(46, 0);
        let current_table = return_table_id(46, 0);
        let stale_peer_mark = return_mark(46, 1);
        let stale_peer_table = return_table_id(46, 1);
        let gw_rule = |mark: u32, table: u32| PolicyRule {
            priority: 100,
            mark: Some(mark),
            mask: Some(u32::MAX),
            table,
        };
        // Keep the desired gateway-slotted rule.
        assert!(!rule_is_stale_ours(
            &gw_rule(current_mark, current_table),
            &[(current_mark, current_table)]
        ));
        // Remove an edge-lb rule that belongs to another no-longer-desired slot.
        assert!(rule_is_stale_ours(
            &gw_rule(stale_peer_mark, stale_peer_table),
            &[(current_mark, current_table)]
        ));
        assert!(rule_is_stale_ours(
            &gw_rule(stale_peer_mark, stale_peer_table),
            &[]
        ));
        // Foreign rules are never touched.
        assert!(!rule_is_stale_ours(
            &PolicyRule {
                priority: 100,
                mark: Some(0x4000),
                mask: Some(u32::MAX),
                table: 500
            },
            &[]
        ));
        assert!(!rule_is_stale_ours(
            &PolicyRule {
                priority: 100,
                mark: None,
                mask: None,
                table: 500
            },
            &[]
        ));
    }

    #[test]
    fn parses_route_entry_extended_table_attr() {
        let mut body = route_body(1001, libc::AF_INET as u8, 32, RT_SCOPE_LINK);
        push_attr_ip(&mut body, RTA_DST, "192.168.0.12".parse().unwrap());
        push_attr_u32(&mut body, RTA_OIF, 2);
        push_attr_ip(&mut body, RTA_PREFSRC, "192.168.0.14".parse().unwrap());
        push_attr_u32(&mut body, RTA_TABLE, 1001);

        let route = parse_route_entry(&body).unwrap();
        assert_eq!(route.table, 1001);
        assert_eq!(route.dst, Some("192.168.0.12".parse().unwrap()));
        assert_eq!(route.oif, Some(2));
        assert_eq!(route.prefsrc, Some("192.168.0.14".parse().unwrap()));
    }
}
