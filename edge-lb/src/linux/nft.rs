//! Backend nftables ruleset generation and application.

use anyhow::{Context, Result};

use crate::config::Config;

use super::nftables;

/// Full ruleset for the agent-owned nft table. Runtime apply uses the
/// nf_tables netlink encoder; this string is kept as a readable debug snapshot.
///
/// Return-path steering is direction-based, not address-based: any packet in
/// the reply direction of a marked connection gets fwmark, no matter which
/// local application address produced it.
pub fn ruleset(cfg: &Config) -> String {
    let n = cfg.network();
    let b = cfg.backend_cfg();
    let mut forward_rules = String::new();
    for port in cfg.backend_return_ports() {
        let mark = port.mark.unwrap_or_else(|| fallback_mark(cfg, &port));
        forward_rules.push_str(&format!(
            "        ip dscp {dscp} {proto} dport {port} counter ct mark set {mark:#x}\n",
            dscp = return_dscp(cfg, &port),
            proto = port.protocol.as_str(),
            port = port.port,
            mark = mark,
        ));
    }
    let mut reply_rules = String::new();
    for mark in return_marks(cfg) {
        reply_rules.push_str(&format!(
            "        ct mark {mark:#x} ct direction reply counter meta mark set {mark:#x}\n",
        ));
    }
    format!(
        "table inet {t}\ndelete table inet {t}\n\ntable inet {t} {{\n\
         chain prerouting {{\n\
         type filter hook prerouting priority mangle; policy accept;\n\
         # Forward: gateway-marked service traffic sets a connection mark.\n{forward_rules}\
         # Reply: marked reply-direction packets get the routing fwmark.\n\
{reply_rules}\
         }}\n\
         chain output {{\n\
         type route hook output priority mangle; policy accept;\n\
         # Replies from host-native services.\n\
{reply_rules}\
         }}\n\
         chain forward {{\n\
         type filter hook forward priority mangle; policy accept;\n\
         oifname \"{vx}\" tcp flags & (fin | syn | rst | ack) == syn counter tcp option maxseg size set {mss}\n\
         }}\n\
        }}\n",
        t = b.nft_table,
        vx = n.vxlan_dev,
        mss = b.mss,
    )
}

fn return_marks(cfg: &Config) -> Vec<u32> {
    let mut marks = cfg
        .backend_return_ports()
        .into_iter()
        .map(|port| port.mark.unwrap_or_else(|| fallback_mark(cfg, &port)))
        .collect::<Vec<_>>();
    marks.sort_unstable();
    marks.dedup();
    marks
}

fn return_dscp(cfg: &Config, port: &crate::config::BackendReturnPort) -> u32 {
    port.dscp.unwrap_or(cfg.network().dscp)
}

fn fallback_mark(cfg: &Config, port: &crate::config::BackendReturnPort) -> u32 {
    let dscp = return_dscp(cfg, port);
    let gateway = port
        .gateway_underlay_ip
        .or_else(|| cfg.active_gateway().ok().map(|gw| gw.underlay_ip));
    let slot = gateway
        .map(|underlay| crate::config::gateway_slot(&cfg.gateway_nodes, underlay))
        .unwrap_or(0);
    crate::config::return_mark(dscp, slot)
}

pub fn apply(cfg: &Config) -> Result<()> {
    let dir = std::path::Path::new(&*cfg.state_dir);
    std::fs::create_dir_all(dir).with_context(|| format!("mkdir {}", dir.display()))?;
    let file = dir.join("backend-return.nft");
    std::fs::write(&file, ruleset(cfg)).with_context(|| format!("writing {}", file.display()))?;
    nftables::apply_return_path(cfg)
}

pub fn table_exists(cfg: &Config) -> bool {
    nftables::table_exists(cfg)
}

pub fn delete_table(cfg: &Config) {
    nftables::delete_table(cfg).ok();
}
