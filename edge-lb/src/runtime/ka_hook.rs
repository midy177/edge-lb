//! Local HA hook helpers.

use std::{io::Write, net::Ipv4Addr, os::unix::net::UnixStream, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{config::Config, linux::arp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KaHookEvent {
    pub instance: String,
    pub state: String,
    pub vip: String,
}

pub fn send(socket: &Path, instance: &str, state: &str, vip: &str) -> Result<()> {
    let event = KaHookEvent {
        instance: instance.to_string(),
        state: state.to_string(),
        vip: vip.to_string(),
    };
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connecting {}", socket.display()))?;
    let payload = serde_json::to_vec(&event).context("encoding HA hook event")?;
    stream
        .write_all(&payload)
        .context("writing HA hook event")?;
    stream.write_all(b"\n").context("terminating HA hook event")
}

pub fn announce_vip(
    cfg: &Config,
    vip: Ipv4Addr,
    vip_config: &crate::runtime::ha::VipConfig,
) -> Result<()> {
    let dev = vip_config
        .garp_device
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&cfg.network().underlay_dev);
    let garp = &vip_config.garp;
    arp::announce_gratuitous_ipv4(
        dev,
        vip,
        garp.count,
        std::time::Duration::from_millis(garp.interval_ms),
        std::time::Duration::from_millis(garp.repeat_after_ms),
        garp.repeat_count,
    )
    .with_context(|| format!("announcing VIP {vip} on {dev}"))
}
