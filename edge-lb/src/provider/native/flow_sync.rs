//! Native flow-table replication for HA.
//!
//! The MASTER gateway periodically dumps the pinned flow map, diffs it
//! against the last acknowledged replica state, and pushes new/updated
//! entries to the backup over the existing peer-token channel. The backup
//! upserts entries into its own pinned map; expiry stays lazy through the
//! datapath's existing `last_seen_ns` timeout check, so no deletion channel
//! is needed. Flows shorter than one sync interval are not replicated —
//! failover only ever guarantees new connections, so only long-lived flows
//! matter.

use std::{
    collections::HashMap,
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

use crate::{config::Config, linux::native_dnat, runtime::ha};

/// Wire payload for `/api/v1/ha/peer/native/flows/repl`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FlowReplRequest {
    pub from: String,
    pub entries: Vec<native_dnat::FlowEntry>,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FlowReplResponse {
    pub applied: usize,
}

/// Default replication interval; bounded below by one second.
const DEFAULT_INTERVAL_SECS: u64 = 3;

pub fn run_worker(cfg: Config) {
    let mut replica: HashMap<edge_lb_common::NativeFlowKey, u64> = HashMap::new();
    tracing::info!("[flow-sync] native flow replication worker started");
    loop {
        if crate::runtime::shutdown::requested() {
            tracing::info!("[flow-sync] shutdown requested");
            return;
        }
        let interval = match sync_once(&cfg, &mut replica) {
            Ok(interval) => interval,
            Err(e) => {
                tracing::debug!("[flow-sync] replication round skipped: {e:#}");
                Duration::from_secs(DEFAULT_INTERVAL_SECS)
            }
        };
        let deadline = Instant::now() + interval;
        while Instant::now() < deadline {
            if crate::runtime::shutdown::requested() {
                return;
            }
            sleep(Duration::from_millis(250).min(deadline - Instant::now()));
        }
    }
}

/// One replication round. Returns the interval to wait.
fn sync_once(
    cfg: &Config,
    replica: &mut HashMap<edge_lb_common::NativeFlowKey, u64>,
) -> Result<Duration> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    let interval = Duration::from_secs(cfg.ha.watch_interval_secs.max(1));
    if !ha_cfg.enabled {
        return Ok(interval.max(Duration::from_secs(DEFAULT_INTERVAL_SECS)));
    }
    let Some(peer) = ha_cfg.peers.first().cloned() else {
        return Ok(interval);
    };
    if !is_master(cfg) {
        // Only the active gateway owns forwarding state worth replicating.
        return Ok(interval);
    }
    let flows = native_dnat::dump_flows(cfg)?;
    let pending = entries_newer_than(&flows, replica);
    if pending.is_empty() {
        return Ok(interval);
    }
    let request = FlowReplRequest {
        from: cfg.node_name.clone(),
        entries: pending.clone(),
    };
    let response = crate::runtime::ha_write::post_peer_json(
        cfg,
        &peer,
        "/api/v1/ha/peer/native/flows/repl",
        &request,
    )?;
    if !(200..300).contains(&response.status) {
        return Err(anyhow::anyhow!(
            "peer {} flow replication failed with HTTP {}: {}",
            peer.name,
            response.status,
            response.body
        ));
    }
    let Ok(parsed) = serde_json::from_str::<FlowReplResponse>(&response.body) else {
        return Err(anyhow::anyhow!("peer flow replication response unreadable"));
    };
    let _ = parsed;
    for (key, value) in &pending {
        replica.insert(*key, value.last_seen_ns);
    }
    tracing::debug!(
        "[flow-sync] replicated {} flow entr{} to {}",
        pending.len(),
        if pending.len() == 1 { "y" } else { "ies" },
        peer.name
    );
    Ok(interval)
}

/// Entries that are new or fresher than the last acknowledged replica state.
fn entries_newer_than(
    flows: &[native_dnat::FlowEntry],
    replica: &HashMap<edge_lb_common::NativeFlowKey, u64>,
) -> Vec<native_dnat::FlowEntry> {
    flows
        .iter()
        .filter(|(key, value)| match replica.get(key) {
            None => true,
            Some(seen) => value.last_seen_ns > *seen,
        })
        .cloned()
        .collect()
}

fn is_master(cfg: &Config) -> bool {
    crate::provider::native::ha::state(cfg)
        .map(|state| state.state == "MASTER")
        .unwrap_or(false)
}

/// Persist replicated flows on the backup node.
pub fn apply_replicated(cfg: &Config, request: &FlowReplRequest) -> Result<usize> {
    if request.from.trim().is_empty() {
        anyhow::bail!("flow replication request is missing its source gateway");
    }
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    let peer = ha_cfg
        .peers
        .first()
        .context("flow replication peer is not configured")?;
    if request.from != peer.name {
        anyhow::bail!(
            "flow replication source {:?} does not match configured peer {:?}",
            request.from,
            peer.name
        );
    }
    let native_state = crate::provider::native::ha::state(cfg)?;
    if native_state.state != "BACKUP" {
        anyhow::bail!(
            "flow replication requires BACKUP state, local state is {}",
            native_state.state
        );
    }
    native_dnat::upsert_flows(cfg, &request.entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use edge_lb_common::{NativeFlowKey, NativeFlowValue};

    fn entry(src: u32, last_seen_ns: u64) -> native_dnat::FlowEntry {
        (
            NativeFlowKey {
                src,
                ..NativeFlowKey::default()
            },
            NativeFlowValue {
                last_seen_ns,
                ..NativeFlowValue::default()
            },
        )
    }

    #[test]
    fn only_new_and_fresher_entries_replicate() {
        let mut replica = HashMap::new();
        replica.insert(
            NativeFlowKey {
                src: 1,
                ..NativeFlowKey::default()
            },
            100,
        );
        replica.insert(
            NativeFlowKey {
                src: 2,
                ..NativeFlowKey::default()
            },
            200,
        );
        let flows = vec![entry(1, 100), entry(2, 300), entry(3, 50)];
        let pending = entries_newer_than(&flows, &replica);
        assert_eq!(pending.len(), 2);
        assert!(pending.iter().any(|(k, _)| k.src == 2));
        assert!(pending.iter().any(|(k, _)| k.src == 3));
    }

    #[test]
    fn wire_request_round_trips() {
        let request = FlowReplRequest {
            from: "gateway-a".to_string(),
            entries: vec![entry(9, 42)],
        };
        let text = serde_json::to_string(&request).unwrap();
        let parsed: FlowReplRequest = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.from, "gateway-a");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].0.src, 9);
        assert_eq!(parsed.entries[0].1.last_seen_ns, 42);
    }
}
