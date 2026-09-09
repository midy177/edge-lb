//! Independent, bounded latest-snapshot delivery. Retries survive daemon restart
//! because the pending cursor lives in the business configuration transaction.

use crate::{
    config::Config,
    runtime::{ha_write, shutdown},
    storage::proxy_replication::{self as store, Receipt},
};
use anyhow::{Context, Result, ensure};
use std::time::{Duration, Instant};

pub fn spawn(cfg: &Config) -> Result<()> {
    let cfg = cfg.clone();
    std::thread::Builder::new()
        .name("edge-lb-proxy-sync".into())
        .spawn(move || run(&cfg))
        .context("spawning proxy replication worker")?;
    Ok(())
}

fn run(cfg: &Config) {
    let mut last_baseline = None;
    let mut previous_error = None;
    while !shutdown::requested() {
        let result = sync_once(cfg, &mut last_baseline);
        match result {
            Ok(()) => {
                if previous_error.take().is_some() {
                    tracing::info!("[proxy-sync] replication recovered");
                }
            }
            Err(error) => {
                let error = format!("{error:#}");
                if previous_error.as_ref() != Some(&error) {
                    tracing::warn!("[proxy-sync] {error}");
                    previous_error = Some(error);
                }
            }
        }
        for _ in 0..30 {
            if shutdown::requested() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn sync_once(cfg: &Config, last_baseline: &mut Option<Instant>) -> Result<()> {
    let Some((peer, snapshot, pending)) = store::outgoing(cfg)? else {
        *last_baseline = None;
        return Ok(());
    };
    if !pending && last_baseline.is_some_and(|time| time.elapsed() < Duration::from_secs(30)) {
        return Ok(());
    }
    let result = (|| {
        let response = ha_write::post_peer_json(
            cfg,
            &peer,
            "/api/v1/ha/peer/proxy-config/replica",
            &snapshot,
        )?;
        ensure!(
            (200..300).contains(&response.status),
            "peer {} rejected proxy snapshot with HTTP {}",
            peer.name,
            response.status
        );
        let receipt: Receipt =
            serde_json::from_str(&response.body).context("decoding proxy replica receipt")?;
        ensure!(
            receipt.matches(&snapshot),
            "proxy replica receipt does not match sent snapshot"
        );
        Ok(())
    })();
    store::record_result(
        cfg,
        &snapshot,
        result
            .as_ref()
            .err()
            .map(|error: &anyhow::Error| format!("{error:#}")),
    )?;
    if result.is_ok() {
        *last_baseline = Some(Instant::now());
    }
    result
}
