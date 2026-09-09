use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use tokio::{runtime::Builder, sync::mpsc, time::timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::transport::Endpoint;

use crate::{
    config::{Config, GatewayNode},
    control::{
        pb::{DiscoveryRequest, NodeConflict, config_discovery_client::ConfigDiscoveryClient},
        snapshot,
    },
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const WATCH_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HA_SNAPSHOT_SETTLE: Duration = Duration::from_millis(500);
static DATAPATH_APPLY_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

struct AppliedSnapshot {
    version: String,
    conflicts: Vec<crate::linux::conflict::NodeConflict>,
}

impl AppliedSnapshot {
    fn conflicts_for(&self, version: &str) -> Option<&[crate::linux::conflict::NodeConflict]> {
        (self.version == version).then_some(self.conflicts.as_slice())
    }
}

pub fn run(cfg: &Config) -> Result<()> {
    crate::linux::privilege::require_root()?;
    let reconnect_interval_secs = cfg
        .backend
        .xds
        .as_ref()
        .map(|xds| xds.reconnect_interval_secs)
        .unwrap_or(cfg.ha.watch_interval_secs);
    tracing::info!(
        "[backend] active_source=xds; subscribing to gateway control plane ({}s reconnect interval)",
        reconnect_interval_secs
    );
    if cfg.gateway_nodes.is_empty() {
        bail!("no gateway control-plane endpoint is configured");
    }
    let endpoints = cfg
        .gateway_nodes
        .iter()
        .filter_map(|gw| gateway_control_addr(cfg, gw).ok())
        .collect::<Vec<_>>();
    tracing::info!("[backend] xDS subscription endpoints={:?}", endpoints);
    let return_path_guard = Arc::new(Mutex::new(None));
    let snapshots = Arc::new(Mutex::new(HashMap::new()));
    let last_applied = Arc::new(Mutex::new(None::<AppliedSnapshot>));
    let mut threads = Vec::new();
    for gw in &cfg.gateway_nodes {
        let endpoint = gateway_control_addr(cfg, gw)?;
        let cfg = cfg.clone();
        let guard = Arc::clone(&return_path_guard);
        let snapshots = Arc::clone(&snapshots);
        let last_applied = Arc::clone(&last_applied);
        let handle = thread::spawn(move || {
            subscribe_loop(
                &cfg,
                endpoint,
                guard,
                snapshots,
                last_applied,
                reconnect_interval_secs,
            );
        });
        threads.push(handle);
    }
    while !crate::runtime::shutdown::requested() {
        thread::sleep(Duration::from_millis(200));
    }
    for thread in threads {
        let _ = thread.join();
    }
    tracing::info!("[backend] xDS subscriber stopped");
    Ok(())
}

fn subscribe_loop(
    cfg: &Config,
    endpoint: String,
    return_path_guard: Arc<Mutex<Option<crate::linux::return_path::ManagedReturnPath>>>,
    snapshots: Arc<Mutex<HashMap<String, crate::control::pb::DiscoveryResponse>>>,
    last_applied: Arc<Mutex<Option<AppliedSnapshot>>>,
    reconnect_interval_secs: u64,
) {
    while !crate::runtime::shutdown::requested() {
        match subscribe_once(
            cfg,
            &endpoint,
            &return_path_guard,
            &snapshots,
            &last_applied,
        ) {
            Ok(()) => tracing::info!("[backend] xDS stream {} ended; reconnecting", endpoint),
            Err(e) => {
                tracing::warn!("[backend] xDS {} failed: {e:#}", endpoint);
                tracing::info!(
                    "[backend] keeping existing datapath and retrying {} after {}s",
                    endpoint,
                    reconnect_interval_secs
                );
            }
        }
        wait_for_reconnect_or_shutdown(Duration::from_secs(reconnect_interval_secs));
    }
}

fn wait_for_reconnect_or_shutdown(duration: Duration) {
    let deadline = std::time::Instant::now() + duration;
    while !crate::runtime::shutdown::requested() && std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        std::thread::sleep(remaining.min(Duration::from_millis(200)));
    }
}

fn cached_version(cfg: &Config) -> String {
    let _ = cfg;
    String::new()
}

fn subscribe_once(
    cfg: &Config,
    endpoint: &str,
    return_path_guard: &Arc<Mutex<Option<crate::linux::return_path::ManagedReturnPath>>>,
    snapshots: &Arc<Mutex<HashMap<String, crate::control::pb::DiscoveryResponse>>>,
    last_applied: &Arc<Mutex<Option<AppliedSnapshot>>>,
) -> Result<()> {
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building backend xDS runtime")?;
    rt.block_on(async move {
        subscribe_gateway(cfg, endpoint, return_path_guard, snapshots, last_applied).await
    })
}

fn gateway_control_addr(cfg: &Config, gw: &GatewayNode) -> Result<String> {
    let port = match cfg.control_plane.gateway_port {
        Some(port) => port,
        None => {
            let listen: SocketAddr = cfg.control_plane.listen.parse().with_context(|| {
                format!("bad control_plane.listen {}", cfg.control_plane.listen)
            })?;
            listen.port()
        }
    };
    Ok(format!("http://{}:{port}", gw.underlay_ip))
}

async fn subscribe_gateway(
    cfg: &Config,
    endpoint: &str,
    return_path_guard: &Arc<Mutex<Option<crate::linux::return_path::ManagedReturnPath>>>,
    snapshots: &Arc<Mutex<HashMap<String, crate::control::pb::DiscoveryResponse>>>,
    last_applied: &Arc<Mutex<Option<AppliedSnapshot>>>,
) -> Result<()> {
    tracing::info!(
        "[backend] xDS connecting endpoint={} node={} return_dev={} underlay_ip={}",
        endpoint,
        cfg.node_name,
        cfg.network().vxlan_dev,
        cfg.local_backend()
            .map(|backend| backend.underlay_ip.to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    );
    let channel = Endpoint::from_shared(endpoint.to_string())
        .with_context(|| format!("building xDS endpoint {endpoint}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("connecting {endpoint}"))?;
    let mut client = ConfigDiscoveryClient::new(channel);
    let (tx, rx) = mpsc::channel(4);
    let mut request = Request::new(ReceiverStream::new(rx));
    if let Some(token) = &cfg.control_plane.token {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {token}")
                .parse()
                .context("invalid control_plane.token metadata")?,
        );
    }
    let version = cached_version(cfg);
    tx.send(discovery_request(cfg, &version, "", true, Vec::new()))
        .await
        .context("sending initial discovery request")?;
    let mut stream = timeout(WATCH_TIMEOUT, client.watch(request))
        .await
        .context("starting xDS watch timed out")??
        .into_inner();
    loop {
        if crate::runtime::shutdown::requested() {
            tracing::info!("[backend] shutdown requested; closing xDS subscription");
            return Ok(());
        }
        let Some(resp) = (match timeout(STREAM_POLL_INTERVAL, stream.message()).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                let _ = tx
                    .send(discovery_request(cfg, "", "", true, Vec::new()))
                    .await;
                continue;
            }
        }) else {
            bail!("control-plane stream closed");
        };
        let version = resp.version.clone();
        let nonce = resp.nonce.clone();
        snapshot::log_recv(cfg, &resp);
        let apply_cfg = cfg.clone();
        let endpoint = endpoint.to_string();
        let snapshots = Arc::clone(snapshots);
        let last_applied = Arc::clone(last_applied);
        let return_path_guard = Arc::clone(return_path_guard);
        // Merge, version check, apply and commit share one serialization boundary.
        // Waiting for netlink must not block the subscription runtime.
        let result = tokio::task::spawn_blocking(move || {
            merge_snapshot(&snapshots, &endpoint, resp, apply_cfg.gateway_nodes.len())?;
            let _apply_guard = DATAPATH_APPLY_LOCK
                .lock()
                .map_err(|_| anyhow::anyhow!("backend datapath apply lock is poisoned"))?;
            let combined = {
                let latest = snapshots
                    .lock()
                    .map_err(|_| anyhow::anyhow!("snapshot store lock is poisoned"))?;
                snapshot::combine_gateway_responses(latest.values().cloned().collect())?
            };
            let combined_version = combined.version.clone();
            let mut applied = last_applied
                .lock()
                .map_err(|_| anyhow::anyhow!("applied version lock is poisoned"))?;
            if let Some(conflicts) = applied
                .as_ref()
                .and_then(|last| last.conflicts_for(&combined_version))
            {
                return Ok::<_, anyhow::Error>(conflicts.to_vec());
            }
            let conflicts = snapshot::backend_conflicts_for_response(&apply_cfg, &combined)?;
            let mut guard = return_path_guard
                .lock()
                .map_err(|_| anyhow::anyhow!("return path guard lock is poisoned"))?;
            *guard = Some(snapshot::apply_managed_reusing(
                &apply_cfg,
                combined,
                guard.take(),
            )?);
            *applied = Some(AppliedSnapshot {
                version: combined_version,
                conflicts: conflicts.clone(),
            });
            Ok(conflicts)
        })
        .await
        .context("backend snapshot task failed")?;
        match result {
            Ok(conflicts) => {
                let _ = tx
                    .send(discovery_request(cfg, &version, &nonce, true, conflicts))
                    .await;
            }
            Err(error) => {
                let _ = tx
                    .send(
                        discovery_request(cfg, &version, &nonce, false, Vec::new())
                            .with_error(format!("{error:#}")),
                    )
                    .await;
                return Err(error.context("snapshot rejected"));
            }
        }
    }
}

fn merge_snapshot(
    snapshots: &Arc<Mutex<HashMap<String, crate::control::pb::DiscoveryResponse>>>,
    endpoint: &str,
    resp: crate::control::pb::DiscoveryResponse,
    expected_gateways: usize,
) -> Result<crate::control::pb::DiscoveryResponse> {
    let mut guard = snapshots
        .lock()
        .map_err(|_| anyhow::anyhow!("snapshot store lock is poisoned"))?;
    guard.insert(endpoint_host(endpoint).to_string(), resp);
    let snapshot_count = guard.len();
    drop(guard);

    if expected_gateways > 1 && snapshot_count < expected_gateways {
        std::thread::sleep(HA_SNAPSHOT_SETTLE);
    }

    let guard = snapshots
        .lock()
        .map_err(|_| anyhow::anyhow!("snapshot store lock is poisoned"))?;
    snapshot::combine_gateway_responses(guard.values().cloned().collect())
}

fn endpoint_host(endpoint: &str) -> &str {
    endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint)
        .rsplit_once(':')
        .map(|(host, _)| host)
        .unwrap_or(endpoint)
}

trait DiscoveryRequestExt {
    fn with_error(self, detail: String) -> Self;
}

impl DiscoveryRequestExt for DiscoveryRequest {
    fn with_error(mut self, detail: String) -> Self {
        self.error_detail = detail;
        self
    }
}

fn discovery_request(
    cfg: &Config,
    version: &str,
    nonce: &str,
    ack: bool,
    conflicts: Vec<crate::linux::conflict::NodeConflict>,
) -> DiscoveryRequest {
    let underlay = cfg
        .local_backend()
        .map(|b| b.underlay_ip.to_string())
        .unwrap_or_default();
    DiscoveryRequest {
        node_name: cfg.node_name.clone(),
        node_role: "backend".to_string(),
        underlay_ip: underlay,
        version: version.to_string(),
        response_nonce: nonce.to_string(),
        ack,
        error_detail: String::new(),
        public_ip: cfg.public_ip.to_string(),
        public_ip_mode: cfg.file.runtime_discovery.public_ip.mode.clone(),
        public_ip_source: cfg.file.runtime_discovery.public_ip.source.clone(),
        underlay_ip_mode: cfg.file.runtime_discovery.underlay_ip.mode.clone(),
        underlay_ip_source: cfg.file.runtime_discovery.underlay_ip.source.clone(),
        conflicts: conflicts
            .into_iter()
            .map(|conflict| NodeConflict {
                severity: conflict.severity,
                kind: conflict.kind,
                subject: conflict.subject,
                detail: conflict.detail,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_snapshot_ack_preserves_last_conflict_observation() {
        let applied = AppliedSnapshot {
            version: "v1".to_string(),
            conflicts: vec![crate::linux::conflict::NodeConflict {
                severity: "warning".to_string(),
                kind: "route_table".to_string(),
                subject: "table 1104".to_string(),
                detail: "foreign route".to_string(),
            }],
        };
        let cfg = Config {
            path: Default::default(),
            file: Default::default(),
        };
        let ack = discovery_request(
            &cfg,
            "gateway-version",
            "new-nonce",
            true,
            applied.conflicts_for("v1").unwrap().to_vec(),
        );
        assert_eq!(ack.conflicts.len(), 1);
        assert_eq!(ack.conflicts[0].kind, "route_table");
        assert_eq!(ack.response_nonce, "new-nonce");
        assert!(applied.conflicts_for("v2").is_none());
    }

    #[test]
    fn clean_snapshot_observation_is_distinct_from_a_cache_miss() {
        let applied = AppliedSnapshot {
            version: "v2".to_string(),
            conflicts: Vec::new(),
        };
        assert_eq!(applied.conflicts_for("v2"), Some([].as_slice()));
        assert!(applied.conflicts_for("v1").is_none());
    }
}
