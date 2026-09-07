//! Native persistent connection-state replication channel.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use tokio::{sync::mpsc, time::timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, transport::Endpoint};

use crate::{
    config::Config,
    control::pb::{self, flow_sync_client::FlowSyncClient},
    linux::native_dnat,
    runtime::{ha, shutdown},
};

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(25);
const RECONCILE_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, serde::Serialize)]
pub struct XsyncStatus {
    pub state: String,
    pub peer: Option<String>,
    pub last_error: Option<String>,
    pub last_ack_applied: usize,
}

static STATUS: OnceLock<Mutex<XsyncStatus>> = OnceLock::new();

fn status() -> &'static Mutex<XsyncStatus> {
    STATUS.get_or_init(|| {
        Mutex::new(XsyncStatus {
            state: "disabled".to_string(),
            peer: None,
            last_error: None,
            last_ack_applied: 0,
        })
    })
}

pub fn snapshot() -> XsyncStatus {
    status()
        .lock()
        .expect("xsync status mutex poisoned")
        .clone()
}

/// gRPC implementation of the gateway-to-gateway xSync stream.
pub async fn replicate(
    cfg: &Config,
    request: Request<tonic::Streaming<pb::FlowSyncRequest>>,
) -> std::result::Result<
    Response<ReceiverStream<std::result::Result<pb::FlowSyncResponse, Status>>>,
    Status,
> {
    let remote = request.remote_addr();
    let mut inbound = request.into_inner();
    let first = inbound
        .message()
        .await
        .map_err(|e| Status::internal(e.to_string()))?
        .ok_or_else(|| Status::invalid_argument("missing flow sync request"))?;
    authorize_proto_request(cfg, remote, &first)
        .map_err(|e| Status::permission_denied(e.to_string()))?;
    let (tx, rx) = mpsc::channel(4);
    let cfg = cfg.clone();
    tokio::spawn(async move {
        let mut current = Some(first);
        loop {
            let request = match current.take() {
                Some(request) => request,
                None => match inbound.message().await {
                    Ok(Some(request)) => request,
                    Ok(None) | Err(_) => break,
                },
            };
            if let Err(error) = authorize_proto_request(&cfg, remote, &request) {
                let _ = tx
                    .send(Err(Status::permission_denied(error.to_string())))
                    .await;
                break;
            }
            let applied = match apply_proto_request(&cfg, &request) {
                Ok(value) => value,
                Err(error) => {
                    let _ = tx.send(Err(Status::internal(error.to_string()))).await;
                    break;
                }
            };
            set_ack(applied);
            if tx
                .send(Ok(pb::FlowSyncResponse {
                    applied: applied as u64,
                }))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    set_state("connected", remote.map(|value| value.to_string()), None);
    Ok(Response::new(ReceiverStream::new(rx)))
}

fn authorize_proto_request(
    cfg: &Config,
    source: Option<std::net::SocketAddr>,
    request: &pb::FlowSyncRequest,
) -> Result<()> {
    let source = source.context("missing flow sync peer address")?;
    let state_dir = Path::new(&*cfg.state_dir);
    let ha_cfg = ha::load_for_state_dir(state_dir)?;
    let peer = ha_cfg
        .peers
        .first()
        .context("xsync peer is not configured")?;
    let peer_ip = peer
        .underlay_ip
        .parse::<std::net::IpAddr>()
        .context("bad xsync peer address")?;
    if source.ip() != peer_ip {
        bail!(
            "xsync source {} is not configured peer {}",
            source.ip(),
            peer_ip
        );
    }
    if request.source != peer.name {
        bail!(
            "xsync source {:?} does not match configured peer {:?}",
            request.source,
            peer.name
        );
    }
    if !ha::session_token_matches(state_dir, &request.token)? {
        bail!("authentication failed for {}", request.source);
    }
    if crate::provider::native::ha::state(cfg)?.state == "MASTER" {
        bail!("MASTER gateway refuses replicated flow state");
    }
    Ok(())
}

fn apply_proto_request(cfg: &Config, request: &pb::FlowSyncRequest) -> Result<usize> {
    let entries = request
        .entries
        .iter()
        .map(entry_from_proto)
        .collect::<Result<Vec<_>>>()?;
    let deletes = request
        .deletes
        .iter()
        .map(key_from_proto)
        .collect::<Result<Vec<_>>>()?;
    Ok(native_dnat::upsert_flows(cfg, &entries)? + native_dnat::delete_flows(cfg, &deletes)?)
}

fn key_to_proto(key: &edge_lb_common::NativeFlowKey) -> pb::FlowKey {
    pb::FlowKey {
        src: key.src,
        dst: key.dst,
        sport: u32::from(key.sport),
        dport: u32::from(key.dport),
        proto: u32::from(key.proto),
    }
}

fn key_from_proto(key: &pb::FlowKey) -> Result<edge_lb_common::NativeFlowKey> {
    Ok(edge_lb_common::NativeFlowKey {
        src: key.src,
        dst: key.dst,
        sport: u16::try_from(key.sport).context("flow sport out of range")?,
        dport: u16::try_from(key.dport).context("flow dport out of range")?,
        proto: u8::try_from(key.proto).context("flow protocol out of range")?,
        _pad: [0; 3],
    })
}

fn entry_to_proto(entry: &native_dnat::FlowEntry) -> pb::FlowEntry {
    let (key, value) = entry;
    pb::FlowEntry {
        key: Some(key_to_proto(key)),
        value: Some(pb::FlowValue {
            service_id: value.service_id,
            endpoint_id: value.endpoint_id,
            vip: value.vip,
            endpoint: value.endpoint,
            vip_port: u32::from(value.vip_port),
            endpoint_port: u32::from(value.endpoint_port),
            timeout_secs: value.timeout_secs,
            last_seen_ns: value.last_seen_ns,
        }),
    }
}

fn entry_from_proto(entry: &pb::FlowEntry) -> Result<native_dnat::FlowEntry> {
    let key = key_from_proto(entry.key.as_ref().context("flow entry key is required")?)?;
    let value = entry
        .value
        .as_ref()
        .context("flow entry value is required")?;
    Ok((
        key,
        edge_lb_common::NativeFlowValue {
            service_id: value.service_id,
            endpoint_id: value.endpoint_id,
            vip: value.vip,
            endpoint: value.endpoint,
            vip_port: u16::try_from(value.vip_port).context("flow VIP port out of range")?,
            endpoint_port: u16::try_from(value.endpoint_port)
                .context("flow endpoint port out of range")?,
            timeout_secs: value.timeout_secs,
            last_seen_ns: value.last_seen_ns,
        },
    ))
}

pub fn run_worker(cfg: Config) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("[xsync] runtime init failed: {error}");
            return;
        }
    };
    runtime.block_on(client_loop_grpc(cfg));
}

async fn client_loop_grpc(cfg: Config) {
    let mut replica = HashMap::new();
    let mut backoff = Duration::from_millis(250);
    while !shutdown::requested() {
        if let Err(error) = sync_session_grpc(&cfg, &mut replica).await {
            set_error(format!("{error:#}"));
            tracing::debug!("[xsync] gRPC session ended: {error:#}");
        }
        let max = ha::load_for_state_dir(Path::new(&*cfg.state_dir))
            .ok()
            .map(|v| v.xsync.reconnect_max_ms.max(250))
            .unwrap_or(5000);
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_millis(max));
    }
}

async fn sync_session_grpc(
    cfg: &Config,
    replica: &mut HashMap<edge_lb_common::NativeFlowKey, u64>,
) -> Result<()> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled
        || !ha_cfg.connection_sync
        || crate::provider::native::ha::state(cfg)?.state != "MASTER"
    {
        tokio::time::sleep(Duration::from_secs(1)).await;
        return Ok(());
    }
    let peer = ha_cfg
        .peers
        .first()
        .context("xsync peer is not configured")?;
    let token = ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir))?
        .context("xsync peer token unavailable")?
        .session_token;
    let control_port = cfg
        .control_plane
        .listen
        .parse::<std::net::SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(ha_cfg.xsync.port);
    let endpoint = format!("http://{}:{}", peer.underlay_ip, control_port);
    let channel = Endpoint::from_shared(endpoint.clone())
        .context("building xSync endpoint")?
        .connect_timeout(Duration::from_secs(5))
        .connect()
        .await
        .with_context(|| format!("connecting xSync endpoint {endpoint}"))?;
    let mut client = FlowSyncClient::new(channel);
    let (tx, rx) = mpsc::channel(4);
    tx.send(pb::FlowSyncRequest {
        source: cfg.node_name.clone(),
        token: token.clone(),
        entries: Vec::new(),
        deletes: Vec::new(),
    })
    .await
    .context("sending xSync handshake")?;
    let mut response = client
        .replicate(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();
    timeout(Duration::from_secs(5), response.message())
        .await??
        .context("xSync handshake was not acknowledged")?;
    let mut events = native_dnat::open_flow_events(cfg)?;
    let mut next_reconcile = Instant::now();
    tracing::info!("[xsync] connected to {} via gRPC", endpoint);
    set_state("connected", Some(endpoint), None);
    loop {
        if shutdown::requested() {
            return Ok(());
        }
        if crate::provider::native::ha::state(cfg)?.state != "MASTER" {
            set_state("standby", None, None);
            return Ok(());
        }
        let mutations = events
            .as_mut()
            .map(native_dnat::drain_flow_events)
            .unwrap_or_default();
        let mut entries = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                native_dnat::FlowMutation::Upsert(entry) => Some(*entry),
                native_dnat::FlowMutation::Delete(_) => None,
            })
            .collect::<Vec<_>>();
        let mut deletes = mutations
            .iter()
            .filter_map(|mutation| match mutation {
                native_dnat::FlowMutation::Delete(key) => Some(*key),
                native_dnat::FlowMutation::Upsert(_) => None,
            })
            .collect::<Vec<_>>();
        if Instant::now() >= next_reconcile {
            if let Err(error) = native_dnat::sweep_flows_and_refresh_loads(cfg) {
                tracing::debug!("[xsync] native flow sweep skipped: {error:#}");
            }
            let flows = native_dnat::dump_flows(cfg)?;
            let current = flows.iter().map(|(key, _)| *key).collect::<HashSet<_>>();
            entries.extend(flows.into_iter().filter(|(key, value)| {
                replica
                    .get(key)
                    .is_none_or(|seen| value.last_seen_ns > *seen)
            }));
            deletes.extend(replica.keys().filter(|key| !current.contains(key)).copied());
            next_reconcile = Instant::now() + RECONCILE_INTERVAL;
        }
        entries.retain(|(key, value)| {
            replica
                .get(key)
                .is_none_or(|seen| value.last_seen_ns > *seen)
        });
        entries.sort_by_key(|(key, value)| {
            (
                key.src,
                key.dst,
                key.sport,
                key.dport,
                key.proto,
                value.last_seen_ns,
            )
        });
        entries.dedup_by(|left, right| left.0 == right.0);
        deletes.sort_by_key(|key| (key.src, key.dst, key.sport, key.dport, key.proto));
        deletes.dedup();
        if !entries.is_empty() || !deletes.is_empty() {
            tx.send(pb::FlowSyncRequest {
                source: cfg.node_name.clone(),
                token: token.clone(),
                entries: entries.iter().map(entry_to_proto).collect(),
                deletes: deletes.iter().map(key_to_proto).collect(),
            })
            .await
            .context("sending xSync request")?;
            let ack = timeout(Duration::from_secs(5), response.message())
                .await??
                .context("xSync peer closed stream")?;
            set_ack(ack.applied as usize);
            for (key, value) in entries {
                replica.insert(key, value.last_seen_ns);
            }
            for key in deletes {
                replica.remove(&key);
            }
        }
        tokio::time::sleep(EVENT_POLL_INTERVAL).await;
    }
}

fn set_state(state_value: &str, peer: Option<String>, error: Option<String>) {
    let mut value = status().lock().expect("xsync status mutex poisoned");
    value.state = state_value.to_string();
    if peer.is_some() {
        value.peer = peer;
    }
    value.last_error = error;
}

fn set_ack(applied: usize) {
    status()
        .lock()
        .expect("xsync status mutex poisoned")
        .last_ack_applied = applied;
}

fn set_error(error: String) {
    set_state("error", None, Some(error));
}

#[cfg(test)]
mod tests {
    #[test]
    fn grpc_poll_interval_is_bounded() {
        assert_eq!(super::EVENT_POLL_INTERVAL.as_millis(), 25);
    }

    #[test]
    fn standby_state_name_is_stable() {
        super::set_state("standby", None, None);
        assert_eq!(super::snapshot().state, "standby");
    }
}
