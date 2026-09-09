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
const MAX_SYNC_OPS_PER_BATCH: usize = 4096;

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

fn entry_to_proto(entry: &native_dnat::FlowEntry, now_ns: u64) -> pb::FlowEntry {
    let (key, value) = entry;
    pb::FlowEntry {
        key: Some(key_to_proto(key)),
        value: Some(pb::FlowValue {
            listener_id: value.listener_id,
            target_id: value.target_id,
            vip: value.vip,
            target: value.target,
            vip_port: u32::from(value.vip_port),
            target_port: u32::from(value.target_port),
            timeout_secs: value.timeout_secs,
            last_seen_age_ns: flow_age_ns(value.last_seen_ns, now_ns),
        }),
    }
}

fn entry_from_proto(entry: &pb::FlowEntry) -> Result<native_dnat::FlowEntry> {
    entry_from_proto_at(entry, native_dnat::monotonic_now_ns())
}

fn entry_from_proto_at(entry: &pb::FlowEntry, now_ns: u64) -> Result<native_dnat::FlowEntry> {
    let key = key_from_proto(entry.key.as_ref().context("flow entry key is required")?)?;
    let value = entry
        .value
        .as_ref()
        .context("flow entry value is required")?;
    Ok((
        key,
        edge_lb_common::NativeFlowValue {
            listener_id: value.listener_id,
            target_id: value.target_id,
            vip: value.vip,
            target: value.target,
            vip_port: u16::try_from(value.vip_port).context("flow VIP port out of range")?,
            target_port: u16::try_from(value.target_port)
                .context("flow target port out of range")?,
            timeout_secs: value.timeout_secs,
            last_seen_ns: local_last_seen_ns(value.last_seen_age_ns, now_ns),
        },
    ))
}

fn flow_age_ns(last_seen_ns: u64, now_ns: u64) -> u64 {
    if last_seen_ns == 0 {
        0
    } else {
        now_ns.saturating_sub(last_seen_ns)
    }
}

fn local_last_seen_ns(age_ns: u64, now_ns: u64) -> u64 {
    if age_ns == 0 {
        now_ns
    } else {
        now_ns.saturating_sub(age_ns)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FlowBatchState {
    Upsert(native_dnat::FlowEntry),
    Delete(edge_lb_common::NativeFlowKey),
}

fn fold_flow_mutations(
    mutations: &[native_dnat::FlowMutation],
) -> (
    Vec<native_dnat::FlowEntry>,
    Vec<edge_lb_common::NativeFlowKey>,
) {
    let mut states = HashMap::new();
    for mutation in mutations {
        match *mutation {
            native_dnat::FlowMutation::Upsert(entry) => {
                states.insert(entry.0, FlowBatchState::Upsert(entry));
            }
            native_dnat::FlowMutation::Delete(key) => {
                states.insert(key, FlowBatchState::Delete(key));
            }
        }
    }
    split_flow_batch(states)
}

fn split_flow_batch(
    states: HashMap<edge_lb_common::NativeFlowKey, FlowBatchState>,
) -> (
    Vec<native_dnat::FlowEntry>,
    Vec<edge_lb_common::NativeFlowKey>,
) {
    let mut entries = Vec::new();
    let mut deletes = Vec::new();
    for state in states.into_values() {
        match state {
            FlowBatchState::Upsert(entry) => entries.push(entry),
            FlowBatchState::Delete(key) => deletes.push(key),
        }
    }
    (entries, deletes)
}

fn collapse_latest_entries(entries: Vec<native_dnat::FlowEntry>) -> Vec<native_dnat::FlowEntry> {
    let mut latest =
        HashMap::<edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowValue>::new();
    for (key, value) in entries {
        if latest
            .get(&key)
            .is_none_or(|existing| value.last_seen_ns >= existing.last_seen_ns)
        {
            latest.insert(key, value);
        }
    }
    let mut out = latest.into_iter().collect::<Vec<_>>();
    out.sort_by_key(|(key, value)| {
        (
            key.src,
            key.dst,
            key.sport,
            key.dport,
            key.proto,
            value.last_seen_ns,
        )
    });
    out
}

fn collapse_delete_keys(
    mut deletes: Vec<edge_lb_common::NativeFlowKey>,
    entries: &[native_dnat::FlowEntry],
) -> Vec<edge_lb_common::NativeFlowKey> {
    let upserts = entries.iter().map(|(key, _)| *key).collect::<HashSet<_>>();
    deletes.retain(|key| !upserts.contains(key));
    deletes.sort_by_key(|key| (key.src, key.dst, key.sport, key.dport, key.proto));
    deletes.dedup();
    deletes
}

fn flow_ack_covers_sent(expected: usize, accepted: u64) -> bool {
    usize::try_from(accepted) == Ok(expected)
}

fn limit_flow_batch(
    mut entries: Vec<native_dnat::FlowEntry>,
    mut deletes: Vec<edge_lb_common::NativeFlowKey>,
) -> (
    Vec<native_dnat::FlowEntry>,
    Vec<edge_lb_common::NativeFlowKey>,
) {
    if entries.len() >= MAX_SYNC_OPS_PER_BATCH {
        entries.truncate(MAX_SYNC_OPS_PER_BATCH);
        deletes.clear();
        return (entries, deletes);
    }
    let remaining = MAX_SYNC_OPS_PER_BATCH - entries.len();
    deletes.truncate(remaining);
    (entries, deletes)
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
    replica.clear();
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
        let (mut entries, mut deletes) = fold_flow_mutations(&mutations);
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
        entries = collapse_latest_entries(entries);
        deletes = collapse_delete_keys(deletes, &entries);
        let (limited_entries, limited_deletes) = limit_flow_batch(entries, deletes);
        entries = limited_entries;
        deletes = limited_deletes;
        if !entries.is_empty() || !deletes.is_empty() {
            let sent_entries = entries.len();
            let sent_deletes = deletes.len();
            let sync_now_ns = native_dnat::monotonic_now_ns();
            tx.send(pb::FlowSyncRequest {
                source: cfg.node_name.clone(),
                token: token.clone(),
                entries: entries
                    .iter()
                    .map(|entry| entry_to_proto(entry, sync_now_ns))
                    .collect(),
                deletes: deletes.iter().map(key_to_proto).collect(),
            })
            .await
            .context("sending xSync request")?;
            let ack = timeout(Duration::from_secs(5), response.message())
                .await??
                .context("xSync peer closed stream")?;
            set_ack(usize::try_from(ack.applied).unwrap_or(usize::MAX));
            let expected = sent_entries.saturating_add(sent_deletes);
            if !flow_ack_covers_sent(expected, ack.applied) {
                tracing::debug!(
                    "[xsync] peer accepted {} of {} flow operation(s); retaining replica backlog",
                    ack.applied,
                    expected
                );
                continue;
            }
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
    use crate::control::pb;
    use crate::linux::native_dnat;

    use edge_lb_common::{NativeFlowKey, NativeFlowValue};

    #[test]
    fn grpc_poll_interval_is_bounded() {
        assert_eq!(super::EVENT_POLL_INTERVAL.as_millis(), 25);
    }

    #[test]
    fn standby_state_name_is_stable() {
        super::set_state("standby", None, None);
        assert_eq!(super::snapshot().state, "standby");
    }

    #[test]
    fn flow_sync_sends_age_instead_of_local_monotonic_time() {
        let entry = (
            NativeFlowKey {
                src: 1,
                dst: 2,
                sport: 12345,
                dport: 80,
                proto: 6,
                _pad: [0; 3],
            },
            NativeFlowValue {
                listener_id: 7,
                target_id: 9,
                vip: 2,
                target: 3,
                vip_port: 80,
                target_port: 8080,
                timeout_secs: 60,
                last_seen_ns: 900,
            },
        );

        let proto = super::entry_to_proto(&entry, 1_000);

        assert_eq!(proto.value.unwrap().last_seen_age_ns, 100);
    }

    #[test]
    fn flow_sync_rebases_age_to_receiver_monotonic_time() {
        let entry = pb::FlowEntry {
            key: Some(pb::FlowKey {
                src: 1,
                dst: 2,
                sport: 12345,
                dport: 80,
                proto: 6,
            }),
            value: Some(pb::FlowValue {
                listener_id: 7,
                target_id: 9,
                vip: 2,
                target: 3,
                vip_port: 80,
                target_port: 8080,
                timeout_secs: 60,
                last_seen_age_ns: 100,
            }),
        };

        let (_, value) = super::entry_from_proto_at(&entry, 5_000).unwrap();

        assert_eq!(value.last_seen_ns, 4_900);
    }

    #[test]
    fn flow_sync_zero_age_maps_to_receiver_now() {
        assert_eq!(super::local_last_seen_ns(0, 5_000), 5_000);
    }

    #[test]
    fn flow_mutation_fold_keeps_last_operation_for_each_key() {
        let key = test_key(12345);
        let value = test_value(900);
        let (entries, deletes) = super::fold_flow_mutations(&[
            native_dnat::FlowMutation::Delete(key),
            native_dnat::FlowMutation::Upsert((key, value)),
        ]);

        assert_eq!(entries, vec![(key, value)]);
        assert!(deletes.is_empty());
    }

    #[test]
    fn flow_batch_keeps_latest_upsert_and_drops_shadowed_delete() {
        let key = test_key(12345);
        let entries = super::collapse_latest_entries(vec![
            (key, test_value(900)),
            (key, test_value(1_100)),
            (test_key(12346), test_value(1_000)),
        ]);
        let deletes = super::collapse_delete_keys(vec![key, key], &entries);

        assert_eq!(
            entries
                .iter()
                .find(|(item, _)| *item == key)
                .unwrap()
                .1
                .last_seen_ns,
            1_100
        );
        assert!(deletes.is_empty());
    }

    #[test]
    fn flow_ack_must_cover_every_sent_operation_before_advancing_replica_index() {
        assert!(super::flow_ack_covers_sent(2, 2));
        assert!(!super::flow_ack_covers_sent(2, 1));
        assert!(!super::flow_ack_covers_sent(1, u64::MAX));
    }

    #[test]
    fn flow_batch_limit_prioritizes_upserts_and_defers_excess_deletes() {
        let entries = (0..super::MAX_SYNC_OPS_PER_BATCH)
            .map(|idx| (test_key(idx as u16), test_value(u64::from(idx as u32))))
            .collect::<Vec<_>>();
        let deletes = vec![test_key(60_000)];

        let (entries, deletes) = super::limit_flow_batch(entries, deletes);

        assert_eq!(entries.len(), super::MAX_SYNC_OPS_PER_BATCH);
        assert!(deletes.is_empty());
    }

    #[test]
    fn flow_batch_limit_keeps_total_operations_bounded() {
        let entries = vec![(test_key(1), test_value(1))];
        let deletes = (0..super::MAX_SYNC_OPS_PER_BATCH)
            .map(|idx| test_key(idx as u16))
            .collect::<Vec<_>>();

        let (entries, deletes) = super::limit_flow_batch(entries, deletes);

        assert_eq!(entries.len(), 1);
        assert_eq!(deletes.len(), super::MAX_SYNC_OPS_PER_BATCH - 1);
    }

    fn test_key(sport: u16) -> NativeFlowKey {
        NativeFlowKey {
            src: 1,
            dst: 2,
            sport,
            dport: 80,
            proto: 6,
            _pad: [0; 3],
        }
    }

    fn test_value(last_seen_ns: u64) -> NativeFlowValue {
        NativeFlowValue {
            listener_id: 7,
            target_id: 9,
            vip: 2,
            target: 3,
            vip_port: 80,
            target_port: 8080,
            timeout_secs: 60,
            last_seen_ns,
        }
    }
}
