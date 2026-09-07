//! Native IPv4 default-DNAT TC datapath.
//!
//! The daemon owns the Aya object and its maps. The ingress program performs
//! the forward rewrite and the return program restores the service source on
//! packets arriving from the backend overlay.

use std::{
    collections::{HashMap as StdHashMap, HashSet},
    fs,
    path::PathBuf,
};

use anyhow::{Context, Result, anyhow, bail};
use aya::{
    Ebpf,
    maps::{HashMap, Map, MapData, RingBuf},
    programs::tc::{
        NlOptions, SchedClassifier, TcAttachOptions, TcAttachType, TcHandle, qdisc_detach_program,
    },
};
use edge_lb_common::{
    DEFAULT_PERSIST_TIMEOUT_SECS, MAX_ENDPOINTS_PER_SERVICE, NATIVE_DNAT_INGRESS_PROGRAM,
    NATIVE_DNAT_RETURN_PROGRAM, NativeEndpointKey, NativeEndpointLoadKey, NativeEndpointValue,
    NativeServiceKey, NativeServiceValue,
};

use crate::{
    config::Config,
    provider::native::{
        NativeTargetState, TargetHealthList, listeners_from_config, target_health_native,
    },
};

const SERVICES: &str = "NATIVE_SERVICES";
const ENDPOINTS: &str = "NATIVE_ENDPOINTS";
const FLOWS: &str = "NATIVE_FLOWS";
const STATS: &str = "NATIVE_STATS";
const FLOW_EVENTS: &str = "NATIVE_FLOW_EVENTS";
const RR_COUNTERS: &str = "NATIVE_RR_COUNTERS";
const ACTIVE_FLOWS: &str = "NATIVE_ACTIVE_FLOWS";
const MAPS: [&str; 7] = [
    SERVICES,
    ENDPOINTS,
    FLOWS,
    RR_COUNTERS,
    ACTIVE_FLOWS,
    STATS,
    FLOW_EVENTS,
];
const INGRESS_PREF_OFFSET: u16 = 10;
const RETURN_PREF_OFFSET: u16 = 11;

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_ebpf.rs"));
}

pub struct NativeDnatAttachment {
    _bpf: Option<Ebpf>,
    pin_dir: PathBuf,
    underlay: String,
    overlay: String,
    pref: u16,
}

/// The current attachment. Holding it means every re-apply closes the previous
/// object's map fds and detaches its filters.
static CURRENT: std::sync::Mutex<Option<NativeDnatAttachment>> = std::sync::Mutex::new(None);
static CURRENT_SIGNATURE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

impl Drop for NativeDnatAttachment {
    fn drop(&mut self) {
        let _ = qdisc_detach_program(
            &self.underlay,
            TcAttachType::Ingress,
            NATIVE_DNAT_INGRESS_PROGRAM,
        );
        let _ = qdisc_detach_program(
            &self.overlay,
            TcAttachType::Ingress,
            NATIVE_DNAT_RETURN_PROGRAM,
        );
        crate::linux::tc::delete_ingress_pref_best_effort(
            &self.underlay,
            self.pref + INGRESS_PREF_OFFSET,
        );
        crate::linux::tc::delete_ingress_pref_best_effort(
            &self.overlay,
            self.pref + RETURN_PREF_OFFSET,
        );
        for name in MAPS {
            let _ = fs::remove_file(self.pin_dir.join(name));
        }
        let _ = fs::remove_dir(&self.pin_dir);
    }
}

fn pin_dir(cfg: &Config) -> PathBuf {
    cfg.pin_dir().join("native-dnat")
}
fn pin_path(cfg: &Config, name: &str) -> PathBuf {
    pin_dir(cfg).join(name)
}

fn read_object() -> Result<Vec<u8>> {
    if let Some(bytes) = embedded::embedded_ebpf() {
        return Ok(bytes.to_vec());
    }
    Err(anyhow!(
        "native DNAT eBPF object is not embedded; build with `make release`"
    ))
}

pub fn attach_owned(cfg: &Config) -> Result<NativeDnatAttachment> {
    let listeners = listeners_from_config(cfg)?;
    if listeners.is_empty() {
        bail!("native DNAT requires at least one listener");
    }
    let n = cfg.network();
    let mut bpf = Ebpf::load(&read_object()?).context("failed to load native DNAT eBPF object")?;
    let observed_endpoints = target_health_native(cfg).ok();
    let pin_dir = pin_dir(cfg);
    fs::create_dir_all(&pin_dir)
        .with_context(|| format!("failed to create {}", pin_dir.display()))?;
    for name in MAPS {
        let _ = fs::remove_file(pin_path(cfg, name));
    }

    let mut service_id = 1u32;
    {
        let mut services: HashMap<&mut MapData, NativeServiceKey, NativeServiceValue> =
            HashMap::try_from(
                bpf.map_mut(SERVICES)
                    .ok_or_else(|| anyhow!("{SERVICES} map missing"))?,
            )?;
        for listener in &listeners {
            let weight_total = listener
                .endpoints
                .iter()
                .filter(|endpoint| {
                    matches!(endpoint.state, NativeTargetState::Active)
                        && observed_endpoint_is_active(
                            observed_endpoints.as_ref(),
                            endpoint.address,
                            listener.key.protocol.ip_proto(),
                            endpoint.port,
                        )
                })
                .map(|endpoint| endpoint.weight)
                .filter(|weight| *weight > 0)
                .sum::<u32>();
            services.insert(
                NativeServiceKey {
                    vip: u32::from_be_bytes(listener.key.vip_ip.octets()),
                    port: listener.key.vip_port.to_be(),
                    proto: listener.key.protocol.ip_proto(),
                    _pad: 0,
                },
                NativeServiceValue {
                    service_id,
                    endpoint_base: 0,
                    endpoint_count: listener.endpoints.len() as u32,
                    weight_total,
                    select: listener.select,
                    flags: 1,
                    timeout_secs: if listener.select == crate::config::LbSelect::Persist.code() {
                        DEFAULT_PERSIST_TIMEOUT_SECS
                    } else {
                        listener.inactive_timeout_secs
                    },
                    dscp: listener.dscp,
                },
                0,
            )?;
            service_id = service_id
                .checked_add(1)
                .context("native service id exhausted")?;
        }
    }
    {
        let mut endpoints: HashMap<&mut MapData, NativeEndpointKey, NativeEndpointValue> =
            HashMap::try_from(
                bpf.map_mut(ENDPOINTS)
                    .ok_or_else(|| anyhow!("{ENDPOINTS} map missing"))?,
            )?;
        for (service_index, listener) in listeners.iter().enumerate() {
            if listener.endpoints.len() > MAX_ENDPOINTS_PER_SERVICE as usize {
                // The eBPF selector scans a compile-time bound; extra
                // endpoints would be silently unreachable.
                anyhow::bail!(
                    "listener {} has {} endpoints; max {}",
                    listener.key.vip_port,
                    listener.endpoints.len(),
                    MAX_ENDPOINTS_PER_SERVICE
                );
            }
            for (endpoint_id, endpoint) in listener.endpoints.iter().enumerate() {
                endpoints.insert(
                    NativeEndpointKey {
                        service_id: service_index as u32 + 1,
                        endpoint_id: endpoint_id as u32,
                    },
                    NativeEndpointValue {
                        address: u32::from_be_bytes(endpoint.address.octets()),
                        port: endpoint.port,
                        weight: endpoint.weight.min(u16::MAX as u32) as u16,
                        flags: u32::from(
                            matches!(endpoint.state, NativeTargetState::Active)
                                && observed_endpoint_is_active(
                                    observed_endpoints.as_ref(),
                                    endpoint.address,
                                    listener.key.protocol.ip_proto(),
                                    endpoint.port,
                                ),
                        ),
                    },
                    0,
                )?;
            }
        }
    }
    for name in MAPS {
        bpf.map(name)
            .ok_or_else(|| anyhow!("{name} map missing"))?
            .pin(pin_path(cfg, name))
            .with_context(|| format!("pinning native DNAT map {name}"))?;
    }

    let pref = cfg.gateway_cfg().dscp_pref;
    crate::linux::tc::add_clsact_best_effort(&n.underlay_dev);
    crate::linux::tc::add_clsact_best_effort(&n.vxlan_dev);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.underlay_dev, pref + INGRESS_PREF_OFFSET);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.vxlan_dev, pref + RETURN_PREF_OFFSET);
    attach_program(
        &mut bpf,
        NATIVE_DNAT_INGRESS_PROGRAM,
        &n.underlay_dev,
        pref + INGRESS_PREF_OFFSET,
    )?;
    attach_program(
        &mut bpf,
        NATIVE_DNAT_RETURN_PROGRAM,
        &n.vxlan_dev,
        pref + RETURN_PREF_OFFSET,
    )?;
    Ok(NativeDnatAttachment {
        _bpf: Some(bpf),
        pin_dir,
        underlay: n.underlay_dev.clone(),
        overlay: n.vxlan_dev.clone(),
        pref,
    })
}

fn observed_endpoint_is_active(
    observed: Option<&TargetHealthList>,
    address: std::net::Ipv4Addr,
    protocol: u8,
    port: u16,
) -> bool {
    let Some(observed) = observed else {
        return true;
    };
    let protocol = match protocol {
        6 => "tcp",
        17 => "udp",
        _ => return true,
    };
    observed
        .entries
        .iter()
        // Probe port and forwarding port are independent. Health belongs to
        // the native health identity, which is keyed by the forwarding
        // port; filtering on probe_port would miss valid observations when a
        // group probes a different port from the listener target port.
        .filter(|entry| entry.name == format!("{address}_{protocol}_{port}"))
        .all(|entry| {
            !matches!(
                entry.current_state.as_deref(),
                Some("nok") | Some("inactive") | Some("down")
            )
        })
}

fn attach_program(bpf: &mut Ebpf, name: &str, dev: &str, priority: u16) -> Result<()> {
    let program: &mut SchedClassifier = bpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("{name} program missing"))?
        .try_into()
        .with_context(|| format!("{name} is not a TC classifier"))?;
    program.load().with_context(|| format!("loading {name}"))?;
    program
        .attach_with_options(
            dev,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions {
                priority,
                handle: TcHandle::from(1),
                classid: None,
            }),
        )
        .with_context(|| format!("attaching {name} to {dev} ingress pref {priority}"))?;
    Ok(())
}

/// Attach and keep the attachment in the process-wide slot, dropping the
/// previous one first (detach + unpin + close fds). The brief filter gap
/// between drop and attach is bounded by the reconcile interval.
pub fn apply(cfg: &Config) -> Result<()> {
    // An automatic target group can temporarily have no matched backends.
    // Keep the control-plane listener, but remove any stale datapath instead
    // of making the gateway daemon fail its startup/reconcile cycle.
    let listeners = listeners_from_config(cfg)?;
    if listeners.is_empty() {
        return cleanup(cfg);
    }
    let signature = format!("{listeners:?}");
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    let mut current_signature = CURRENT_SIGNATURE.lock().unwrap_or_else(|e| e.into_inner());
    // Probe state is refreshed directly in the pinned maps. Keep the TC
    // programs and flow map in place when the listener definition itself did
    // not change; rebuilding here would create a needless packet gap and
    // discard active flow state on every reconcile.
    if current.is_some()
        && current_signature.as_deref() == Some(signature.as_str())
        && attached(cfg)
    {
        refresh_target_health(cfg)?;
        return Ok(());
    }
    if let Some(old) = current.take() {
        drop(old);
    }
    *current = Some(attach_owned(cfg)?);
    *current_signature = Some(signature);
    Ok(())
}

/// A flow-table entry as exchanged with the HA peer. Field order is the wire
/// contract; both gateways in a pair share one architecture, so the raw
/// repr(C) integers serialize consistently.
pub type FlowEntry = (
    edge_lb_common::NativeFlowKey,
    edge_lb_common::NativeFlowValue,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlowMutation {
    Upsert(FlowEntry),
    Delete(edge_lb_common::NativeFlowKey),
}

pub type FlowEventReader = RingBuf<MapData>;

/// Open the pinned event stream. Older datapath objects may not have this map.
pub fn open_flow_events(cfg: &Config) -> Result<Option<FlowEventReader>> {
    let pin = pin_path(cfg, FLOW_EVENTS);
    if !pin.exists() {
        return Ok(None);
    }
    let data = MapData::from_pin(&pin).with_context(|| format!("opening pinned {FLOW_EVENTS}"))?;
    let map = Map::from_map_data(data).with_context(|| format!("{FLOW_EVENTS} is not a map"))?;
    Ok(Some(RingBuf::try_from(map).with_context(|| {
        format!("{FLOW_EVENTS} is not a ring buffer")
    })?))
}

/// Drain flow mutations without blocking the xSync worker.
pub fn drain_flow_events(reader: &mut FlowEventReader) -> Vec<FlowMutation> {
    let mut events = Vec::new();
    while let Some(item) = reader.next() {
        if item.len() != std::mem::size_of::<edge_lb_common::NativeFlowEvent>() {
            tracing::warn!(
                "[native-dnat] ignoring flow event with unexpected size {}",
                item.len()
            );
            continue;
        }
        let event = unsafe {
            std::ptr::read_unaligned(item.as_ptr() as *const edge_lb_common::NativeFlowEvent)
        };
        events.push(if event.op == 2 {
            FlowMutation::Delete(event.key)
        } else {
            FlowMutation::Upsert((event.key, event.value))
        });
    }
    events
}

fn open_pinned_flows(
    cfg: &Config,
) -> Result<Option<HashMap<MapData, edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowValue>>>
{
    let pin = pin_path(cfg, FLOWS);
    if !pin.exists() {
        return Ok(None);
    }
    let map_data = MapData::from_pin(&pin).with_context(|| format!("opening pinned {FLOWS}"))?;
    let map = Map::from_map_data(map_data).with_context(|| format!("{FLOWS} is not a hash map"))?;
    let flows: HashMap<MapData, edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowValue> =
        HashMap::try_from(map).with_context(|| format!("{FLOWS} key/value layout mismatch"))?;
    Ok(Some(flows))
}

/// Dump the pinned flow table. Empty when the datapath is not attached.
pub fn dump_flows(cfg: &Config) -> Result<Vec<FlowEntry>> {
    let Some(flows) = open_pinned_flows(cfg)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in flows.iter() {
        out.push(entry.with_context(|| format!("iterating {FLOWS}"))?);
    }
    Ok(out)
}

pub fn sweep_flows_and_refresh_loads(cfg: &Config) -> Result<usize> {
    let now = monotonic_now_ns();
    let Some(mut flows) = open_pinned_flows(cfg)? else {
        return Ok(0);
    };
    let mut expired = Vec::new();
    let mut loads = StdHashMap::<NativeEndpointLoadKey, u32>::new();
    let mut seen_pairs =
        HashSet::<(edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowKey)>::new();
    for entry in flows.iter() {
        let (key, value) = entry.with_context(|| format!("iterating {FLOWS}"))?;
        if flow_expired(value.last_seen_ns, value.timeout_secs, now) {
            expired.push(key);
            continue;
        }
        let pair = canonical_flow_pair(key, value);
        if seen_pairs.insert(pair) {
            let load_key = NativeEndpointLoadKey {
                service_id: value.service_id,
                endpoint_id: value.endpoint_id,
            };
            loads
                .entry(load_key)
                .and_modify(|load| *load = load.saturating_add(1))
                .or_insert(1);
        }
    }
    for key in &expired {
        let _ = flows.remove(key);
    }
    replace_active_flows(cfg, &loads)?;
    Ok(expired.len())
}

/// Upsert replicated flow entries into the pinned flow table. An entry is
/// only applied when it is new or strictly fresher than the local copy, so
/// a lagging MASTER replica never regresses a flow's last-seen timestamp.
/// Returns how many entries were applied.
pub fn upsert_flows(cfg: &Config, entries: &[FlowEntry]) -> Result<usize> {
    let pin = pin_path(cfg, FLOWS);
    if !pin.exists() {
        // Datapath detached on this node: nothing to apply. The caller may
        // treat this as success; entries would be rebuilt on next attach.
        return Ok(0);
    }
    let Some(mut flows) = open_pinned_flows(cfg)? else {
        return Ok(0);
    };
    let mut applied = 0usize;
    for (key, value) in entries {
        if !flow_apply_applies(flows.get(key, 0).ok().as_ref(), value) {
            continue;
        }
        flows.insert(*key, *value, 0)?;
        applied += 1;
    }
    Ok(applied)
}

/// Delete replicated flow-map records. Missing keys are treated as already
/// applied so reconnects and duplicate delete events remain idempotent.
pub fn delete_flows(cfg: &Config, keys: &[edge_lb_common::NativeFlowKey]) -> Result<usize> {
    let pin = pin_path(cfg, FLOWS);
    if !pin.exists() {
        return Ok(0);
    }
    let Some(mut flows) = open_pinned_flows(cfg)? else {
        return Ok(0);
    };
    let mut deleted = 0usize;
    for key in keys {
        if flows.remove(key).is_ok() {
            deleted += 1;
        }
    }
    Ok(deleted)
}

/// Apply decision, extracted for tests: apply when absent or when the
/// replica's `last_seen_ns` is newer than the local one.
fn flow_apply_applies(
    local: Option<&edge_lb_common::NativeFlowValue>,
    replica: &edge_lb_common::NativeFlowValue,
) -> bool {
    match local {
        None => true,
        Some(local) => replica.last_seen_ns > local.last_seen_ns,
    }
}

fn flow_expired(last_seen_ns: u64, timeout_secs: u32, now_ns: u64) -> bool {
    if last_seen_ns == 0 || timeout_secs == 0 {
        return false;
    }
    now_ns.saturating_sub(last_seen_ns) > timeout_secs as u64 * 1_000_000_000
}

fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    if rc != 0 {
        return 0;
    }
    (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64)
}

fn canonical_flow_pair(
    key: edge_lb_common::NativeFlowKey,
    value: edge_lb_common::NativeFlowValue,
) -> (edge_lb_common::NativeFlowKey, edge_lb_common::NativeFlowKey) {
    let endpoint_port = value.endpoint_port.to_be();
    let (forward, reverse) = if key.src == value.endpoint && key.sport == endpoint_port {
        let forward = edge_lb_common::NativeFlowKey {
            src: key.dst,
            dst: value.vip,
            sport: key.dport,
            dport: value.vip_port,
            proto: key.proto,
            _pad: [0; 3],
        };
        (forward, key)
    } else {
        let reverse = edge_lb_common::NativeFlowKey {
            src: value.endpoint,
            dst: key.src,
            sport: endpoint_port,
            dport: key.sport,
            proto: key.proto,
            _pad: [0; 3],
        };
        (key, reverse)
    };
    if flow_key_sort_tuple(&forward) <= flow_key_sort_tuple(&reverse) {
        (forward, reverse)
    } else {
        (reverse, forward)
    }
}

fn flow_key_sort_tuple(key: &edge_lb_common::NativeFlowKey) -> (u32, u32, u16, u16, u8) {
    (key.src, key.dst, key.sport, key.dport, key.proto)
}

fn replace_active_flows(
    cfg: &Config,
    loads: &StdHashMap<NativeEndpointLoadKey, u32>,
) -> Result<()> {
    let pin = pin_path(cfg, ACTIVE_FLOWS);
    if !pin.exists() {
        return Ok(());
    }
    let map_data =
        MapData::from_pin(&pin).with_context(|| format!("opening pinned {ACTIVE_FLOWS}"))?;
    let map = Map::from_map_data(map_data)
        .with_context(|| format!("{ACTIVE_FLOWS} is not a hash map"))?;
    let mut active: HashMap<MapData, NativeEndpointLoadKey, u32> = HashMap::try_from(map)
        .with_context(|| format!("{ACTIVE_FLOWS} key/value layout mismatch"))?;
    let existing = active
        .iter()
        .map(|entry| entry.map(|(key, _)| key))
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("iterating {ACTIVE_FLOWS}"))?;
    for key in existing {
        if !loads.contains_key(&key) {
            let _ = active.remove(&key);
        }
    }
    for (key, value) in loads {
        active.insert(*key, *value, 0)?;
    }
    Ok(())
}

/// Refresh the active/inactive flag of every endpoint in the pinned
/// ENDPOINTS map from observed probe state, without touching TC attachment
/// or the running programs. Called by the probe worker on health
/// transitions; safe to run when the datapath is not attached (no-op).
pub fn refresh_target_health(cfg: &Config) -> Result<()> {
    let pin = pin_path(cfg, ENDPOINTS);
    if !pin.exists() {
        return Ok(());
    }
    let listeners = listeners_from_config(cfg)?;
    let observed = target_health_native(cfg).ok();
    let map_data =
        MapData::from_pin(&pin).with_context(|| format!("opening pinned {ENDPOINTS}"))?;
    let map =
        Map::from_map_data(map_data).with_context(|| format!("{ENDPOINTS} is not a hash map"))?;
    let mut endpoints: HashMap<MapData, NativeEndpointKey, NativeEndpointValue> =
        HashMap::try_from(map).with_context(|| format!("{ENDPOINTS} key/value layout mismatch"))?;
    let mut changed = 0usize;
    for (service_index, listener) in listeners.iter().enumerate() {
        for (endpoint_id, endpoint) in listener.endpoints.iter().enumerate() {
            let key = NativeEndpointKey {
                service_id: service_index as u32 + 1,
                endpoint_id: endpoint_id as u32,
            };
            let Some(mut value) = endpoints.get(&key, 0).ok() else {
                continue;
            };
            let active = matches!(endpoint.state, NativeTargetState::Active)
                && observed_endpoint_is_active(
                    observed.as_ref(),
                    endpoint.address,
                    listener.key.protocol.ip_proto(),
                    endpoint.port,
                );
            let flags = u32::from(active);
            if value.flags != flags {
                value.flags = flags;
                endpoints.insert(key, value, 0)?;
                changed += 1;
                tracing::info!(
                    "[native-dnat] endpoint {}:{} {} -> {} (service {})",
                    endpoint.address,
                    endpoint.port,
                    if flags == 1 { "inactive" } else { "active" },
                    if flags == 1 { "active" } else { "inactive" },
                    service_index + 1
                );
            }
        }
    }
    refresh_service_weights(cfg, &listeners, observed.as_ref())?;
    if changed == 0 {
        tracing::debug!("[native-dnat] endpoint health refresh: no changes");
    }
    Ok(())
}

fn refresh_service_weights(
    cfg: &Config,
    listeners: &[crate::provider::native::NativeListener],
    observed: Option<&TargetHealthList>,
) -> Result<()> {
    let pin = pin_path(cfg, SERVICES);
    if !pin.exists() {
        return Ok(());
    }
    let map_data = MapData::from_pin(&pin).with_context(|| format!("opening pinned {SERVICES}"))?;
    let map =
        Map::from_map_data(map_data).with_context(|| format!("{SERVICES} is not a hash map"))?;
    let mut services: HashMap<MapData, NativeServiceKey, NativeServiceValue> =
        HashMap::try_from(map).with_context(|| format!("{SERVICES} key/value layout mismatch"))?;
    for (service_index, listener) in listeners.iter().enumerate() {
        let key = NativeServiceKey {
            vip: u32::from_be_bytes(listener.key.vip_ip.octets()),
            port: listener.key.vip_port.to_be(),
            proto: listener.key.protocol.ip_proto(),
            _pad: 0,
        };
        let Some(mut value) = services.get(&key, 0).ok() else {
            continue;
        };
        value.weight_total = listener
            .endpoints
            .iter()
            .filter(|endpoint| {
                matches!(endpoint.state, NativeTargetState::Active)
                    && observed_endpoint_is_active(
                        observed,
                        endpoint.address,
                        listener.key.protocol.ip_proto(),
                        endpoint.port,
                    )
            })
            .map(|endpoint| endpoint.weight)
            .filter(|weight| *weight > 0)
            .sum();
        services.insert(key, value, 0).with_context(|| {
            format!(
                "updating native service weight for service {}",
                service_index + 1
            )
        })?;
    }
    Ok(())
}

pub fn cleanup(cfg: &Config) -> Result<()> {
    let mut current = CURRENT.lock().unwrap_or_else(|e| e.into_inner());
    let mut current_signature = CURRENT_SIGNATURE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = current.take() {
        drop(old);
    }
    *current_signature = None;
    let n = cfg.network();
    let pref = cfg.gateway_cfg().dscp_pref;
    let _ = qdisc_detach_program(
        &n.underlay_dev,
        TcAttachType::Ingress,
        NATIVE_DNAT_INGRESS_PROGRAM,
    );
    let _ = qdisc_detach_program(
        &n.vxlan_dev,
        TcAttachType::Ingress,
        NATIVE_DNAT_RETURN_PROGRAM,
    );
    crate::linux::tc::delete_ingress_pref_best_effort(&n.underlay_dev, pref + INGRESS_PREF_OFFSET);
    crate::linux::tc::delete_ingress_pref_best_effort(&n.vxlan_dev, pref + RETURN_PREF_OFFSET);
    for name in MAPS {
        let _ = fs::remove_file(pin_path(cfg, name));
    }
    let _ = fs::remove_dir(pin_dir(cfg));
    Ok(())
}

pub fn attached(cfg: &Config) -> bool {
    let pref = cfg.gateway_cfg().dscp_pref;
    crate::linux::tc::show_ingress(&cfg.network().underlay_dev)
        .unwrap_or_default()
        .lines()
        .any(|line| {
            line.contains(&format!("pref {}", pref + INGRESS_PREF_OFFSET))
                && line.contains(NATIVE_DNAT_INGRESS_PROGRAM)
        })
}

pub fn stats(cfg: &Config) -> Result<edge_lb_common::NativeDatapathStats> {
    let data =
        MapData::from_pin(pin_path(cfg, STATS)).context("native DNAT stats map is not pinned")?;
    let map = Map::from_map_data(data)?;
    let stats: aya::maps::PerCpuArray<MapData, edge_lb_common::NativeDatapathStats> =
        map.try_into()?;
    let values = stats.get(&0, 0)?;
    Ok(values.iter().copied().fold(
        edge_lb_common::NativeDatapathStats::default(),
        |mut total, value| {
            total.service_hit = total.service_hit.saturating_add(value.service_hit);
            total.service_miss = total.service_miss.saturating_add(value.service_miss);
            total.return_miss = total.return_miss.saturating_add(value.return_miss);
            total.target_miss = total.target_miss.saturating_add(value.target_miss);
            total.rewritten = total.rewritten.saturating_add(value.rewritten);
            total.checksum_error = total.checksum_error.saturating_add(value.checksum_error);
            total
        },
    ))
}

#[cfg(test)]
mod tests {
    use aya::programs::SchedClassifier;

    fn flow_key(src: u32, dst: u32, sport: u16, dport: u16) -> edge_lb_common::NativeFlowKey {
        edge_lb_common::NativeFlowKey {
            src,
            dst,
            sport: sport.to_be(),
            dport: dport.to_be(),
            proto: 6,
            _pad: [0; 3],
        }
    }

    #[test]
    fn flow_expiry_uses_monotonic_nanoseconds() {
        assert!(!super::flow_expired(0, 1, 10_000_000_000));
        assert!(!super::flow_expired(1_000_000_000, 0, 10_000_000_000));
        assert!(!super::flow_expired(1_000_000_000, 10, 5_000_000_000));
        assert!(super::flow_expired(1_000_000_000, 3, 5_000_000_001));
    }

    #[test]
    fn canonical_flow_pair_is_identical_from_both_directions() {
        let forward = flow_key(0x0a00_0001, 0xc0a8_000a, 40000, 80);
        let reverse = flow_key(0xc0a8_000b, 0x0a00_0001, 8080, 40000);
        let value = edge_lb_common::NativeFlowValue {
            vip: 0xc0a8_000a,
            endpoint: 0xc0a8_000b,
            vip_port: 80_u16.to_be(),
            endpoint_port: 8080,
            ..edge_lb_common::NativeFlowValue::default()
        };
        assert_eq!(
            super::canonical_flow_pair(forward, value),
            super::canonical_flow_pair(reverse, value)
        );
    }

    #[test]
    fn preferences_are_disjoint_from_marker() {
        assert_eq!(super::INGRESS_PREF_OFFSET, 10);
        assert_eq!(super::RETURN_PREF_OFFSET, 11);
    }

    #[test]
    fn health_identity_uses_forwarding_port_not_probe_port() {
        let endpoint = crate::provider::native::TargetHealthEntry {
            host_name: "192.0.2.10".to_string(),
            name: "192.0.2.10_tcp_8080".to_string(),
            probe_type: Some("http".to_string()),
            probe_port: Some(9090),
            current_state: Some("nok".to_string()),
            ..crate::provider::native::TargetHealthEntry::default()
        };
        let list = super::TargetHealthList {
            entries: vec![endpoint],
        };

        assert!(!super::observed_endpoint_is_active(
            Some(&list),
            "192.0.2.10".parse().unwrap(),
            6,
            8080,
        ));
    }

    /// Load the ingress classifier without attaching. Privileged only; on
    /// failure the full verifier log is printed so load errors (e.g. the
    /// E2BIG truncated-log case seen in containers) are diagnosable.
    #[test]
    fn native_ingress_program_loads_when_privileged() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target/bpfel-unknown-none/release/edge-lb-ebpf");
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!("skipping: {} not built", path.display());
            return;
        };
        let mut bpf = match aya::Ebpf::load(&bytes) {
            Ok(bpf) => bpf,
            Err(e) => panic!("Ebpf::load failed: {e}"),
        };
        let program: &mut SchedClassifier = bpf
            .program_mut(edge_lb_common::NATIVE_DNAT_INGRESS_PROGRAM)
            .expect("native_dnat_ingress missing")
            .try_into()
            .expect("not a classifier");
        if let Err(e) = program.load() {
            let log = match &e {
                aya::programs::ProgramError::LoadError { verifier_log, .. } => {
                    format!("{verifier_log}")
                }
                other => format!("{other}"),
            };
            panic!("program load failed: {e}\n--- full verifier log ---\n{log}");
        }
    }
}
