use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

use crate::{
    config::{Config, Listener, Protocol, Service, TargetEndpoint, TargetGroup},
    runtime::state::{ManagedRuntimeRule, ManagedTarget},
};

use super::{
    api_model::{
        HealthProbeConfig, RuntimeRuleSpec, RuntimeRuleStateEntry, RuntimeRuleStateList,
        RuntimeRuleTarget, TargetHealthEntry, TargetHealthList,
    },
    model::RuntimeRuleEntry,
};

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct NativeProxyState {
    #[serde(default)]
    listeners: Vec<RuntimeRuleStateEntry>,
    #[serde(default)]
    target_health: Vec<TargetHealthEntry>,
}

/// The probe worker and API handlers mutate the same state file from
/// different threads; every read-modify-write takes this lock.
static STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set whenever desired proxy state or target health changes on disk.
/// The gateway run loop consumes it to refresh the native datapath maps —
/// without this, CRUD only reached the kernel when some unrelated trigger
/// (boot, config reload, subscription churn) happened to fire.
static PROXY_STATE_DIRTY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn mark_state_dirty() {
    PROXY_STATE_DIRTY.store(true, std::sync::atomic::Ordering::Release);
}

/// One-shot: true when proxy state changed since the last check.
pub fn take_state_dirty() -> bool {
    PROXY_STATE_DIRTY.swap(false, std::sync::atomic::Ordering::AcqRel)
}

/// Mutate observed target health records under the state lock. Desired listener
/// configuration is untouched; this is the probe worker's write path.
pub fn mutate_target_health<F>(cfg: &Config, mutate: F) -> Result<()>
where
    F: FnOnce(&mut Vec<TargetHealthEntry>),
{
    let _guard = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut state = load_state(cfg)?;
    mutate(&mut state.target_health);
    save_state(cfg, &state)
}

fn with_state_lock<T>(f: impl FnOnce() -> Result<T>) -> Result<T> {
    let _guard = STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    f()
}

pub fn runtime_rules_native(cfg: &Config) -> Result<RuntimeRuleStateList> {
    let mut entries = Vec::new();
    for entry in load_state(cfg)?.listeners {
        if let Some(existing) = entries
            .iter_mut()
            .find(|existing: &&mut RuntimeRuleStateEntry| same_listener_identity(existing, &entry))
        {
            for ip in &entry.spec.vip_ips {
                if !existing.spec.vip_ips.contains(ip) {
                    existing.spec.vip_ips.push(ip.clone());
                }
            }
            merge_protocols(existing, &entry);
        } else {
            entries.push(entry);
        }
    }
    Ok(RuntimeRuleStateList { rules: entries })
}

pub fn target_health_native(cfg: &Config) -> Result<TargetHealthList> {
    Ok(TargetHealthList {
        entries: load_state(cfg)?.target_health,
    })
}

pub fn target_health(cfg: &Config) -> Result<Vec<TargetHealthEntry>> {
    Ok(load_state(cfg)?.target_health)
}

pub fn target_groups_native(cfg: &Config) -> Result<Vec<TargetGroup>> {
    if let Ok(repository) = crate::storage::repository()
        && let Some(payload) = repository.get("target_groups", "config")?
    {
        return serde_json::from_str(&payload).context("parsing stored target groups");
    }
    target_groups_from_config(cfg)
}

fn target_groups_from_config(cfg: &Config) -> Result<Vec<TargetGroup>> {
    let mut groups = BTreeMap::new();
    for group in cfg.target_groups.iter().cloned() {
        groups.insert(group.name.clone(), group);
    }
    Ok(groups.into_values().collect())
}

pub fn create_runtime_rule_state(
    cfg: &Config,
    entry: &RuntimeRuleStateEntry,
    target_group_probe: Option<&HealthProbeConfig>,
) -> Result<()> {
    with_state_lock(|| {
        let mut state = load_state(cfg)?;
        let mut entry = entry.clone();
        if entry.spec.vip_ips.is_empty() {
            entry.spec.vip_ips = default_external_ips(cfg);
        }
        normalize_entry(&mut entry);
        // The management/native state keeps one listener with an IP list.
        // The eBPF map expands that list into scalar VIP keys only when it is
        // attached. Persist only the canonical aggregate for this listener.
        state
            .listeners
            .retain(|existing| !same_listener_identity(existing, &entry));
        if target_group_probe.is_some_and(HealthProbeConfig::enabled) {
            entry.spec.monitor = true;
            ensure_probe_health_records(&mut state, &entry, target_group_probe.unwrap());
        } else {
            ensure_default_health_records(&mut state, &entry);
        }
        state.listeners.push(entry);
        // Reconcile calls this every tick; only a real content change may
        // re-arm the datapath dirty flag, otherwise the loop re-attaches
        // forever and wipes the flow table every interval.
        let changed = save_state_if_changed(cfg, &mut state)?;
        if changed {
            mark_state_dirty();
        }
        Ok(())
    })
}

pub fn replace_runtime_rule_state_by_name(
    cfg: &Config,
    name: &str,
    entry: &RuntimeRuleStateEntry,
    target_group_probe: Option<&HealthProbeConfig>,
) -> Result<()> {
    let _ = delete_listener(cfg, name)?;
    create_runtime_rule_state(cfg, entry, target_group_probe)
}

pub fn expanded_runtime_rule_entries(
    cfg: &Config,
    entry: &RuntimeRuleStateEntry,
) -> Vec<RuntimeRuleStateEntry> {
    let ips = if entry.spec.vip_ips.is_empty() {
        default_external_ips(cfg)
    } else {
        entry
            .spec
            .vip_ips
            .iter()
            .map(|ip| ip.trim().to_string())
            .filter(|ip| !ip.is_empty())
            .collect()
    };
    let protocols = if entry.protocols.is_empty() {
        vec![entry.spec.protocol.clone()]
    } else {
        entry.protocols.clone()
    };
    ips.into_iter()
        .flat_map(|ip| {
            protocols.iter().map(move |protocol| {
                let mut next = entry.clone();
                next.spec.vip_ips = vec![ip.clone()];
                next.spec.protocol = protocol.clone();
                next.protocols = vec![protocol.clone()];
                next
            })
        })
        .collect()
}

pub fn delete_listener(cfg: &Config, name: &str) -> Result<bool> {
    with_state_lock(|| {
        let mut state = load_state(cfg)?;
        let before = state.listeners.len();
        state.listeners.retain(|lb| listener_name(lb) != name);
        let changed = before != state.listeners.len();
        if changed {
            save_state(cfg, &state)?;
            mark_state_dirty();
        }
        Ok(changed)
    })
}

pub fn delete_runtime_rule(cfg: &Config, svc: &Service) -> Result<()> {
    let _ = delete_listener(cfg, &svc.name)?;
    Ok(())
}

pub fn upsert_target_group(cfg: &Config, group: &TargetGroup) -> Result<()> {
    if let Ok(repository) = crate::storage::repository() {
        let mut groups = repository
            .get("target_groups", "config")?
            .map(|payload| serde_json::from_str::<Vec<TargetGroup>>(&payload))
            .transpose()
            .context("parsing stored target groups")?
            .unwrap_or_else(|| target_groups_from_config(cfg).unwrap_or_default());
        if let Some(existing) = groups
            .iter_mut()
            .find(|existing| existing.name == group.name)
        {
            *existing = group.clone();
        } else {
            groups.push(group.clone());
        }
        repository.put(
            "target_groups",
            "config",
            crate::storage::next_revision(),
            serde_json::to_string(&groups).context("encoding target groups")?,
        )?;
    }
    mark_state_dirty();
    Ok(())
}

pub fn delete_target_group(_cfg: &Config, name: &str) -> Result<bool> {
    with_state_lock(|| {
        let mut db_changed = false;
        if let Ok(repository) = crate::storage::repository()
            && let Some(payload) = repository.get("target_groups", "config")?
        {
            let mut groups: Vec<TargetGroup> =
                serde_json::from_str(&payload).context("parsing stored target groups")?;
            let before = groups.len();
            groups.retain(|group| group.name != name);
            if before != groups.len() {
                repository.put(
                    "target_groups",
                    "config",
                    crate::storage::next_revision(),
                    serde_json::to_string(&groups).context("encoding target groups")?,
                )?;
                db_changed = true;
            }
        }
        if db_changed {
            mark_state_dirty();
        }
        Ok(db_changed)
    })
}

pub fn create_or_update_listener(cfg: &Config, listener: &Listener) -> Result<()> {
    let group = cfg
        .target_groups
        .iter()
        .find(|group| group.name == listener.target_group)
        .with_context(|| format!("target group {} not found", listener.target_group))?;
    for entry in listener_entries(cfg, listener, group)? {
        create_runtime_rule_state(cfg, &entry, target_group_probe(group).as_ref())?;
    }
    Ok(())
}

pub fn ensure_runtime_rule(cfg: &Config, svc: &Service) -> Result<&'static str> {
    for entry in service_entries(cfg, svc)? {
        create_runtime_rule_state(cfg, &entry, service_probe(svc).as_ref())?;
    }
    Ok("updated")
}

pub fn desired_runtime_rules(cfg: &Config, svc: &Service) -> Vec<ManagedRuntimeRule> {
    let mut out = Vec::new();
    for protocol in svc.protocols() {
        for vip_ips in default_external_ips(cfg) {
            let endpoints = cfg
                .service_endpoints(svc)
                .into_iter()
                .map(|endpoint| ManagedTarget {
                    backend_ip: cfg.resolve_endpoint_address(&endpoint).to_string(),
                    backend_port: endpoint.port,
                    weight: endpoint.weight,
                    probe_type: svc.probe_type.clone(),
                    probe_port: svc.probe_port.or(Some(endpoint.port)),
                    probe_req: svc.probe_req.clone(),
                    probe_resp: svc.probe_resp.clone(),
                    period_secs: svc.period_secs,
                    retries: svc.retries,
                })
                .collect::<Vec<_>>();
            let first = endpoints.first().cloned().unwrap_or_default();
            out.push(ManagedRuntimeRule {
                service: svc.name.clone(),
                vip_ip: vip_ips,
                protocol: protocol.as_str().to_string(),
                vip_port: svc.vip_port,
                backend_port: first.backend_port,
                backend_ip: first.backend_ip,
                backend_weight: first.weight,
                endpoints,
                select: svc.select.code(),
                mode: svc.mode.code(),
                bgp: svc.bgp,
                monitor: svc.monitor,
                inactive_timeout: svc.inactive_timeout,
                mark: svc.mark,
                security: svc.security.map(|s| s.code()),
                host: svc.host.clone(),
                proxy_protocol_v2: svc.proxy_protocol_v2,
                egress: svc.egress,
            });
        }
    }
    out
}

pub fn get_runtime_rules(cfg: &Config) -> Result<Vec<RuntimeRuleEntry>> {
    Ok(runtime_rules_native(cfg)?
        .rules
        .into_iter()
        .map(runtime_rule_entry_from_native)
        .collect())
}

pub fn hydrate_proxy_config_from_api(cfg: &mut Config) -> Result<()> {
    let native_listeners = runtime_rules_native(cfg)?.rules;
    let mut target_groups = BTreeMap::new();
    let mut listeners = Vec::new();
    let mut services = Vec::new();
    for group in target_groups_native(cfg)? {
        target_groups.insert(group.name.clone(), group);
    }
    for lb in native_listeners {
        let args = &lb.spec;
        let name = listener_name(&lb);
        let endpoints = lb
            .targets
            .iter()
            .map(|endpoint| TargetEndpoint {
                backend: None,
                address: endpoint
                    .address
                    .parse()
                    .unwrap_or_else(|_| "0.0.0.0".parse().unwrap()),
                port: endpoint.target_port,
                weight: endpoint.weight.max(1),
            })
            .collect::<Vec<_>>();
        let generated_target_group = format!("{name}-targets");
        let target_group = target_groups
            .get(&generated_target_group)
            .map(|group| group.name.clone())
            .or_else(|| {
                target_groups
                    .values()
                    .find(|group| target_group_matches(group, args, &endpoints))
                    .map(|group| group.name.clone())
            })
            .unwrap_or_else(|| generated_target_group.clone());
        target_groups
            .entry(target_group.clone())
            .or_insert_with(|| TargetGroup {
                name: target_group.clone(),
                monitor: args.monitor,
                probe_type: args.probetype.clone(),
                probe_port: args.probeport,
                probe_req: args.probereq.clone(),
                probe_resp: args.proberesp.clone(),
                probe_status: None,
                probe_skip_tls_verify: false,
                period_secs: args.probe_timeout,
                retries: args.probe_retries,
                targets: endpoints
                    .iter()
                    .map(|endpoint| crate::config::BackendTarget {
                        backend: None,
                        address: endpoint.address,
                        weight: endpoint.weight,
                    })
                    .collect(),
            });
        let protocols = protocols_from_entry(&lb);
        listeners.push(Listener {
            name: name.clone(),
            port: args.port,
            target_port: endpoints.first().map(|endpoint| endpoint.port).unwrap_or(0),
            target_group: target_group.clone(),
            vip_ips: args
                .vip_ips
                .iter()
                .filter_map(|ip| ip.parse().ok())
                .collect(),
            protocols: protocols.clone(),
            select: select_from_code(args.sel),
            mode: mode_from_code(args.mode),
            bgp: args.bgp,
            inactive_timeout: (args.inactive_timeout != 0).then_some(args.inactive_timeout),
            mark: (args.block != 0).then_some(args.block),
            security: None,
            host: args.host.clone(),
            proxy_protocol_v2: args.proxyprotocolv2,
            egress: args.egress,
        });
        if let Some(first) = endpoints.first() {
            services.push(Service {
                name,
                vip_port: args.port,
                target_group: Some(target_group),
                backend_ip: first.address,
                backend_port: first.port,
                backend_weight: first.weight,
                select: select_from_code(args.sel),
                mode: mode_from_code(args.mode),
                bgp: args.bgp,
                monitor: args.monitor,
                probe_type: args.probetype.clone(),
                probe_port: args.probeport,
                probe_req: args.probereq.clone(),
                probe_resp: args.proberesp.clone(),
                period_secs: args.probe_timeout,
                retries: args.probe_retries,
                inactive_timeout: (args.inactive_timeout != 0).then_some(args.inactive_timeout),
                mark: (args.block != 0).then_some(args.block),
                host: args.host.clone(),
                proxy_protocol_v2: args.proxyprotocolv2,
                egress: args.egress,
                protocols,
                endpoints,
                ..Service::default()
            });
        }
    }
    cfg.file.target_groups = target_groups.into_values().collect();
    cfg.file.listeners = listeners;
    cfg.file.services = services;
    Ok(())
}

fn target_group_matches(
    group: &TargetGroup,
    args: &RuntimeRuleSpec,
    endpoints: &[TargetEndpoint],
) -> bool {
    group.monitor == args.monitor
        && group.probe_type.as_deref() == args.probetype.as_deref()
        && group.probe_port == args.probeport
        && group.probe_req.as_deref() == args.probereq.as_deref()
        && group.probe_resp.as_deref() == args.proberesp.as_deref()
        && group
            .targets
            .iter()
            .map(|target| (target.address, target.weight))
            .eq(endpoints
                .iter()
                .map(|endpoint| (endpoint.address, endpoint.weight)))
}

pub fn default_external_ip(cfg: &Config) -> String {
    default_external_ips(cfg)
        .into_iter()
        .next()
        .unwrap_or_else(|| cfg.network().gateway_ip.to_string())
}

fn default_external_ips(cfg: &Config) -> Vec<String> {
    crate::provider::native::effective_vip_ips(cfg, &[])
        .map(|values| values.into_iter().map(|value| value.to_string()).collect())
        .unwrap_or_else(|_| vec![cfg.network().gateway_ip.to_string()])
}

fn service_entries(cfg: &Config, svc: &Service) -> Result<Vec<RuntimeRuleStateEntry>> {
    let endpoints = cfg
        .service_endpoints(svc)
        .into_iter()
        .map(|endpoint| RuntimeRuleTarget {
            address: cfg.resolve_endpoint_address(&endpoint).to_string(),
            target_port: endpoint.port,
            weight: endpoint.weight,
            state: Some("active".to_string()),
            counter: Some("0:0".to_string()),
        })
        .collect::<Vec<_>>();
    // A business listener is one resource even when it serves both TCP and
    // UDP. Keep the protocol list on that resource; the native datapath
    // expands it into protocol-specific lookup keys at attach time. Writing
    // one entry per protocol here would make the later entry replace the
    // former one in the canonical state, so a tcp+udp listener would end up
    // serving only whichever protocol happened to be written last.
    let protocols = svc.protocols();
    let first_protocol = protocols
        .first()
        .copied()
        .context("service must select at least one protocol")?;
    let mut entry = RuntimeRuleStateEntry {
        spec: spec(
            &svc.name,
            svc.vip_port,
            first_protocol,
            svc.select.code(),
            svc.mode.code(),
            svc.monitor,
            svc.inactive_timeout.unwrap_or(240),
        ),
        targets: endpoints,
        protocols: protocols
            .iter()
            .map(|protocol| protocol.as_str().to_string())
            .collect(),
    };
    entry.spec.vip_ips = default_external_ips(cfg);
    if let Some(probe) = service_probe(svc) {
        entry.spec.probetype = probe.probe_type;
        entry.spec.probeport = probe.probe_port;
        entry.spec.probereq = probe.probe_req;
        entry.spec.proberesp = probe.probe_resp;
        entry.spec.probe_timeout = probe.probe_duration;
        entry.spec.probe_retries = probe.inactive_retries;
    }
    Ok(vec![entry])
}

fn listener_entries(
    cfg: &Config,
    listener: &Listener,
    group: &TargetGroup,
) -> Result<Vec<RuntimeRuleStateEntry>> {
    if listener.target_port == 0 {
        bail!(
            "listener {} target_port must be in range 1..=65535",
            listener.name
        );
    }
    let endpoints = group
        .targets
        .iter()
        .map(|endpoint| RuntimeRuleTarget {
            address: cfg.resolve_backend_target_address(endpoint).to_string(),
            // Target groups own backend membership and health probing. The
            // listener owns the forwarding port, so a backend target
            // may legitimately have no port of its own.
            target_port: listener.target_port,
            weight: endpoint.weight,
            state: Some("active".to_string()),
            counter: Some("0:0".to_string()),
        })
        .collect::<Vec<_>>();
    // A target group may be empty while automation is waiting for a matching
    // backend. Keep the listener configuration valid; the native datapath
    // will install no forwarding entry until a target is available.
    let protocol = listener
        .protocols
        .first()
        .copied()
        .context("listener must select at least one protocol")?;
    let mut args = spec(
        &listener.name,
        listener.port,
        protocol,
        listener.select.code(),
        listener.mode.code(),
        group.monitor,
        listener.inactive_timeout.unwrap_or(240),
    );
    args.probetype = group.probe_type.clone();
    args.probeport = group.probe_port;
    args.probereq = group.probe_req.clone();
    args.proberesp = group.probe_resp.clone();
    args.probe_timeout = group.period_secs;
    args.probe_retries = group.retries;
    Ok(vec![RuntimeRuleStateEntry {
        spec: args,
        protocols: listener
            .protocols
            .iter()
            .map(|protocol| protocol.as_str().to_string())
            .collect(),
        targets: endpoints,
    }])
}

fn spec(
    name: &str,
    port: u16,
    protocol: Protocol,
    select: u32,
    mode: u32,
    monitor: bool,
    inactive_timeout: u32,
) -> RuntimeRuleSpec {
    RuntimeRuleSpec {
        vip_ips: Vec::new(),
        port,
        protocol: protocol.as_str().to_string(),
        sel: select,
        mode,
        monitor,
        inactive_timeout,
        name: Some(name.to_string()),
        ..RuntimeRuleSpec::default()
    }
}

fn target_group_probe(group: &TargetGroup) -> Option<HealthProbeConfig> {
    group.monitor.then(|| HealthProbeConfig {
        probe_type: group.probe_type.clone(),
        probe_port: group.probe_port,
        probe_req: group.probe_req.clone(),
        probe_resp: group.probe_resp.clone(),
        expected_status: group.probe_status,
        skip_tls_verify: group.probe_skip_tls_verify,
        probe_duration: group.period_secs,
        inactive_retries: group.retries,
    })
}

fn service_probe(svc: &Service) -> Option<HealthProbeConfig> {
    svc.monitor.then(|| HealthProbeConfig {
        probe_type: svc.probe_type.clone(),
        probe_port: svc.probe_port,
        probe_req: svc.probe_req.clone(),
        probe_resp: svc.probe_resp.clone(),
        expected_status: svc.probe_status,
        skip_tls_verify: svc.probe_skip_tls_verify,
        probe_duration: svc.period_secs,
        inactive_retries: svc.retries,
    })
}

fn ensure_probe_health_records(
    state: &mut NativeProxyState,
    lb: &RuntimeRuleStateEntry,
    probe: &HealthProbeConfig,
) {
    let protocols = listener_protocols(lb);
    for protocol in protocols {
        for endpoint in &lb.targets {
            let probe_type = probe
                .probe_type
                .as_deref()
                .unwrap_or(&protocol)
                .to_ascii_lowercase();
            let probe_port = probe.probe_port.unwrap_or(endpoint.target_port);
            let name = target_health_key(&endpoint.address, &protocol, endpoint.target_port);
            // Preserve observed health from the probe worker (see
            // ensure_default_health_records).
            let current_state = state
                .target_health
                .iter()
                .find(|item| item.name == name)
                .and_then(|item| item.current_state.clone())
                .unwrap_or_else(|| "unknown".to_string());
            upsert_health_entry(
                &mut state.target_health,
                TargetHealthEntry {
                    host_name: endpoint.address.clone(),
                    name,
                    inactive_retries: probe.inactive_retries,
                    probe_type: Some(probe_type),
                    probe_req: probe.probe_req.clone(),
                    probe_resp: probe.probe_resp.clone(),
                    probe_duration: probe.probe_duration,
                    probe_port: Some(probe_port),
                    current_state: Some(current_state),
                    ..TargetHealthEntry::default()
                },
            );
        }
    }
}

fn ensure_default_health_records(state: &mut NativeProxyState, lb: &RuntimeRuleStateEntry) {
    let protocols = listener_protocols(lb);
    for protocol in protocols {
        for endpoint in &lb.targets {
            let name = target_health_key(&endpoint.address, &protocol, endpoint.target_port);
            // Keep observed health from the probe worker; reconcile must not
            // reset it, or state content (and the dirty flag) flaps every tick.
            let current_state = state
                .target_health
                .iter()
                .find(|item| item.name == name)
                .and_then(|item| item.current_state.clone())
                .unwrap_or_else(|| "ok".to_string());
            upsert_health_entry(
                &mut state.target_health,
                TargetHealthEntry {
                    host_name: endpoint.address.clone(),
                    name,
                    inactive_retries: Some(0),
                    probe_type: Some("none".to_string()),
                    probe_duration: Some(0),
                    probe_port: Some(endpoint.target_port),
                    current_state: Some(current_state),
                    ..TargetHealthEntry::default()
                },
            );
        }
    }
}

fn listener_protocols(lb: &RuntimeRuleStateEntry) -> Vec<String> {
    if lb.protocols.is_empty() {
        vec![lb.spec.protocol.to_ascii_lowercase()]
    } else {
        lb.protocols
            .iter()
            .map(|protocol| protocol.to_ascii_lowercase())
            .collect()
    }
}

fn normalize_entry(entry: &mut RuntimeRuleStateEntry) {
    entry.spec.protocol = entry.spec.protocol.to_ascii_lowercase();
    if entry.protocols.is_empty() {
        entry.protocols = vec![entry.spec.protocol.clone()];
    } else {
        entry.protocols = entry
            .protocols
            .iter()
            .map(|protocol| protocol.to_ascii_lowercase())
            .collect();
        entry.protocols.dedup();
        if let Some(protocol) = entry.protocols.first() {
            entry.spec.protocol = protocol.clone();
        }
    }
    entry.spec.vip_ips.retain_mut(|ip| {
        *ip = ip.trim().to_string();
        !ip.is_empty()
    });
    if entry.spec.inactive_timeout == 0 {
        entry.spec.inactive_timeout = 240;
    }
    for endpoint in &mut entry.targets {
        endpoint.weight = endpoint.weight.max(1);
        endpoint.state.get_or_insert_with(|| "active".to_string());
        endpoint.counter.get_or_insert_with(|| "0:0".to_string());
    }
}

fn merge_protocols(existing: &mut RuntimeRuleStateEntry, incoming: &RuntimeRuleStateEntry) {
    let existing_protocols = if existing.protocols.is_empty() {
        vec![existing.spec.protocol.clone()]
    } else {
        existing.protocols.clone()
    };
    let incoming_protocols = if incoming.protocols.is_empty() {
        vec![incoming.spec.protocol.clone()]
    } else {
        incoming.protocols.clone()
    };
    existing.protocols = existing_protocols;
    for protocol in incoming_protocols {
        if !existing
            .protocols
            .iter()
            .any(|current| current.eq_ignore_ascii_case(&protocol))
        {
            existing.protocols.push(protocol.to_ascii_lowercase());
        }
    }
    if is_generated_listener_name(existing.spec.name.as_deref(), existing.spec.port)
        && is_generated_listener_name(incoming.spec.name.as_deref(), incoming.spec.port)
    {
        existing.spec.name = Some(format!(
            "{}-{}",
            existing.protocols.join("-"),
            existing.spec.port
        ));
    }
}

fn is_generated_listener_name(name: Option<&str>, port: u16) -> bool {
    let Some(name) = name.map(str::trim) else {
        return true;
    };
    ["tcp", "udp", "tcp-udp", "udp-tcp"].iter().any(|protocol| {
        name == format!("{protocol}-{port}") || name == format!("auto-{protocol}-{port}")
    })
}

fn upsert_listener_entry(items: &mut Vec<RuntimeRuleStateEntry>, entry: RuntimeRuleStateEntry) {
    let name = listener_name(&entry);
    items.retain(|item| !(listener_name(item) == name && same_service_key(item, &entry)));
    items.push(entry);
}

fn upsert_health_entry(items: &mut Vec<TargetHealthEntry>, entry: TargetHealthEntry) {
    if let Some(existing) = items.iter_mut().find(|item| item.name == entry.name) {
        *existing = entry;
    } else {
        items.push(entry);
    }
}

fn listener_name(lb: &RuntimeRuleStateEntry) -> String {
    lb.spec
        .name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let protocols = if lb.protocols.is_empty() {
                vec![lb.spec.protocol.clone()]
            } else {
                lb.protocols.clone()
            };
            format!("{}-{}", protocols.join("-"), lb.spec.port)
        })
}

fn target_health_key(ip: &str, protocol: &str, port: u16) -> String {
    format!(
        "{}_{}_{}",
        ip.trim(),
        protocol.trim().to_ascii_lowercase(),
        port
    )
}

fn same_service_key(a: &RuntimeRuleStateEntry, b: &RuntimeRuleStateEntry) -> bool {
    let a = &a.spec;
    let b = &b.spec;
    a.vip_ips == b.vip_ips
        && a.port == b.port
        && a.protocol.eq_ignore_ascii_case(&b.protocol)
        && a.host.as_deref().unwrap_or("").trim() == b.host.as_deref().unwrap_or("").trim()
}

fn same_listener_identity(a: &RuntimeRuleStateEntry, b: &RuntimeRuleStateEntry) -> bool {
    let a = &a.spec;
    let b = &b.spec;
    a.vip_ips
        .iter()
        .any(|ip| b.vip_ips.iter().any(|other| ip == other))
        && a.port == b.port
        && a.host.as_deref().unwrap_or("").trim() == b.host.as_deref().unwrap_or("").trim()
        && (a.name.as_deref().unwrap_or("").trim() == b.name.as_deref().unwrap_or("").trim()
            || (is_generated_listener_name(a.name.as_deref(), a.port)
                && is_generated_listener_name(b.name.as_deref(), b.port)))
}

fn runtime_rule_entry_from_native(item: RuntimeRuleStateEntry) -> RuntimeRuleEntry {
    let args = item.spec;
    let endpoints = item
        .targets
        .iter()
        .map(|endpoint| ManagedTarget {
            backend_ip: endpoint.address.clone(),
            backend_port: endpoint.target_port,
            weight: endpoint.weight,
            ..ManagedTarget::default()
        })
        .collect::<Vec<_>>();
    let first = endpoints.first().cloned().unwrap_or_default();
    RuntimeRuleEntry {
        name: args.name,
        vip_ip: args.vip_ips.first().cloned().unwrap_or_default(),
        protocol: args.protocol,
        vip_port: args.port,
        backend_port: first.backend_port,
        backend_ip: first.backend_ip,
        backend_weight: first.weight,
        endpoints,
        select: args.sel,
        mode: args.mode,
        bgp: args.bgp,
        monitor: args.monitor,
        inactive_timeout: (args.inactive_timeout != 0).then_some(args.inactive_timeout),
        mark: (args.block != 0).then_some(args.block),
        security: args.security,
        host: args.host,
        proxy_protocol_v2: args.proxyprotocolv2,
        egress: args.egress,
    }
}

fn select_from_code(value: u32) -> crate::config::LbSelect {
    match value {
        edge_lb_common::NATIVE_SELECT_HASH => crate::config::LbSelect::Hash,
        edge_lb_common::NATIVE_SELECT_PRIORITY => crate::config::LbSelect::Priority,
        edge_lb_common::NATIVE_SELECT_PERSIST => crate::config::LbSelect::Persist,
        edge_lb_common::NATIVE_SELECT_LC => crate::config::LbSelect::Lc,
        _ => crate::config::LbSelect::Rr,
    }
}

fn mode_from_code(value: u32) -> crate::config::LbMode {
    match value {
        1 => crate::config::LbMode::Onearm,
        2 => crate::config::LbMode::Fullnat,
        3 => crate::config::LbMode::Dsr,
        4 => crate::config::LbMode::Fullproxy,
        5 => crate::config::LbMode::Hostonearm,
        _ => crate::config::LbMode::Default,
    }
}

fn protocol_from_str(value: &str) -> Option<Protocol> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tcp" => Some(Protocol::Tcp),
        "udp" => Some(Protocol::Udp),
        _ => None,
    }
}

fn protocols_from_entry(entry: &RuntimeRuleStateEntry) -> Vec<Protocol> {
    let values = if entry.protocols.is_empty() {
        std::slice::from_ref(&entry.spec.protocol)
    } else {
        entry.protocols.as_slice()
    };
    let mut protocols = Vec::new();
    for value in values {
        if let Some(protocol) = protocol_from_str(value)
            && !protocols.contains(&protocol)
        {
            protocols.push(protocol);
        }
    }
    protocols
}

fn push_unique(items: &mut Vec<String>, value: String) {
    if !items.iter().any(|item| item == &value) {
        items.push(value);
    }
}

fn load_state(_cfg: &Config) -> Result<NativeProxyState> {
    match crate::storage::repository()?.get("native_proxy_state", "config")? {
        Some(payload) => {
            serde_json::from_str(&payload).context("parsing stored native proxy state")
        }
        None => Ok(NativeProxyState::default()),
    }
}

fn save_state(_cfg: &Config, state: &NativeProxyState) -> Result<()> {
    let payload = serde_json::to_string(state).context("serializing native proxy state")?;
    crate::storage::repository()?.put(
        "native_proxy_state",
        "config",
        crate::storage::next_revision(),
        payload,
    )
}

/// Serialize and write only when the canonical form differs from disk;
/// returns whether a write happened.
fn save_state_if_changed(_cfg: &Config, state: &mut NativeProxyState) -> Result<bool> {
    let text = serde_json::to_string_pretty(&*state).context("serializing native proxy state")?;
    if let Some(existing) = crate::storage::repository()?.get("native_proxy_state", "config")? {
        // Compare decoded state rather than JSON formatting. Formatting-only
        // differences must never re-arm the gateway datapath reconcile loop.
        if serde_json::from_str::<NativeProxyState>(&existing)
            .map(|current| current == *state)
            .unwrap_or(false)
        {
            return Ok(false);
        }
    }
    crate::storage::repository()?.put(
        "native_proxy_state",
        "config",
        crate::storage::next_revision(),
        text,
    )?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_listener_expands_to_both_transport_keys() {
        let entry = RuntimeRuleStateEntry {
            spec: RuntimeRuleSpec {
                vip_ips: vec!["192.0.2.10".to_string()],
                port: 9999,
                protocol: "tcp".to_string(),
                ..RuntimeRuleSpec::default()
            },
            protocols: vec!["tcp".to_string(), "udp".to_string()],
            ..RuntimeRuleStateEntry::default()
        };

        let expanded = expanded_runtime_rule_entries(
            &Config {
                file: crate::config::FileConfig::default(),
                path: crate::config::DEFAULT_CONFIG_PATH.into(),
            },
            &entry,
        );

        assert_eq!(expanded.len(), 2);
        assert_eq!(expanded[0].spec.protocol, "tcp");
        assert_eq!(expanded[1].spec.protocol, "udp");
        assert_eq!(expanded[0].protocols, vec!["tcp"]);
        assert_eq!(expanded[1].protocols, vec!["udp"]);
    }
}
