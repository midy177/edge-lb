//! Gateway node: VXLAN termination, native datapath rules, DSCP marking and UI/API.

use std::{
    fs,
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};

use crate::{
    api,
    config::Config,
    control,
    linux::{
        dscp,
        net::{self, VxlanSpec},
        privilege,
    },
    provider::native,
    runtime::{discovery, shutdown, state::AgentState},
};

#[derive(Default)]
pub struct ApplyOptions {
    pub object: Option<std::path::PathBuf>,
    pub native_prog_id: Option<u32>,
}

pub fn apply(cfg: &Config, opts: &ApplyOptions) -> Result<()> {
    apply_inner(cfg, opts, DscpAttachMode::Persistent).map(|_| ())
}

#[derive(Clone, Copy)]
enum DscpAttachMode {
    Persistent,
    Managed,
}

enum DscpUpdate {
    Keep,
    Replace(dscp::DscpAttachment),
    Clear,
}

fn apply_inner(cfg: &Config, opts: &ApplyOptions, mode: DscpAttachMode) -> Result<DscpUpdate> {
    privilege::require_root()?;
    let _ = opts.native_prog_id;
    let n = cfg.network();
    let g = cfg.gateway_cfg();
    let backend_peers = control::active_backend_nodes(cfg)
        .unwrap_or_else(|e| {
            tracing::warn!("[gateway] active backend peer lookup skipped: {e:#}");
            Vec::new()
        })
        .into_iter()
        .filter(|b| !b.underlay_ip.is_unspecified())
        .map(|b| b.underlay_ip)
        .collect::<Vec<_>>();
    tracing::info!(
        "[gateway] apply node={} active={} hub_dev={} underlay_dev={} underlay_ip={} public_ip={} overlay={} overlay_cidr={} vni={} vxlan_port={} mtu={} dscp={} runtime_listeners={} backend_peers={}",
        cfg.node_name,
        is_active_gateway(cfg),
        n.vxlan_dev,
        n.underlay_dev,
        cfg.underlay_ip,
        cfg.public_ip,
        g.overlay_ip,
        n.overlay_cidr,
        n.vni,
        n.vxlan_port,
        n.vxlan_mtu,
        n.dscp,
        cfg.services.len(),
        backend_peers.len(),
    );
    warn_if_underlay_xdp_present(cfg, &[]);

    // Native DNAT rewrites the destination before route lookup; forwarding is
    // required and capacity knobs are raised conservatively for production.
    crate::linux::sysctl::ensure_gateway_datapath_tuning()
        .with_context(|| "applying gateway datapath sysctl tuning")?;

    // 1. VXLAN toward backend peers.
    let spec = VxlanSpec {
        dev: &n.vxlan_dev,
        vni: n.vni,
        dstport: n.vxlan_port,
        remote: None,
        underlay_dev: &n.underlay_dev,
        local_addr: &g.overlay_ip,
        mtu: n.vxlan_mtu,
    };
    let created = net::ensure_vxlan(&spec)?;
    if created {
        tracing::info!(
            "[gateway] {} created (multipoint remote vni {} dstport {})",
            n.vxlan_dev,
            n.vni,
            n.vxlan_port
        );
    } else {
        tracing::debug!(
            "[gateway] {} already present (multipoint remote vni {} dstport {})",
            n.vxlan_dev,
            n.vni,
            n.vxlan_port
        );
    }
    net::sync_vxlan_peers(&n.vxlan_dev, &backend_peers)?;
    net::set_accept_local(&n.vxlan_dev, true)?;
    tracing::debug!(
        "[gateway] enabled accept_local on {} for native reverse DNAT VIP replies",
        n.vxlan_dev
    );
    tracing::debug!(
        "[gateway] vxlan peers synced on {}: {backend_peers:?}",
        n.vxlan_dev
    );

    let mut state = AgentState::load(Path::new(&*cfg.state_dir))?;
    state.created_vxlan = created;

    let mut service_cfg = cfg.clone();
    let hydrated = match native::hydrate_proxy_config_from_api(&mut service_cfg) {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!("[gateway] loading native proxy state failed: {e:#}");
            service_cfg = cfg.clone();
            false
        }
    };
    if let Err(error) = restore_business_listeners(&mut service_cfg) {
        tracing::warn!("[gateway] restoring SQLite listeners skipped: {error:#}");
    }

    // 4. Listener runtime rules. DSCP return-path marking is derived later only from
    // default-mode listeners because they preserve real client IPs.
    for svc in &service_cfg.services {
        if service_cfg.service_endpoints(svc).iter().any(|endpoint| {
            service_cfg
                .resolve_endpoint_address(endpoint)
                .is_unspecified()
        }) {
            tracing::warn!(
                "[gateway] service {} skipped: unresolved endpoint (target_group={} vip_port={} protocols={:?})",
                svc.name,
                svc.target_group.as_deref().unwrap_or("unbound"),
                svc.vip_port,
                svc.protocols()
            );
            continue;
        }
        match native::ensure_runtime_rule(&service_cfg, svc)? {
            "created" => tracing::info!("[gateway] listener rule created for {}", svc.name),
            "updated" => tracing::debug!("[gateway] listener rule reconciled for {}", svc.name),
            _ => tracing::debug!("[gateway] listener rule unchanged for {}", svc.name),
        }
    }
    let mut ports = dscp_ports(&service_cfg);
    if ports.is_empty() && !hydrated {
        ports = state.dscp_ports.clone();
        ports.sort_unstable();
        ports.dedup();
    } else {
        state.dscp_ports = ports.clone();
    }

    state.vxlan_ifindex = net::ifindex(&n.vxlan_dev).ok();

    // Both datapaths pin into bpffs; wait for the mount once, before either
    // attaches (native DNAT used to run first and fail during boot races).
    dscp::wait_for_bpffs(Duration::from_secs(10))?;

    // 2. Native default-DNAT datapath. It owns the listener and target maps,
    // while the DSCP marker remains a separate classifier in this phase.
    if service_cfg.services.is_empty() {
        crate::linux::native_dnat::cleanup(&service_cfg).ok();
        tracing::info!("[gateway] native DNAT detached: no listeners configured");
    } else {
        crate::linux::native_dnat::apply(&service_cfg)
            .with_context(|| "applying native DNAT datapath")?;
        tracing::debug!("[gateway] native DNAT datapath reconciled and maps refreshed");
    }

    // 3. DSCP marker at underlay ingress. Native DNAT will take ownership of
    // DSCP writing after return-path integration is complete.
    let dscp_update = if ports.is_empty() {
        dscp::detach(cfg, &n.underlay_dev).ok();
        tracing::info!(
            "[gateway] dscp marker detached from {} ingress: no listener ports configured",
            n.underlay_dev
        );
        DscpUpdate::Clear
    } else {
        let managed = match mode {
            DscpAttachMode::Persistent => {
                dscp::attach(cfg, &n.underlay_dev, n.dscp, &ports, opts.object.as_deref())
                    .with_context(|| "attaching DSCP marker")?;
                None
            }
            DscpAttachMode::Managed => {
                if dscp::attached(cfg, &n.underlay_dev) && dscp::maps_match_current_abi(cfg) {
                    match dscp::set(cfg, n.dscp, &ports) {
                        Ok(()) => None,
                        Err(error) => {
                            tracing::warn!(
                                "[gateway] DSCP map refresh failed; reloading marker: {error:#}"
                            );
                            Some(
                                dscp::attach_owned(
                                    cfg,
                                    &n.underlay_dev,
                                    n.dscp,
                                    &ports,
                                    opts.object.as_deref(),
                                )
                                .with_context(|| "attaching DSCP marker")?,
                            )
                        }
                    }
                } else {
                    Some(
                        dscp::attach_owned(
                            cfg,
                            &n.underlay_dev,
                            n.dscp,
                            &ports,
                            opts.object.as_deref(),
                        )
                        .with_context(|| "attaching DSCP marker")?,
                    )
                }
            }
        };
        let action = if managed.is_some() {
            "attached"
        } else if matches!(mode, DscpAttachMode::Managed) {
            "reused"
        } else {
            "attached"
        };
        tracing::info!(
            "[gateway] dscp marker {action} on {} ingress pref {} (dscp {} ports {ports:?})",
            n.underlay_dev,
            dscp::pref(cfg),
            n.dscp
        );
        managed.map(DscpUpdate::Replace).unwrap_or(DscpUpdate::Keep)
    };

    state.save(Path::new(&*cfg.state_dir))?;
    Ok(dscp_update)
}

fn restore_business_listeners(cfg: &mut Config) -> Result<()> {
    let listeners = crate::api::load_persisted_listeners(cfg)?;
    if listeners.is_empty() {
        return Ok(());
    }
    let groups = native::target_groups_native(cfg)?;
    cfg.file.target_groups = groups.clone();
    cfg.file.services.clear();
    for listener in listeners {
        let Some(group) = groups
            .iter()
            .find(|group| group.name == listener.target_group)
        else {
            tracing::warn!(
                "[gateway] listener {} skipped: target group {} not found",
                listener.name,
                listener.target_group
            );
            continue;
        };
        let endpoints = group
            .targets
            .iter()
            .map(|target| crate::config::TargetEndpoint {
                backend: target.backend.clone(),
                address: cfg.resolve_backend_target_address(target),
                port: listener.target_port,
                weight: target.weight,
            })
            .collect::<Vec<_>>();
        let Some(first) = endpoints.first() else {
            continue;
        };
        cfg.file.services.push(crate::config::Service {
            name: listener.name,
            vip_port: listener.port,
            target_group: Some(group.name.clone()),
            backend: first.backend.clone(),
            backend_ip: first.address,
            backend_port: first.port,
            backend_weight: first.weight,
            select: listener.select,
            mode: listener.mode,
            monitor: group.monitor,
            probe_type: group.probe_type.clone(),
            probe_port: group.probe_port,
            probe_req: group.probe_req.clone(),
            probe_resp: group.probe_resp.clone(),
            probe_status: group.probe_status,
            probe_skip_tls_verify: group.probe_skip_tls_verify,
            period_secs: group.period_secs,
            retries: group.retries,
            inactive_timeout: listener.inactive_timeout,
            protocols: listener.protocols.clone(),
            endpoints,
            ..crate::config::Service::default()
        });
    }
    if !cfg.file.services.is_empty() {
        tracing::info!(
            "[gateway] restored {} listener(s) from SQLite business configuration",
            cfg.file.services.len()
        );
    }
    Ok(())
}

pub fn run(cfg: &Config) -> Result<()> {
    privilege::require_root()?;
    shutdown::install();
    crate::storage::initialize(Path::new(&*cfg.state_dir))?;
    let mut cfg = cfg.clone();
    let _ = control::merge_active_backend_subscriptions(&mut cfg);
    native::ha::reconcile_vip(&cfg).with_context(|| "reconciling HA VIP at startup")?;
    crate::notify::spawn_dispatcher(&cfg);
    let mut dscp_attachment =
        match apply_inner(&cfg, &ApplyOptions::default(), DscpAttachMode::Managed)? {
            DscpUpdate::Replace(attachment) => Some(attachment),
            DscpUpdate::Keep | DscpUpdate::Clear => None,
        };
    match api::reconcile_automations(&cfg) {
        Ok(true) => {
            tracing::info!(
                "[gateway] automation templates changed native proxy state during startup; refreshing datapath"
            );
            drop(dscp_attachment.take());
            dscp_attachment =
                match apply_inner(&cfg, &ApplyOptions::default(), DscpAttachMode::Managed)? {
                    DscpUpdate::Replace(attachment) => Some(attachment),
                    DscpUpdate::Keep | DscpUpdate::Clear => None,
                };
        }
        Ok(false) => {}
        Err(e) => tracing::warn!("[gateway] startup automation reconcile skipped: {e:#}"),
    }
    let mut cached_dscp_ports = AgentState::load(Path::new(&*cfg.state_dir))?.dscp_ports;
    spawn_ui(&cfg);
    spawn_probe_worker(&cfg);
    spawn_flow_sync_worker(&cfg);
    crate::runtime::bfd::spawn(&cfg);
    control::spawn_gateway(&cfg);
    tracing::info!(
        "[gateway] watching for drift ({}s interval); node={} hub_dev={} underlay_dev={} active={} runtime_listeners={} backends={} UI/API listen {}; control-plane {}",
        cfg.ha.watch_interval_secs,
        cfg.node_name,
        cfg.network().vxlan_dev,
        cfg.network().underlay_dev,
        is_active_gateway(&cfg),
        cfg.services.len(),
        control::active_backend_nodes(&cfg)
            .map(|nodes| nodes.len())
            .unwrap_or_default(),
        cfg.api.listen,
        if cfg.control_plane.enabled {
            cfg.control_plane.listen.as_str()
        } else {
            "disabled"
        }
    );
    let mut last_config_mtime = config_mtime(&cfg);
    let mut pending_node_change: Option<Instant> = None;
    while !shutdown::requested() {
        let mut needs_full = false;
        if let Err(error) = native::ha::reconcile_vip(&cfg) {
            tracing::warn!("[gateway] HA VIP reconcile skipped: {error:#}");
        }
        match control::merge_active_backend_subscriptions(&mut cfg) {
            Ok(true) => {
                pending_node_change = Some(Instant::now());
                tracing::info!(
                    "[gateway] active backend subscriptions changed; reconcile debounced for 3s"
                );
            }
            Ok(false) => {}
            Err(e) => tracing::warn!("[gateway] backend subscription merge skipped: {e:#}"),
        }
        if config_mtime(&cfg) != last_config_mtime {
            match crate::config::FileConfig::load_file(&cfg.path) {
                Ok(Some(mut file)) => {
                    if let Err(e) = discovery::resolve_auto_ips(&mut file) {
                        tracing::warn!(
                            "[gateway] config reload skipped: IP auto discovery failed: {e:#}"
                        );
                        sleep(Duration::from_secs(cfg.ha.watch_interval_secs));
                        continue;
                    }
                    crate::runtime::ha::merge_gateway_peers_best_effort(&mut file);
                    if let Err(e) = {
                        cfg.file = file;
                        control::merge_active_backend_subscriptions(&mut cfg)
                    } {
                        tracing::warn!("[gateway] backend subscription merge skipped: {e:#}");
                    }
                    tracing::info!("[gateway] config file changed; reloading and reconciling");
                    needs_full = true;
                    last_config_mtime = config_mtime(&cfg);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("[gateway] config reload skipped: {e:#}"),
            }
        }
        if native::take_state_dirty() {
            tracing::info!("[gateway] native proxy state changed; reconciling datapath");
            needs_full = true;
        }
        if pending_node_change.is_some_and(|started| started.elapsed() >= Duration::from_secs(3)) {
            pending_node_change = None;
            needs_full = true;
            tracing::info!("[gateway] backend node change debounce elapsed; reconciling");
        }
        if !needs_full {
            match heal(&cfg, &cached_dscp_ports) {
                Ok(true) => needs_full = true,
                Ok(false) => {}
                Err(e) => tracing::warn!("[gateway] drift check skipped: {e:#}"),
            }
        }
        if needs_full {
            if dscp_attachment.is_some() && !dscp::attached(&cfg, &cfg.network().underlay_dev) {
                drop(dscp_attachment.take());
            }
            match apply_inner(&cfg, &ApplyOptions::default(), DscpAttachMode::Managed) {
                Ok(DscpUpdate::Replace(attachment)) => {
                    dscp_attachment = Some(attachment);
                    cached_dscp_ports = AgentState::load(Path::new(&*cfg.state_dir))?.dscp_ports;
                }
                Ok(DscpUpdate::Clear) => {
                    dscp_attachment = None;
                    cached_dscp_ports.clear();
                }
                Ok(DscpUpdate::Keep) => {
                    cached_dscp_ports = AgentState::load(Path::new(&*cfg.state_dir))?.dscp_ports;
                }
                Err(e) => tracing::error!("[gateway] apply failed: {e:#}"),
            }
            match api::reconcile_automations(&cfg) {
                Ok(true) => {
                    tracing::info!(
                        "[gateway] automation templates changed native proxy state; refreshing datapath"
                    );
                    if dscp_attachment.is_some()
                        && !dscp::attached(&cfg, &cfg.network().underlay_dev)
                    {
                        drop(dscp_attachment.take());
                    }
                    match apply_inner(&cfg, &ApplyOptions::default(), DscpAttachMode::Managed) {
                        Ok(DscpUpdate::Replace(attachment)) => {
                            dscp_attachment = Some(attachment);
                            cached_dscp_ports =
                                AgentState::load(Path::new(&*cfg.state_dir))?.dscp_ports;
                        }
                        Ok(DscpUpdate::Clear) => {
                            dscp_attachment = None;
                            cached_dscp_ports.clear();
                        }
                        Ok(DscpUpdate::Keep) => {
                            cached_dscp_ports =
                                AgentState::load(Path::new(&*cfg.state_dir))?.dscp_ports;
                        }
                        Err(e) => {
                            tracing::error!("[gateway] apply after automation failed: {e:#}")
                        }
                    }
                }
                Ok(false) => {}
                Err(e) => tracing::warn!("[gateway] automation reconcile skipped: {e:#}"),
            }
        }
        sleep(Duration::from_secs(cfg.ha.watch_interval_secs));
    }
    tracing::info!("[gateway] shutdown requested; handing off HA VIP and detaching datapath");
    if let Err(error) = native::ha::handoff_or_release_on_shutdown(&cfg) {
        tracing::warn!("[gateway] HA shutdown handoff skipped: {error:#}");
    }
    dscp::detach(&cfg, &cfg.network().underlay_dev).ok();
    drop(dscp_attachment);
    crate::linux::native_dnat::cleanup(&cfg).ok();
    Ok(())
}

fn config_mtime(cfg: &Config) -> Option<std::time::SystemTime> {
    fs::metadata(&cfg.path).and_then(|m| m.modified()).ok()
}

fn spawn_ui(cfg: &Config) {
    let cfg = cfg.clone();
    std::thread::Builder::new()
        .name("edge-lb-ui".to_string())
        .stack_size(512 * 1024)
        .spawn(move || {
            if let Err(e) = api::serve(&cfg, None) {
                tracing::error!("[gateway] UI/API server stopped: {e:#}");
            }
        })
        .expect("spawn UI/API thread");
}

/// Target health probing runs on its own thread so the API stays a pure
/// reader of observed state; transitions refresh the native health map.
fn spawn_probe_worker(cfg: &Config) {
    let cfg = cfg.clone();
    std::thread::Builder::new()
        .name("edge-lb-probe".to_string())
        .stack_size(1024 * 1024)
        .spawn(move || native::run_probe_worker(cfg))
        .expect("spawn probe worker thread");
}

/// The MASTER gateway replicates long-lived flows to the backup so HA
/// failover keeps established connections working.
fn spawn_flow_sync_worker(cfg: &Config) {
    let cfg = cfg.clone();
    std::thread::Builder::new()
        .name("edge-lb-flow-sync".to_string())
        .stack_size(1024 * 1024)
        .spawn(move || native::xsync::run_worker(cfg))
        .expect("spawn flow sync worker thread");
}

fn dscp_ports(cfg: &Config) -> Vec<u32> {
    let mut ports = cfg
        .services
        .iter()
        .filter(|svc| svc.mode.preserves_client_ip())
        .map(|s| s.vip_port as u32)
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn warn_if_underlay_xdp_present(cfg: &Config, listener_ports: &[u32]) {
    let _ = (cfg, listener_ports);
}

/// Cheap drift checks between full reconciles.
fn heal(cfg: &Config, cached_dscp_ports: &[u32]) -> Result<bool> {
    if let Err(error) = crate::linux::native_dnat::sweep_flows_and_refresh_loads(cfg) {
        tracing::debug!("[gateway] native flow sweep skipped: {error:#}");
    }
    let n = cfg.network();
    if !net::link_exists(&n.vxlan_dev) || !net::is_up(&n.vxlan_dev) {
        tracing::warn!("[gateway] {} missing or down; re-applying", n.vxlan_dev);
        return Ok(true);
    }
    let ports = cached_dscp_ports;
    if ports.is_empty() {
        if dscp::attached(cfg, &n.underlay_dev) {
            dscp::detach(cfg, &n.underlay_dev).ok();
            tracing::info!(
                "[gateway] dscp marker detached from {} ingress: no listener ports configured",
                n.underlay_dev
            );
        }
        return Ok(false);
    }

    if !dscp::attached(cfg, &n.underlay_dev) {
        tracing::warn!(
            "[gateway] dscp filter lost on {}; re-applying",
            n.underlay_dev
        );
        return Ok(true);
    }
    Ok(false)
}

fn is_active_gateway(cfg: &Config) -> bool {
    cfg.active_gateway()
        .map(|gateway| gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip)
        .unwrap_or(true)
}

pub fn show(cfg: &Config) -> Result<()> {
    crate::storage::initialize(Path::new(&*cfg.state_dir))?;
    let n = cfg.network();
    section("vxlan device");
    println!(
        "{}: exists={} up={} mtu={} remote={:?}",
        n.vxlan_dev,
        net::link_exists(&n.vxlan_dev),
        net::is_up(&n.vxlan_dev),
        net::link_mtu(&n.vxlan_dev).unwrap_or_default(),
        net::vxlan_remote(&n.vxlan_dev)
    );
    section("dscp marker");
    println!(
        "attached={} device={} dscp={}",
        dscp::attached(cfg, &n.underlay_dev),
        n.underlay_dev,
        n.dscp
    );
    section("native listeners");
    println!(
        "{}",
        serde_json::to_string_pretty(&native::runtime_rules_native(cfg)?).unwrap_or_default()
    );
    section("dscp marker stats");
    match dscp::stats(cfg) {
        Ok(s) => println!("matched={} changed={}", s.matched, s.changed),
        Err(e) => println!("(unavailable: {e})"),
    }
    section("desired runtime rules");
    for svc in &cfg.services {
        for lb in native::desired_runtime_rules(cfg, svc) {
            println!(
                "{}: {} {}:{} -> {}:{}",
                svc.name, lb.vip_ip, lb.protocol, lb.vip_port, lb.backend_ip, lb.backend_port
            );
        }
    }
    Ok(())
}

pub struct CleanupOptions {
    pub rules: bool,
    pub datapath: bool,
}

pub fn cleanup(cfg: &Config, opts: &CleanupOptions) -> Result<()> {
    privilege::require_root()?;
    let n = cfg.network();
    // Our DSCP filter only.
    crate::linux::tc::delete_ingress_pref_best_effort(&n.underlay_dev, cfg.gateway_cfg().dscp_pref);
    println!(
        "[gateway] dscp filter removed from {} ingress",
        n.underlay_dev
    );

    dscp::detach(cfg, &n.underlay_dev).ok();
    net::set_accept_local(&n.vxlan_dev, false).ok();
    if opts.datapath {
        crate::linux::native_dnat::cleanup(cfg).ok();
    }

    if opts.rules {
        for svc in &cfg.services {
            native::delete_runtime_rule(cfg, svc).ok();
        }
        println!("[gateway] managed listener rules removed");
    }
    Ok(())
}

fn section(title: &str) {
    println!("\n=== {title} ===");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{FileConfig, LbMode, Protocol, Service};

    #[test]
    fn dscp_ports_include_only_default_mode_listeners() {
        let cfg = Config {
            file: FileConfig {
                services: vec![
                    Service {
                        name: "default".to_string(),
                        vip_port: 48080,
                        protocols: vec![Protocol::Tcp],
                        mode: LbMode::Default,
                        ..Service::default()
                    },
                    Service {
                        name: "onearm".to_string(),
                        vip_port: 48081,
                        protocols: vec![Protocol::Tcp],
                        mode: LbMode::Onearm,
                        ..Service::default()
                    },
                    Service {
                        name: "fullnat".to_string(),
                        vip_port: 48082,
                        protocols: vec![Protocol::Udp],
                        mode: LbMode::Fullnat,
                        ..Service::default()
                    },
                ],
                ..FileConfig::default()
            },
            path: "/tmp/edge-lb-test.toml".into(),
        };

        assert_eq!(dscp_ports(&cfg), vec![48080]);
    }
}
