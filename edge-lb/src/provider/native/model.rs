use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config::{Config, Protocol, Service};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NativeProtocol {
    Tcp,
    Udp,
}

impl NativeProtocol {
    pub fn ip_proto(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}

impl TryFrom<Protocol> for NativeProtocol {
    type Error = anyhow::Error;

    fn try_from(value: Protocol) -> Result<Self> {
        match value {
            Protocol::Tcp => Ok(Self::Tcp),
            Protocol::Udp => Ok(Self::Udp),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NativeListenerKey {
    pub vip_ip: Ipv4Addr,
    pub vip_port: u16,
    pub protocol: NativeProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTarget {
    /// Backend target address in the native datapath map.
    pub address: Ipv4Addr,
    /// Forwarding port owned by the listener configuration.
    pub port: u16,
    pub weight: u32,
    pub state: NativeTargetState,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NativeTargetState {
    #[default]
    Active,
    Inactive,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeListener {
    pub name: String,
    pub key: NativeListenerKey,
    pub select: u32,
    pub inactive_timeout_secs: u32,
    pub dscp: u32,
    pub endpoints: Vec<NativeTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRuleEntry {
    pub name: Option<String>,
    pub vip_ip: String,
    pub protocol: String,
    pub vip_port: u16,
    pub backend_port: u16,
    pub backend_ip: String,
    pub backend_weight: u32,
    pub endpoints: Vec<crate::runtime::state::ManagedTarget>,
    pub select: u32,
    pub mode: u32,
    pub bgp: bool,
    pub monitor: bool,
    pub inactive_timeout: Option<u32>,
    pub mark: Option<u32>,
    pub security: Option<u32>,
    pub host: Option<String>,
    pub proxy_protocol_v2: bool,
    pub egress: bool,
}

pub fn listeners_from_config(cfg: &Config) -> Result<Vec<NativeListener>> {
    if !cfg.listeners.is_empty() {
        let mut out = Vec::new();
        for listener in &cfg.listeners {
            let group = cfg
                .target_groups
                .iter()
                .find(|group| group.name == listener.target_group)
                .with_context(|| {
                    format!(
                        "listener {} references missing target group {}",
                        listener.name, listener.target_group
                    )
                })?;
            out.extend(listener_from_target_group(cfg, listener, group)?);
        }
        return Ok(out);
    }

    // Runtime service entries are an internal projection used by the native
    // datapath when listener/target-group resources have already been
    // materialized.
    let mut out = Vec::new();
    for service in &cfg.services {
        out.extend(listener_from_service(cfg, service)?);
    }
    Ok(out)
}

fn listener_from_target_group(
    cfg: &Config,
    listener: &crate::config::Listener,
    group: &crate::config::TargetGroup,
) -> Result<Vec<NativeListener>> {
    if !listener.mode.preserves_client_ip() {
        bail!(
            "native datapath only supports default DNAT mode for listener {}",
            listener.name
        );
    }

    let endpoints = group
        .targets
        .iter()
        .map(|endpoint| {
            let address = ipv4_addr(cfg.resolve_backend_target_address(endpoint))?;
            Ok(NativeTarget {
                address,
                port: listener.target_port,
                weight: endpoint.weight,
                state: NativeTargetState::Active,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if endpoints.is_empty() {
        // Automatic target groups may legitimately be empty while no backend
        // matches their filter. Keep the control-plane resource, but omit it
        // from the native datapath until a backend appears.
        return Ok(Vec::new());
    }

    let mut listeners = Vec::new();
    let listener_vips = effective_vip_ips(cfg, &listener.vip_ips)?;
    for vip_ip in listener_vips {
        for protocol in &listener.protocols {
            listeners.push(NativeListener {
                name: listener.name.clone(),
                key: NativeListenerKey {
                    vip_ip,
                    vip_port: listener.port,
                    protocol: NativeProtocol::try_from(*protocol)?,
                },
                select: listener.select.code(),
                inactive_timeout_secs: listener.inactive_timeout.unwrap_or(240),
                dscp: cfg.network().dscp,
                endpoints: endpoints.clone(),
            });
        }
    }
    Ok(listeners)
}

pub fn listener_from_service(cfg: &Config, service: &Service) -> Result<Vec<NativeListener>> {
    if !service.mode.preserves_client_ip() {
        bail!(
            "native datapath only supports default DNAT mode for service {}",
            service.name
        );
    }

    let vip_ips = effective_vip_ips(cfg, &[])?;
    let endpoints = cfg
        .service_endpoints(service)
        .into_iter()
        .map(|endpoint| {
            let address = ipv4_addr(cfg.resolve_endpoint_address(&endpoint))?;
            Ok(NativeTarget {
                address,
                port: endpoint.port,
                weight: endpoint.weight,
                state: NativeTargetState::Active,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    if endpoints.is_empty() {
        bail!("service {} needs at least one endpoint", service.name);
    }

    let mut listeners = Vec::new();
    for vip_ip in vip_ips {
        for protocol in service.protocols() {
            let protocol = NativeProtocol::try_from(protocol)?;
            listeners.push(NativeListener {
                name: service.name.clone(),
                key: NativeListenerKey {
                    vip_ip,
                    vip_port: service.vip_port,
                    protocol,
                },
                select: service.select.code(),
                inactive_timeout_secs: service.inactive_timeout.unwrap_or(240),
                dscp: cfg.network().dscp,
                endpoints: endpoints.clone(),
            });
        }
    }
    Ok(listeners)
}

pub fn effective_vip_ips(cfg: &Config, configured: &[IpAddr]) -> Result<Vec<Ipv4Addr>> {
    let gateway = ipv4_addr(cfg.network().gateway_ip)
        .context("native datapath needs an IPv4 gateway address")?;
    let shared = crate::runtime::ha::load_for_state_dir(Path::new(&*cfg.state_dir))
        .ok()
        .filter(|ha| ha.enabled && matches!(ha.vip.provider, crate::runtime::ha::VipProvider::L2))
        .and_then(|ha| ha.vip.private_vip)
        .and_then(|vip| vip.parse::<IpAddr>().ok())
        .and_then(|vip| ipv4_addr(vip).ok());
    merge_vip_ips(gateway, configured, shared)
}

fn merge_vip_ips(
    gateway: Ipv4Addr,
    configured: &[IpAddr],
    shared: Option<Ipv4Addr>,
) -> Result<Vec<Ipv4Addr>> {
    let mut values = vec![gateway];
    for vip in configured {
        let vip = ipv4_addr(*vip)?;
        if !values.contains(&vip) {
            values.push(vip);
        }
    }
    if let Some(vip) = shared
        && !values.contains(&vip)
    {
        values.push(vip);
    }
    Ok(values)
}

fn ipv4_addr(value: IpAddr) -> Result<Ipv4Addr> {
    match value {
        IpAddr::V4(v4) if !v4.is_unspecified() => Ok(v4),
        IpAddr::V4(_) => bail!("IP address must not be 0.0.0.0"),
        IpAddr::V6(v6) => bail!("native datapath does not support IPv6 yet: {v6}"),
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::config::{
        BackendTarget, Config, DEFAULT_CONFIG_PATH, FileConfig, LbMode, Listener, Protocol,
        Service, TargetEndpoint, TargetGroup,
    };

    use super::*;

    #[test]
    fn service_conversion_preserves_default_dnat_shape() {
        let mut cfg = FileConfig::default();
        cfg.network.gateway_ip = "192.0.2.10".parse().unwrap();
        cfg.network.dscp = 46;
        cfg.services.push(Service {
            name: "tcp-8080".to_string(),
            vip_port: 8080,
            protocols: vec![Protocol::Tcp],
            mode: LbMode::Default,
            endpoints: vec![TargetEndpoint {
                backend: None,
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20)),
                port: 18080,
                weight: 3,
            }],
            ..Service::default()
        });

        let cfg = Config {
            file: cfg,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let listeners = listeners_from_config(&cfg).unwrap();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].key.vip_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(listeners[0].key.vip_port, 8080);
        assert_eq!(listeners[0].key.protocol, NativeProtocol::Tcp);
        assert_eq!(listeners[0].dscp, 46);
        assert_eq!(
            listeners[0].endpoints[0].address,
            Ipv4Addr::new(192, 0, 2, 20)
        );
        assert_eq!(listeners[0].endpoints[0].port, 18080);
        assert_eq!(listeners[0].endpoints[0].weight, 3);
    }

    #[test]
    fn non_default_mode_is_rejected() {
        let mut cfg = FileConfig::default();
        cfg.network.gateway_ip = "192.0.2.10".parse().unwrap();
        cfg.services.push(Service {
            name: "fullnat".to_string(),
            vip_port: 8080,
            protocols: vec![Protocol::Tcp],
            mode: LbMode::Fullnat,
            endpoints: vec![TargetEndpoint {
                backend: None,
                address: "192.0.2.20".parse().unwrap(),
                port: 18080,
                weight: 1,
            }],
            ..Service::default()
        });

        let cfg = Config {
            file: cfg,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let err = listeners_from_config(&cfg).unwrap_err().to_string();

        assert!(err.contains("only supports default DNAT"));
    }

    #[test]
    fn empty_target_group_is_not_a_datapath_error() {
        let mut cfg = Config {
            path: std::path::PathBuf::from("/tmp/edge-lb-test.toml"),
            file: FileConfig::default(),
        };
        cfg.file.target_groups.push(TargetGroup {
            name: "empty".to_string(),
            ..TargetGroup::default()
        });
        cfg.file.listeners.push(Listener {
            name: "tcp-80".to_string(),
            port: 80,
            target_port: 8080,
            target_group: "empty".to_string(),
            ..Listener::default()
        });
        assert!(listeners_from_config(&cfg).unwrap().is_empty());
    }

    #[test]
    fn target_group_endpoints_are_expanded_with_weights() {
        let mut file = FileConfig::default();
        file.network.gateway_ip = "192.0.2.10".parse().unwrap();
        file.target_groups.push(TargetGroup {
            name: "api-targets".to_string(),
            targets: vec![
                BackendTarget {
                    backend: None,
                    address: "192.0.2.20".parse().unwrap(),
                    weight: 2,
                },
                BackendTarget {
                    backend: None,
                    address: "192.0.2.21".parse().unwrap(),
                    weight: 5,
                },
            ],
            ..TargetGroup::default()
        });
        file.listeners.push(crate::config::Listener {
            name: "api".to_string(),
            port: 8080,
            target_group: "api-targets".to_string(),
            protocols: vec![Protocol::Tcp],
            mode: LbMode::Default,
            ..crate::config::Listener::default()
        });

        let cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let listeners = listeners_from_config(&cfg).unwrap();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].endpoints.len(), 2);
        assert_eq!(listeners[0].endpoints[0].weight, 2);
        assert_eq!(listeners[0].endpoints[1].weight, 5);
    }

    #[test]
    fn listener_model_takes_precedence_over_runtime_projection() {
        let mut file = FileConfig::default();
        file.network.gateway_ip = "192.0.2.10".parse().unwrap();
        file.target_groups.push(TargetGroup {
            name: "api-targets".to_string(),
            targets: vec![BackendTarget {
                address: "192.0.2.20".parse().unwrap(),
                weight: 7,
                ..BackendTarget::default()
            }],
            ..TargetGroup::default()
        });
        file.listeners.push(crate::config::Listener {
            name: "listener-api".to_string(),
            port: 8080,
            target_group: "api-targets".to_string(),
            protocols: vec![Protocol::Tcp],
            ..crate::config::Listener::default()
        });
        file.services.push(Service {
            name: "runtime-service".to_string(),
            vip_port: 9090,
            protocols: vec![Protocol::Tcp],
            mode: LbMode::Default,
            endpoints: vec![TargetEndpoint {
                address: "192.0.2.30".parse().unwrap(),
                port: 19090,
                weight: 1,
                ..TargetEndpoint::default()
            }],
            ..Service::default()
        });

        let cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let listeners = listeners_from_config(&cfg).unwrap();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].name, "listener-api");
        assert_eq!(listeners[0].key.vip_port, 8080);
        assert_eq!(listeners[0].endpoints[0].weight, 7);
    }

    #[test]
    fn listener_vip_list_expands_to_independent_runtime_keys() {
        let mut file = FileConfig::default();
        file.network.gateway_ip = "192.0.2.1".parse().unwrap();
        file.target_groups.push(TargetGroup {
            name: "api-targets".to_string(),
            targets: vec![BackendTarget {
                address: "192.0.2.20".parse().unwrap(),
                weight: 1,
                ..BackendTarget::default()
            }],
            ..TargetGroup::default()
        });
        file.listeners.push(crate::config::Listener {
            name: "api".to_string(),
            port: 8080,
            target_group: "api-targets".to_string(),
            vip_ips: vec!["192.0.2.10".parse().unwrap(), "192.0.2.11".parse().unwrap()],
            ..crate::config::Listener::default()
        });

        let cfg = Config {
            file,
            path: DEFAULT_CONFIG_PATH.into(),
        };
        let listeners = listeners_from_config(&cfg).unwrap();

        assert_eq!(listeners.len(), 3);
        assert_eq!(listeners[0].key.vip_ip, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(listeners[1].key.vip_ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(listeners[2].key.vip_ip, Ipv4Addr::new(192, 0, 2, 11));
    }

    #[test]
    fn shared_vip_is_installed_for_backup_datapath() {
        let values = merge_vip_ips(
            Ipv4Addr::new(192, 0, 2, 1),
            &[],
            Some(Ipv4Addr::new(192, 0, 2, 100)),
        )
        .unwrap();
        assert_eq!(
            values,
            vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 100)]
        );
    }
}
