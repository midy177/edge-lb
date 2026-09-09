use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use tokio::{runtime::Builder, sync::mpsc, time::sleep};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, transport::Server};

use crate::{
    config::{Config, FileConfig},
    control::{
        auth,
        pb::{
            DiscoveryRequest, DiscoveryResponse, GatewayPeerInfo, PairGatewayRequest,
            PairGatewayResponse,
            config_discovery_server::{ConfigDiscovery, ConfigDiscoveryServer},
            flow_sync_server::{FlowSync, FlowSyncServer},
        },
        registry, snapshot,
    },
    runtime::ha::{self, GatewayHaRuntimeConfig, GatewayIdentity},
};

pub fn spawn(cfg: &Config) {
    if !cfg.control_plane.enabled {
        return;
    }
    let cfg = cfg.clone();
    std::thread::Builder::new()
        .name("edge-lb-xds".to_string())
        .stack_size(512 * 1024)
        .spawn(move || {
            if let Err(e) = serve(&cfg) {
                tracing::error!("[control] gRPC server stopped: {e:#}");
            }
        })
        .expect("spawn xDS control-plane thread");
}

fn serve(cfg: &Config) -> Result<()> {
    let addr: SocketAddr = cfg
        .control_plane
        .listen
        .parse()
        .with_context(|| format!("bad control_plane.listen {}", cfg.control_plane.listen))?;
    let loopback = match addr.ip() {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback(),
    };
    if !loopback && cfg.control_plane.token.is_none() {
        bail!("control_plane.token is required for non-loopback gRPC listen");
    }
    let trusted_cidrs = auth::trusted_source_cidrs(cfg);

    let service = GatewayDiscovery {
        config_path: cfg.path.clone(),
        fallback: cfg.clone(),
    };
    tracing::info!(
        "[control] xDS/xSync gRPC listening on http://{} (trusted {:?})",
        addr,
        trusted_cidrs
    );
    Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building control-plane runtime")?
        .block_on(async move {
            Server::builder()
                .add_service(ConfigDiscoveryServer::new(service))
                .add_service(FlowSyncServer::new(FlowSyncService {
                    fallback: cfg.clone(),
                }))
                .serve(addr)
                .await
                .map_err(anyhow::Error::from)
        })
}

#[derive(Clone)]
struct GatewayDiscovery {
    config_path: PathBuf,
    fallback: Config,
}

#[derive(Clone)]
struct FlowSyncService {
    fallback: Config,
}

#[tonic::async_trait]
impl FlowSync for FlowSyncService {
    type ReplicateStream =
        ReceiverStream<std::result::Result<crate::control::pb::FlowSyncResponse, Status>>;

    async fn replicate(
        &self,
        request: Request<tonic::Streaming<crate::control::pb::FlowSyncRequest>>,
    ) -> std::result::Result<Response<Self::ReplicateStream>, Status> {
        crate::provider::native::xsync::replicate(&self.fallback, request).await
    }
}

#[tonic::async_trait]
impl ConfigDiscovery for GatewayDiscovery {
    type WatchStream = ReceiverStream<std::result::Result<DiscoveryResponse, Status>>;

    async fn watch(
        &self,
        request: Request<tonic::Streaming<DiscoveryRequest>>,
    ) -> std::result::Result<Response<Self::WatchStream>, Status> {
        let remote = request.remote_addr();
        let meta = request.metadata().clone();
        auth::authorize(&self.fallback, remote, &meta)?;

        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await
            .map_err(|e| Status::invalid_argument(e.to_string()))?
            .ok_or_else(|| Status::invalid_argument("missing discovery request"))?;
        if first.node_role != "backend" {
            return Err(Status::permission_denied(
                "only backend nodes may subscribe",
            ));
        }
        if !valid_backend_registration(&first) {
            return Err(Status::permission_denied(
                "backend registration is incomplete or invalid",
            ));
        }

        let peer = first.node_name.clone();
        let peer_underlay = first
            .underlay_ip
            .parse::<IpAddr>()
            .map_err(|e| Status::invalid_argument(format!("bad backend underlay_ip: {e}")))?;
        let stream_id = nonce();
        registry::upsert(&first, remote, &stream_id, &self.fallback.state_dir);
        tracing::info!(
            "[control] backend subscribed node={} public_ip={} public_ip_mode={} public_ip_source={} underlay_ip={} underlay_ip_mode={} underlay_ip_source={} peer={} stream={}",
            first.node_name,
            first.public_ip,
            first.public_ip_mode,
            first.public_ip_source,
            first.underlay_ip,
            first.underlay_ip_mode,
            first.underlay_ip_source,
            remote
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            stream_id
        );
        let (tx, rx) = mpsc::channel(4);
        let path = self.config_path.clone();
        let fallback = self.fallback.clone();
        let sender_peer = peer.clone();
        tokio::spawn(async move {
            let mut last_sent = String::new();
            loop {
                match load_snapshot(&path, &fallback, peer_underlay).await {
                    Ok(resp) if resp.version != last_sent => {
                        last_sent = resp.version.clone();
                        snapshot::log_send(&sender_peer, &resp);
                        if tx.send(Ok(resp)).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        let _ = tx
                            .send(Err(Status::internal(format!(
                                "snapshot build failed: {e:#}"
                            ))))
                            .await;
                        break;
                    }
                }
                sleep(Duration::from_secs(fallback.ha.watch_interval_secs)).await;
            }
        });
        let receiver_peer = peer;
        let receiver_stream_id = stream_id;
        tokio::spawn(async move {
            while let Ok(Some(req)) = inbound.message().await {
                registry::touch(&receiver_peer, &receiver_stream_id, &req);
                if req.ack {
                    if req.conflicts.is_empty() {
                        tracing::debug!(
                            "[control] backend {} ACK version {} nonce {}",
                            receiver_peer,
                            req.version,
                            req.response_nonce
                        );
                    } else {
                        tracing::warn!(
                            "[control] backend {} ACK version {} nonce {} conflicts={}",
                            receiver_peer,
                            req.version,
                            req.response_nonce,
                            req.conflicts.len()
                        );
                    }
                }
                if !req.ack && !req.error_detail.is_empty() {
                    tracing::warn!(
                        "[control] backend {} NACK version {} nonce {}: {}",
                        receiver_peer,
                        req.version,
                        req.response_nonce,
                        req.error_detail
                    );
                }
            }
            registry::remove(&receiver_peer, &receiver_stream_id);
            tracing::debug!("[control] backend {receiver_peer} stream {receiver_stream_id} closed");
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn pair_gateway(
        &self,
        request: Request<PairGatewayRequest>,
    ) -> std::result::Result<Response<PairGatewayResponse>, Status> {
        let remote = request.remote_addr();
        let meta = request.metadata().clone();
        auth::authorize(&self.fallback, remote, &meta)?;
        if !matches!(self.fallback.node_role, crate::config::NodeRole::Gateway) {
            return Err(Status::permission_denied(
                "gateway pairing is only available on gateway nodes",
            ));
        }

        let req = request.into_inner();
        let caller = req
            .caller
            .ok_or_else(|| Status::invalid_argument("missing caller identity"))
            .and_then(identity_from_pb)?;
        if req.session_token.trim().is_empty() {
            return Err(Status::invalid_argument("session_token is required"));
        }

        let mut file = FileConfig::load_file(&self.config_path)
            .map_err(internal_status)?
            .unwrap_or_else(|| self.fallback.file.clone());
        crate::runtime::discovery::resolve_auto_ips(&mut file).map_err(internal_status)?;
        file.validate().map_err(internal_status)?;
        let cfg = Config {
            path: self.config_path.clone(),
            file,
        };
        let local = ha::local_identity(&cfg);
        ha::validate_identity_pair(&local, &caller)
            .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
        let state_dir = Path::new(&*cfg.state_dir);
        let existing = ha::load_for_state_dir(state_dir).map_err(internal_status)?;
        ha::ensure_peer_slot_available(&existing, &caller)
            .map_err(|e| Status::failed_precondition(format!("{e:#}")))?;

        let incoming: GatewayHaRuntimeConfig = if req.ha_config_json.trim().is_empty() {
            GatewayHaRuntimeConfig::default()
        } else {
            serde_json::from_str(&req.ha_config_json)
                .map_err(|e| Status::invalid_argument(format!("bad ha_config_json: {e}")))?
        };
        let incoming = ha::normalize_runtime_config(incoming);
        let local_cfg = ha::reciprocal_config(&incoming, &local, &caller)
            .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
        ha::save_for_state_dir(state_dir, &local_cfg).map_err(internal_status)?;

        let caller_secret = ha::new_session_token_secret(&caller, req.session_token);
        ha::save_secrets_for_state_dir(state_dir, &caller_secret).map_err(internal_status)?;
        tracing::info!(
            "[control] HA gateway paired local={} peer={} peer_underlay={} remote={} session_token_id={}",
            local.name,
            caller.name,
            caller.underlay_ip,
            remote
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            caller_secret.session_token_id
        );

        Ok(Response::new(PairGatewayResponse {
            responder: Some(identity_to_pb(&local)),
            warnings: Vec::new(),
        }))
    }
}

pub(super) fn identity_from_pb(
    value: GatewayPeerInfo,
) -> std::result::Result<GatewayIdentity, Status> {
    Ok(GatewayIdentity {
        name: required(value.node_name, "node_name")?,
        underlay_ip: required(value.underlay_ip, "underlay_ip")?,
        public_ip: value.public_ip,
        api_addr: value.api_addr,
        xds_addr: value.xds_addr,
        overlay_cidr: required(value.overlay_cidr, "overlay_cidr")?,
        overlay_ip: required(value.gateway_overlay_ip, "gateway_overlay_ip")?,
        dscp: value.dscp,
        vni: value.vni,
        vxlan_port: u16::try_from(value.vxlan_port)
            .map_err(|_| Status::invalid_argument("vxlan_port out of range"))?,
        mtu: value.mtu,
        version: value.version,
        capabilities: value.capabilities,
    })
}

pub(super) fn identity_to_pb(identity: &GatewayIdentity) -> GatewayPeerInfo {
    GatewayPeerInfo {
        node_name: identity.name.clone(),
        underlay_ip: identity.underlay_ip.clone(),
        public_ip: identity.public_ip.clone(),
        api_addr: identity.api_addr.clone(),
        xds_addr: identity.xds_addr.clone(),
        overlay_cidr: identity.overlay_cidr.clone(),
        gateway_overlay_ip: identity.overlay_ip.clone(),
        dscp: identity.dscp,
        vni: identity.vni,
        vxlan_port: u32::from(identity.vxlan_port),
        mtu: identity.mtu,
        version: identity.version.clone(),
        capabilities: identity.capabilities.clone(),
    }
}

fn required(value: String, field: &str) -> std::result::Result<String, Status> {
    if value.trim().is_empty() {
        Err(Status::invalid_argument(format!("{field} is required")))
    } else {
        Ok(value)
    }
}

fn internal_status(error: anyhow::Error) -> Status {
    Status::internal(format!("{error:#}"))
}

fn valid_backend_registration(req: &DiscoveryRequest) -> bool {
    !req.node_name.trim().is_empty()
        && req
            .underlay_ip
            .parse::<IpAddr>()
            .is_ok_and(|ip| !ip.is_unspecified())
}

async fn load_snapshot(
    path: &Path,
    fallback: &Config,
    peer_underlay: IpAddr,
) -> Result<DiscoveryResponse> {
    let path = path.to_path_buf();
    let fallback = fallback.clone();
    tokio::task::spawn_blocking(move || build_snapshot(&path, &fallback, peer_underlay))
        .await
        .context("snapshot build task failed")?
}

fn build_snapshot(
    path: &Path,
    fallback: &Config,
    peer_underlay: IpAddr,
) -> Result<DiscoveryResponse> {
    let mut file = FileConfig::load_file(path)?.unwrap_or_else(|| fallback.file.clone());
    crate::runtime::discovery::resolve_auto_ips(&mut file)?;
    crate::runtime::ha::merge_gateway_peers_best_effort(&mut file);
    registry::merge_into(&mut file)?;
    file.validate().context("invalid gateway config")?;
    let mut cfg = Config {
        path: path.to_path_buf(),
        file,
    };
    crate::provider::native::hydrate_proxy_config_from_api(&mut cfg)
        .context("loading native proxy state for xDS snapshot")?;
    snapshot::response_for_backend(&cfg, peer_underlay)
}

fn nonce() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}")
}
