use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use tokio::runtime::Builder;
use tonic::{Request, metadata::MetadataValue, transport::Endpoint};

use crate::{
    config::Config,
    control::{
        gateway::{identity_from_pb, identity_to_pb},
        pb::{PairGatewayRequest, config_discovery_client::ConfigDiscoveryClient},
    },
    runtime::ha::{self, GatewayHaRuntimeConfig},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize)]
pub struct PairGatewayResult {
    pub status: String,
    pub local: PairedGateway,
    pub peer: PairedGateway,
    pub ha_config_storage: String,
    pub session_token_storage: String,
    pub datapath_refresh_required: bool,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairedGateway {
    pub name: String,
    pub underlay_ip: String,
    pub public_ip: String,
    pub api_addr: String,
    pub xds_addr: String,
    pub overlay_cidr: String,
    pub overlay_ip: String,
    pub dscp: u32,
    pub vni: u32,
    pub vxlan_port: u16,
    pub mtu: u32,
    pub version: String,
    pub capabilities: Vec<String>,
}

pub fn pair_gateway(
    cfg: &Config,
    endpoint: &str,
    bootstrap_token: &str,
    desired: &GatewayHaRuntimeConfig,
) -> Result<PairGatewayResult> {
    if !matches!(cfg.node_role, crate::config::NodeRole::Gateway) {
        bail!("HA gateway pairing is only available on gateway nodes");
    }
    if bootstrap_token.trim().is_empty() {
        bail!("bootstrap_token is required");
    }
    let rt = Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building HA pairing runtime")?;
    rt.block_on(async move { pair_gateway_async(cfg, endpoint, bootstrap_token, desired).await })
}

async fn pair_gateway_async(
    cfg: &Config,
    endpoint: &str,
    bootstrap_token: &str,
    desired: &GatewayHaRuntimeConfig,
) -> Result<PairGatewayResult> {
    let endpoint = normalize_endpoint(endpoint);
    let channel = Endpoint::from_shared(endpoint.clone())
        .with_context(|| format!("building HA peer endpoint {endpoint}"))?
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .connect()
        .await
        .with_context(|| format!("connecting HA peer {endpoint}"))?;
    let mut client = ConfigDiscoveryClient::new(channel);
    let local = ha::local_identity(cfg);
    let session_token = ha::generate_session_token();
    let mut request = Request::new(PairGatewayRequest {
        caller: Some(identity_to_pb(&local)),
        ha_config_json: serde_json::to_string(desired).context("serializing HA config")?,
        session_token: session_token.clone(),
    });
    let auth = MetadataValue::try_from(format!("Bearer {bootstrap_token}"))
        .context("invalid bootstrap token metadata")?;
    request.metadata_mut().insert("authorization", auth);

    let response = client
        .pair_gateway(request)
        .await
        .with_context(|| format!("pairing HA peer {endpoint}"))?
        .into_inner();
    let peer = response
        .responder
        .ok_or_else(|| anyhow::anyhow!("HA peer response missing responder identity"))
        .and_then(|pb| identity_from_pb(pb).map_err(anyhow::Error::from))?;
    ha::validate_identity_pair(&local, &peer)?;
    let local_cfg = ha::config_with_peer(desired, &local, &peer)?;
    let state_dir = Path::new(&*cfg.state_dir);
    ha::save_for_state_dir(state_dir, &local_cfg)?;
    let secret = ha::new_session_token_secret(&peer, session_token);
    ha::save_secrets_for_state_dir(state_dir, &secret)?;

    tracing::info!(
        "[control] HA gateway pairing complete local={} peer={} peer_underlay={} session_token_id={}",
        local.name,
        peer.name,
        peer.underlay_ip,
        secret.session_token_id
    );

    Ok(PairGatewayResult {
        status: "paired".to_string(),
        local: PairedGateway::from(local),
        peer: PairedGateway::from(peer),
        ha_config_storage: "sqlite".to_string(),
        session_token_storage: "sqlite".to_string(),
        datapath_refresh_required: local_cfg.enabled && local_cfg.connection_sync,
        warnings: response.warnings,
    })
}

fn normalize_endpoint(endpoint: &str) -> String {
    if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    }
}

impl From<ha::GatewayIdentity> for PairedGateway {
    fn from(value: ha::GatewayIdentity) -> Self {
        Self {
            name: value.name,
            underlay_ip: value.underlay_ip,
            public_ip: value.public_ip,
            api_addr: value.api_addr,
            xds_addr: value.xds_addr,
            overlay_cidr: value.overlay_cidr,
            overlay_ip: value.overlay_ip,
            dscp: value.dscp,
            vni: value.vni,
            vxlan_port: value.vxlan_port,
            mtu: value.mtu,
            version: value.version,
            capabilities: value.capabilities,
        }
    }
}
