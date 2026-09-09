//! Shared HA write-authority helpers for gateway-local configuration APIs.

use std::{path::Path, sync::OnceLock, time::Duration};

use anyhow::{Context, Result, bail};
use reqwest::blocking::Client;
use serde::Serialize;

use crate::{config::Config, runtime::ha};

const MASTER: &str = "MASTER";
const BACKUP: &str = "BACKUP";
const STOP: &str = "STOP";

static PEER_CLIENT: OnceLock<Client> = OnceLock::new();

fn peer_client() -> Result<&'static Client> {
    if let Some(client) = PEER_CLIENT.get() {
        return Ok(client);
    }
    let client = Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(2)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent(concat!("edge-lb/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("building HA peer client")?;
    let _ = PEER_CLIENT.set(client);
    PEER_CLIENT.get().context("initializing HA peer client")
}

pub enum WriteRole {
    LocalMaster(Option<ha::GatewayHaPeer>),
    Backup(ha::GatewayHaPeer),
}

pub struct PeerHttpResponse {
    pub status: u16,
    pub body: String,
}

pub fn write_role(cfg: &Config) -> Result<WriteRole> {
    let ha_cfg = ha::load_for_state_dir(Path::new(&*cfg.state_dir))?;
    if !ha_cfg.enabled {
        return Ok(WriteRole::LocalMaster(None));
    }
    let peer = ha_cfg.peers.first().cloned();
    let state = local_ha_state(cfg).unwrap_or_else(|e| {
        tracing::warn!("[ha-write] reading local HA state failed: {e:#}");
        active_gateway_state(cfg)
    });
    match state.as_deref() {
        Some(MASTER) => Ok(WriteRole::LocalMaster(peer)),
        Some(BACKUP | STOP) => peer
            .map(WriteRole::Backup)
            .context("local gateway is not MASTER and no HA peer is configured"),
        _ => {
            if active_gateway_is_local(cfg) {
                Ok(WriteRole::LocalMaster(peer))
            } else {
                peer.map(WriteRole::Backup)
                    .context("local gateway is not active and no HA peer is configured")
            }
        }
    }
}

pub fn put_peer_json<T: Serialize>(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    path: &str,
    value: &T,
) -> Result<PeerHttpResponse> {
    send_peer_json(cfg, peer, reqwest::Method::PUT, path, value)
}

pub fn post_peer_json<T: Serialize>(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    path: &str,
    value: &T,
) -> Result<PeerHttpResponse> {
    send_peer_json(cfg, peer, reqwest::Method::POST, path, value)
}

#[allow(dead_code)]
pub fn get_peer(cfg: &Config, peer: &ha::GatewayHaPeer, path: &str) -> Result<PeerHttpResponse> {
    let secrets = ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir))?
        .context("HA peer token is not available")?;
    if secrets.session_token.trim().is_empty() {
        bail!("HA peer token is empty");
    }
    let base = peer_api_base(peer)?;
    let url = format!("{base}{path}");
    let response = peer_client()?
        .get(&url)
        .timeout(Duration::from_secs(5))
        .bearer_auth(&secrets.session_token)
        .send()
        .with_context(|| format!("reading HA peer {}", peer.name))?;
    let status = response.status().as_u16();
    let body = response.text().context("reading HA peer response body")?;
    Ok(PeerHttpResponse { status, body })
}

pub fn peer_api_base(peer: &ha::GatewayHaPeer) -> Result<String> {
    let addr = peer
        .api_addr
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{}:18080", peer.underlay_ip));
    if addr.starts_with("http://") || addr.starts_with("https://") {
        Ok(addr.trim_end_matches('/').to_string())
    } else {
        Ok(format!("http://{}", addr.trim_end_matches('/')))
    }
}

fn send_peer_json<T: Serialize>(
    cfg: &Config,
    peer: &ha::GatewayHaPeer,
    method: reqwest::Method,
    path: &str,
    value: &T,
) -> Result<PeerHttpResponse> {
    let secrets = ha::load_secrets_for_state_dir(Path::new(&*cfg.state_dir))?
        .context("HA peer token is not available")?;
    if secrets.session_token.trim().is_empty() {
        bail!("HA peer token is empty");
    }
    let base = peer_api_base(peer)?;
    let url = format!("{base}{path}");
    let response = peer_client()?
        .request(method, &url)
        .bearer_auth(&secrets.session_token)
        .json(value)
        .send()
        .with_context(|| format!("sending HA write to peer {}", peer.name))?;
    let status = response.status().as_u16();
    let body = response.text().context("reading HA peer response body")?;
    Ok(PeerHttpResponse { status, body })
}

fn local_ha_state(cfg: &Config) -> Result<Option<String>> {
    Ok(active_gateway_state(cfg))
}

fn active_gateway_state(cfg: &Config) -> Option<String> {
    active_gateway_is_local(cfg).then(|| MASTER.to_string())
}

fn active_gateway_is_local(cfg: &Config) -> bool {
    cfg.active_gateway()
        .map(|gateway| gateway.name == cfg.node_name || gateway.underlay_ip == cfg.underlay_ip)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn peer_client_reuses_connection_without_caching_request_token() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        let worker = thread::spawn(move || {
            let mut observations = Vec::new();
            for _ in 0..2 {
                let request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap();
                let token = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Authorization"))
                    .map(|header| header.value.as_str().to_string());
                observations.push((request.remote_addr().copied(), token));
                request
                    .respond(tiny_http::Response::from_string("ok"))
                    .unwrap();
            }
            observations
        });
        for token in ["test-token-first", "test-token-rotated"] {
            let response = peer_client()
                .unwrap()
                .post(&url)
                .bearer_auth(token)
                .send()
                .unwrap();
            assert_eq!(response.text().unwrap(), "ok");
        }
        let observations = worker.join().unwrap();
        assert_eq!(observations[0].0, observations[1].0);
        assert_eq!(
            observations[0].1.as_deref(),
            Some("Bearer test-token-first")
        );
        assert_eq!(
            observations[1].1.as_deref(),
            Some("Bearer test-token-rotated")
        );
    }

    #[test]
    fn peer_client_does_not_follow_redirects() {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let url = format!("http://{}", server.server_addr());
        let worker =
            thread::spawn(move || {
                let request = server
                    .recv_timeout(Duration::from_secs(5))
                    .unwrap()
                    .unwrap();
                request
                    .respond(tiny_http::Response::empty(307).with_header(
                        tiny_http::Header::from_bytes("Location", "/unexpected").unwrap(),
                    ))
                    .unwrap();
            });
        let response = peer_client().unwrap().post(url).send().unwrap();
        assert_eq!(response.status().as_u16(), 307);
        worker.join().unwrap();
    }
}
