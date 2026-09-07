use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use tiny_http::Server;

use crate::{
    api::{
        auth,
        response::{Reply, respond},
    },
    config::Config,
};

mod ui_files {
    include!(concat!(env!("OUT_DIR"), "/ui_files.rs"));
}

pub fn serve(cfg: &Config, listen_override: Option<String>) -> Result<()> {
    let listen: SocketAddr = listen_override
        .or_else(|| Some(cfg.api.listen.clone()))
        .and_then(|l| l.parse().ok())
        .context("invalid listen address")?;
    let loopback = match listen.ip() {
        IpAddr::V4(v) => v.is_loopback(),
        IpAddr::V6(v) => v.is_loopback(),
    };
    if !loopback && cfg.api.auth_token.is_none() {
        bail!(
            "refusing to listen on {listen} without auth_token: \
             set gateway.api.auth_token in {} or bind 127.0.0.1",
            cfg.path.display()
        );
    }
    let server =
        Arc::new(Server::http(listen).map_err(|e| anyhow::anyhow!("binding {listen}: {e}"))?);
    tracing::info!(
        "edge-lb API/UI listening on http://{listen} (node {} role {:?})",
        cfg.node_name,
        cfg.node_role
    );
    if !loopback {
        tracing::info!(
            "token auth enabled; trusted API sources {:?}",
            auth::api_trusted_source_cidrs(cfg)
        );
    }
    let token = cfg.api.auth_token.clone();
    let path = cfg.path.clone();
    let mut threads = Vec::new();
    for idx in 0..4 {
        let server = Arc::clone(&server);
        let token = token.clone();
        let path = path.clone();
        threads.push(
            std::thread::Builder::new()
                .name(format!("edge-lb-api-{idx}"))
                .stack_size(512 * 1024)
                .spawn(move || {
                    loop {
                        let Ok(request) = server.recv() else {
                            continue;
                        };
                        if let Err(e) = handle(request, &path, token.as_deref()) {
                            tracing::warn!("[api] {e:#}");
                        }
                    }
                })
                .expect("spawn API worker thread"),
        );
    }
    for t in threads {
        let _ = t.join();
    }
    Ok(())
}

fn handle(
    mut request: tiny_http::Request,
    config_path: &std::path::Path,
    token: Option<&str>,
) -> Result<()> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("").to_string();

    if !path.starts_with("/api/") {
        let reply = serve_static(&path);
        return respond(request, reply);
    }
    let cfg = super::router::load_config(config_path, super::router::load_options(&method, &path))?;
    match request.remote_addr().map(SocketAddr::ip) {
        Some(ip) if auth::trusted_api_remote(&cfg, ip) => {}
        Some(ip) => return respond(request, Reply::error(403, format!("untrusted source {ip}"))),
        None => return respond(request, Reply::error(403, "missing remote address")),
    }
    let got = bearer_token(&request);
    let token = cfg.api.auth_token.as_deref().or(token);
    let admin_ok = match token {
        Some(token) => got.as_deref().is_some_and(|got| got == token),
        None => true,
    };
    // Peer requests use the paired token, while ordinary API requests use the
    // admin token. Match the canonical versioned path as received by the API.
    let peer_path = path.starts_with("/api/v1/ha/peer/");
    let peer_ok = if peer_path {
        match got.as_deref() {
            Some(got) => crate::runtime::ha::session_token_matches(
                std::path::Path::new(&*cfg.state_dir),
                got,
            )
            .unwrap_or(false),
            None => false,
        }
    } else {
        false
    };
    if (peer_path && !peer_ok) || (!peer_path && !admin_ok) {
        return respond(
            request,
            Reply::error(401, "missing or invalid bearer token"),
        );
    }

    let mut body = String::new();
    request.as_reader().read_to_string(&mut body).ok();

    let reply = super::router::route(&method, &path, &body, &cfg, config_path);
    respond(request, reply)
}

fn bearer_token(request: &tiny_http::Request) -> Option<String> {
    let value = request
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))?
        .value
        .as_str()
        .trim();
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

fn serve_static(path: &str) -> Reply {
    match ui_files::find_ui_file(path) {
        Some((mime, bytes)) => Reply {
            status: 200,
            content_type: mime,
            body: bytes.to_vec(),
        },
        None => Reply {
            status: 404,
            content_type: "text/plain; charset=utf-8".into(),
            body: b"UI not built: run `make ui` and rebuild the agent\n".to_vec(),
        },
    }
}
