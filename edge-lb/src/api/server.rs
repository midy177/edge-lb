use std::{
    io::Read,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, mpsc},
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
    serve_requests(&server, |request| {
        if let Err(e) = handle(request, &path, token.as_deref()) {
            tracing::warn!("[api] {e:#}");
        }
    })
}

const API_WORKERS: usize = 4;
const QUEUE_CAPACITY: usize = 32;
const MAX_API_BODY_BYTES: usize = 1024 * 1024;

// Only terminal replica writes may use the reserved worker. An /active write
// can call back to the peer and would recreate the same wait cycle here.
fn is_replica_write(method: &tiny_http::Method, url: &str) -> bool {
    matches!(
        (method, url.split('?').next().unwrap_or("")),
        (
            tiny_http::Method::Post,
            "/api/v1/ha/peer/proxy-config/replica"
        ) | (
            tiny_http::Method::Put,
            "/api/v1/ha/peer/notifications/replica"
                | "/api/v1/ha/peer/automation-templates/replica"
        )
    )
}

fn serve_requests(server: &Server, handler: impl Fn(tiny_http::Request) + Sync) -> Result<()> {
    std::thread::scope(|scope| {
        let (public_tx, public_rx) = mpsc::sync_channel(QUEUE_CAPACITY);
        let (replica_tx, replica_rx) = mpsc::sync_channel(QUEUE_CAPACITY);
        let public_rx = Arc::new(Mutex::new(public_rx));
        let replica_rx = Arc::new(Mutex::new(replica_rx));
        let handler = &handler;
        for idx in 0..=API_WORKERS {
            let rx = if idx == API_WORKERS {
                Arc::clone(&replica_rx)
            } else {
                Arc::clone(&public_rx)
            };
            std::thread::Builder::new()
                .name(if idx == API_WORKERS {
                    "edge-lb-api-replica".into()
                } else {
                    format!("edge-lb-api-{idx}")
                })
                .stack_size(512 * 1024)
                .spawn_scoped(scope, move || {
                    loop {
                        let request = { rx.lock().expect("API request queue poisoned").recv() };
                        match request {
                            Ok(request) => handler(request),
                            Err(_) => break,
                        }
                    }
                })
                .context("spawning API worker")?;
        }
        // Dispatch must never wait for a full ordinary queue: replica requests
        // still need to reach their worker while every ordinary worker waits.
        let result = loop {
            let request = match server.recv() {
                Ok(request) => request,
                Err(error) => break Err(error).context("receiving API request"),
            };
            let tx = if is_replica_write(request.method(), request.url()) {
                &replica_tx
            } else {
                &public_tx
            };
            if let Err(error) = tx.try_send(request) {
                let request = match error {
                    mpsc::TrySendError::Full(request)
                    | mpsc::TrySendError::Disconnected(request) => request,
                };
                let _ = respond(request, Reply::error(503, "API request queue is full"));
            }
        };
        drop(public_tx);
        drop(replica_tx);
        result
    })
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

    let body = match read_api_body(&mut request) {
        Ok(body) => body,
        Err(reply) => return respond(request, reply),
    };

    let reply = super::router::route(&method, &path, &body, &cfg, config_path);
    respond(request, reply)
}

fn read_api_body(request: &mut tiny_http::Request) -> Result<String, Reply> {
    if request
        .body_length()
        .is_some_and(|len| len > MAX_API_BODY_BYTES)
    {
        return Err(Reply::error(
            413,
            format!("request body exceeds {MAX_API_BODY_BYTES} bytes"),
        ));
    }

    let mut bytes = Vec::new();
    request
        .as_reader()
        .take((MAX_API_BODY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| Reply::error(400, format!("failed to read request body: {error}")))?;
    if bytes.len() > MAX_API_BODY_BYTES {
        return Err(Reply::error(
            413,
            format!("request body exceeds {MAX_API_BODY_BYTES} bytes"),
        ));
    }

    String::from_utf8(bytes)
        .map_err(|error| Reply::error(400, format!("request body is not valid UTF-8: {error}")))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Condvar, time::Duration};
    use tiny_http::{Header, HeaderField, Method, TestRequest};

    struct TestServer {
        server: Arc<Server>,
        thread: Option<std::thread::JoinHandle<Result<()>>>,
    }

    impl TestServer {
        fn start(
            server: Arc<Server>,
            handler: impl Fn(tiny_http::Request) + Send + Sync + 'static,
        ) -> Self {
            let worker_server = Arc::clone(&server);
            Self {
                server,
                thread: Some(std::thread::spawn(move || {
                    serve_requests(&worker_server, handler)
                })),
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.server.unblock();
            let _ = self.thread.take().unwrap().join();
        }
    }

    fn http_server() -> (Arc<Server>, String) {
        let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
        let url = format!("http://{}", server.server_addr());
        (server, url)
    }

    fn client() -> reqwest::blocking::Client {
        reqwest::blocking::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn header(name: &str, value: &str) -> Header {
        Header {
            field: HeaderField::from_bytes(name.as_bytes()).unwrap(),
            value: value.parse().unwrap(),
        }
    }

    fn leaked_static_string(value: String) -> &'static str {
        Box::leak(value.into_boxed_str())
    }

    #[test]
    fn api_body_reader_accepts_valid_small_body() {
        let mut request = TestRequest::new()
            .with_method(Method::Post)
            .with_path("/api/v1/listener-configs")
            .with_body("{\"name\":\"tcp-80\"}")
            .into();

        let body = match read_api_body(&mut request) {
            Ok(body) => body,
            Err(reply) => panic!("unexpected error response {}", reply.status),
        };
        assert_eq!(body, "{\"name\":\"tcp-80\"}");
    }

    #[test]
    fn api_body_reader_rejects_declared_oversized_body_before_reading() {
        let mut request = TestRequest::new()
            .with_method(Method::Post)
            .with_path("/api/v1/listener-configs")
            .with_header(header(
                "Content-Length",
                &(MAX_API_BODY_BYTES + 1).to_string(),
            ))
            .into();

        let reply = match read_api_body(&mut request) {
            Ok(body) => panic!("unexpected body with {} bytes", body.len()),
            Err(reply) => reply,
        };
        assert_eq!(reply.status, 413);
    }

    #[test]
    fn api_body_reader_rejects_chunked_body_over_actual_limit() {
        let chunk = "x".repeat(MAX_API_BODY_BYTES + 1);
        let encoded = leaked_static_string(format!(
            "{:x}\r\n{chunk}\r\n0\r\n\r\n",
            MAX_API_BODY_BYTES + 1
        ));
        let mut request = TestRequest::new()
            .with_method(Method::Post)
            .with_path("/api/v1/listener-configs")
            .with_header(header("Transfer-Encoding", "chunked"))
            .with_body(encoded)
            .into();

        let reply = match read_api_body(&mut request) {
            Ok(body) => panic!("unexpected body with {} bytes", body.len()),
            Err(reply) => reply,
        };
        assert_eq!(reply.status, 413);
    }

    #[test]
    fn reserved_worker_only_accepts_terminal_replica_methods_and_paths() {
        assert!(is_replica_write(
            &Method::Post,
            "/api/v1/ha/peer/proxy-config/replica?trace=1"
        ));
        for resource in ["notifications", "automation-templates"] {
            assert!(is_replica_write(
                &Method::Put,
                &format!("/api/v1/ha/peer/{resource}/replica")
            ));
        }
        for path in [
            "/api/v1/ha/peer/proxy-config/active",
            "/api/v1/ha/peer/proxy-config/replica/extra",
            "/api/v1/ha/peer/activate",
            "/api/ha/peer/proxy-config/replica",
            "/api/v1/ha/peer/notifications/replica",
        ] {
            assert!(!is_replica_write(&Method::Post, path), "{path}");
        }
        assert!(!is_replica_write(
            &Method::Get,
            "/api/v1/ha/peer/proxy-config/replica"
        ));
    }

    #[test]
    fn four_backup_writes_can_receive_master_callbacks_without_wait_cycle() {
        let (backup_server, backup_url) = http_server();
        let (master_server, master_url) = http_server();
        let arrivals = Arc::new((Mutex::new(0), Condvar::new()));
        let arrived = Arc::clone(&arrivals);
        let forward_client = client();
        let _backup = TestServer::start(backup_server, move |request| {
            if is_replica_write(request.method(), request.url()) {
                let _ = respond(
                    request,
                    Reply::json(200, serde_json::json!({"saved": true})),
                );
                return;
            }
            // All four ordinary workers must be occupied before forwarding.
            let (count, ready) = &*arrived;
            let mut count = count.lock().unwrap();
            *count += 1;
            ready.notify_all();
            let (count, _) = ready
                .wait_timeout_while(count, Duration::from_secs(3), |count| *count < API_WORKERS)
                .unwrap();
            let all_arrived = *count == API_WORKERS;
            drop(count);
            let result = forward_client
                .post(format!("{master_url}/api/v1/ha/peer/proxy-config/active"))
                .send()
                .and_then(|response| response.error_for_status())
                .and_then(|response| response.text());
            let status = if all_arrived && result.is_ok() {
                200
            } else {
                502
            };
            let _ = respond(request, Reply::json(status, serde_json::json!({})));
        });
        let callback_client = client();
        let callback_url = format!("{backup_url}/api/v1/ha/peer/proxy-config/replica");
        let _master = TestServer::start(master_server, move |request| {
            let result = callback_client
                .post(&callback_url)
                .send()
                .and_then(|response| response.error_for_status())
                .and_then(|response| response.text());
            let status = if result.is_ok() { 200 } else { 502 };
            let _ = respond(request, Reply::json(status, serde_json::json!({})));
        });
        let caller = client();
        let results = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..API_WORKERS)
                .map(|_| {
                    let caller = &caller;
                    let url = &backup_url;
                    scope.spawn(move || {
                        caller
                            .post(format!("{url}/api/v1/listener-configs"))
                            .send()
                            .and_then(|response| response.error_for_status())
                            .and_then(|response| response.text())
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(*arrivals.0.lock().unwrap(), API_WORKERS);
        for result in results {
            assert!(result.is_ok(), "forward/callback failed: {result:?}");
        }
    }

    #[test]
    fn full_ordinary_queue_returns_503_without_blocking_replica_dispatch() {
        use std::io::{Read, Write};
        let (server, _) = http_server();
        let address = server.server_addr().to_ip().unwrap();
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let waiting = Arc::clone(&gate);
        let (started_tx, started_rx) = mpsc::channel();
        let _server = TestServer::start(server, move |request| {
            if !is_replica_write(request.method(), request.url()) {
                let _ = started_tx.send(());
                let (released, ready) = &*waiting;
                let _guard = ready
                    .wait_timeout_while(
                        released.lock().unwrap(),
                        Duration::from_secs(10),
                        |released| !*released,
                    )
                    .unwrap();
            }
            let _ = respond(request, Reply::json(200, serde_json::json!({})));
        });
        let request = |path: &str| {
            let mut stream = std::net::TcpStream::connect(address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            write!(stream, "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            stream
        };
        let mut streams: Vec<_> = (0..API_WORKERS)
            .map(|_| request("/api/v1/listener-configs"))
            .collect();
        for _ in 0..API_WORKERS {
            started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        }
        streams.extend((0..=QUEUE_CAPACITY).map(|_| request("/api/v1/listener-configs")));
        for stream in &streams {
            stream.set_nonblocking(true).unwrap();
        }
        // Raw sockets ensure queue pressure is not capped by an HTTP client's
        // own connection scheduler. Wait for a rejection before releasing work.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        let mut overflow = false;
        while std::time::Instant::now() < deadline && !overflow {
            for stream in &streams {
                let mut bytes = [0; 128];
                if let Ok(n) = stream.peek(&mut bytes) {
                    overflow |= String::from_utf8_lossy(&bytes[..n]).contains(" 503 ");
                }
            }
            if !overflow {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        let mut replica = request("/api/v1/ha/peer/proxy-config/replica");
        let mut response = String::new();
        let result = replica.read_to_string(&mut response);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(overflow, "ordinary queue did not reject excess work");
        result.unwrap();
        assert!(response.starts_with("HTTP/1.1 200 "), "{response}");
    }
}
