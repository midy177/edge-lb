//! TCP/UDP response service.
//!
//! Both transports return the cached discovery response only when the request
//! payload is `discover`; other non-empty payloads are echoed unchanged.

use crate::{discover_all, log, output};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const DISCOVER_COMMAND: &[u8] = b"discover";
const MAX_REQUEST: usize = 4096;
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(2);

pub struct Config {
    pub debug: bool,
    pub tcp_addr: Option<String>,
    pub udp_addr: Option<String>,
}

/// Bind requested listeners and run until the process is terminated.
pub fn run(cfg: Config) -> Result<(), String> {
    let response = Arc::new(discover_all(cfg.debug));

    let tcp = match &cfg.tcp_addr {
        Some(addr) => Some(
            TcpListener::bind(addr)
                .map_err(|e| format!("failed to bind TCP listener {addr}: {e}"))?,
        ),
        None => None,
    };
    let udp = match &cfg.udp_addr {
        Some(addr) => Some(
            UdpSocket::bind(addr).map_err(|e| format!("failed to bind UDP socket {addr}: {e}"))?,
        ),
        None => None,
    };

    if tcp.is_none() && udp.is_none() {
        return Err("no TCP or UDP listener configured".to_string());
    }

    if let Some(listener) = tcp {
        let debug = cfg.debug;
        let response = response.clone();
        let fallback_addr = cfg.tcp_addr.clone().unwrap_or_default();
        let addr = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or(fallback_addr);
        log::logln(&format!("server: TCP listening on {addr}"));
        thread::spawn(move || serve_tcp(listener, debug, response));
    }

    if let Some(socket) = udp {
        let debug = cfg.debug;
        let response = response.clone();
        let fallback_addr = cfg.udp_addr.clone().unwrap_or_default();
        let addr = socket
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or(fallback_addr);
        log::logln(&format!("server: UDP listening on {addr}"));
        thread::spawn(move || serve_udp(socket, debug, response));
    }

    loop {
        thread::park();
    }
}

fn serve_tcp(listener: TcpListener, debug: bool, response: Arc<output::Response>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let response = response.clone();
                thread::spawn(move || handle_tcp(stream, debug, response));
            }
            Err(e) => log::debug_if(debug, &format!("server: TCP accept failed: {e}")),
        }
    }
}

fn handle_tcp(mut stream: TcpStream, debug: bool, response: Arc<output::Response>) {
    let peer = stream.peer_addr().ok();

    let request = match read_tcp_request(&mut stream) {
        Ok(req) => req,
        Err(e) => {
            log::debug_if(debug, &format!("server: TCP read failed: {e}"));
            Vec::new()
        }
    };
    if request.is_empty() {
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }

    let payload = response_payload(&response, peer, &request);
    if let Err(e) = stream.write_all(&payload) {
        log::debug_if(debug, &format!("server: TCP write failed: {e}"));
        return;
    }
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);

    if let Some(peer) = peer {
        log::debug_if(debug, &format!("server: TCP responded to {peer}"));
    }
}

fn read_tcp_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(TCP_READ_TIMEOUT))?;

    let mut request = Vec::with_capacity(128);
    let mut buf = [0_u8; 512];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }

        let done = extend_tcp_request(&mut request, &buf[..n]);
        if done {
            break;
        }
    }

    Ok(request)
}

fn extend_tcp_request(request: &mut Vec<u8>, chunk: &[u8]) -> bool {
    let remaining = MAX_REQUEST.saturating_sub(request.len());
    if remaining == 0 {
        return true;
    }

    let chunk = &chunk[..chunk.len().min(remaining)];
    if let Some(pos) = chunk.iter().position(|b| *b == b'\n') {
        request.extend_from_slice(&chunk[..=pos]);
        return true;
    }
    request.extend_from_slice(chunk);

    request.len() >= MAX_REQUEST
}

#[cfg(test)]
fn tcp_request_from_chunks(chunks: &[&[u8]]) -> Vec<u8> {
    let mut request = Vec::new();
    for chunk in chunks {
        if extend_tcp_request(&mut request, chunk) {
            break;
        }
    }
    request
}

fn serve_udp(socket: UdpSocket, debug: bool, response: Arc<output::Response>) {
    let mut buf = [0_u8; MAX_REQUEST];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                log::debug_if(debug, &format!("server: UDP receive failed: {e}"));
                continue;
            }
        };
        if !should_respond_udp(n) {
            log::debug_if(
                debug,
                &format!("server: ignored empty UDP datagram from {peer}"),
            );
            continue;
        }

        let payload = response_payload(&response, Some(peer), &buf[..n]);
        match socket.send_to(&payload, peer) {
            Ok(_) => log::debug_if(debug, &format!("server: UDP responded to {peer}")),
            Err(e) => log::debug_if(debug, &format!("server: UDP send to {peer} failed: {e}")),
        }
    }
}

fn response_payload(base: &output::Response, peer: Option<SocketAddr>, request: &[u8]) -> Vec<u8> {
    if !is_discover_request(request) {
        return request.to_vec();
    }

    let mut ret = base.clone();
    if let Some(peer) = peer {
        ret.client_ip = peer.ip().to_string();
        ret.client_port = peer.port();
    }
    let mut body = output::encode_response(&ret);
    body.push('\n');
    body.into_bytes()
}

fn is_discover_request(request: &[u8]) -> bool {
    trim_ascii_whitespace(request) == DISCOVER_COMMAND
}

fn should_respond_udp(len: usize) -> bool {
    len > 0
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_request_uses_cached_base_and_request_source() {
        let base = output::Response {
            hostname: "node1".to_string(),
            private_ipv4: "10.0.0.5".to_string(),
            public_ipv4: "203.0.113.7".to_string(),
            public_ipv6: "".to_string(),
            client_ip: "".to_string(),
            client_port: 0,
        };
        let peer = Some("192.0.2.10:53124".parse().unwrap());

        assert_eq!(
            response_payload(&base, peer, b"discover\n"),
            b"{\"hostname\":\"node1\",\"private_ipv4\":\"10.0.0.5\",\
              \"public_ipv4\":\"203.0.113.7\",\"public_ipv6\":\"\",\
              \"client_ip\":\"192.0.2.10\",\"client_port\":53124}\n"
        );
        assert_eq!(base.client_ip, "");
        assert_eq!(base.client_port, 0);
    }

    #[test]
    fn non_discover_requests_are_echoed() {
        let base = output::Response::default();
        assert_eq!(
            response_payload(&base, None, b"hello\r\n"),
            b"hello\r\n".to_vec()
        );
        assert_eq!(
            response_payload(&base, None, b"discover-now"),
            b"discover-now".to_vec()
        );
    }

    #[test]
    fn discover_request_allows_outer_ascii_whitespace() {
        assert!(is_discover_request(b"discover"));
        assert!(is_discover_request(b" discover\r\n"));
        assert!(!is_discover_request(b"discover now"));
        assert!(!is_discover_request(b""));
    }

    #[test]
    fn tcp_request_can_arrive_in_chunks() {
        assert_eq!(
            tcp_request_from_chunks(&[b"disc", b"over\n"]),
            b"discover\n".to_vec()
        );
        assert!(is_discover_request(&tcp_request_from_chunks(&[
            b"disc", b"over\n"
        ])));
    }

    #[test]
    fn tcp_request_uses_first_line_and_size_limit() {
        assert_eq!(
            tcp_request_from_chunks(&[b"hello\nignored"]),
            b"hello\n".to_vec()
        );

        let long = vec![b'a'; MAX_REQUEST + 128];
        let request = tcp_request_from_chunks(&[&long]);
        assert_eq!(request.len(), MAX_REQUEST);
    }

    #[test]
    fn udp_empty_datagrams_are_ignored() {
        assert!(!should_respond_udp(0));
        assert!(should_respond_udp(1));
    }
}
