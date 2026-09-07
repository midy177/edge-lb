//! Backend identity server for edge-lb load-balancing tests.
//!
//! In service mode it listens on TCP and/or UDP, returns this node's discovered
//! network identity for the `discover` payload, and echoes other payloads.
//!
//! Module layout:
//! * `cli` — command-line parsing (`-provider` is a placeholder: accepted,
//!   never used)
//! * `log` — timestamped output helpers
//! * `output` — response structure and JSON encoding
//! * `discover` — the discovery engine (underlay IP, public IP, hostname)
//! * `server` — TCP/UDP response service
//! * `system` — OS interfaces (interface addresses, default route)

mod cli;
mod discover;
mod log;
mod output;
mod server;
mod system;

use std::process::ExitCode;

fn main() -> ExitCode {
    let prog = std::env::args()
        .next()
        .unwrap_or_else(|| "backend-server".into());
    let args: Vec<String> = std::env::args().skip(1).collect();

    let cfg = match cli::parse(&args) {
        Ok(c) => c,
        Err(cli::ParseError::Help) => {
            eprint!("{}", cli::usage(&prog));
            return ExitCode::SUCCESS;
        }
        Err(cli::ParseError::Fail(msg)) => {
            eprintln!("{msg}");
            eprint!("{}", cli::usage(&prog));
            return ExitCode::from(2);
        }
    };

    let debug = cfg.debug;

    if cfg.service_enabled() {
        return match server::run(server::Config {
            debug,
            tcp_addr: cfg.tcp_addr(),
            udp_addr: cfg.udp_addr(),
        }) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => log::fatal(&e),
        };
    }

    match cfg.field.as_deref().unwrap_or("") {
        "hostname" => match discover::hostname::discover() {
            Ok(h) => {
                println!("{h}");
                ExitCode::SUCCESS
            }
            Err(e) => log::fatal(&e),
        },
        "privatev4" => match discover::underlay::discover(debug) {
            Ok(ip) => {
                println!("{ip}");
                ExitCode::SUCCESS
            }
            Err(e) => log::fatal(&e),
        },
        "publicv4" => match discover::publicip::discover_v4(debug) {
            Ok(ip) => {
                println!("{ip}");
                ExitCode::SUCCESS
            }
            Err(e) => log::fatal(&e),
        },
        "publicv6" => match discover::publicip::discover_v6(debug) {
            Ok(ip) => {
                println!("{ip}");
                ExitCode::SUCCESS
            }
            Err(e) => log::fatal(&e),
        },
        "" => {
            let ret = discover_all(debug);
            println!("{}", output::encode_response(&ret));
            ExitCode::SUCCESS
        }
        _ => log::fatal("valid fields are: hostname, privatev4, publicv4, publicv6"),
    }
}

/// Run every discovery and collect the results; failed lookups stay empty,
/// like the Go version's default (non-debug) behaviour.
fn discover_all(debug: bool) -> output::Response {
    let mut ret = output::Response::default();

    // Local syscall — no network involved; run it before the slow lookups.
    match discover::hostname::discover() {
        Ok(h) => ret.hostname = h,
        Err(e) => log::debug_if(debug, &format!("failed to get hostname: {e}")),
    }
    let public = discover::publicip::discover_v4(debug);
    match discover::underlay::discover(debug) {
        Ok(ip) => ret.private_ipv4 = ip.to_string(),
        Err(e) => log::debug_if(debug, &format!("failed to get private IPv4 address: {e}")),
    }
    match &public {
        Ok(ip) => ret.public_ipv4 = ip.to_string(),
        Err(e) => log::debug_if(debug, &format!("failed to get public IPv4 address: {e}")),
    }
    match discover::publicip::discover_v6(debug) {
        Ok(ip) => ret.public_ipv6 = ip.to_string(),
        Err(e) => log::debug_if(debug, &format!("failed to get public IPv6 address: {e}")),
    }

    ret
}
