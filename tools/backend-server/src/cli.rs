//! Command-line parsing:
//! `-flag value`, `-flag=value`, `--flag value`, `--flag=value`; boolean flags
//! accept `-flag` or `-flag=true` (never a space-separated value); parsing
//! stops at the first positional argument or a bare `--`.

/// Parsed command-line configuration.
///
/// `provider` is intentionally absent: the flag is accepted as a no-op
/// placeholder, but its value is discarded at parse time.
#[derive(Default)]
pub struct Config {
    pub debug: bool,
    pub field: Option<String>,
    pub serve: bool,
    pub listen: Option<String>,
    pub tcp: Option<String>,
    pub udp: Option<String>,
}

impl Config {
    /// Whether any service-mode flag was supplied.
    pub fn service_enabled(&self) -> bool {
        self.serve || self.tcp.is_some() || self.udp.is_some()
    }

    /// Effective TCP listen address. `None` means TCP is disabled.
    pub fn tcp_addr(&self) -> Option<String> {
        if self.tcp.is_some() {
            return self.tcp.clone();
        }
        if self.serve {
            return Some(self.listen_addr());
        }
        None
    }

    /// Effective UDP listen address. `None` means UDP is disabled.
    pub fn udp_addr(&self) -> Option<String> {
        if self.udp.is_some() {
            return self.udp.clone();
        }
        if self.serve {
            return Some(self.listen_addr());
        }
        None
    }

    fn listen_addr(&self) -> String {
        self.listen
            .clone()
            .unwrap_or_else(|| "0.0.0.0:8080".to_string())
    }
}

#[derive(Debug)]
pub enum ParseError {
    /// `-h` / `-help`: print usage and exit 0 (Go flag ErrHelp behaviour).
    Help,
    /// Print the message followed by usage to stderr; exit code 2.
    Fail(String),
}

/// Usage text.
pub fn usage(prog: &str) -> String {
    let mut s = format!("Usage of {prog}:\n");
    s.push_str("  -debug\n");
    s.push_str("    \tdebug mode\n");
    s.push_str("  -field string\n");
    s.push_str(
        "    \treturn only a single field.  Options are: \"hostname\", \
         \"publicv4\", publicv6\", \"privatev4\"\n",
    );
    s.push_str("  -provider string\n");
    s.push_str("    \tprovider type.  Options are: \"aws\", \"azure\", \"do\", gcp\"\n");
    s.push_str("  -serve\n");
    s.push_str("    \trun TCP and UDP response service\n");
    s.push_str("  -listen string\n");
    s.push_str("    \tlisten address for -serve TCP and UDP service (default \"0.0.0.0:8080\")\n");
    s.push_str("  -tcp string\n");
    s.push_str("    \trun TCP response service on this address\n");
    s.push_str("  -udp string\n");
    s.push_str("    \trun UDP response service on this address\n");
    s
}

/// Parse arguments the way Go's `flag` package does.
pub fn parse(args: &[String]) -> Result<Config, ParseError> {
    let mut cfg = Config::default();
    let mut i = 0;

    while i < args.len() {
        let arg = &args[i];

        // A non-flag argument terminates parsing (Go: flag.Parse stops there).
        if !arg.starts_with('-') || arg.len() < 2 {
            break;
        }

        let mut num_minuses = 1;
        if arg.starts_with("--") {
            if arg.len() == 2 {
                break; // bare "--" terminates flag parsing
            }
            num_minuses = 2;
        }

        let body = &arg[num_minuses..];
        if body.is_empty() || body.starts_with('-') || body.starts_with('=') {
            return Err(ParseError::Fail(format!("bad flag syntax: {arg}")));
        }

        let (name, value, has_value) = match body.find('=') {
            Some(p) => (&body[..p], body[p + 1..].to_string(), true),
            None => (body, String::new(), false),
        };

        match name {
            "debug" => {
                if has_value {
                    match value.parse::<bool>() {
                        Ok(v) => cfg.debug = v,
                        Err(_) => {
                            return Err(ParseError::Fail(format!(
                                "invalid boolean value \"{value}\" for -debug: parse error"
                            )));
                        }
                    }
                } else {
                    cfg.debug = true;
                }
            }
            "serve" => {
                if has_value {
                    match value.parse::<bool>() {
                        Ok(v) => cfg.serve = v,
                        Err(_) => {
                            return Err(ParseError::Fail(format!(
                                "invalid boolean value \"{value}\" for -serve: parse error"
                            )));
                        }
                    }
                } else {
                    cfg.serve = true;
                }
            }
            "provider" => {
                // Placeholder: accepted, value ignored.
                if !has_value {
                    i += 1;
                    if i >= args.len() {
                        return Err(ParseError::Fail(format!("flag needs an argument: -{name}")));
                    }
                }
            }
            "field" => {
                let value = if has_value {
                    value
                } else {
                    i += 1;
                    if i >= args.len() {
                        return Err(ParseError::Fail(format!("flag needs an argument: -{name}")));
                    }
                    args[i].clone()
                };
                if name == "field" {
                    cfg.field = Some(value);
                }
            }
            "listen" | "tcp" | "udp" => {
                let value = if has_value {
                    value
                } else {
                    i += 1;
                    if i >= args.len() {
                        return Err(ParseError::Fail(format!("flag needs an argument: -{name}")));
                    }
                    args[i].clone()
                };
                match name {
                    "listen" => cfg.listen = Some(value),
                    "tcp" => cfg.tcp = Some(value),
                    "udp" => cfg.udp = Some(value),
                    _ => unreachable!(),
                }
            }
            "h" | "help" => return Err(ParseError::Help),
            _ => {
                return Err(ParseError::Fail(format!(
                    "flag provided but not defined: -{name}"
                )));
            }
        }

        i += 1;
    }

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn supported_flag_forms() {
        // `-provider` is a placeholder: accepted (with its value) but ignored.
        let c = parse(&args(&["-provider", "gcp", "-field", "publicv4", "-debug"])).unwrap();
        assert!(c.debug);
        assert_eq!(c.field.as_deref(), Some("publicv4"));

        let c = parse(&args(&["--field=hostname"])).unwrap();
        assert_eq!(c.field.as_deref(), Some("hostname"));
        assert!(!c.debug);

        let c = parse(&args(&["-debug=false"])).unwrap();
        assert!(!c.debug);

        // `-field ""` behaves like the Go version: empty value, flag present.
        let c = parse(&args(&["-field", ""])).unwrap();
        assert_eq!(c.field.as_deref(), Some(""));
    }

    #[test]
    fn provider_is_placeholder() {
        // Any provider value parses fine and is simply discarded.
        assert!(parse(&args(&["-provider", "aws"])).is_ok());
        assert!(parse(&args(&["-provider=gcp"])).is_ok());
        assert!(parse(&args(&["--provider", "do"])).is_ok());
    }

    #[test]
    fn parsing_stops_at_positional() {
        // Everything from the first positional onward is ignored, like Go.
        let c = parse(&args(&["-debug", "extra", "-field", "publicv4"])).unwrap();
        assert!(c.debug);
        assert_eq!(c.field, None);

        let c = parse(&args(&["-debug", "--", "-field", "publicv4"])).unwrap();
        assert!(c.debug);
        assert_eq!(c.field, None);
    }

    #[test]
    fn error_messages_match_go() {
        assert!(matches!(
            parse(&args(&["-nope"])),
            Err(ParseError::Fail(m)) if m == "flag provided but not defined: -nope"
        ));
        assert!(matches!(
            parse(&args(&["-provider"])),
            Err(ParseError::Fail(m)) if m == "flag needs an argument: -provider"
        ));
        assert!(matches!(
            parse(&args(&["-debug=x"])),
            Err(ParseError::Fail(m))
                if m == "invalid boolean value \"x\" for -debug: parse error"
        ));
        assert!(matches!(
            parse(&args(&["-serve=x"])),
            Err(ParseError::Fail(m))
                if m == "invalid boolean value \"x\" for -serve: parse error"
        ));
        assert!(matches!(parse(&args(&["-h"])), Err(ParseError::Help)));
        assert!(matches!(parse(&args(&["-help"])), Err(ParseError::Help)));
        assert!(matches!(
            parse(&args(&["---x"])),
            Err(ParseError::Fail(m)) if m == "bad flag syntax: ---x"
        ));
        assert!(matches!(
            parse(&args(&["-=v"])),
            Err(ParseError::Fail(m)) if m == "bad flag syntax: -=v"
        ));
    }

    #[test]
    fn service_flags_choose_listeners() {
        let c = parse(&args(&["-serve"])).unwrap();
        assert!(c.service_enabled());
        assert_eq!(c.tcp_addr().as_deref(), Some("0.0.0.0:8080"));
        assert_eq!(c.udp_addr().as_deref(), Some("0.0.0.0:8080"));

        let c = parse(&args(&["-serve", "-listen", "127.0.0.1:9000"])).unwrap();
        assert_eq!(c.tcp_addr().as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(c.udp_addr().as_deref(), Some("127.0.0.1:9000"));

        let c = parse(&args(&["-tcp", "127.0.0.1:9001"])).unwrap();
        assert!(c.service_enabled());
        assert_eq!(c.tcp_addr().as_deref(), Some("127.0.0.1:9001"));
        assert_eq!(c.udp_addr(), None);

        let c = parse(&args(&[
            "-serve",
            "-listen",
            "127.0.0.1:9000",
            "-udp=127.0.0.1:9002",
        ]))
        .unwrap();
        assert_eq!(c.tcp_addr().as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(c.udp_addr().as_deref(), Some("127.0.0.1:9002"));
    }
}
