//! Response structure and JSON encoding.

/// All fields are always present.
#[derive(Clone, Default)]
pub struct Response {
    pub hostname: String,
    pub private_ipv4: String,
    pub public_ipv4: String,
    pub public_ipv6: String,
    pub client_ip: String,
    pub client_port: u16,
}

/// Fixed key order, all fields always present; the caller adds the newline.
pub fn encode_response(r: &Response) -> String {
    format!(
        "{{\"hostname\":{},\"private_ipv4\":{},\"public_ipv4\":{},\"public_ipv6\":{},\"client_ip\":{},\"client_port\":{}}}",
        json_escape(&r.hostname),
        json_escape(&r.private_ipv4),
        json_escape(&r.public_ipv4),
        json_escape(&r.public_ipv6),
        json_escape(&r.client_ip),
        r.client_port
    )
}

/// JSON string escaping for the characters that can appear in hostnames and IP
/// address literals.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_encoding_matches_go() {
        let mut r = Response::default();
        assert_eq!(
            encode_response(&r),
            "{\"hostname\":\"\",\"private_ipv4\":\"\",\"public_ipv4\":\"\",\"public_ipv6\":\"\",\
             \"client_ip\":\"\",\"client_port\":0}"
        );

        r.hostname = "node1.example.com".into();
        r.private_ipv4 = "10.0.0.5".into();
        r.public_ipv4 = "203.0.113.7".into();
        r.client_ip = "192.0.2.10".into();
        r.client_port = 53124;
        assert_eq!(
            encode_response(&r),
            "{\"hostname\":\"node1.example.com\",\"private_ipv4\":\"10.0.0.5\",\
             \"public_ipv4\":\"203.0.113.7\",\"public_ipv6\":\"\",\
             \"client_ip\":\"192.0.2.10\",\"client_port\":53124}"
        );
    }

    #[test]
    fn json_escape_control_chars() {
        assert_eq!(json_escape("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_escape("\n\t"), "\"\\n\\t\"");
        assert_eq!(json_escape("\u{1}"), "\"\\u0001\"");
    }
}
