//! Signature helpers for notification channels.

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn dingtalk_sign(timestamp_ms: i64, secret: &str) -> String {
    let string_to_sign = format!("{timestamp_ms}\n{secret}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(string_to_sign.as_bytes());
    let b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
    urlencoding::encode(&b64).into_owned()
}

pub fn feishu_sign(timestamp_secs: i64, secret: &str) -> String {
    let key = format!("{timestamp_secs}\n{secret}");
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key size");
    mac.update(b"");
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

pub fn hmac_sha256_hex(secret: &str, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

pub fn now_millis() -> i64 {
    (crate::events::now_unix() as i64) * 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_hex_len() {
        assert_eq!(hmac_sha256_hex("k", b"body").len(), 64);
    }
}
