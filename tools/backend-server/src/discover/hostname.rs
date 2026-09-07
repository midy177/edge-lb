//! Hostname discovery: the system hostname, read directly via the
//! `gethostname(2)` syscall (`libc`). No subprocess, no DNS involved.

use std::ffi::CStr;

/// POSIX guarantees hostnames fit in `HOST_NAME_MAX`; 256 covers every
/// supported platform (Linux caps at 64, macOS at 256, RFC 1123 at 255).
const HOST_BUF_LEN: usize = 256;

/// Return the system hostname, without any trailing dot.
pub fn discover() -> Result<String, String> {
    let mut buf = [0u8; HOST_BUF_LEN];
    // SAFETY: `buf` is an owned, valid buffer of HOST_BUF_LEN bytes;
    // gethostname writes at most that many bytes including the NUL.
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr().cast::<libc::c_char>(), buf.len()) };
    if ret != 0 {
        return Err(format!(
            "gethostname failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let name = CStr::from_bytes_until_nul(&buf)
        .map_err(|_| "hostname buffer is not NUL-terminated".to_string())?
        .to_string_lossy();
    let name = name.trim().trim_end_matches('.');
    if name.is_empty() {
        return Err("hostname is empty".to_string());
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_hostname_is_nonempty() {
        // Every POSIX system (CI runners included) has a hostname set.
        let h = discover().unwrap();
        assert!(!h.is_empty());
        assert!(!h.ends_with('.'));
    }
}
