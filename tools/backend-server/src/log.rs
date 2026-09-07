//! Timestamped stderr logging using local time.

use std::time::{SystemTime, UNIX_EPOCH};

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    // SAFETY: `tm` is a plain C struct; localtime_r writes into it and never
    // retains the pointer. Zero-initializing is the standard pattern.
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&secs, &mut tm).is_null() {
            return String::new();
        }
        format!(
            "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
}

/// Log to stderr with a local date-time prefix.
pub fn logln(msg: &str) {
    eprintln!("{} {}", timestamp(), msg);
}

/// Log only when `-debug` is enabled.
pub fn debug_if(enabled: bool, msg: &str) {
    if enabled {
        logln(msg);
    }
}

/// Log, then exit with status 1.
pub fn fatal(msg: &str) -> ! {
    logln(msg);
    std::process::exit(1)
}
