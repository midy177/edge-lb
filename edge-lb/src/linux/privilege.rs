//! Process privilege checks for operations that modify Linux networking state.

use anyhow::Result;

/// Refuse to continue unless running with effective UID 0.
pub fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "this command modifies kernel/network state; re-run as root (sudo)"
        ))
    }
}
