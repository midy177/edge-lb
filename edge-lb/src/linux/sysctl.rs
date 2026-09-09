use anyhow::{Context, Result};
use std::fs;
use std::io;

const IPV4_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";
const SOMAXCONN: &str = "/proc/sys/net/core/somaxconn";
const NETDEV_MAX_BACKLOG: &str = "/proc/sys/net/core/netdev_max_backlog";
const RMEM_MAX: &str = "/proc/sys/net/core/rmem_max";
const WMEM_MAX: &str = "/proc/sys/net/core/wmem_max";
const TCP_MAX_SYN_BACKLOG: &str = "/proc/sys/net/ipv4/tcp_max_syn_backlog";
const TCP_FIN_TIMEOUT: &str = "/proc/sys/net/ipv4/tcp_fin_timeout";
const NF_CONNTRACK_MAX: &str = "/proc/sys/net/netfilter/nf_conntrack_max";

const TARGET_SOMAXCONN: u64 = 65_535;
const TARGET_NETDEV_MAX_BACKLOG: u64 = 250_000;
const TARGET_SOCKET_BUFFER_MAX: u64 = 134_217_728;
const TARGET_TCP_MAX_SYN_BACKLOG: u64 = 65_535;
const TARGET_TCP_FIN_TIMEOUT: u64 = 15;
const TARGET_NF_CONNTRACK_MAX: u64 = 262_144;

/// Native gateway DNAT requires the kernel to forward the rewritten packet.
/// This is deliberately convergent and is not reverted during cleanup because
/// forwarding is a host capability shared by other networking components.
pub fn ensure_ipv4_forwarding() -> Result<()> {
    let current =
        fs::read_to_string(IPV4_FORWARD).with_context(|| format!("reading {IPV4_FORWARD}"))?;
    if current.trim() == "1" {
        return Ok(());
    }
    fs::write(IPV4_FORWARD, b"1\n")
        .with_context(|| format!("enabling IPv4 forwarding through {IPV4_FORWARD}"))?;
    tracing::info!("[linux] enabled IPv4 forwarding for native gateway DNAT");
    Ok(())
}

/// Gateway datapath tuning is intentionally conservative: required forwarding
/// remains fatal, while capacity knobs are raised only when they are below the
/// default production floor.
pub fn ensure_gateway_datapath_tuning() -> Result<()> {
    ensure_ipv4_forwarding().with_context(|| "enabling IPv4 forwarding")?;
    apply_common_datapath_tuning("gateway");
    apply_conntrack_capacity_floor("gateway");
    Ok(())
}

/// Backend return-path tuning mirrors gateway capacity knobs. IPv4 forwarding
/// is also required because replies may traverse host bridges or containers
/// before policy routing sends them through edge-return.
pub fn ensure_backend_datapath_tuning() -> Result<()> {
    ensure_ipv4_forwarding().with_context(|| "enabling IPv4 forwarding")?;
    apply_common_datapath_tuning("backend");
    apply_conntrack_capacity_floor("backend");
    Ok(())
}

fn apply_common_datapath_tuning(role: &str) {
    ensure_sysctl_floor(role, SOMAXCONN, TARGET_SOMAXCONN);
    ensure_sysctl_floor(role, NETDEV_MAX_BACKLOG, TARGET_NETDEV_MAX_BACKLOG);
    ensure_sysctl_floor(role, RMEM_MAX, TARGET_SOCKET_BUFFER_MAX);
    ensure_sysctl_floor(role, WMEM_MAX, TARGET_SOCKET_BUFFER_MAX);
    ensure_sysctl_floor(role, TCP_MAX_SYN_BACKLOG, TARGET_TCP_MAX_SYN_BACKLOG);
    ensure_sysctl_ceiling(role, TCP_FIN_TIMEOUT, TARGET_TCP_FIN_TIMEOUT);
}

fn apply_conntrack_capacity_floor(role: &str) {
    ensure_sysctl_floor(role, NF_CONNTRACK_MAX, TARGET_NF_CONNTRACK_MAX);
}

fn ensure_sysctl_floor(role: &str, path: &str, floor: u64) {
    ensure_sysctl_with(
        role,
        path,
        |current| {
            if current < floor { Some(floor) } else { None }
        },
    );
}

fn ensure_sysctl_ceiling(role: &str, path: &str, ceiling: u64) {
    ensure_sysctl_with(role, path, |current| {
        if current > ceiling {
            Some(ceiling)
        } else {
            None
        }
    });
}

fn ensure_sysctl_with<F>(role: &str, path: &str, target: F)
where
    F: FnOnce(u64) -> Option<u64>,
{
    let current = match read_sysctl_u64(path) {
        Ok(value) => value,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            tracing::debug!("[linux] {role} sysctl tuning skipped: {path} is not available");
            return;
        }
        Err(err) => {
            tracing::warn!("[linux] {role} sysctl tuning skipped: reading {path}: {err}");
            return;
        }
    };

    let Some(next) = target(current) else {
        return;
    };

    if let Err(err) = fs::write(path, format!("{next}\n")) {
        tracing::warn!("[linux] {role} sysctl tuning failed: writing {path}={next}: {err}");
        return;
    }
    tracing::info!("[linux] {role} sysctl tuned {path}: {current} -> {next}");
}

fn read_sysctl_u64(path: &str) -> io::Result<u64> {
    let raw = fs::read_to_string(path)?;
    raw.trim()
        .parse::<u64>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestSysctl(std::path::PathBuf);

    impl TestSysctl {
        fn new() -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("edge-lb-sysctl-{}-{nonce}", std::process::id()));
            fs::File::create_new(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &str {
            self.0.to_str().unwrap()
        }
    }

    impl Drop for TestSysctl {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn forwarding_path_is_the_kernel_sysctl() {
        assert_eq!(IPV4_FORWARD, "/proc/sys/net/ipv4/ip_forward");
    }

    #[test]
    fn conntrack_path_is_the_kernel_sysctl() {
        assert_eq!(NF_CONNTRACK_MAX, "/proc/sys/net/netfilter/nf_conntrack_max");
    }

    #[test]
    fn floor_tuning_never_lowers_existing_values() {
        let file = TestSysctl::new();
        for current in [TARGET_NF_CONNTRACK_MAX, TARGET_NF_CONNTRACK_MAX + 1] {
            let original = format!("{current:020}\n");
            fs::write(&file.0, &original).unwrap();
            ensure_sysctl_floor("test", file.path(), TARGET_NF_CONNTRACK_MAX);
            assert_eq!(fs::read_to_string(&file.0).unwrap(), original);
        }
        fs::write(&file.0, "1\n").unwrap();
        ensure_sysctl_floor("test", file.path(), TARGET_NF_CONNTRACK_MAX);
        assert_eq!(
            read_sysctl_u64(file.path()).unwrap(),
            TARGET_NF_CONNTRACK_MAX
        );
    }

    #[test]
    fn tcp_fin_timeout_tuning_never_raises_lower_values() {
        let file = TestSysctl::new();
        for current in [TARGET_TCP_FIN_TIMEOUT, TARGET_TCP_FIN_TIMEOUT - 1] {
            let original = format!("{current:020}\n");
            fs::write(&file.0, &original).unwrap();
            ensure_sysctl_ceiling("test", file.path(), TARGET_TCP_FIN_TIMEOUT);
            assert_eq!(fs::read_to_string(&file.0).unwrap(), original);
        }
        fs::write(&file.0, "60\n").unwrap();
        ensure_sysctl_ceiling("test", file.path(), TARGET_TCP_FIN_TIMEOUT);
        assert_eq!(
            read_sysctl_u64(file.path()).unwrap(),
            TARGET_TCP_FIN_TIMEOUT
        );
    }

    #[test]
    fn invalid_or_missing_sysctl_is_not_overwritten_or_created() {
        let file = TestSysctl::new();
        fs::write(&file.0, "invalid\n").unwrap();
        ensure_sysctl_floor("test", file.path(), TARGET_NF_CONNTRACK_MAX);
        ensure_sysctl_ceiling("test", file.path(), TARGET_TCP_FIN_TIMEOUT);
        assert_eq!(fs::read_to_string(&file.0).unwrap(), "invalid\n");
        fs::remove_file(&file.0).unwrap();
        ensure_sysctl_floor("test", file.path(), TARGET_NF_CONNTRACK_MAX);
        ensure_sysctl_ceiling("test", file.path(), TARGET_TCP_FIN_TIMEOUT);
        assert!(!file.0.exists());
    }
}
