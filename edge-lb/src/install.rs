//! Local installer for systemd-based Linux hosts.

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};

use crate::{
    cli::{InstallArgs, InstallRole, UninstallServiceArgs},
    config::{Config, NodeRole},
    linux::privilege,
};

const CONFIG_DIR: &str = "/etc/edge-lb";
const STATE_DIR: &str = "/var/lib/edge-lb";
const LOG_DIR: &str = "/var/log/edge-lb";
pub fn install_service(cfg: &Config, args: &InstallArgs) -> Result<()> {
    privilege::require_root()?;
    if !cfg!(target_os = "linux") {
        bail!("install service is supported only on Linux systemd hosts");
    }

    let bin_path = install_binary(&args.prefix)?;
    fs::create_dir_all(CONFIG_DIR).context("creating /etc/edge-lb")?;
    fs::create_dir_all(STATE_DIR).context("creating /var/lib/edge-lb")?;
    fs::create_dir_all(LOG_DIR).context("creating /var/log/edge-lb")?;
    let role = write_config(cfg, args)?;
    write_unit(&bin_path, args)?;

    let unit = format!("{}.service", args.service_name);
    systemd_reload().context("systemd daemon-reload")?;
    systemd_enable(&unit).context("systemd enable")?;
    if !args.no_start {
        systemd_restart(&unit).context("systemd restart")?;
    }

    println!(
        "installed {} as {}.service (role {})",
        bin_path.display(),
        args.service_name,
        role.as_str()
    );
    Ok(())
}

pub fn uninstall_service(args: &UninstallServiceArgs) -> Result<()> {
    privilege::require_root()?;
    if !cfg!(target_os = "linux") {
        bail!("uninstall service is supported only on Linux systemd hosts");
    }
    let unit = format!("{}.service", args.service_name);
    systemd_stop(&unit).ok();
    systemd_disable(&unit).ok();
    let unit_path = PathBuf::from(format!("/etc/systemd/system/{unit}"));
    if unit_path.exists() {
        fs::remove_file(&unit_path).with_context(|| format!("removing {}", unit_path.display()))?;
    }
    systemd_reload().context("systemd daemon-reload")?;
    println!("uninstalled {unit}; config, state and datapath resources were left intact");
    Ok(())
}

fn systemd_proxy<'a>(
    connection: &'a zbus::blocking::Connection,
) -> Result<zbus::blocking::Proxy<'a>> {
    zbus::blocking::Proxy::new(
        connection,
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1",
        "org.freedesktop.systemd1.Manager",
    )
    .context("creating systemd D-Bus proxy")
}

fn systemd_reload() -> Result<()> {
    let connection = zbus::blocking::Connection::system().context("connecting to systemd D-Bus")?;
    systemd_proxy(&connection)?.call_method("Reload", &())?;
    Ok(())
}

fn systemd_enable(unit: &str) -> Result<()> {
    let connection = zbus::blocking::Connection::system().context("connecting to systemd D-Bus")?;
    systemd_proxy(&connection)?.call_method("EnableUnitFiles", &(vec![unit], false, true))?;
    Ok(())
}

fn systemd_restart(unit: &str) -> Result<()> {
    let connection = zbus::blocking::Connection::system().context("connecting to systemd D-Bus")?;
    systemd_proxy(&connection)?.call_method("RestartUnit", &(unit, "replace"))?;
    Ok(())
}

fn systemd_stop(unit: &str) -> Result<()> {
    let connection = zbus::blocking::Connection::system().context("connecting to systemd D-Bus")?;
    systemd_proxy(&connection)?.call_method("StopUnit", &(unit, "replace"))?;
    Ok(())
}

fn systemd_disable(unit: &str) -> Result<()> {
    let connection = zbus::blocking::Connection::system().context("connecting to systemd D-Bus")?;
    systemd_proxy(&connection)?.call_method("DisableUnitFiles", &(vec![unit], false))?;
    Ok(())
}

fn install_binary(prefix: &Path) -> Result<PathBuf> {
    let current = std::env::current_exe().context("resolving current executable")?;
    let bin_dir = prefix.join("bin");
    fs::create_dir_all(&bin_dir).with_context(|| format!("creating {}", bin_dir.display()))?;
    let target = bin_dir.join("edge-lb");
    if canonical(&current) != canonical(&target) {
        fs::copy(&current, &target)
            .with_context(|| format!("copying {} to {}", current.display(), target.display()))?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod 0755 {}", target.display()))?;
    }
    Ok(target)
}

fn write_config(cfg: &Config, args: &InstallArgs) -> Result<InstallRole> {
    let role = args.role.unwrap_or(match cfg.node_role {
        NodeRole::Gateway => InstallRole::Gateway,
        NodeRole::Backend => InstallRole::Backend,
    });
    let path = Path::new(CONFIG_DIR).join("config.toml");
    if path.exists() && !args.force {
        println!("keeping existing {}", path.display());
        return Ok(role);
    }
    let mut file = cfg.file.clone();
    file.node_role = match role {
        InstallRole::Gateway => NodeRole::Gateway,
        InstallRole::Backend => NodeRole::Backend,
    };
    if let Some(value) = &args.node_name {
        file.node_name = value.clone();
    }
    if let Some(value) = args.public_ip {
        file.public_ip = value;
    }
    if let Some(value) = args.underlay_ip {
        file.underlay_ip = value;
    }
    if let Some(value) = &args.underlay_dev {
        file.network.underlay_dev = value.clone();
    }
    if let Some(value) = args.vni {
        file.network.vni = value;
    }
    if let Some(value) = args.vxlan_port {
        file.network.vxlan_port = value;
    }
    if let Some(value) = args.dscp {
        file.network.dscp = value;
    }
    file.state_dir = STATE_DIR.into();
    file.validate()
        .context("validating generated service config")?;
    file.save_atomic(&path)?;
    Ok(role)
}

fn write_unit(bin_path: &Path, args: &InstallArgs) -> Result<()> {
    let unit_path = PathBuf::from(format!("/etc/systemd/system/{}.service", args.service_name));
    let unit = format!(
        "[Unit]\n\
         Description=Edge LB\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         [Service]\n\
         Type=simple\n\
         Environment=MALLOC_ARENA_MAX=2\n\
         OOMScoreAdjust=-900\n\
         ExecStart={} --config /etc/edge-lb/config.toml\n\
         Restart=always\n\
         RestartSec=3\n\n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bin_path.display()
    );
    fs::write(&unit_path, unit).with_context(|| format!("writing {}", unit_path.display()))?;
    Ok(())
}

fn canonical(path: &Path) -> Option<PathBuf> {
    path.canonicalize().ok()
}
