#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: scripts/deb.sh <rust-target> [version] [gateway|backend|all]}"
version="${2:-0.1.0}"
role="${3:-all}"

case "$target" in
  x86_64-unknown-linux-gnu) arch="amd64" ;;
  aarch64-unknown-linux-gnu) arch="arm64" ;;
  *) echo "unsupported deb target: $target" >&2; exit 1 ;;
esac

case "$role" in
  gateway|backend|all) ;;
  *) echo "unsupported package role: $role" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
release_binary="$root/target/$target/release/edge-lb"
compressed_binary="$root/dist/compressed/edge-lb-${version}-${arch}-upx"
binary="$release_binary"
if [ -x "$compressed_binary" ]; then
  binary="$compressed_binary"
fi

[ -x "$binary" ] || { echo "missing binary: $binary" >&2; exit 1; }
command -v dpkg-deb >/dev/null || { echo "missing dpkg-deb" >&2; exit 1; }

build_role_package() {
  local pkg_role="$1"
  local package_name="edge-lb-$pkg_role"
  local other_role="gateway"
  local description_role="gateway"
  if [ "$pkg_role" = "gateway" ]; then
    other_role="backend"
    description_role="gateway control-plane and native DNAT datapath"
  else
    description_role="backend VXLAN return-path"
  fi

  local pkg="$root/dist/deb/${package_name}_${version}_${arch}"
  rm -rf "$pkg"
  mkdir -p \
    "$pkg/DEBIAN" \
    "$pkg/usr/local/bin" \
    "$pkg/usr/share/doc/$package_name" \
    "$pkg/usr/share/edge-lb" \
    "$pkg/lib/systemd/system"

  cp "$binary" "$pkg/usr/local/bin/edge-lb"
  cp "$root/deploy/config.gateway.example.toml" "$pkg/usr/share/edge-lb/config.gateway.example.toml"
  cp "$root/deploy/config.backend.example.toml" "$pkg/usr/share/edge-lb/config.backend.example.toml"
  cp "$root/deploy/edge-lb@.service" "$pkg/lib/systemd/system/edge-lb@.service"
  cp "$root/deploy/PACKAGE-README.md" "$pkg/usr/share/doc/$package_name/README.md"
  chmod 0755 "$pkg/usr/local/bin/edge-lb"

  local installed_size
  installed_size="$(du -sk "$pkg" | awk '{print $1}')"

  cat > "$pkg/DEBIAN/control" <<EOF
Package: $package_name
Version: $version
Section: net
Priority: optional
Architecture: $arch
Installed-Size: $installed_size
Maintainer: edge-lb maintainers
Depends: iproute2, nftables, ca-certificates
Provides: edge-lb
Conflicts: edge-lb, edge-lb-$other_role
Replaces: edge-lb
Description: Edge LB $description_role agent
 Rust agent for native default-mode DNAT/SNAT load balancing, DSCP marking,
 VXLAN return-path routing, and an xDS-like gateway/backend control plane.
EOF

  cat > "$pkg/DEBIAN/postinst" <<EOF
#!/usr/bin/env bash
set -e
install -d -m 0755 /etc/edge-lb /var/lib/edge-lb /var/log/edge-lb
if [ ! -f /etc/edge-lb/config.toml ]; then
  install -m 0644 /usr/share/edge-lb/config.$pkg_role.example.toml /etc/edge-lb/config.toml
fi
if command -v systemctl >/dev/null; then
  systemctl daemon-reload || true
fi
EOF

  cat > "$pkg/DEBIAN/prerm" <<'EOF'
#!/usr/bin/env bash
set -e
if command -v systemctl >/dev/null; then
  systemctl stop 'edge-lb@*.service' 2>/dev/null || true
fi
EOF

  chmod 0755 "$pkg/DEBIAN/postinst" "$pkg/DEBIAN/prerm"

  local out="$root/dist/${package_name}_${version}_${arch}.deb"
  mkdir -p "$root/dist"
  dpkg-deb --build --root-owner-group "$pkg" "$out"
  echo "$out"
}

if [ "$role" = "all" ]; then
  build_role_package gateway
  build_role_package backend
else
  build_role_package "$role"
fi
