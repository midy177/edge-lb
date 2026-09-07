#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: scripts/package.sh <rust-target> [version]}"
version="${2:-0.1.0}"

case "$target" in
  x86_64-unknown-linux-gnu) arch="amd64" ;;
  aarch64-unknown-linux-gnu) arch="arm64" ;;
  *) echo "unsupported package target: $target" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"
work="$dist/pkg/edge-lb"
binary="$root/target/$target/release/edge-lb"

[ -x "$binary" ] || { echo "missing binary: $binary" >&2; exit 1; }

rm -rf "$dist/pkg"
mkdir -p "$work"
cp "$binary" "$work/edge-lb"
cp "$root/deploy/edge-lb.service.template" "$work/"
cp "$root/deploy/config.gateway.example.toml" "$work/"
cp "$root/deploy/config.backend.example.toml" "$work/"
cp "$root/deploy/install.sh" "$work/"
cp "$root/deploy/PACKAGE-README.md" "$work/README.md"
chmod 0755 "$work/edge-lb" "$work/install.sh"

tarball="$dist/edge-lb-$version-linux-$arch.tar.gz"
mkdir -p "$dist"
tar -C "$dist/pkg" -czf "$tarball" edge-lb
echo "$tarball"
