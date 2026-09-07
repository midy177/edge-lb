#!/usr/bin/env bash
set -euo pipefail

role=""
force=""

while [ "$#" -gt 0 ]; do
  case "$1" in
    backend|gateway) [ -z "$role" ] || { echo "role specified more than once" >&2; exit 1; }; role="$1"; shift ;;
    --force) force="--force"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

case "$role" in
  backend|gateway) ;;
  *) echo "usage: install.sh backend|gateway [--force]" >&2; exit 1 ;;
esac

[ "${EUID:-1}" = 0 ] || { echo "run as root" >&2; exit 1; }

dir="$(cd "$(dirname "$0")" && pwd)"
install -d -m 0755 /usr/local/bin /etc/edge-lb /var/lib/edge-lb /var/log/edge-lb
install -m 0755 "$dir/edge-lb" /usr/local/bin/edge-lb

if [ ! -f /etc/edge-lb/config.toml ] || [ -n "$force" ]; then
  template="$dir/config.$role.example.toml"
  [ -f "$template" ] || { echo "missing config template: $template" >&2; exit 1; }
  install -m 0644 "$template" /etc/edge-lb/config.toml
fi

/usr/local/bin/edge-lb install "$role" $force
