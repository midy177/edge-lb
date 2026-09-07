#!/usr/bin/env bash
set -euo pipefail

vip="192.168.0.6"
port="8080"
duration="90"
concurrency="8"
payload="discover"
failover_after="20"
gateway_ssh=""
target_gateway=""
api_listen="127.0.0.1:18080"
out_dir=""

usage() {
  cat <<'USAGE'
Usage:
  edge-lb-ha-failover-pressure.sh --gateway-ssh USER@HOST --target-gateway NAME [options]

Options:
  --vip IP                 HA VIP. Default: 192.168.0.6
  --port PORT              Listener port. Default: 8080
  --duration SECONDS       Total pressure duration. Default: 90
  --concurrency N          Number of workers per protocol. Default: 8
  --payload TEXT           Payload sent with a trailing newline. Default: discover
  --failover-after SEC     Seconds before failover. Default: 20
  --gateway-ssh USER@HOST  Gateway SSH endpoint used to call local API.
  --target-gateway NAME    HA target gateway name, for example VM-0-16-ubuntu.
  --api-listen HOST:PORT   Gateway local API listen endpoint. Default: 127.0.0.1:18080
  --out-dir DIR            Output directory. Default: /tmp/edge-lb-ha-failover-<timestamp>
  -h, --help               Show this help.

The script starts a TCP+UDP pressure run, triggers /api/v1/ha/failover on the
selected gateway after --failover-after seconds, then prints before/during/after
success statistics using the pressure script raw results.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vip) vip="$2"; shift 2 ;;
    --port) port="$2"; shift 2 ;;
    --duration) duration="$2"; shift 2 ;;
    --concurrency) concurrency="$2"; shift 2 ;;
    --payload) payload="$2"; shift 2 ;;
    --failover-after) failover_after="$2"; shift 2 ;;
    --gateway-ssh) gateway_ssh="$2"; shift 2 ;;
    --target-gateway) target_gateway="$2"; shift 2 ;;
    --api-listen) api_listen="$2"; shift 2 ;;
    --out-dir) out_dir="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$gateway_ssh" || -z "$target_gateway" ]]; then
  usage >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pressure_script="$script_dir/edge-lb-ha-pressure.sh"
if [[ ! -x "$pressure_script" ]]; then
  echo "missing executable pressure script: $pressure_script" >&2
  exit 1
fi

if [[ -z "$out_dir" ]]; then
  out_dir="/tmp/edge-lb-ha-failover-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$out_dir"

failover_marker="$out_dir/failover.timestamp"
failover_response="$out_dir/failover.response.json"

"$pressure_script" \
  --vip "$vip" \
  --port "$port" \
  --protocol both \
  --duration "$duration" \
  --concurrency "$concurrency" \
  --payload "$payload" \
  --out-dir "$out_dir/pressure" &
pressure_pid=$!

sleep "$failover_after"
date -Is > "$failover_marker"

ssh "$gateway_ssh" "
  set -eu
  TOK=\$(sudo awk '\$0 ~ /^\\[gateway\\.api\\]/ {in_api=1; next} \$0 ~ /^\\[/ {in_api=0} in_api && \$1 == \"auth_token\" {gsub(/\\\"/,\"\",\$3); print \$3; exit}' /etc/edge-lb/config.toml)
  curl -sS -X POST \
    -H \"Authorization: Bearer \$TOK\" \
    -H 'Content-Type: application/json' \
    --data '{\"gateway\":\"$target_gateway\"}' \
    http://$api_listen/api/v1/ha/failover
" | tee "$failover_response"
echo

wait "$pressure_pid" || true

results="$out_dir/pressure/results.tsv"
summary="$out_dir/failover-summary.txt"
marker_epoch=$(date -d "$(cat "$failover_marker")" +%s)

{
  echo "edge-lb HA failover pressure summary"
  echo "target=$vip:$port duration=${duration}s concurrency=$concurrency failover_after=${failover_after}s target_gateway=$target_gateway"
  echo "failover_at=$(cat "$failover_marker")"
  echo "failover_response=$(tr '\n' ' ' < "$failover_response")"
  echo
  awk -F '\t' -v marker="$marker_epoch" '
    function epoch(ts, cmd, v) {
      cmd="date -d \"" ts "\" +%s";
      cmd | getline v;
      close(cmd);
      return v;
    }
    {
      t=epoch($1);
      if (t < marker - 2) phase="before";
      else if (t <= marker + 5) phase="during";
      else phase="after";
      key=phase "/" $2;
      total[key]++;
      ok[key]+=$3;
      latency_ms[key]+=$4;
    }
    END {
      for (key in total) {
        fail=total[key]-ok[key];
        avg=(total[key] ? latency_ms[key]/total[key] : 0);
        printf "%s total=%d ok=%d fail=%d success_rate=%.2f%% avg_latency_ms=%.1f\n",
          key, total[key], ok[key], fail, (ok[key]*100.0/total[key]), avg;
      }
    }
  ' "$results"
  echo
  echo "raw_results=$results"
} | tee "$summary"
