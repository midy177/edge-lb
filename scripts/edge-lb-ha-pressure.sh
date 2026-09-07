#!/usr/bin/env bash
set -euo pipefail

vip="192.168.0.6"
port="8080"
protocol="both"
duration="60"
concurrency="8"
payload="discover"
timeout_secs="1"
sleep_after_send="1"
expect_regex='"private_ipv4"|hostname'
out_dir=""

usage() {
  cat <<'USAGE'
Usage:
  edge-lb-ha-pressure.sh [options]

Options:
  --vip IP                 HA VIP or gateway IP. Default: 192.168.0.6
  --port PORT              Listener port. Default: 8080
  --protocol tcp|udp|both  Protocols to test. Default: both
  --duration SECONDS       Test duration. Default: 60
  --concurrency N          Number of workers per protocol. Default: 8
  --payload TEXT           Payload sent with a trailing newline. Default: discover
  --timeout SECONDS        nc timeout. Default: 1
  --expect REGEX           Success regex matched against response.
  --out-dir DIR            Output directory. Default: /tmp/edge-lb-ha-pressure-<timestamp>
  -h, --help               Show this help.

The script uses netcat-style commands:
  (printf 'discover\n'; sleep 1) | nc -v -w 1 <vip> <port>
  (printf 'discover\n'; sleep 1) | nc -uv -w 1 <vip> <port>

Success requires the response body to match --expect, so UDP tests do not count
nc's optimistic "Connection succeeded" line as a successful datapath response.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --vip) vip="$2"; shift 2 ;;
    --port) port="$2"; shift 2 ;;
    --protocol) protocol="$2"; shift 2 ;;
    --duration) duration="$2"; shift 2 ;;
    --concurrency) concurrency="$2"; shift 2 ;;
    --payload) payload="$2"; shift 2 ;;
    --timeout) timeout_secs="$2"; shift 2 ;;
    --expect) expect_regex="$2"; shift 2 ;;
    --out-dir) out_dir="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$protocol" in
  tcp|udp|both) ;;
  *) echo "--protocol must be tcp, udp, or both" >&2; exit 2 ;;
esac

case "$port" in
  ''|*[!0-9]*) echo "--port must be numeric" >&2; exit 2 ;;
esac
if (( port < 1 || port > 65535 )); then
  echo "--port must be in range 1..65535" >&2
  exit 2
fi

case "$duration" in
  ''|*[!0-9]*) echo "--duration must be numeric" >&2; exit 2 ;;
esac
case "$concurrency" in
  ''|*[!0-9]*) echo "--concurrency must be numeric" >&2; exit 2 ;;
esac
if (( duration < 1 || concurrency < 1 )); then
  echo "--duration and --concurrency must be positive" >&2
  exit 2
fi

if ! command -v nc >/dev/null 2>&1; then
  echo "nc is required" >&2
  exit 1
fi

if [[ -z "$out_dir" ]]; then
  out_dir="/tmp/edge-lb-ha-pressure-$(date +%Y%m%d-%H%M%S)"
fi
mkdir -p "$out_dir"

results="$out_dir/results.tsv"
summary="$out_dir/summary.txt"
: > "$results"

protocols=()
if [[ "$protocol" == "both" ]]; then
  protocols=(tcp udp)
else
  protocols=("$protocol")
fi

end_epoch=$(( $(date +%s) + duration ))

now_ms() {
  local seconds nanos
  seconds=$(date +%s)
  nanos=$(date +%N)
  case "$nanos" in
    ''|*[!0-9]*) nanos=0 ;;
  esac
  printf '%s\n' $((10#$seconds * 1000 + 10#$nanos / 1000000))
}

extract_backend() {
  sed -n 's/.*"private_ipv4":"\([^"]*\)".*/\1/p' | head -n 1
}

run_once() {
  local proto="$1"
  local start end elapsed_ms ok backend output line

  start=$(now_ms)
  if [[ "$proto" == "udp" ]]; then
    output=$((printf '%s\n' "$payload"; sleep "$sleep_after_send") | nc -uv -w "$timeout_secs" "$vip" "$port" 2>&1 || true)
  else
    output=$((printf '%s\n' "$payload"; sleep "$sleep_after_send") | nc -v -w "$timeout_secs" "$vip" "$port" 2>&1 || true)
  fi
  end=$(now_ms)
  elapsed_ms=$((end - start))

  if printf '%s' "$output" | grep -Eq "$expect_regex"; then
    ok=1
  else
    ok=0
  fi

  backend=$(printf '%s\n' "$output" | extract_backend)
  if [[ -z "$backend" ]]; then
    backend="-"
  fi
  line=$(printf '%s' "$output" | tr '\t\r\n' ' ' | sed 's/  */ /g' | cut -c 1-220)
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$(date -Is)" "$proto" "$ok" "$elapsed_ms" "$backend" "$line" >> "$results"
}

worker() {
  local proto="$1"
  while (( $(date +%s) < end_epoch )); do
    run_once "$proto"
  done
}

pids=()
for proto in "${protocols[@]}"; do
  for _ in $(seq 1 "$concurrency"); do
    worker "$proto" &
    pids+=("$!")
  done
done

for pid in "${pids[@]}"; do
  wait "$pid" || true
done

{
  echo "edge-lb HA pressure summary"
  echo "target=$vip:$port protocol=$protocol duration=${duration}s concurrency=$concurrency payload=$payload"
  echo
  awk -F '\t' '
    {
      key=$2;
      total[key]++;
      ok[key]+=$3;
      latency_ms[key]+=$4;
      backend[$2 SUBSEP $5]+=$3;
    }
    END {
      for (key in total) {
        fail=total[key]-ok[key];
        avg=(total[key] ? latency_ms[key]/total[key] : 0);
        printf "%s total=%d ok=%d fail=%d success_rate=%.2f%% avg_latency_ms=%.1f\n",
          key, total[key], ok[key], fail, (ok[key]*100.0/total[key]), avg;
      }
      print "";
      print "backend distribution:";
      for (item in backend) {
        split(item, parts, SUBSEP);
        printf "%s backend=%s ok=%d\n", parts[1], parts[2], backend[item];
      }
    }
  ' "$results"
  echo
  echo "raw_results=$results"
} | tee "$summary"
