#!/usr/bin/env bash
# Sample CPU/memory of the proxy container while k6 runs. k6 itself does not report cgroup stats.
#
# Usage (from repo root):
#   ./benches/load/k6/run-with-docker-stats.sh run --insecure-skip-tls-verify benches/load/k6/fingerprints.js
#
# Env:
#   COMPOSE_FILE   default: examples/docker-compose.release-ebpf.yml
#   DOCKER_SERVICE default: proxy
#   STATS_FILE     default: benches/load/k6/last-docker-stats.tsv
#   STATS_INTERVAL sample period in seconds (default: 1)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$REPO_ROOT"

COMPOSE_FILE="${COMPOSE_FILE:-examples/docker-compose.release-ebpf.yml}"
SERVICE="${DOCKER_SERVICE:-proxy}"
STATS_FILE="${STATS_FILE:-benches/load/k6/last-docker-stats.tsv}"
INTERVAL="${STATS_INTERVAL:-1}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <k6 args...>" >&2
  echo "example: $0 run --insecure-skip-tls-verify benches/load/k6/fingerprints.js" >&2
  exit 1
fi

CID="$(docker compose -f "$COMPOSE_FILE" ps -q "$SERVICE" 2>/dev/null || true)"
if [[ -z "$CID" ]]; then
  echo "error: no running container for service '$SERVICE' ($COMPOSE_FILE). Start compose first." >&2
  exit 1
fi

CNAME="$(docker inspect -f '{{.Name}}' "$CID" | sed 's#^/##')"
echo "Sampling docker stats for container $CNAME ($CID) -> $STATS_FILE (every ${INTERVAL}s)" >&2

{
  echo -e "timestamp\tcontainer\tcpu_percent\tmem_usage\tmem_percent"
  while true; do
    ts="$(date -Iseconds)"
    # CPUPerc can exceed 100% on multi-core hosts (sum of cores used).
    line="$(docker stats "$CID" --no-stream --format "{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}")"
    echo -e "$ts\t$CNAME\t$line"
    sleep "$INTERVAL"
  done
} >"$STATS_FILE" &
STATS_PID=$!

cleanup() {
  kill "$STATS_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

"$@"
STATUS=$?
echo "k6 exit: $STATUS — stats log: $STATS_FILE" >&2
exit "$STATUS"
