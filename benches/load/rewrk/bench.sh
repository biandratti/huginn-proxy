#!/bin/sh
# rewrk load benchmark for huginn-proxy (HTTPS, HTTP/1.1 + HTTP/2).
#
# Requires rewrk (with OpenSSL support):
#   sudo apt install pkg-config libssl-dev
#   cargo install rewrk
#
# Start the proxy stack first, then run this script from the repo root:
#
#   Without eBPF:
#     docker compose -f examples/docker-compose.release-without-ebpf.yml up -d
#     EBPF=false benches/load/rewrk/bench.sh
#
#   With eBPF (requires CAP_BPF / kernel >= 5.11):
#     docker compose -f examples/docker-compose.release-ebpf.yml up -d
#     EBPF=true benches/load/rewrk/bench.sh
#
# Override defaults via env:
#   CONNECTIONS=512 THREADS=4 DURATION=15s HOST=https://127.0.0.1:7000 ./bench.sh

set -e

CONNECTIONS=${CONNECTIONS:-512}
THREADS=${THREADS:-4}
DURATION=${DURATION:-15s}
HOST=${HOST:-https://127.0.0.1:7000}
EBPF=${EBPF:-false}

if ! command -v rewrk >/dev/null 2>&1; then
    echo "rewrk not found."
    exit 1
fi

# Trust the dev self-signed cert so rewrk (OpenSSL) accepts it without an --insecure flag.
# SSL_CERT_FILE is respected by OpenSSL / native-tls on Linux.
if [ -z "$SSL_CERT_FILE" ] && [ -f "examples/certs/server.crt" ]; then
    export SSL_CERT_FILE="examples/certs/server.crt"
fi

echo "----------------------------"
echo "huginn-proxy rewrk benchmark"
echo "  host:        $HOST"
echo "  connections: $CONNECTIONS"
echo "  threads:     $THREADS"
echo "  duration:    $DURATION"
echo "  ebpf:        $EBPF"
echo "----------------------------"
echo ""

echo "[ 1/2 ] HTTP/1.1"
rewrk -c "$CONNECTIONS" -t "$THREADS" -d "$DURATION" -h "$HOST/" --pct

sleep 3

echo ""
echo "[ 2/2 ] HTTP/2"
rewrk -c "$CONNECTIONS" -t "$THREADS" -d "$DURATION" -h "$HOST/" --http2 --pct

echo ""
echo "Proxy metrics: http://127.0.0.1:9090/metrics"