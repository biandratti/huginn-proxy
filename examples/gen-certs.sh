#!/usr/bin/env bash
# Generate the self-signed TLS certificates used by the Docker Compose examples
# (docker-compose.ebpf.yml, docker-compose.without-ebpf.yml).
#
# Produces, in examples/certs/:
#   server.key   Private key (mode 644 - readable by the proxy container user).
#   server.crt   Self-signed certificate with SAN for localhost, 127.0.0.1 and ::1.
#
# These are throwaway TEST credentials for local development only - never use them in production.
# Rerun this script to regenerate (e.g. when the cert expires after 365 days).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"

mkdir -p "${CERTS_DIR}"

# Self-signed cert with SAN. CN-only certs are rejected by many TLS stacks (rustls included),
# so subjectAltName is required. Includes DNS:localhost, IPv4 loopback, and IPv6 loopback so
# both `curl -4` and `curl -6` work against the published ports.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${CERTS_DIR}/server.key" \
  -out    "${CERTS_DIR}/server.crt" \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1"

chmod 644 "${CERTS_DIR}/server.key" "${CERTS_DIR}/server.crt"

echo "Generated ${CERTS_DIR}/server.key and ${CERTS_DIR}/server.crt"
