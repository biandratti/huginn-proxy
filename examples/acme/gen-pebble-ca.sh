#!/usr/bin/env bash
# Regenerate the local test PKI used by the Pebble ACME demo (docker-compose.acme.yml).
#
# Produces, in this directory:
#   pebble-ca.pem      CA certificate. Mounted into the proxy and trusted via
#                      `[acme].directory_ca_path` so the proxy accepts Pebble's HTTPS directory.
#   pebble-cert.pem    Leaf cert for Pebble's own HTTPS interface (SAN: pebble, localhost, 127.0.0.1).
#   pebble-key.pem     Private key for the leaf above. Mounted into the Pebble container.
#
# These are throwaway TEST credentials for local development only - never use them in production.
# The CA key is intentionally not kept; rerun this script to mint a fresh PKI.
set -euo pipefail

cd "$(dirname "$0")"

tmp_ca_key="$(mktemp)"
trap 'rm -f "$tmp_ca_key"' EXIT

# Self-signed test CA.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tmp_ca_key" \
  -out pebble-ca.pem \
  -days 3650 \
  -subj "/CN=huginn-proxy Pebble Test CA"

# Leaf for Pebble's HTTPS interface. SAN must include the compose service name `pebble`,
# since the proxy reaches the directory at https://pebble:14000/dir and verifies the hostname.
openssl req -newkey rsa:2048 -nodes \
  -keyout pebble-key.pem \
  -out pebble.csr \
  -subj "/CN=pebble" \
  -addext "subjectAltName=DNS:pebble,DNS:localhost,IP:127.0.0.1"

openssl x509 -req \
  -in pebble.csr \
  -CA pebble-ca.pem -CAkey "$tmp_ca_key" -CAcreateserial \
  -out pebble-cert.pem \
  -days 3650 \
  -copy_extensions copy

rm -f pebble.csr pebble-ca.srl

echo "Regenerated pebble-ca.pem, pebble-cert.pem, pebble-key.pem"
