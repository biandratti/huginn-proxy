## Examples

This directory contains Docker Compose examples and configuration files to help you get started with huginn-proxy.

> [!IMPORTANT]
> **macOS (Docker Desktop) limitations:** The compose files bind ports on both IPv4 (`0.0.0.0`) and
> IPv6 (`[::]`). Docker Desktop may fail to bind the `[::]` entries — if you get port binding errors
> on startup, remove the `[::]:*` lines from the `ports` section of the compose file you are using.
> Additionally, all traffic from the macOS host is NATed through Docker Desktop's gateway
> (`192.168.65.1`), so the proxy always sees an IPv4 source address — even when using `curl -6`.
> See [Enable IPv6 locally](#2-enable-ipv6-locally) for the workaround.

---

## Building from Source

### Standard build (no eBPF)

No extra system dependencies required.

```bash
cargo build --release -p huginn-proxy
```

### With TCP SYN fingerprinting (eBPF/XDP) - Linux only

eBPF/XDP is a **Linux-only** feature. It does not compile or run on macOS or Windows.
Requires Linux kernel ≥ 5.11 and the Rust nightly toolchain with `rust-src` (installed
automatically via `rust-toolchain.toml` in the XDP subcrate).

```bash
# Build with the ebpf-tcp feature (no clang or kernel headers needed)
cargo build --release -p huginn-proxy --features ebpf-tcp
```

> **Runtime requirements:** the resulting binary needs `CAP_BPF`, `CAP_NET_ADMIN`, and `CAP_PERFMON`
> (or root). See [EBPF-SETUP.md](../EBPF-SETUP.md) for kernel requirements, Docker, and Kubernetes
> deployment details.

---

## Quick Start (Docker Compose)

### 1. Generate TLS Certificates (first time only)

**Create the certificates directory:**

```bash
mkdir -p examples/certs
sudo chown -R $USER:$USER examples/certs/
```

**Option A: Self-signed certificate (default, works with `curl -k` but browsers will show warnings)**

Include **SAN** (`subjectAltName`) so `https://localhost`, `https://127.0.0.1`, and IPv6 loopback match the
certificate — CN-only certs are rejected by many TLS stacks. Requires OpenSSL 1.1.1 or newer (`openssl version`).

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/server.key \
  -out examples/certs/server.crt \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1"

chmod 644 examples/certs/server.key examples/certs/server.crt
```

**Option B: Trusted local certificate (recommended for browser testing)**

For browser testing without security warnings, use `mkcert` to generate locally-trusted certificates:

```bash
# Install mkcert (if not already installed)
# Linux: sudo apt install libnss3-tools && wget https://github.com/FiloSottile/mkcert/releases/latest/download/mkcert-v1.4.4-linux-amd64 -O mkcert && chmod +x mkcert && sudo mv mkcert /usr/local/bin/
# macOS: brew install mkcert
# Windows: choco install mkcert

# Install local CA (one-time setup)
mkcert -install

# Names/IPs listed become Subject Alternative Names (SAN). The browser checks the URL against
# them — include every form you will type: hostname, IPv4 loopback, IPv6 loopback.
mkcert -key-file examples/certs/server.key -cert-file examples/certs/server.crt localhost 127.0.0.1 ::1

chmod 644 examples/certs/server.key examples/certs/server.crt
```

> **Note:** With self-signed certificates, browsers will show a security warning. You can either:
> - Click "Advanced" → "Continue to localhost (unsafe)" to proceed
> - Use Option B with `mkcert` for trusted certificates
> - Use `curl -k` for command-line testing (ignores certificate validation)

### 2. Enable IPv6 locally

Docker requires explicit IPv6 configuration on the host before the compose files can publish
IPv6 ports and create dual-stack networks.

**Linux (Docker Engine):**

```bash
sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80"
}
EOF

sudo systemctl restart docker
```

**macOS (Docker Desktop):**

Docker Desktop runs a Linux VM — all `curl` from the macOS host goes through Docker Desktop's NAT
gateway (`192.168.65.1`), so the proxy always sees an IPv4 source regardless of `-6` or `[::1]`.
To get a real IPv6 fingerprint, run a container **inside** the Docker network:

```bash
PROXY_IPV6=$(docker inspect \
  $(docker compose -f examples/docker-compose.without-ebpf.yml ps -q proxy) \
  --format '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}}{{end}}')

docker run --rm \
  --network examples_default \
  curlimages/curl \
  -sk "https://[${PROXY_IPV6}]:7000/api/test"
```

To enable IPv6 in Docker Desktop's engine config, go to **Settings → Docker Engine** and add:

```json
{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80"
}
```

Then click **Apply & restart**.

### 3. Start Services

Pick **one** stack. Both give you **JA4** (and related TLS/JA4H-style signals) and **Akamai-style** HTTP fingerprinting
from the proxy. The only fork is whether you also run **TCP SYN** capture via **eBPF/XDP**.

|                                 | **eBPF stack** (`docker-compose.ebpf.yml`)                           | **Without-eBPF stack** (`docker-compose.without-ebpf.yml`) |
|---------------------------------|----------------------------------------------------------------------|------------------------------------------------------------|
| **Fingerprints**                | JA4 + Akamai + **TCP SYN** (kernel)                                  | JA4 + Akamai **only** (no TCP SYN)                         |
| **Images built from this repo** | **Two:** `proxy` (Dockerfile target `ebpf`) + `ebpf-agent`           | **One:** `proxy` (Dockerfile target `plain`)               |
| **Extra volume**                | **`bpffs`** — shared BPF filesystem for maps between proxy and agent | None                                                       |
| **Host requirements**           | Linux kernel ≥ 5.11, Docker grants `cap_add` (see compose)           | Any recent Linux kernel, no BPF caps                       |

Both files also start the same **demo backends** (`traefik/whoami`) — that is unrelated to the choice above.

```bash
# JA4 + Akamai + TCP SYN — two images + bpffs volume (kernel ≥ 5.11)
docker compose -f examples/docker-compose.ebpf.yml up --build

# JA4 + Akamai — single proxy image, no eBPF agent or bpffs volume
docker compose -f examples/docker-compose.without-ebpf.yml up --build
```

Alternatively, pull a pre-built image from the registry:

| Image                                            | Description                                                          |
|--------------------------------------------------|----------------------------------------------------------------------|
| `ghcr.io/<owner>/huginn-proxy:latest`            | Proxy with eBPF/XDP — requires Linux kernel ≥ 5.11 and `cap_add`     |
| `ghcr.io/<owner>/huginn-proxy-plain:latest`      | Proxy without eBPF — runs on any Linux kernel, no extra capabilities |
| `ghcr.io/<owner>/huginn-proxy-ebpf-agent:latest` | XDP agent — pairs with the proxy image above                         |

### 4. Test the Proxy

Use `127.0.0.1` here so the host matches published ports reliably (some systems resolve `localhost` to IPv6 first; the
compose example publishes both IPv4 and IPv6, but explicit IPv4 avoids surprises in CI and scripts).

```bash
curl -sk https://127.0.0.1:7000/api/test
curl http://127.0.0.1:9090/metrics | grep huginn_proxy
```

To pick a stack explicitly when using a hostname (e.g. `localhost`), curl supports `-4` / `--ipv4` and `-6` / `--ipv6`:

```bash
curl -4 -sk https://localhost:7000/api/test    # IPv4 only
curl -6 -sk https://localhost:7000/api/test    # IPv6 only (or https://[::1]:7000/...)

curl -4 http://localhost:9090/metrics | grep huginn_proxy
curl -6 http://localhost:9090/metrics | grep huginn_proxy
```

**Browser:** Open `https://localhost:7000/` (or `https://127.0.0.1:7000/` if your cert includes that name in SAN —
`mkcert` Option B lists both). The self-signed **Option A** cert uses `CN=localhost`, so the hostname `localhost`
matches; you may still need to accept the browser warning unless you use `mkcert`.

---

## Endpoints

| Service    | URL                             | Description          |
|------------|---------------------------------|----------------------|
| Proxy      | `https://127.0.0.1:7000/`       | HTTPS proxy          |
| Proxy      | `http://127.0.0.1:9090/health`  | Health               |
| Proxy      | `http://127.0.0.1:9090/ready`   | Readiness            |
| Proxy      | `http://127.0.0.1:9090/live`    | Liveness             |
| Proxy      | `http://127.0.0.1:9090/metrics` | Prometheus metrics   |
| eBPF Agent | `http://127.0.0.1:9091/health`  | Health               |
| eBPF Agent | `http://127.0.0.1:9091/ready`   | Readiness (BPF pins) |
| eBPF Agent | `http://127.0.0.1:9091/live`    | Liveness             |
| eBPF Agent | `http://127.0.0.1:9091/metrics` | Prometheus metrics   |

eBPF compose examples map agent HTTP on the proxy service (`9091:9091`).

---

## Configuration Files

The `config/` directory contains example configurations:

- **`compose.toml`** - Basic proxy setup (default for Docker Compose)
- **`rate-limit-example.toml`** - Advanced rate limiting configuration

To switch configurations, edit `docker-compose.ebpf.yml` and change the `command` and `volumes` sections.

---

## Telemetry

The observability stack runs **Prometheus** (`prom/prometheus`) and **Grafana** as a separate Docker Compose project alongside the main proxy stack. Prometheus scrapes metrics from the proxy (`port 9090`) and the eBPF agent (`port 9091`) via `host.docker.internal`. Grafana is pre-provisioned with a data source and a dashboard — no manual setup needed.

### Prerequisites

The main proxy stack must already be running and exposing ports `9090` and `9091` on the host before starting the observability stack. Prometheus reaches the proxy via `host.docker.internal` (mapped to `host-gateway` inside the container).

### Start

Run the observability stack from the repo root:

```bash
docker compose -f examples/docker-compose.observability.yml up -d
```

### Access Grafana

1. Open `http://localhost:3000` in your browser.
2. Log in with **admin / huginn**.
3. The **Huginn Proxy** dashboard loads automatically as the default home dashboard.

---

## Advanced Examples

### Rate Limiting

To test rate limiting, switch to `rate-limit-example.toml` in `docker-compose.ebpf.yml`:

```yaml
environment:
  - HUGINN_CONFIG_PATH=/config/rate-limit-example.toml
volumes:
  - ./config/rate-limit-example.toml:/config/rate-limit-example.toml:ro
  - ./certs:/config/certs:ro
```

This configuration demonstrates:

- IP-based rate limiting
- Per-route rate limits
- Header-based limits (API keys)
- Combined strategies

**Test rate limiting:**

```bash
# Send 150 parallel requests to trigger rate limits
# /api endpoint: 50 req/s limit, burst of 100
seq 1 150 | xargs -P 50 -I {} curl -sk https://127.0.0.1:7000/api/test 2>&1 \
  | grep -c "Too Many Requests"

# View a 429 response
seq 1 150 | xargs -P 50 -I {} curl -sk https://127.0.0.1:7000/api/test 2>&1 \
  | grep "Too Many Requests" | head -1

# Test different endpoints with different limits
curl -sk https://127.0.0.1:7000/public/test     # 200 req/s
curl -sk https://127.0.0.1:7000/premium/test    # Header-based
```

### TLS Fingerprinting

Verify that TLS and HTTP/2 fingerprints are injected:

```bash
curl -sk https://127.0.0.1:7000/api/test | jq '.headers | with_entries(select(.key | startswith("x-")))'
```

Expected headers:

- `x-huginn-net-ja4`: TLS fingerprint, sorted ciphers/extensions, hashed (FoxIO JA4)
- `x-huginn-net-ja4_r`: TLS fingerprint, original ClientHello order, hashed (FoxIO JA4_r)
- `x-huginn-net-ja4_o`: TLS fingerprint, sorted, raw hex values (FoxIO JA4_o)
- `x-huginn-net-ja4_or`: TLS fingerprint, original order, raw hex values (FoxIO JA4_or)
- `x-huginn-net-akamai`: HTTP/2 fingerprint
- `x-huginn-net-tcp`: TCP SYNC fingerprint

---

## Troubleshooting

**Connection refused?**

- Ensure services are running: `docker compose -f examples/docker-compose.ebpf.yml ps` (or
  `docker-compose.without-ebpf.yml`)
- Check logs: `docker compose -f examples/docker-compose.ebpf.yml logs proxy`

**Rate limits not working?**

- Verify configuration is loaded correctly in logs
- Check that you're making parallel requests (sequential requests may not hit the limit)

**TLS errors in browser (`ERR_CERT_AUTHORITY_INVALID`)?**

- **Self-signed certificates:** Browsers will show a security warning. Click "Advanced" → "Continue to localhost (
  unsafe)" to proceed, or use `mkcert` (Option B above) for trusted certificates
- **Command-line testing:** Use `curl -k` flag to ignore certificate validation
- **Certificate expired:** Regenerate certificates using the commands above
- **Docker Compose:** Ensure certificates are mounted correctly in `docker-compose.ebpf.yml` volumes section
