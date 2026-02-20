## Examples

This directory contains Docker Compose examples and configuration files to help you get started with huginn-proxy.

---

## Quick Start

### 1. Generate TLS Certificates (first time only)

**Create the certificates directory:**

```bash
mkdir -p examples/certs
```

**Option A: Self-signed certificate (default, works with `curl -k` but browsers will show warnings)**

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/server.key \
  -out examples/certs/server.crt \
  -days 365 \
  -subj "/CN=localhost"

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

# Generate trusted certificate for localhost
mkcert -key-file examples/certs/server.key -cert-file examples/certs/server.crt localhost 127.0.0.1 ::1

chmod 644 examples/certs/server.key examples/certs/server.crt
```

> **Note:** With self-signed certificates, browsers will show a security warning. You can either:
> - Click "Advanced" → "Continue to localhost (unsafe)" to proceed
> - Use Option B with `mkcert` for trusted certificates
> - Use `curl -k` for command-line testing (ignores certificate validation)

### 2. Start Services

```bash
docker compose -f examples/docker-compose.yml up --build
```

### 3. Test the Proxy

```bash
# Health check
curl http://localhost:9090/health

# Basic request
curl -sk https://localhost:7000/api/test | jq .

# View metrics
curl http://localhost:9090/metrics | grep huginn_proxy
```

---

## Available Endpoints

| Service       | Endpoint                        | Description           |
|---------------|---------------------------------|-----------------------|
| Proxy (HTTPS) | `https://localhost:7000/`       | Main proxy endpoint   |
| Health Check  | `http://localhost:9090/health`  | Service health status |
| Metrics       | `http://localhost:9090/metrics` | Prometheus metrics    |

---

## Configuration Files

The `config/` directory contains example configurations:

- **`compose.toml`** - Basic proxy setup (default for Docker Compose)
- **`rate-limit-example.toml`** - Advanced rate limiting configuration

To switch configurations, edit `docker-compose.yml` and change the `command` and `volumes` sections.

---

## Advanced Examples

### Rate Limiting

To test rate limiting, switch to `rate-limit-example.toml` in `docker-compose.yml`:

```yaml
command: [ "/usr/local/bin/huginn-proxy", "/config/rate-limit-example.toml" ]
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
seq 1 150 | xargs -P 50 -I {} curl -sk https://localhost:7000/api/test 2>&1 \
  | grep -c "Too Many Requests"

# View a 429 response
seq 1 150 | xargs -P 50 -I {} curl -sk https://localhost:7000/api/test 2>&1 \
  | grep "Too Many Requests" | head -1

# Test different endpoints with different limits
curl -sk https://localhost:7000/public/test | jq .     # 200 req/s
curl -sk https://localhost:7000/premium/test | jq .    # Header-based
```

### TLS Fingerprinting

Verify that TLS and HTTP/2 fingerprints are injected:

```bash
curl -sk https://localhost:7000/api/test | jq '.headers | with_entries(select(.key | startswith("x-")))'
```

Expected headers:

- `x-huginn-net-ja4` - TLS fingerprint
- `x-huginn-net-ja4-raw` - TLS fingerprint not normalized
- `x-huginn-net-akamai` - HTTP/2 fingerprint

---

## Troubleshooting

**Connection refused?**

- Ensure services are running: `docker compose -f examples/docker-compose.yml ps`
- Check logs: `docker compose -f examples/docker-compose.yml logs proxy`

**Rate limits not working?**

- Verify configuration is loaded correctly in logs
- Check that you're making parallel requests (sequential requests may not hit the limit)

**TLS errors in browser (`ERR_CERT_AUTHORITY_INVALID`)?**

- **Self-signed certificates:** Browsers will show a security warning. Click "Advanced" → "Continue to localhost (
  unsafe)" to proceed, or use `mkcert` (Option B above) for trusted certificates
- **Command-line testing:** Use `curl -k` flag to ignore certificate validation
- **Certificate expired:** Regenerate certificates using the commands above
- **Docker Compose:** Ensure certificates are mounted correctly in `docker-compose.yml` volumes section
