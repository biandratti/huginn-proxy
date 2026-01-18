## Examples

This directory contains Docker Compose examples and configuration files to help you get started with huginn-proxy.

---

## Quick Start

### 1. Generate TLS Certificates (first time only)

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/server.key \
  -out examples/certs/server.crt \
  -days 365 \
  -subj "/CN=localhost"

chmod 644 examples/certs/server.key examples/certs/server.crt
```

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

| Service | Endpoint | Description |
|---------|----------|-------------|
| Proxy (HTTPS) | `https://localhost:7000/` | Main proxy endpoint |
| Health Check | `http://localhost:9090/health` | Service health status |
| Metrics | `http://localhost:9090/metrics` | Prometheus metrics |

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
command: ["/usr/local/bin/huginn-proxy", "/config/rate-limit-example.toml"]
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
curl -sk https://localhost:7000/api/test | jq '.headers | with_entries(select(.key | startswith("x-huginn")))'
```

Expected headers:
- `x-huginn-net-ja4` - TLS fingerprint
- `x-huginn-net-akamai` - HTTP/2 fingerprint

---

## Troubleshooting

**Connection refused?**
- Ensure services are running: `docker compose -f examples/docker-compose.yml ps`
- Check logs: `docker compose -f examples/docker-compose.yml logs proxy`

**Rate limits not working?**
- Verify configuration is loaded correctly in logs
- Check that you're making parallel requests (sequential requests may not hit the limit)

**TLS errors?**
- Use `-k` flag with curl for self-signed certificates
- Regenerate certificates if expired
