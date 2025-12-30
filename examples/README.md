## Examples

### TLS self-signed certs (for compose/demo)
Generate a local certificate and key:
```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout examples/certs/server.key \
  -out examples/certs/server.crt \
  -days 365 \
  -subj "/CN=localhost"
```

**Note:** The proxy runs as a non-root user (`app`) inside the container. Ensure the certificate files are readable:
```bash
chmod 644 examples/certs/server.key
chmod 644 examples/certs/server.crt
```

### Docker Compose smoke
```bash
docker compose -f examples/docker-compose.yml up --build
```

### Endpoints

#### Proxy Server
- **HTTPS Proxy**: `https://localhost:7000/` (use `-k` for curl with the self-signed cert)
- **HTTP Proxy**: `http://localhost:7000/` (if TLS is disabled)

#### Metrics Server
- **Prometheus Metrics**: `http://localhost:9090/metrics`

#### Backend Services
- **Backend A**: `http://localhost:9000/` (routes matching `/api`)
- **Backend B**: `http://localhost:9001/` (default routes)


### Example Requests

```bash
# Proxy request (HTTPS)
curl -k https://localhost:7000/api/test

# Metrics and health endpoints
curl http://localhost:9090/metrics
curl http://localhost:9090/health
```
