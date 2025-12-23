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

### Docker Compose smoke
```bash
docker compose -f examples/docker-compose.yml up --build
```
- Proxy: `http://localhost:7000/` (or `https://localhost:7000/` if `mode = "tls_termination"`, use `-k` for curl with the self-signed cert).
- Metrics: `http://localhost:9900/metrics`.

Edit `examples/config/compose.toml` to switch between `mode = "forward"` and `mode = "tls_termination"`, and to point to the generated cert/key.

