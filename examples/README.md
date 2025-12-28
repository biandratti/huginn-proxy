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
- Proxy: `https://localhost:7000/` (use `-k` for curl with the self-signed cert)
- Backend: `http://localhost:9000/`

Edit `examples/config/compose.toml` to customize the configuration.
