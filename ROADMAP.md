# Roadmap - Huginn Proxy

## Upcoming Features

### Documentation
- [ ] Usage examples (Kubernetes, Docker)
- [ ] Metrics documentation

### Operational Features
- [x] Kubernetes probe support (via dedicated health check endpoints: `/health`, `/ready`, `/live`)
- [ ] Granular timeouts (read/write/TLS handshake)
- [ ] Preserve Host header (configurable)
- [ ] Backend health checks (active polling)
- [ ] Connection pooling for backends

### Security & TLS
- [ ] IP filtering
- [ ] Rate limiting
- [ ] Security headers (HSTS, CSP, etc.)
- [ ] mTLS support
- [ ] OCSP stapling
- [ ] Session resumption

### Routing & Path Handling
- [ ] Path stripping (remove prefix before forwarding to backend)
- [ ] Regex-based route matching (optional, for advanced use cases)
- [ ] Path rewriting (modify path before forwarding)

### Advanced Features
- [ ] Advanced load balancing algorithms (least connections, weighted)
- [ ] Request/response transformation
- [ ] Circuit breakers
- [ ] Throughput metrics (bytes received/sent)
- [ ] Timeout metrics by type
- [ ] TCP fingerprinting
- [ ] Production hardening and security audit
