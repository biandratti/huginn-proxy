# Roadmap - Huginn Proxy

## Upcoming Features

### Documentation
- [ ] Usage examples (Kubernetes, Docker)
- [ ] Metrics documentation

### Operational Features
- [ ] Granular timeouts (read/write/TLS handshake)
- [ ] Preserve Host header (configurable)
- [ ] Backend health checks (active polling)
- [ ] Connection pooling for backends

### Security & TLS
- [ ] mTLS support
- [ ] OCSP stapling
- [ ] Session resumption

### Routing & Path Handling
- [ ] Regex-based route matching (optional, for advanced use cases)

### Advanced Features
- [ ] Advanced load balancing algorithms (least connections, weighted)
- [ ] Request/response transformation
- [ ] Circuit breakers
- [ ] Throughput metrics (bytes received/sent)
- [ ] Timeout metrics by type
- [ ] TCP fingerprinting
- [ ] Production hardening and security audit
