# Roadmap - Huginn Proxy

## Upcoming Features

### Testing & Quality
- [ ] Stress tests (multiple concurrent connections)

### Documentation
- [ ] Usage examples (Kubernetes, Docker)
- [ ] Metrics documentation

### Operational Features
- [ ] Kubernetes probe support
- [ ] Granular timeouts (read/write/TLS handshake)
- [ ] Preserve Host header (configurable)
- [ ] Backend health checks (active polling)
- [ ] Connection pooling for backends

### Security & TLS
- [ ] Connection limits (DoS protection)
- [ ] Advanced TLS (tls.options) configuration (versions, cipher suites)
- [ ] Rate limiting
- [ ] Configurable keep-alive (HTTP/1.1)
- [ ] Security headers (HSTS, CSP, etc.)
- [ ] mTLS support
- [ ] OCSP stapling
- [ ] Session resumption
- [ ] IP filtering

### Advanced Features
- [ ] Advanced load balancing algorithms (least connections, weighted)
- [ ] Request/response transformation
- [ ] Circuit breakers
- [ ] Throughput metrics (bytes received/sent)
- [ ] Timeout metrics by type
- [ ] TCP fingerprinting
- [ ] Production hardening and security audit
