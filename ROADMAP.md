# Roadmap - Huginn Proxy

## Upcoming Features

### Testing & Quality
- [ ] E2E tests with Docker Compose
- [ ] Integration tests with real backends
- [ ] Stress tests (multiple concurrent connections)
- [ ] Fingerprint injection validation
- [ ] Health checks tests
- [ ] Performance benchmarking and optimization

### Documentation
- [ ] Improved README (quick start, features, configuration)
- [ ] Architecture documentation
- [ ] Complete configuration guide
- [ ] Usage examples (Kubernetes, Docker)
- [ ] Metrics documentation

### CI/CD
- [ ] Tests across multiple Rust versions
- [ ] Multi-target builds (linux-x86_64, linux-arm64)
- [ ] Automated releases
- [ ] Published Docker images

### Operational Features
- [ ] Kubernetes probe support
- [ ] Granular timeouts (read/write/TLS handshake)
- [ ] Preserve Host header (configurable)
- [ ] Backend health checks (active polling)
- [ ] Connection pooling for backends

### Security & TLS
- [ ] Connection limits (DoS protection)
- [ ] Advanced TLS configuration (versions, cipher suites)
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
