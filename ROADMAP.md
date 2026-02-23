# Roadmap - Huginn Proxy

## Upcoming Features

### Documentation

- [ ] Grafana dashboard templates

### Operational Features

- [ ] Backend health checks (active polling)

### Security & TLS

- [ ] OCSP stapling

### Routing & Path Handling

- [ ] Regex-based route matching (optional, for advanced use cases)

### Advanced Features

- [ ] Advanced load balancing algorithms (least connections, weighted)
- [ ] Request/response transformation
- [ ] Circuit breakers
- [ ] TCP fingerprinting
- [ ] Production hardening and security audit

### Measure

- [ ] Benchmark `force_new_connection` latency overhead vs connection pooling (replace README estimate with measured p50/p99)
- [ ] Benchmark eBPF SYN map lookup latency impact on request handling
