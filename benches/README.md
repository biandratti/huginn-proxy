# Huginn Proxy Benchmarks

This directory contains performance benchmarks for Huginn Proxy, measuring various aspects of proxy performance including throughput, latency, concurrent connections, and fingerprinting overhead.

## Available Benchmarks

| Benchmark | Description | Metrics |
|-----------|-------------|---------|
| **Request Throughput** | Measures requests per second (RPS) | RPS, latency |
| **Concurrent Connections** | Tests performance with multiple concurrent connections | RPS by concurrency level, latency degradation |
| **Fingerprinting Overhead** | Measures overhead of TLS and HTTP/2 fingerprinting | Overhead percentage, throughput comparison |
| **Load Balancing** | Tests round-robin load balancing performance | Distribution, latency per backend |
| **TLS Handshake** | Measures TLS handshake overhead | Handshake time, throughput comparison |
| **Latency Distribution** | Analyzes latency percentiles (p50, p95, p99, p99.9) | Min, p50, p95, p99, p99.9, max, mean |

## Running Benchmarks

### Prerequisites

1. **Proxy must be running**: The benchmarks require a running Huginn Proxy instance.
   - Default URL: `https://localhost:7000`
   - Override with `PROXY_URL` environment variable

2. **Backend services**: Ensure backend services are running and accessible through the proxy.

### Basic Usage

```bash
# Run all benchmarks (single proxy with fingerprinting enabled)
cargo bench --bench bench_proxy

# Run with custom proxy URL
PROXY_URL=https://proxy.example.com:7000 cargo bench --bench bench_proxy

# Run load test comparison (enabled vs disabled)
# Uses different routes on the same proxy instance:
# - /api/test: Fingerprinting enabled
# - /static/test: Fingerprinting disabled
#
# The proxy must have routes configured with different fingerprinting settings:
# routes = [
#   { prefix = "/api", backend = "backend-a:9000", fingerprinting = true },
#   { prefix = "/static", backend = "backend-b:9000", fingerprinting = false },
#   { prefix = "/", backend = "backend-b:9000" }
# ]
#
PROXY_URL=https://localhost:7000 cargo bench --bench bench_proxy

# Run specific benchmark
cargo bench --bench bench_proxy -- request_throughput

# Generate HTML reports
cargo bench --bench bench_proxy -- --output-format html
```

### Using Docker Compose

If you're using the Docker Compose setup from `examples/`:

```bash
# Start services
cd examples && docker compose up -d --build

# Run benchmarks with comparison (from project root)
# Uses different routes on the same proxy:
# - /api/test: Fingerprinting enabled
# - /static/test: Fingerprinting disabled
PROXY_URL=https://localhost:7000 cargo bench --bench bench_proxy

# Stop services
cd examples && docker compose down
```

**Note:** The docker-compose setup includes:
- `proxy`: Single proxy instance with fingerprinting configurable per route
  - `/api` route: Fingerprinting enabled (default)
  - `/static` route: Fingerprinting disabled
  - Default route `/`: Fingerprinting enabled (catch-all)
- `backend-a` and `backend-b`: Backend services

**Important:** Routes must be explicitly defined. If no route matches, the proxy returns 404 (consistent with rust-rpxy and Traefik). Always include a catch-all route (`prefix = "/"`) if you want to handle all requests.

## Benchmark Details

### Request Throughput

Measures the number of requests per second the proxy can handle:
- **HTTP/1.1**: Simple HTTP/1.1 requests
- **HTTP/2**: HTTP/2 requests with prior knowledge

### Concurrent Connections

Tests proxy performance under different concurrency levels:
- 10 concurrent connections
- 100 concurrent connections
- 1000 concurrent connections

### Fingerprinting Overhead

Compares performance with and without fingerprinting using different routes:
- **With fingerprinting**: Requests to `/api/test` route (fingerprinting enabled)
- **Without fingerprinting**: Requests to `/static/test` route (fingerprinting disabled)
- **TLS Fingerprinting**: JA4 fingerprint extraction (HTTP/1.1 and HTTP/2)
- **HTTP/2 Fingerprinting**: Akamai HTTP/2 fingerprint extraction (HTTP/2 only)

### Load Balancing

Tests route-based load balancing:
- Distribution across backends based on route matching
- Latency per backend
- Total throughput with multiple backends
- **Note**: Round-robin only applies when routes match. Unmatched routes return 404.

### TLS Handshake

Measures TLS handshake overhead:
- Handshake time per request
- Throughput comparison (TLS vs non-TLS)

### Latency Distribution

Analyzes latency percentiles:
- Minimum latency
- P50 (median)
- P95
- P99
- P99.9
- Maximum latency
- Mean latency

## Output

Benchmarks generate:
1. **Criterion reports**: Detailed statistical analysis in `target/criterion/`
2. **HTML reports**: Visual charts and graphs (when using `--output-format html`)
3. **Console output**: Summary report with key metrics

## Performance Targets

Expected performance (baseline):
- **RPS**: >10,000 req/s (without fingerprinting)
- **RPS with fingerprinting**: >5,000 req/s
- **Latency P99**: <100ms (local network)
- **Fingerprinting overhead**: <50% (TLS + HTTP/2)

## Contributing

When adding new benchmarks:
1. Follow the existing benchmark structure
2. Use `criterion_group!` and `criterion_main!` macros
3. Include comprehensive performance analysis in the final report
4. Document any new optimization techniques or insights
5. Update this README with new benchmark descriptions

