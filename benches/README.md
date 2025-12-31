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
  - `/api` route: Fingerprinting enabled
  - `/static` route: Fingerprinting disabled
  - Default route `/`: Fingerprinting enabled (catch-all)
- `backend-a` and `backend-b`: Backend services

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

## Current Results

### Performance Overview

| Metric | Value |
|--------|-------|
| **HTTP/1.1 Throughput** | ~60 req/s |
| **HTTP/2 Throughput** | ~47 req/s |
| **Concurrent Connections (10)** | ~72 ms |
| **Concurrent Connections (100)** | ~187 ms |
| **Concurrent Connections (1000)** | ~1.8 s |

### Fingerprinting Overhead

| Configuration | Throughput (req/s) | Overhead |
|---------------|-------------------|----------|
| **HTTP/1.1 with fingerprinting** | ~1,601 | -2.7% |
| **HTTP/1.1 without fingerprinting** | ~1,646 | baseline |
| **HTTP/2 with fingerprinting** | ~1,271 | -1.7% |
| **HTTP/2 without fingerprinting** | ~1,293 | baseline |

### Notes

- **Measurement method**: 5 iterations averaged, 10,000 requests per iteration, 50 concurrent connections
- **Overall overhead**: ~-2.2% (minimal impact)
- **HTTP/1.1**: Fingerprinting adds ~2.7% overhead (TLS fingerprint extraction)
- **HTTP/2**: Fingerprinting adds ~1.7% overhead (TLS + HTTP/2 fingerprint extraction)
- **Success rate**: 100% (all requests successful)
- **Results**: Averaged across 2 benchmark runs for consistency

### Comparison with Reference Values

| Benchmark | Huginn Proxy | Reference |
|-----------|--------------|-----------|
| Reverse proxy with fingerprinting | ~1,200-1,700 req/s | ~2,000-16,000 req/s |
| Simple HTTP server | N/A | ~29,650 req/s |

**Note**: Current benchmarks are running against a real proxy with TLS termination, which adds significant overhead compared to in-memory packet processing benchmarks. Results are averaged across multiple iterations and benchmark runs for reliability.
