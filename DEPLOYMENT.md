# Deployment Guide

Production deployment examples for Docker and Kubernetes.

Image tags and release binaries (GHCR, musl/glibc, eBPF): see [DEPLOYMENT-MATRIX.md](DEPLOYMENT-MATRIX.md).

## Docker

### Standalone Container

Basic HTTP proxy:

```bash
docker run -d \
  --name huginn-proxy \
  -p 7000:7000 \
  -p 9090:9090 \
  -v $(pwd)/config.toml:/config/config.toml:ro \
  huginn-proxy:latest \
  /usr/local/bin/huginn-proxy /config/config.toml
```

With TLS:

```bash
docker run -d \
  --name huginn-proxy \
  -p 7000:7000 \
  -p 9090:9090 \
  -v $(pwd)/config.toml:/config/config.toml:ro \
  -v $(pwd)/certs:/config/certs:ro \
  huginn-proxy:latest \
  /usr/local/bin/huginn-proxy /config/config.toml
```

**Note:** Certificate files must be readable by user `app` (UID 100).

### Docker Compose

See `examples/docker-compose.yml` for a complete setup with:
- eBPF agent (TCP SYN fingerprinting, `/metrics` and `/ready` on configurable port)
- Proxy (TLS termination, `/health`, `/ready`, `/live`, `/metrics` on port 9090)
- Multiple backends
- TLS termination
- Health checks for both agent and proxy

Run with:

```bash
cd examples
docker compose up -d
```

Without TCP fingerprinting, use the plain variant:

```bash
cd examples
docker compose -f docker-compose.plain.yml up -d
```

## Kubernetes

Two workloads: the eBPF agent as **DaemonSet** (1 per node) and the proxy as **Deployment** (N replicas).

### eBPF Agent (DaemonSet)

Loads XDP and pins BPF maps to `/sys/fs/bpf/huginn/`. Exposes `/metrics` and `/ready` on a configurable address and port (env vars `HUGINN_EBPF_METRICS_ADDR`, `HUGINN_EBPF_METRICS_PORT`; e.g. `127.0.0.1:9091`). Use an HTTP readiness probe to the same address and port, path `/ready`.

Key security settings:

```yaml
spec:
  hostNetwork: true                    # XDP on the node's real interface
  containers:
    - name: ebpf-agent
      securityContext:
        capabilities:
          add: [BPF, NET_ADMIN, PERFMON]
        seccompProfile:
          type: Unconfined              # bpf() syscall required
      env:
        - name: HUGINN_EBPF_INTERFACE
          value: "eth0"                 # or node's primary interface
        - name: HUGINN_EBPF_DST_IP_V4
          value: "0.0.0.0"
        - name: HUGINN_EBPF_DST_PORT
          value: "7000"
        - name: HUGINN_EBPF_PIN_PATH
          value: "/sys/fs/bpf/huginn"
        - name: HUGINN_EBPF_METRICS_ADDR
          value: "127.0.0.1"
        - name: HUGINN_EBPF_METRICS_PORT
          value: "9091"
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
      readinessProbe:
        httpGet:
          path: /ready
          port: 9091
        initialDelaySeconds: 5
        periodSeconds: 5
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: DirectoryOrCreate
```

### Proxy (Deployment)

**With TCP fingerprinting** (`tcp_enabled = true`): requires the DaemonSet above.

```yaml
spec:
  containers:
    - name: proxy
      securityContext:
        capabilities:
          add: [BPF]                    # BPF_OBJ_GET to read pinned maps
        seccompProfile:
          type: RuntimeDefault
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
          readOnly: true
  volumes:
    - name: bpffs
      hostPath:
        path: /sys/fs/bpf
        type: Directory
```

**Without TCP fingerprinting** (`tcp_enabled = false`): no DaemonSet, no capabilities, no volumes.

```yaml
spec:
  containers:
    - name: proxy
      securityContext:
        seccompProfile:
          type: RuntimeDefault
```

### Key differences vs Docker Compose

| | Docker Compose | Kubernetes |
|---|---|---|
| bpffs | Docker named volume (`type: bpf`) | `hostPath: /sys/fs/bpf` (already mounted by systemd) |
| Agent network | `network_mode: "service:proxy"` | `hostNetwork: true` |
| AppArmor | `apparmor:unconfined` (Ubuntu/Debian) | Not needed (Pod Security Standards) |
| Proxy scaling | single container | Deployment + HPA |

## Health Check Endpoints

### Proxy (observability server)

- `/health` - General health check
- `/ready` - readiness probe (checks if proxy can accept traffic)
- `/live` - liveness probe (checks if proxy is alive)
- `/metrics` - Prometheus metrics

### eBPF agent (observability server)

- `/health` - General health check
- `/ready` - readiness probe: 200 if BPF map pins exist under `HUGINN_EBPF_PIN_PATH`
- `/live` - liveness probe
- `/metrics` - Prometheus metrics

## TLS Certificate Management

### Certificate Rotation

Huginn Proxy supports hot reload for TLS certificates:

1. Update certificate files (Secret in Kubernetes, volume in Docker)
2. Proxy detects changes after `watch_delay_secs` (default: 60s)
3. New connections use new certificates
4. Existing connections continue with old certificates until closed

No restart required.

### Certificate Permissions

**Docker:** Certificates must be readable by user `app` (UID 100).

```bash
chmod 400 server.crt server.key
```

**Kubernetes:** Secret volumes are mounted with `defaultMode: 0400` (read-only for owner).

## Performance Tuning

Key settings for production:

```toml
[security]
max_connections = 1024

[backend_pool]
enabled = true
idle_timeout = 90
pool_max_idle_per_host = 128

[timeout]
connect_ms = 5000
connection_handling_secs = 300
```

Adjust resource limits based on your workload (see Deployment manifest example above).

