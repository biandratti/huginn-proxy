# Deployment Guide

Production deployment examples for Docker and Kubernetes.

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
- eBPF agent (TCP SYN fingerprinting)
- Multiple backends
- TLS termination
- Health checks
- Metrics endpoint

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

Loads XDP and pins BPF maps to `/sys/fs/bpf/huginn/`. Key security settings:

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
      volumeMounts:
        - name: bpffs
          mountPath: /sys/fs/bpf
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

Available endpoints on metrics port (default: 9090):

- `/health` - General health check
- `/ready` - Kubernetes readiness probe (checks if proxy can accept traffic)
- `/live` - Kubernetes liveness probe (checks if proxy is alive)
- `/metrics` - Prometheus metrics

All endpoints return 200 OK when healthy.

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

