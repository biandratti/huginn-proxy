# Deployment Guide

Production deployment examples for Docker and Kubernetes.

Image tags and release binaries (GHCR, musl/glibc, eBPF): see [DEPLOYMENT-MATRIX.md](DEPLOYMENT-MATRIX.md).

## Docker

### Overview

Use a published image from GHCR (see [DEPLOYMENT-MATRIX.md](DEPLOYMENT-MATRIX.md)). The **`huginn-proxy-plain`** image needs no extra Linux capabilities on the host; the default **`huginn-proxy`** image includes eBPF support for TCP SYN fingerprinting and may need `CAP_BPF` when that feature is enabled.

From the **repository root**, mount a real config **file** on the host. If the path does not exist, Docker creates an empty **directory** with that name and the proxy fails with `Is a directory (os error 21)` — remove any mistaken `config.toml` directory (`rm -rf ./config.toml`) and point at the file under `examples/config/`.

The checked-in example is `examples/config/compose.toml` (same one `examples/docker-compose.yml` uses). Backends there are `backend-a` / `backend-b` (Docker Compose DNS names); for a working stack use Compose below, or change backends to addresses reachable from the container.

**Note:** The process runs as user `app` (UID **10001**). Certificate and key files under `/config/certs` must be readable by that user (e.g. `chmod` / `chown` on the host copy).

### Docker Compose

| File | Images | Use case |
| --- | --- | --- |
| `examples/docker-compose.yml` | Built from this repo | Full stack with eBPF agent (dev / CI) |
| `examples/docker-compose.plain.yml` | Built from this repo | Proxy only (no eBPF in the binary) |
| `examples/docker-compose.release-ebpf.yml` | **GHCR** `huginn-proxy` + `huginn-proxy-ebpf-agent` | Same as above, using published images |
| `examples/docker-compose.release.yml` | **GHCR** `huginn-proxy-plain` | Same as plain, using published images |

Published image names and tags (`latest` / `vX.Y.Z`): [DEPLOYMENT-MATRIX.md](DEPLOYMENT-MATRIX.md). The three GHCR packages are separate repositories (`huginn-proxy`, `huginn-proxy-plain`, `huginn-proxy-ebpf-agent`); **do not** add `-ebpf-agent` as a suffix on the tag.

Compose that **builds** from this repository (TLS, backends, plain vs eBPF) is documented in [`examples/README.md`](examples/README.md).

Pre-built images from GHCR (pin `latest` to a release tag in the compose file if you need reproducibility):

```bash
cd examples
docker compose -f docker-compose.release.yml pull
docker compose -f docker-compose.release.yml up -d
```

With eBPF agent + proxy from GHCR (Linux host; requires `CAP_BPF` and the `bpffs` volume, same as `docker-compose.yml`):

```bash
cd examples
docker compose -f docker-compose.release-ebpf.yml pull
docker compose -f docker-compose.release-ebpf.yml up -d
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
          value: "0.0.0.0"
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
          add: [BPF]
        seccompProfile:
          type: RuntimeDefault
      env:
        - name: HUGINN_CONFIG_PATH
          value: "/config/config.toml"
        - name: HUGINN_WATCH
          value: "true"
        - name: HUGINN_WATCH_DELAY_SECS
          value: "60"
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
      env:
        - name: HUGINN_CONFIG_PATH
          value: "/config/config.toml"
        - name: HUGINN_WATCH
          value: "true"
        - name: HUGINN_WATCH_DELAY_SECS
          value: "60"
```

`HUGINN_CONFIG_PATH` sets the config file path without changing the container `command`. Useful when the same image is shared across environments (staging, prod) and only the ConfigMap mount point differs — override the path via env var rather than patching the Deployment spec each time.

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

## Static and Dynamic settings

Settings are split into two groups. **Dynamic** settings take effect on the next
reload (SIGHUP or file-watcher); no connections are dropped. **Static** settings
are read once at startup — a process restart is required to apply changes.
If a reload detects changes in static sections, the proxy logs an error and
continues running with the old values.

### Dynamic (hot-reloadable)

| TOML key | Description |
|---|---|
| `[[backends]]` | Backend list (addresses, pool config, HTTP version) |
| `[[routes]]` | Path-prefix routing rules, including per-route `fingerprinting` toggle, path rewriting, and rate limits |
| `[backend_pool]` | Connection pool settings (`enabled`, `idle_timeout`, `pool_max_idle_per_host`) |
| `preserve_host` | Forward original `Host` header to backends |
| `[headers]` | Global request/response header manipulation |
| `[security].headers` | Security response headers (HSTS, CSP, custom) |
| `[security].ip_filter` | IP allow/deny list |
| `[security].rate_limit` | Rate limiting policy and counters |

> **Note on rate-limit counters:** existing in-memory counters are preserved
> across reloads unless `limit_by` or `window_seconds` changes, in which case
> they are reset.

### Static (requires restart)

| TOML key | Description |
|---|---|
| `[listen]` | Bind addresses, backlog, `reuse_port` |
| `[tls]` | TLS termination (cert/key hot-reload is handled separately — see below) |
| `[fingerprint]` | Fingerprinting feature flags (`tcp_enabled`, `tls_enabled`, `http_enabled`, `max_capture`) — static because they control eBPF program loading and capture buffers at startup |
| `[logging]` | Log level and format |
| `[telemetry]` | Metrics port and OpenTelemetry log level |
| `[timeout]` | Connect / connection-handling timeouts |
| `[security].max_connections` | Maximum concurrent connections |

> **TLS certificate rotation** is the exception: cert and key files are watched
> independently of the main config. New connections pick up the new certificate
> without a restart; existing connections are unaffected.

## TLS Certificate Management

### Certificate Rotation

Huginn Proxy supports hot reload for TLS certificates:

1. Enable the file watcher (`HUGINN_WATCH=true`)
2. Update certificate files (Secret in Kubernetes, volume in Docker)
3. Proxy detects changes after the debounce window (`HUGINN_WATCH_DELAY_SECS`, default: 60s)
4. New connections use new certificates
5. Existing connections continue with old certificates until closed

No restart required.

### Certificate Permissions

**Docker:** Certificates must be readable by user `app` (UID 100).

```bash
chmod 400 server.crt server.key
```

**Kubernetes:** Secret volumes are mounted with `defaultMode: 0400` (read-only for owner).