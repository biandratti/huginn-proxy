## Examples

Docker Compose stacks for huginn-proxy. On Linux or macOS, one command creates a certificate the browser trusts and starts the stack.

```bash
./examples/up            # JA4 + Akamai
./examples/up --ebpf     # Linux only: also starts the eBPF agent
```

`./examples/up` needs Docker and `mkcert`. It installs a local CA (the system asks once), writes `examples/certs`, pulls the published images in `examples/docker-compose.release-without-ebpf.yml`, waits until the proxy is healthy, and opens `https://localhost`. `--no-open` skips the browser. `--ebpf` uses `examples/docker-compose.release-ebpf.yml` and exits on macOS, where eBPF does not run.

If `mkcert` is missing, the script prints the install line and stops. It does not download the binary.

CI does not run this script. `.github/actions/setup-docker-compose` still generates a self-signed certificate and starts `docker-compose.ebpf.yml`.

> [!IMPORTANT]
> The compose files publish IPv4 and IPv6. Docker Desktop on macOS can fail to bind `[::]`. If startup reports a port bind error, remove the `[::]:*` lines from the compose file you are using. Traffic from the macOS host is NATed through `192.168.65.1`, so the proxy sees an IPv4 client even for `curl -6`.

---

## What you get

| | `./examples/up` | `./examples/up --ebpf` |
| --- | --- | --- |
| Fingerprints | JA4 + Akamai | JA4 + Akamai + TCP SYN |
| Compose file | `docker-compose.release-without-ebpf.yml` | `docker-compose.release-ebpf.yml` |
| Host | Linux or macOS | Linux, kernel ≥ 5.11 |

Both stacks publish **80** (HTTP, `301` to HTTPS) and **443**, mount `config/compose.yaml`, and start two `traefik/whoami` backends. The proxy container is UID `10001`.

```bash
curl -sk https://127.0.0.1/api/test
curl -sI http://127.0.0.1/api/test
curl http://127.0.0.1:9090/metrics | grep huginn_proxy
```

With `./examples/up`, `https://localhost` is trusted. A self-signed certificate (the CI one) still needs `curl -k` or a browser warning.

Headers on `/api/test`:

- `x-tls-ja4`, `x-tls-ja4-r`, `x-tls-ja4-o`, `x-tls-ja4-ro`
- `x-tls-ja4-s1`, `x-tls-ja4-rs1`
- `x-http2-akamai`
- `x-tcp-p0f` (eBPF stack only)

---

## Build from this repo

`./examples/up` pulls GHCR images (`:latest`). To build the proxy from this checkout instead, use the compose files CI uses:

```bash
docker compose -f examples/docker-compose.without-ebpf.yml up --build
docker compose -f examples/docker-compose.ebpf.yml up --build
```

Create `examples/certs` first with `./examples/up --no-open`, then stop the release stack (`docker compose -f examples/docker-compose.release-without-ebpf.yml down`) before starting a build file. Both bind-mount the same `examples/certs`.

Pin `:latest` to a release tag in the release compose file for a reproducible pull. Image names: [DEPLOYMENT-MATRIX.md](../DEPLOYMENT-MATRIX.md).

---

## Endpoints

| Service | URL | Description |
| --- | --- | --- |
| Proxy | `https://127.0.0.1/` | HTTPS proxy |
| Proxy | `http://127.0.0.1/` | HTTP, `301` to HTTPS |
| Proxy | `http://127.0.0.1:9090/health` | Health (liveness alias) |
| Proxy | `http://127.0.0.1:9090/ready` | Readiness |
| Proxy | `http://127.0.0.1:9090/live` | Liveness |
| Proxy | `http://127.0.0.1:9090/metrics` | Prometheus metrics |
| eBPF agent | `http://127.0.0.1:9091/health` | Health (liveness alias) |
| eBPF agent | `http://127.0.0.1:9091/ready` | Readiness |
| eBPF agent | `http://127.0.0.1:9091/live` | Liveness |
| eBPF agent | `http://127.0.0.1:9091/metrics` | Prometheus metrics |

The eBPF compose file publishes agent HTTP on the proxy service (`9091:9091`).

---

## Configuration

`config/compose.yaml` is what the compose files mount (HTTP `80`, HTTPS `443`, `https_redirection`). `config/compose.toml` is the same stack; its volume lines in the compose files are commented out.

`config/local.toml` is for a process on the host, without Docker:

```bash
cargo run -p huginn-proxy -- examples/config/local.toml
```

Generate `examples/certs` with `./examples/up --no-open` first. This listens on `127.0.0.1:8443`.

---

## Telemetry

Prometheus, Grafana, and cAdvisor run as a second Compose project. Prometheus scrapes the proxy (`9090`), the eBPF agent (`9091`) via `host.docker.internal`, and cAdvisor for per-container CPU and memory. Grafana loads the Huginn Proxy dashboard on its own. Optional cAdvisor UI: `http://localhost:8099/`.

Start the proxy stack first (`./examples/up` or `./examples/up --ebpf`), then:

```bash
docker compose -f examples/docker-compose.observability.yml up -d
```

Open `http://localhost:3000` and log in with **admin / huginn**.

---

## Troubleshooting

**Connection refused.** `docker compose -f examples/docker-compose.release-without-ebpf.yml ps` (or `docker-compose.release-ebpf.yml`). Logs: `docker compose -f examples/docker-compose.release-without-ebpf.yml logs proxy`.

**`ERR_CERT_AUTHORITY_INVALID`.** The browser is not using the mkcert CA. Run `./examples/up` again and accept the system prompt. Firefox also needs the NSS tools (`nss` on macOS, `libnss3-tools` on Debian/Ubuntu). `curl -k` skips verification.

**Port bind error on `[::]` (macOS).** Remove the `[::]:*` port lines from the compose file in use.

**Stop.** `docker compose -f examples/docker-compose.release-without-ebpf.yml down`, or `docker-compose.release-ebpf.yml` if that is the stack running.
