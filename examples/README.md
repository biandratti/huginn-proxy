## Examples

Docker Compose stacks for huginn-proxy. On Linux or macOS, one command creates a certificate the browser trusts and starts the stack. `./examples/setup/certs` creates only the certificate, for development builds.

```bash
./examples/setup/up            # menu: proxy, proxy + Telemetry, proxy + eBPF, proxy + eBPF + Telemetry
./examples/setup/up --ebpf     # skip the menu: also starts the eBPF agent
./examples/setup/up --telemetry  # skip the menu: also starts Grafana, Prometheus, cAdvisor (Grafana: http://localhost:3000, admin / huginn)
./examples/setup/down          # stop the release stack and telemetry
```

`./examples/setup/up` needs Docker and `mkcert`. It installs a local CA (the system asks once), writes `examples/certs`, pulls the published images in `examples/docker-compose.release-without-ebpf.yml`, waits until the proxy is healthy, and opens `https://localhost`. `--no-open` skips the browser. `--ebpf` uses `examples/docker-compose.release-ebpf.yml`. On macOS that agent runs inside Docker Desktop's Linux VM and attaches the XDP hook there. The native macOS binary has no eBPF. `--telemetry` starts `examples/docker-compose.observability.yml` (Prometheus, Grafana, cAdvisor) after the proxy is healthy. Without a terminal and without flags, only the proxy starts.

If `mkcert` is missing, the script prints the install line and stops. It does not download the binary.

CI does not run this script. `.github/actions/setup-docker-compose` still generates a self-signed certificate and starts `docker-compose.ebpf.yml`.

> [!IMPORTANT]
> The compose files publish IPv4 and IPv6. On macOS, `./examples/setup/up` adds `examples/setup/ipv4.yml` (or `ipv4-ebpf.yml`) so Docker Desktop only publishes `0.0.0.0`. Do not edit the `[::]` lines: Linux and CI use them. Traffic from the macOS host is NATed through `192.168.65.1`, so the proxy sees an IPv4 client even for `curl -6`.

---

## What you get

| | `./examples/setup/up` | `./examples/setup/up --ebpf` |
| --- | --- | --- |
| Fingerprints | JA4 + Akamai | JA4 + Akamai + TCP SYN |
| Compose file | `docker-compose.release-without-ebpf.yml` | `docker-compose.release-ebpf.yml` |
| Host | Linux or macOS | Linux, or macOS via Docker Desktop |

Both stacks publish **80** (HTTP, `301` to HTTPS) and **443**, mount `config/compose.yaml`, and start two `traefik/whoami` backends. The proxy container is UID `10001`.

```bash
curl -sk https://127.0.0.1/api/test
curl -sI http://127.0.0.1/api/test
curl http://127.0.0.1:9090/metrics | grep huginn_proxy
```

With `./examples/setup/up`, `https://localhost` is trusted. A self-signed certificate (the CI one) still needs `curl -k` or a browser warning.

Headers on `/api/test`:

- `x-tls-ja4`, `x-tls-ja4-r`, `x-tls-ja4-o`, `x-tls-ja4-ro`
- `x-tls-ja4-s1`, `x-tls-ja4-rs1`
- `x-http2-akamai`
- `x-tcp-p0f` (eBPF stack only)

---

## Build from this repo

`./examples/setup/up` pulls GHCR images (`:latest`). To build the proxy from this checkout instead, create the certificates once, then use the compose files CI uses:

```bash
./examples/setup/certs
docker compose -f examples/docker-compose.without-ebpf.yml up --build
docker compose -f examples/docker-compose.ebpf.yml up --build
```

On macOS, add the IPv4 override. Docker Desktop does not bind `[::]`:

```bash
docker compose -f examples/docker-compose.without-ebpf.yml -f examples/setup/ipv4.yml up --build
docker compose -f examples/docker-compose.ebpf.yml -f examples/setup/ipv4-ebpf.yml up --build
```

`./examples/setup/certs` only makes `examples/certs` (local CA plus `server.crt` and `server.key`). It starts no container. If a release stack is running, stop it with `./examples/setup/down` before the build file. Both bind-mount the same `examples/certs`.

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

Generate `examples/certs` with `./examples/setup/certs` first. This listens on `127.0.0.1:8443`.

---

## Telemetry

Prometheus, Grafana, and cAdvisor run as a second Compose project. Prometheus scrapes the proxy (`9090`), the eBPF agent (`9091`) via `host.docker.internal`, and cAdvisor for per-container CPU and memory. Grafana loads the Huginn Proxy dashboard on its own. Optional cAdvisor UI: `http://localhost:8099/`.

Start the proxy stack first (`./examples/setup/up` or `./examples/setup/up --ebpf`), then:

```bash
docker compose -f examples/docker-compose.observability.yml up -d
```

Open `http://localhost:3000` and log in with **admin / huginn**.

---

## Troubleshooting

**Connection refused.** `docker compose -f examples/docker-compose.release-without-ebpf.yml ps` (or `docker-compose.release-ebpf.yml`). Logs: `docker compose -f examples/docker-compose.release-without-ebpf.yml logs proxy`.

**`ERR_CERT_AUTHORITY_INVALID`.** The browser is not using the mkcert CA. Run `./examples/setup/up` again and accept the system prompt. Firefox also needs the NSS tools (`nss` on macOS, `libnss3-tools` on Debian/Ubuntu). `curl -k` skips verification.

**Port bind error on `[::]` (macOS).** `./examples/setup/up` already publishes IPv4 only. For a build compose file, add `-f examples/setup/ipv4.yml` (or `examples/setup/ipv4-ebpf.yml`). Leave the `[::]` lines in the compose files.

**Stop.** `./examples/setup/down`. It stops the release stack and the observability stack. Certificates in `examples/certs` stay.
