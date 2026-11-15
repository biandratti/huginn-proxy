## Examples

Linux or macOS. Two ways to run the stack: pull the published images, or build this checkout.

## Requirements

- Docker, running, with Compose v2 (`docker compose`)
- [`mkcert`](https://github.com/FiloSottile/mkcert#installation), with its NSS tools if you use Firefox. The install steps for your system are on that page.

The scripts check for `mkcert` and link to that page if it is missing. They do not install it.

A Rust toolchain is only needed for `cargo run` in [Development](#development).

## Latest images

`./examples/setup/up` installs the local CA (the system asks once), writes `examples/certs`, pulls the GHCR images tagged `:latest`, waits until the proxy is healthy, and opens `https://localhost`.

```bash
./examples/setup/up
```

In a terminal it asks what to start:

```text
1) Proxy
2) Proxy + Telemetry
3) Proxy + eBPF
4) Proxy + eBPF + Telemetry
```

Flags skip the menu. Without a terminal and without flags, only the proxy starts.

```bash
./examples/setup/up --ebpf        # docker-compose.release-ebpf.yml
./examples/setup/up --telemetry   # also Prometheus, Grafana, cAdvisor
./examples/setup/up --no-open     # do not open a browser
./examples/setup/down             # stop the release stack and telemetry
```

| | `./examples/setup/up` | `./examples/setup/up --ebpf` |
| --- | --- | --- |
| Fingerprints | JA4 + Akamai | JA4 + Akamai + TCP SYN |
| Compose file | `docker-compose.release-without-ebpf.yml` | `docker-compose.release-ebpf.yml` |
| Host | Linux or macOS | Linux, or macOS via Docker Desktop |

Both publish **80** (HTTP, `301` to HTTPS) and **443**, mount `config/compose.yaml`, and start two `traefik/whoami` backends. The proxy container is UID `10001`. `https://localhost` is trusted. CI uses a self-signed certificate instead, so that stack still needs `curl -k`.

```bash
curl -sk https://127.0.0.1/api/test
curl -sI http://127.0.0.1/api/test
curl http://127.0.0.1:9090/metrics | grep huginn_proxy
```

Headers on `/api/test`: `x-tls-ja4`, `x-tls-ja4-r`, `x-tls-ja4-o`, `x-tls-ja4-ro`, `x-tls-ja4-s1`, `x-tls-ja4-rs1`, `x-http2-akamai`, and `x-tcp-p0f` when the eBPF agent is running.

On macOS the script adds `examples/setup/ipv4.yml` (or `ipv4-ebpf.yml`) and publishes `0.0.0.0` only. Docker Desktop does not bind `[::]`. Leave those lines in the compose files: Linux and CI use them. Host traffic is NATed through `192.168.65.1`, so the proxy sees an IPv4 client. The eBPF agent runs inside Docker Desktop's Linux VM. The native macOS binary has no eBPF.

CI does not run this script. `.github/actions/setup-docker-compose` generates its own certificate and starts `docker-compose.ebpf.yml`.

Pin `:latest` to a release tag in the release compose file for a reproducible pull. Image names: [DEPLOYMENT-MATRIX.md](../DEPLOYMENT-MATRIX.md).

## Development

Build the proxy from this checkout. Create the certificate first. `./examples/setup/certs` does not start a container. If a release stack is running, `./examples/setup/down` before the build file. Both bind-mount `examples/certs`.

```bash
./examples/setup/certs
docker compose -f examples/docker-compose.without-ebpf.yml up --build
docker compose -f examples/docker-compose.ebpf.yml up --build
```

On macOS, add the IPv4 override:

```bash
docker compose -f examples/docker-compose.without-ebpf.yml -f examples/setup/ipv4.yml up --build
docker compose -f examples/docker-compose.ebpf.yml -f examples/setup/ipv4-ebpf.yml up --build
```

To run the proxy on the host, without Docker, generate the certificate and then:

```bash
cargo run -p huginn-proxy -- examples/config/local.toml
```

That listens on `127.0.0.1:8443`. `config/compose.yaml` is what the compose files mount (HTTP `80`, HTTPS `443`). `config/compose.toml` is the same stack. Its volume lines in the compose files are commented out.

## Telemetry

`--telemetry` starts Prometheus, Grafana, and cAdvisor after the proxy is healthy. Prometheus scrapes the proxy (`9090`), the eBPF agent (`9091`) via `host.docker.internal`, and cAdvisor. Grafana opens at `http://localhost:3000` with **admin / huginn**. cAdvisor UI: `http://localhost:8099/`.

The same stack on its own, after the proxy is already up:

```bash
docker compose -f examples/docker-compose.observability.yml up -d
```

## Endpoints

| Service | URL |
| --- | --- |
| Proxy | `https://127.0.0.1/` and `http://127.0.0.1/` (`301` to HTTPS) |
| Proxy health | `http://127.0.0.1:9090/health`, `/ready`, `/live`, `/metrics` |
| eBPF agent | `http://127.0.0.1:9091/health`, `/ready`, `/live`, `/metrics` |

The eBPF compose file publishes agent HTTP on the proxy service (`9091:9091`).

## Troubleshooting

**Connection refused.** `docker compose -f examples/docker-compose.release-without-ebpf.yml ps` (or `docker-compose.release-ebpf.yml`). Logs: `docker compose -f examples/docker-compose.release-without-ebpf.yml logs proxy`.

**`ERR_CERT_AUTHORITY_INVALID`.** Run `./examples/setup/up` again and accept the system prompt. Firefox needs the NSS package from [Requirements](#requirements). `curl -k` skips verification.

**Port bind error on `[::]` (macOS).** `./examples/setup/up` already publishes IPv4 only. For a build file, add `-f examples/setup/ipv4.yml` or `examples/setup/ipv4-ebpf.yml`.

**Stop.** `./examples/setup/down`. Certificates in `examples/certs` stay.
