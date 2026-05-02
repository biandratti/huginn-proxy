# Contributing to huginn-proxy

huginn-proxy is a reverse proxy built around passive fingerprinting. Contributions that fit that goal are welcome — if you're unsure whether something belongs here, open an issue first.

## Getting started

```bash
git clone https://github.com/YOUR_USERNAME/huginn-proxy.git
cd huginn-proxy
cargo build --workspace
cargo test --workspace --all-features --exclude tests-e2e --exclude tests-browsers
```

Requires Rust stable. Install from [rustup.rs](https://rustup.rs/).

## Codebase layout

| Path | Role |
| --- | --- |
| `huginn-proxy/` | proxy binary |
| `huginn-proxy-lib/` | core proxy logic |
| `huginn-ebpf/` | reads pinned BPF maps |
| `huginn-ebpf-agent/` | XDP agent binary |
| `huginn-ebpf-common/` | shared types |
| `huginn-ebpf-xdp/` | XDP kernel program (nightly, outside workspace) |
| `examples/` | Docker Compose stacks and configs |
| `src/` | documentation site (Astro Starlight) |

## eBPF

The XDP crate (`huginn-ebpf-xdp`) is Linux-only and needs `bpf-linker` + Rust nightly with `rust-src`. For most changes — proxy logic, config, fingerprinting, docs — the standard workspace build is enough. The CI action `.github/actions/setup-ebpf-build` handles the full setup automatically.

```bash
# standard
cargo build --workspace

# with TCP SYN fingerprinting
cargo build --workspace --features ebpf-tcp
```

## Before opening a PR

```bash
# format
cargo fmt --all

# lint (workspace)
cargo clippy --workspace --all-features --all-targets -- \
  -D warnings \
  -D clippy::expect_used \
  -D clippy::unreachable \
  -D clippy::arithmetic_side_effects \
  -D clippy::unwrap_used \
  -D clippy::todo \
  -D clippy::redundant_clone \
  -D clippy::unimplemented \
  -D clippy::missing_panics_doc \
  -D clippy::redundant_field_names

# lint (XDP crate — Linux only)
cd huginn-ebpf-xdp && cargo clippy -- \
  -D warnings \
  -D clippy::expect_used \
  -D clippy::unreachable \
  -D clippy::arithmetic_side_effects \
  -D clippy::unwrap_used \
  -D clippy::todo \
  -D clippy::redundant_clone \
  -D clippy::unimplemented \
  -D clippy::missing_panics_doc \
  -D clippy::redundant_field_names

# Cargo.toml ordering
cargo sort --workspace --check

# validate a config without starting the proxy
cargo run -p huginn-proxy -- --validate examples/config/compose.toml
```

If you add or change config keys, update `SETTINGS.md` and the relevant page under `src/content/docs/docs/`. Same for Prometheus metrics and `TELEMETRY.md`.

## Issues

- **Security vulnerabilities** — contact the maintainers directly, don't open a public issue.
- **Performance** — include a profile or benchmark showing the regression. Flamegraphs are helpful.
- **Fingerprinting accuracy** — describe the client/OS, the expected signature, and what the proxy produced. Packet captures are very useful.
- **Bugs** — include `rustc --version`, OS + kernel version, build features (`ebpf-tcp` or not), and `RUST_LOG=debug` output.

## Documentation site

```bash
npm install
npm run dev
```

Pages are under `src/content/docs/docs/`. The sidebar is in `astro.config.mjs`.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
