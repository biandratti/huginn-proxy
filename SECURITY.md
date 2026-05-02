# Security Policy

## Supported versions

huginn-proxy follows [Semantic Versioning](https://semver.org/). Only the latest release is actively supported.

## Reporting a vulnerability

If you find a security vulnerability in huginn-proxy, please **do not open a public issue**. Use [GitHub Security Advisories](https://github.com/biandratti/huginn-proxy/security/advisories/new) to report it privately.

Include as much detail as you can:

- Description of the vulnerability and potential impact
- Steps to reproduce (config snippet, curl command, packet capture if relevant)
- huginn-proxy version and build features (`ebpf-tcp` or standard)
- OS and kernel version (especially for eBPF-related issues)

If the report is confirmed, a patch will be released and you will be credited in the advisory unless you prefer otherwise.

## Scope

Areas particularly relevant for security reports:

- **TLS termination** — certificate handling, session resumption, cipher negotiation
- **mTLS** — client certificate validation bypasses
- **IP filtering** — ACL bypass or spoofing via forwarded headers
- **Rate limiting** — bypass via header manipulation or distributed requests
- **Fingerprint injection** — header spoofing that reaches backends despite proxy overrides
- **eBPF/XDP** — privilege escalation or memory safety issues in the kernel path
- **Config hot reload** — unsafe config swap or race conditions
