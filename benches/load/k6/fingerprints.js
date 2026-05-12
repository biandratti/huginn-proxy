// Load test + checks: backend (traefik/whoami) echoes the request as plain text.
// Fingerprint headers injected by the proxy appear in the echoed request headers.
//
//   k6 run --insecure-skip-tls-verify benches/load/k6/fingerprints.js
//
// Fingerprint checks (all ON by default — pass via --env):
//   --env NO_CHECK_JA4=true      skip JA4 TLS fingerprint checks
//   --env NO_CHECK_AKAMAI=true   skip Akamai HTTP/2 check (auto-skipped with K6_NO_HTTP2=true)
//   --env NO_CHECK_TCP_SYN=true  skip TCP SYN check (use without eBPF agent)
//
// When TCP SYN checks are active, keep-alive is disabled so every request opens a fresh TCP
// connection (new source port → new SYN → eBPF lookup fires each time).
//
// Load modes:
//   --env VUS=N --env DURATION=Xs   steady load (default: 5 VUs / 30s)
//   --env RAMP=true                 ramp 10 → 50 → 150 → 300 VUs to find saturation point

import http from "k6/http";
import {check} from "k6";

const baseUrl = __ENV.BASE_URL || "https://127.0.0.1:7000";
const targetPath = __ENV.TARGET_PATH || "/test";
const noHttp2 = __ENV.K6_NO_HTTP2 === "true";
const ramp = __ENV.RAMP === "true";

const checkJa4 = __ENV.NO_CHECK_JA4 !== "true";
const checkAkamai = __ENV.NO_CHECK_AKAMAI !== "true" && !noHttp2;
const checkTcpSyn = __ENV.NO_CHECK_TCP_SYN !== "true";

// Ramp scenario: gradually increase VUs to find the proxy saturation point.
// Watch http_req_duration and checks_failed to identify where performance degrades.
const rampStages = [
    {duration: "30s", target: 10}, // warm-up
    {duration: "1m", target: 50}, // moderate load
    {duration: "1m", target: 150}, // high load
    {duration: "1m", target: 300}, // stress — find the ceiling
    {duration: "30s", target: 0}, // cool-down
];

// In ramp mode the proxy is intentionally driven to saturation, so some errors at the
// high-VU stages are expected. Use a lenient error-rate threshold instead of rate==0.
const failedRateThreshold = ramp
    ? `rate<=${__ENV.K6_FAILED_RATE || 0.02}`
    : `rate==${__ENV.K6_FAILED_RATE || 0}`;

export const options = {
    ...(ramp
        ? {stages: rampStages}
        : {vus: Number(__ENV.VUS || 5), duration: __ENV.DURATION || "30s"}),
    // Full TLS handshake per request when TCP SYN checks are active (keep-alive skips the SYN).
    noConnectionReuse: checkTcpSyn,
    thresholds: {
        checks: [`rate>=${__ENV.K6_CHECKS_RATE || 0.99}`],
        http_req_failed: [failedRateThreshold],
    },
};

/**
 * Parse the plain-text body emitted by traefik/whoami.
 *
 * Format:
 *   Hostname: <name>
 *   IP: …
 *   RemoteAddr: …
 *   GET /path HTTP/1.1
 *   Host: …
 *   Header-Name: value
 *
 * Returns a map of lowercase header name → value string, or null on parse failure.
 */
function parseWhoami(text) {
    const headers = {};
    let inHeaders = false;

    for (const line of text.split("\n")) {
        const trimmed = line.trimEnd();
        if (!inHeaders) {
            const parts = trimmed.split(" ");
            if (
                parts.length >= 3 &&
                ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"].includes(parts[0]) &&
                parts[parts.length - 1].startsWith("HTTP/")
            ) {
                inHeaders = true;
            }
        } else {
            const colon = trimmed.indexOf(": ");
            if (colon !== -1) {
                const name = trimmed.slice(0, colon).toLowerCase();
                const value = trimmed.slice(colon + 2);
                headers[name] = value;
            }
        }
    }

    return inHeaders ? headers : null;
}

// FoxIO JA4 line: t|q + version + proto + ciphers + _ + hex + _ + hex
const JA4_LINE_PATTERN = /^[tq]\d{2}[a-z]\d{4}[a-z0-9]{2}_[0-9a-f]+_[0-9a-f]+$/;
// Akamai HTTP/2: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-headers
const AKAMAI_PATTERN = /^[\d:;]+\|\d+\|\d+\|[mapsi,]+$/;

function headerMatchesJa4Line(h, name) {
    const v = h[name];
    return typeof v === "string" && JA4_LINE_PATTERN.test(v);
}

function headerNonEmpty(h, name) {
    const v = h[name];
    return typeof v === "string" && v.length > 0;
}

export default function () {
    const url =
        baseUrl.endsWith("/") && targetPath.startsWith("/")
            ? `${baseUrl.replace(/\/$/, "")}${targetPath}`
            : `${baseUrl}${targetPath}`;

    const res = http.get(url);

    const okStatus = check(res, {
        "status is 200": (r) => r.status === 200,
    });
    if (!okStatus) {
        return;
    }

    const headers = parseWhoami(res.body);

    check(headers, {
        "body has echo headers": (h) => h !== null && typeof h === "object",
    });

    if (!headers) {
        return;
    }

    if (checkJa4) {
        check(headers, {
            "echo: x-tls-ja4 valid": (h) => headerMatchesJa4Line(h, "x-tls-ja4"),
            "echo: x-tls-ja4-r present": (h) => headerNonEmpty(h, "x-tls-ja4-r"),
            "echo: x-tls-ja4-o present": (h) => headerMatchesJa4Line(h, "x-tls-ja4-o"),
            "echo: x-tls-ja4-or present": (h) => headerNonEmpty(h, "x-tls-ja4-or"),
            "echo: x-tls-ja4-s1 valid": (h) => headerMatchesJa4Line(h, "x-tls-ja4-s1"),
            "echo: x-tls-ja4-s1r present": (h) => headerNonEmpty(h, "x-tls-ja4-s1r"),
        });
    }

    if (checkAkamai) {
        check(headers, {
            "echo: x-http2-akamai valid (HTTP/2)": (h) => {
                const v = h["x-http2-akamai"];
                return typeof v === "string" && AKAMAI_PATTERN.test(v);
            },
        });
    }

    if (checkTcpSyn) {
        check(headers, {
            "echo: x-tcp-p0f valid (eBPF)": (h) => {
                const v = h["x-tcp-p0f"];
                return typeof v === "string" && (v.startsWith("4:") || v.startsWith("6:"));
            },
        });
    }
}
