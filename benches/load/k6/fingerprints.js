// Load test + checks: backend echoes request headers as JSON — fingerprints appear there,
// not on the TLS response to the client.
//
//   k6 run --insecure-skip-tls-verify benches/load/k6/fingerprints.js
//
// HTTP/1.1 only (JA4, no Akamai): K6_NO_HTTP2=true k6 run --insecure-skip-tls-verify ...
// Optional eBPF SYN header: EXPECT_TCP_SYN=true (only when maps are populated).

import http from "k6/http";
import { check } from "k6";

const baseUrl = __ENV.BASE_URL || "https://127.0.0.1:7000";
const targetPath = __ENV.TARGET_PATH || "/api/";
const noHttp2 = __ENV.K6_NO_HTTP2 === "true";
// Akamai only applies to HTTP/2; disable check when forcing HTTP/1.1
const expectAkamai =
  !noHttp2 && __ENV.EXPECT_AKAMAI !== "false";
const expectTcpSyn = __ENV.EXPECT_TCP_SYN === "true";

export const options = {
  vus: Number(__ENV.VUS || 5),
  duration: __ENV.DURATION || "30s",
  thresholds: {
    // Strict CI: set K6_CHECKS_RATE=1 for rate===1
    checks: [`rate>=${__ENV.K6_CHECKS_RATE || 0.99}`],
    http_req_failed: ["rate==0"],
  },
};

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") {
    return undefined;
  }
  const want = name.toLowerCase();
  for (const k of Object.keys(headers)) {
    if (k.toLowerCase() === want) {
      return headers[k];
    }
  }
  return undefined;
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

  let body;
  try {
    body = res.json();
  } catch (_) {
    check(null, {
      "body is JSON": () => false,
    });
    return;
  }

  const headers = body && body.headers;
  check(body, {
    "json has headers object": (b) =>
      b !== null && typeof b === "object" && typeof b.headers === "object",
  });

  check(null, {
    "echo: x-huginn-net-ja4 present": () => {
      const v = getHeader(headers, "x-huginn-net-ja4");
      return typeof v === "string" && v.length > 0;
    },
  });

  check(null, {
    "echo: x-huginn-net-ja4_r present": () => {
      const v = getHeader(headers, "x-huginn-net-ja4_r");
      return typeof v === "string" && v.length > 0;
    },
  });

  if (expectAkamai) {
    check(null, {
      "echo: x-huginn-net-akamai present (HTTP/2)": () => {
        const v = getHeader(headers, "x-huginn-net-akamai");
        return typeof v === "string" && v.length > 0;
      },
    });
  }

  if (expectTcpSyn) {
    check(null, {
      "echo: x-huginn-net-tcp present (eBPF)": () => {
        const v = getHeader(headers, "x-huginn-net-tcp");
        return typeof v === "string" && v.length > 0;
      },
    });
  }
}
