# Browser Integration Tests

This package contains browser integration tests that verify real browser behavior through the proxy, including TLS and HTTP/2 fingerprinting.

## Overview

These tests use WebDriver (Selenium) to control real browsers and verify that:
- Browsers can connect through the proxy
- TLS fingerprints (JA4) are correctly captured
- HTTP/2 fingerprints (Akamai format) are correctly captured
- Fingerprints are consistent across multiple requests
- Different browsers produce different fingerprints

## Requirements

### Chrome Tests
- Chrome/Chromium browser installed
- `chromedriver` running on port 9515
- Proxy running on `https://localhost:7000`

### Firefox Tests
- Firefox browser installed
- `geckodriver` running on port 4444
- Proxy running on `https://localhost:7000`

## Running Tests

### Prerequisites

1. Start the proxy (via Docker Compose):
   ```bash
   cd examples
   docker compose up -d
   ```

2. Start the appropriate WebDriver:
   ```bash
   # For Chrome tests
   chromedriver --port=9515
   
   # For Firefox tests
   geckodriver --port=4444
   ```

### Running Tests

```bash
# Run Chrome tests
cargo test --package tests-browsers --test chrome -- --nocapture --test-threads=1

# Run Firefox tests
cargo test --package tests-browsers --test firefox -- --nocapture --test-threads=1

# Run all browser tests
cargo test --package tests-browsers -- --nocapture --test-threads=1
```

## Test Structure

- `tests/chrome.rs` - Chrome-specific tests
- `tests/firefox.rs` - Firefox-specific tests (includes cross-browser comparison)

## Differences from `tests-e2e`

- **Dependencies**: Browser tests require WebDriver dependencies (`thirtyfour`, `serial_test`)
- **Infrastructure**: Require browser binaries and WebDriver servers
- **Isolation**: Separated to avoid pulling browser dependencies into general E2E tests
- **CI**: Run in separate GitHub Actions jobs with browser-specific setup
