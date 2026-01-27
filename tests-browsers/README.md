# Browser Integration Tests

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