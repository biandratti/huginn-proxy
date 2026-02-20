# Deployment Guide

Production deployment examples for Docker and Kubernetes.

## Docker

### Standalone Container

Basic HTTP proxy:

```bash
docker run -d \
  --name huginn-proxy \
  -p 7000:7000 \
  -p 9090:9090 \
  -v $(pwd)/config.toml:/config/config.toml:ro \
  huginn-proxy:latest \
  /usr/local/bin/huginn-proxy /config/config.toml
```

With TLS:

```bash
docker run -d \
  --name huginn-proxy \
  -p 7000:7000 \
  -p 9090:9090 \
  -v $(pwd)/config.toml:/config/config.toml:ro \
  -v $(pwd)/certs:/config/certs:ro \
  huginn-proxy:latest \
  /usr/local/bin/huginn-proxy /config/config.toml
```

**Note:** Certificate files must be readable by user `app` (UID 100).

### Docker Compose

See `examples/docker-compose.yml` for a complete setup with:
- Multiple backends
- TLS termination
- Health checks
- Metrics endpoint

Run with:

```bash
cd examples
docker compose up -d
```

## Kubernetes

### ConfigMap

Create a ConfigMap with your proxy configuration:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: huginn-proxy-config
  namespace: default
data:
  config.toml: |
    listen = "0.0.0.0:7000"
    preserve_host = true
    
    backends = [
      { address = "backend-service:8080", http_version = "preserve" }
    ]
    
    routes = [
      { prefix = "/api", backend = "backend-service:8080" },
      { prefix = "/", backend = "backend-service:8080" }
    ]
    
    [telemetry]
    metrics_port = 9090
    
    [logging]
    level = "info"
    
    [timeout]
    connect_ms = 5000
    idle_ms = 60000
    shutdown_secs = 30
    tls_handshake_secs = 15
    connection_handling_secs = 300
    
    [security]
    max_connections = 1024
```

### TLS Secret

Create a Secret for TLS certificates:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: huginn-proxy-tls
  namespace: default
type: Opaque
data:
  server.crt: <base64-encoded-cert>
  server.key: <base64-encoded-key>
```

Create from files:

```bash
kubectl create secret generic huginn-proxy-tls \
  --from-file=server.crt=./certs/server.crt \
  --from-file=server.key=./certs/server.key \
  --namespace=default
```

### ConfigMap with TLS

Add TLS configuration to your ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: huginn-proxy-config
data:
  config.toml: |
    listen = "0.0.0.0:7000"
    backends = [
      { address = "backend-service:8080" }
    ]
    routes = [
      { prefix = "/", backend = "backend-service:8080" }
    ]
    
    [tls]
    cert_path = "/config/certs/server.crt"
    key_path = "/config/certs/server.key"
    alpn = ["h2", "http/1.1"]
    watch_delay_secs = 60
    
    [telemetry]
    metrics_port = 9090
```

### Deployment

Basic deployment with health checks:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: huginn-proxy
  namespace: default
spec:
  replicas: 2
  selector:
    matchLabels:
      app: huginn-proxy
  template:
    metadata:
      labels:
        app: huginn-proxy
    spec:
      containers:
      - name: proxy
        image: huginn-proxy:latest
        imagePullPolicy: IfNotPresent
        args: ["/usr/local/bin/huginn-proxy", "/config/config.toml"]
        ports:
        - name: proxy
          containerPort: 7000
          protocol: TCP
        - name: metrics
          containerPort: 9090
          protocol: TCP
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 500m
            memory: 512Mi
        livenessProbe:
          httpGet:
            path: /live
            port: 9090
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 3
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /ready
            port: 9090
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 2
          failureThreshold: 2
        startupProbe:
          httpGet:
            path: /health
            port: 9090
          initialDelaySeconds: 0
          periodSeconds: 2
          timeoutSeconds: 2
          failureThreshold: 30
        volumeMounts:
        - name: config
          mountPath: /config
          readOnly: true
        - name: tls-certs
          mountPath: /config/certs
          readOnly: true
      volumes:
      - name: config
        configMap:
          name: huginn-proxy-config
      - name: tls-certs
        secret:
          secretName: huginn-proxy-tls
          defaultMode: 0400
```

### Services

Proxy service for incoming traffic:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: huginn-proxy
  namespace: default
spec:
  type: LoadBalancer
  selector:
    app: huginn-proxy
  ports:
  - name: https
    port: 443
    targetPort: 7000
    protocol: TCP
```

Metrics service for Prometheus:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: huginn-proxy-metrics
  namespace: default
  labels:
    app: huginn-proxy
spec:
  type: ClusterIP
  selector:
    app: huginn-proxy
  ports:
  - name: metrics
    port: 9090
    targetPort: 9090
    protocol: TCP
```

## Health Check Endpoints

Available endpoints on metrics port (default: 9090):

- `/health` - General health check
- `/ready` - Kubernetes readiness probe (checks if proxy can accept traffic)
- `/live` - Kubernetes liveness probe (checks if proxy is alive)
- `/metrics` - Prometheus metrics

All endpoints return 200 OK when healthy.

## TLS Certificate Management

### Certificate Rotation

Huginn Proxy supports hot reload for TLS certificates:

1. Update certificate files (Secret in Kubernetes, volume in Docker)
2. Proxy detects changes after `watch_delay_secs` (default: 60s)
3. New connections use new certificates
4. Existing connections continue with old certificates until closed

No restart required.

### Certificate Permissions

**Docker:** Certificates must be readable by user `app` (UID 100).

```bash
chmod 400 server.crt server.key
```

**Kubernetes:** Secret volumes are mounted with `defaultMode: 0400` (read-only for owner).

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

## Troubleshooting

Check logs:

```bash
# Docker
docker logs huginn-proxy

# Kubernetes
kubectl logs -f deployment/huginn-proxy
```

Enable debug logging:

```toml
[logging]
level = "debug"
```

Verify health:

```bash
curl http://localhost:9090/health
```

## Next Steps

- Review [TELEMETRY.md](TELEMETRY.md) for metrics documentation
- Check [FEATURES.md](FEATURES.md) for available features
