# Envoy AVP Authorizer
[![Build Status](https://github.com/robmdunn/envoy-avp-authorizer/workflows/CI/badge.svg)](https://github.com/robmdunn/envoy-avp-authorizer/actions)
[![Release](https://github.com/robmdunn/envoy-avp-authorizer/workflows/Release/badge.svg)](https://github.com/robmdunn/envoy-avp-authorizer/releases)

An external authorization service for [Envoy Proxy](https://www.envoyproxy.io/) using [Amazon Verified Permissions (AVP)](https://aws.amazon.com/verified-permissions/) for policy-based access control.

## Quick Start

### Using Docker

```bash
# Pull the latest image
docker pull ghcr.io/robmdunn/envoy-avp-authorizer:latest

# Run with basic configuration
docker run -p 50051:50051 -p 9000:9000 \
  ghcr.io/robmdunn/envoy-avp-authorizer:latest \
  --policy-store-id your-avp-policy-store-id \
  --jwt-issuer https://your-identity-provider.com \
  --jwks-url https://your-identity-provider.com/.well-known/jwks.json
```

### Using Binary

```bash
# Download the latest binary for your platform
curl -L https://github.com/robmdunn/envoy-avp-authorizer/releases/latest/download/envoy-avp-authorizer-linux-x86_64 -o envoy-avp-authorizer
chmod +x envoy-avp-authorizer

# Run the service
./envoy-avp-authorizer \
  --policy-store-id your-avp-policy-store-id \
  --jwt-issuer https://your-identity-provider.com \
  --jwks-url https://your-identity-provider.com/.well-known/jwks.json
```

## Deployment

### Binary Downloads

Pre-built binaries are available for multiple platforms:

| Platform | Download |
|----------|----------|
| Linux x86_64 | [envoy-avp-authorizer-linux-x86_64](https://github.com/robmdunn/envoy-avp-authorizer/releases/latest/download/envoy-avp-authorizer-linux-x86_64) |
| Linux ARM64 | [envoy-avp-authorizer-linux-aarch64](https://github.com/robmdunn/envoy-avp-authorizer/releases/latest/download/envoy-avp-authorizer-linux-aarch64) |
| macOS Intel | [envoy-avp-authorizer-macos-x86_64](https://github.com/robmdunn/envoy-avp-authorizer/releases/latest/download/envoy-avp-authorizer-macos-x86_64) |
| macOS Apple Silicon | [envoy-avp-authorizer-macos-aarch64](https://github.com/robmdunn/envoy-avp-authorizer/releases/latest/download/envoy-avp-authorizer-macos-aarch64) |


### Building from Source

```bash
# Clone the repository
git clone https://github.com/robmdunn/envoy-avp-authorizer.git
cd envoy-avp-authorizer

# Build with Cargo
cargo build --release
```

## Configuration

### Command Line Options

```bash
envoy-avp-authorizer --help
```

| Option | Environment Variable | Default | Description |
|--------|---------------------|---------|-------------|
| `--policy-store-id` | `AVP_POLICY_STORE_ID` | Required | Amazon Verified Permissions policy store ID |
| `--jwt-issuer` | `AVP_JWT_ISSUER` | Required | JWT token issuer URL |
| `--jwks-url` | `AVP_JWKS_URL` | Required | JWKS endpoint URL for JWT validation |
| `--jwt-audience` | `AVP_JWT_AUDIENCE` | Optional | Expected JWT audience |
| `--region` | `AVP_REGION` | `us-east-1` | AWS region for AVP |
| `--address` | `AVP_LISTEN_ADDRESS` | `0.0.0.0:50051` | gRPC server listen address |
| `--jwks-cache-duration` | `AVP_JWKS_CACHE_DURATION` | `3600` | JWKS cache duration (seconds) |
| `--policy-cache-ttl` | `AVP_POLICY_CACHE_TTL` | `60` | Policy cache TTL (seconds) |
| `--policy-cache-size` | `AVP_POLICY_CACHE_SIZE` | `10000` | Maximum policy cache entries |
| `--api-prefix-pattern` | `AVP_API_PREFIX_PATTERN` | `/api/v*/` | API prefix pattern to strip |
| `--resource-mapping-path` | `AVP_RESOURCE_MAPPING_PATH` | Optional | Path to custom resource mapping config |
| `--log-level` | `AVP_LOG_LEVEL` | `info` | Log level (trace, debug, info, warn, error) |
| `--enable-metrics` | `AVP_ENABLE_METRICS` | `false` | Enable Prometheus metrics server |

### AWS Configuration

The service uses the AWS SDK and supports all standard AWS credential sources:

- **IAM roles**: When running on EC2, ECS, or EKS IRSA or Pod Identity (recommended)
- **Credential processes**: [`oidc-cli`](https://github.com/robmdunn/oidc-cli), etc.
- **Environment variables**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
- **Credential files**: `~/.aws/credentials`

Required IAM permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "verifiedpermissions:IsAuthorizedWithToken"
      ],
      "Resource": "arn:aws:verifiedpermissions::YOUR_ACCOUNT:policy-store/YOUR_POLICY_STORE_ID"
    }
  ]
}
```

### Resource Mapping

The service includes flexible resource mapping to convert HTTP requests to Cedar resources. You can customize this with a JSON configuration file:

```json
{
  "patterns": [
    {
      "pattern": "users/{userId}/documents/{id}",
      "resource_type": "Document",
      "resource_id": "${id}",
      "parents": [
        {
          "parent_type": "User",
          "parent_id": "${userId}"
        }
      ],
      "parameter_groups": {}
    }
  ],
  "action_mappings": [
    {
      "path_pattern": "documents/{id}",
      "mappings": {
        "GET": "read",
        "PUT": "update",
        "DELETE": "delete"
      }
    }
  ]
}
```

## Deployment

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: envoy-avp-authorizer
  labels:
    app: envoy-avp-authorizer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: envoy-avp-authorizer
  template:
    metadata:
      labels:
        app: envoy-avp-authorizer
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "9000"
        prometheus.io/path: "/metrics"
    spec:
      containers:
      - name: envoy-avp-authorizer
        image: ghcr.io/robmdunn/envoy-avp-authorizer:latest
        ports:
        - containerPort: 50051
          name: grpc
        - containerPort: 9000
          name: metrics
        env:
        - name: AVP_POLICY_STORE_ID
          valueFrom:
            secretKeyRef:
              name: avp-config
              key: policy-store-id
        - name: AVP_JWT_ISSUER
          value: "https://your-issuer.com"
        - name: AVP_JWKS_URL
          value: "https://your-issuer.com/.well-known/jwks.json"
        - name: AVP_ENABLE_METRICS
          value: "true"
        - name: AVP_LOG_LEVEL
          value: "info"
        resources:
          requests:
            memory: "64Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        livenessProbe:
          exec:
            command: ["/bin/grpc_health_probe", "-addr=localhost:50051"]
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          exec:
            command: ["/bin/grpc_health_probe", "-addr=localhost:50051"]
          initialDelaySeconds: 5
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: envoy-avp-authorizer
  labels:
    app: envoy-avp-authorizer
spec:
  selector:
    app: envoy-avp-authorizer
  ports:
  - name: grpc
    port: 50051
    targetPort: 50051
  - name: metrics
    port: 9000
    targetPort: 9000
  type: ClusterIP
---
apiVersion: v1
kind: Secret
metadata:
  name: avp-config
type: Opaque
stringData:
  policy-store-id: "your-avp-policy-store-id"
```

### Envoy Configuration

Configure Envoy to use the external authorization service:

```yaml
static_resources:
  listeners:
  - name: listener_0
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 8080
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          stat_prefix: ingress_http
          http_filters:
          - name: envoy.filters.http.ext_authz
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz
              transport_api_version: V3
              grpc_service:
                envoy_grpc:
                  cluster_name: ext_authz
                timeout: 0.25s
              failure_mode_allow: false
              include_peer_certificate: true
          - name: envoy.filters.http.router
            typed_config:
              "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
          route_config:
            name: local_route
            virtual_hosts:
            - name: local_service
              domains: ["*"]
              routes:
              - match:
                  prefix: "/"
                route:
                  cluster: backend_service
  clusters:
  - name: ext_authz
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    typed_extension_protocol_options:
      envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
        "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
        explicit_http_config:
          http2_protocol_options: {}
    load_assignment:
      cluster_name: ext_authz
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: envoy-avp-authorizer.default.svc.cluster.local
                port_value: 50051
  - name: backend_service
    type: STRICT_DNS
    lb_policy: ROUND_ROBIN
    load_assignment:
      cluster_name: backend_service
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: your-backend-service
                port_value: 8080
```

### Istio Deployment

See: [Istio Deployment Example](examples/istio/istio.md)

## Monitoring

### Metrics

When `--enable-metrics` is set, Prometheus metrics are available at `:9000/metrics`:

- `avp_requests_total` - Total authorization requests by method, path, and status
- `check_request_duration_seconds` - Request duration histogram
- `jwt_validation_total` - JWT validation attempts
- `jwt_validation_failures` - JWT validation failures
- `avp_cache_hits_total` - Cache hit counter
- `avp_cache_misses_total` - Cache miss counter
- `avp_request_duration_seconds` - AVP API request duration
- `jwks_refresh_total` - JWKS refresh attempts
- `jwks_refresh_failures` - JWKS refresh failures

### Logging

The service uses structured logging with the following levels:

- `TRACE`: Very detailed debugging
- `DEBUG`: General debugging information
- `INFO`: General operational messages (default)
- `WARN`: Warning conditions (including denials)
- `ERROR`: Error conditions

### Health Checks

The service implements gRPC health checks on the same port as the main service:

```bash
# Check health using grpc_health_probe
grpc_health_probe -addr=localhost:50051

# Or using grpcurl
grpcurl -plaintext localhost:50051 grpc.health.v1.Health/Check
```

## Development

### Prerequisites

- Rust (`rustup install stable`)
- Docker (for containerized testing)
- AWS CLI (for development testing)

### Building

```bash
# Development build
cargo build

# Release build
cargo build --release
``` 

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
