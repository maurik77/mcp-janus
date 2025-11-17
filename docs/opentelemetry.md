# OpenTelemetry Integration for MCP Proxy

This document describes the comprehensive OpenTelemetry observability integration added to the MCP Proxy Server.

## Overview

The MCP Proxy now includes full OpenTelemetry instrumentation for distributed tracing, metrics collection, and observability. This enables monitoring of authentication flows, token exchanges, proxy operations, and upstream service calls.

## Architecture

### Components

1. **Telemetry Initialization** (`internal/infrastructure/telemetry/`)
   - Configures OpenTelemetry SDK with OTLP exporters
   - Sets up tracer and meter providers
   - Manages graceful shutdown

2. **Distributed Tracing**
   - Automatic HTTP request tracing via `otelgin` middleware
   - Custom spans for business operations:
     - Authentication flows
     - Token exchange and validation
     - Proxy forwarding
     - Upstream API calls

3. **Business Metrics**
   - Counters for requests, successes, and failures
   - Histograms for operation durations
   - Custom metrics for MCP-specific operations

## Configuration

Add the following section to your `config.yaml`:

```yaml
telemetry:
  enabled: true                    # Enable/disable OpenTelemetry
  service_name: mcp-proxy          # Service name for traces/metrics
  service_version: 1.0.0           # Service version
  otlp_endpoint: localhost:4318    # OTLP HTTP endpoint
```

### Environment Variables

You can also configure via environment variables:

- `MCP_TELEMETRY_ENABLED` - Enable/disable telemetry (true/false)
- `MCP_TELEMETRY_OTLP_ENDPOINT` - OTLP endpoint (e.g., `localhost:4318`)

## Traces

### Span Hierarchy

``` text
HTTP Request (otelgin middleware)
├─ proxy.AuthMiddleware
│  ├─ Token extraction
│  ├─ Token decryption
│  └─ JWT validation
└─ proxy.ProxyHandler
   └─ Upstream request forwarding

auth.RegisterClient
├─ Client ID generation
└─ Encryption

auth.AuthenticateRequest
├─ Client ID decoding
├─ Redirect URI validation
└─ IdP authorization URL generation

auth.RetrieveAccessToken
├─ Client validation
├─ Token exchange with IdP
└─ Token encryption
```

### Span Attributes

All spans include relevant attributes:

- `http.method`, `http.path`, `http.status_code` - HTTP request details
- `client.id` - OAuth client identifier
- `user.id` - Authenticated user (from JWT sub claim)
- `upstream.name`, `upstream.base_url`, `upstream.target_url` - Upstream service details
- `redirect_uri`, `code_challenge_method` - OAuth flow parameters

### Events

Key events recorded in spans:

- "Token extracted"
- "Token decrypted"
- "JWT validated"
- "Token received from IdP"
- "Forwarding request to upstream"

## Metrics

### Authentication Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `mcp.proxy.auth.requests.total` | Counter | Total authentication requests | `client.id` |
| `mcp.proxy.auth.success.total` | Counter | Successful authentications | `client.id` |
| `mcp.proxy.auth.failure.total` | Counter | Failed authentications | `client.id`, `reason` |
| `mcp.proxy.client.registration.total` | Counter | Client registrations | `success` |

### Token Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `mcp.proxy.token.exchange.total` | Counter | Token exchanges | `success` |
| `mcp.proxy.token.exchange.duration` | Histogram | Token exchange duration (ms) | - |
| `mcp.proxy.token.validation.total` | Counter | Token validations | `success` |
| `mcp.proxy.token.validation.failures.total` | Counter | Validation failures | `reason` |
| `mcp.proxy.token.decryption.failures.total` | Counter | Decryption failures | - |

### Proxy Metrics

| Metric | Type | Description | Labels |
|--------|------|-------------|--------|
| `mcp.proxy.requests.total` | Counter | Total proxy requests | `http.method`, `http.path`, `http.status_code` |
| `mcp.proxy.request.duration` | Histogram | Request duration (ms) | `http.method` |
| `mcp.proxy.errors.total` | Counter | Proxy errors | `error.type` |
| `mcp.proxy.upstream.requests.total` | Counter | Upstream requests | `upstream`, `success` |
| `mcp.proxy.upstream.errors.total` | Counter | Upstream errors | `upstream` |

## Backend Setup

### OpenTelemetry Collector

Deploy an OpenTelemetry Collector to receive traces and metrics:

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
      grpc:
        endpoint: 0.0.0.0:4317

processors:
  batch:

exporters:
  jaeger:
    endpoint: jaeger:14250
    tls:
      insecure: true
  prometheus:
    endpoint: "0.0.0.0:8889"
  logging:
    loglevel: debug

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [jaeger, logging]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [prometheus, logging]
```

Run the collector:

```bash
docker run -p 4318:4318 -p 4317:4317 -p 8889:8889 \
  -v $(pwd)/otel-collector-config.yaml:/etc/otel-collector-config.yaml \
  otel/opentelemetry-collector:latest \
  --config=/etc/otel-collector-config.yaml
```

### Jaeger (for Traces)

```bash
docker run -d --name jaeger \
  -p 16686:16686 \
  -p 14250:14250 \
  jaegertracing/all-in-one:latest
```

Access Jaeger UI at: http://localhost:16686

### Prometheus (for Metrics)

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'otel-collector'
    scrape_interval: 10s
    static_configs:
      - targets: ['localhost:8889']
```

```bash
docker run -d --name prometheus \
  -p 9090:9090 \
  -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml \
  prom/prometheus:latest
```

Access Prometheus at: http://localhost:9090

### Grafana (Visualization)

```bash
docker run -d --name grafana \
  -p 3000:3000 \
  grafana/grafana:latest
```

1. Access Grafana at: http://localhost:3000 (admin/admin)
2. Add Prometheus data source: http://prometheus:9090
3. Add Jaeger data source: http://jaeger:16686
4. Import dashboards or create custom ones

## Production Considerations

### Security

1. **TLS Configuration**: Enable TLS for OTLP endpoints in production:

   ```go
   otlptracehttp.WithTLSClientConfig(&tls.Config{...})
   ```

2. **Authentication**: Use API keys or mutual TLS for collector authentication

3. **Data Sanitization**: The instrumentation avoids logging sensitive data (tokens, secrets)

### Performance

1. **Sampling**: Configure trace sampling in production:

   ```go
   sdktrace.WithSampler(sdktrace.TraceIDRatioBased(0.1)) // 10% sampling
   ```

2. **Batch Processing**: Traces and metrics are batched to reduce overhead
   - Trace batch timeout: 5 seconds
   - Metric export interval: 10 seconds

3. **Resource Limits**: Configure appropriate resource limits in the collector

### High Availability

1. Deploy multiple collector instances behind a load balancer
2. Use persistent storage for metrics (e.g., remote write to Prometheus)
3. Configure appropriate retention policies

## Monitoring Queries

### Example PromQL Queries

```promql
# Request rate by endpoint
rate(mcp_proxy_requests_total[5m])

# Error rate
rate(mcp_proxy_errors_total[5m]) / rate(mcp_proxy_requests_total[5m])

# Token exchange success rate
rate(mcp_proxy_token_exchange_total{success="true"}[5m]) / 
rate(mcp_proxy_token_exchange_total[5m])

# 95th percentile request duration
histogram_quantile(0.95, rate(mcp_proxy_request_duration_bucket[5m]))

# Authentication failures by reason
sum by (reason) (rate(mcp_proxy_auth_failure_total[5m]))
```

### Useful Trace Queries (Jaeger)

- Service: `mcp-proxy`
- Operation: `proxy.AuthMiddleware`, `auth.RetrieveAccessToken`, etc.
- Tags: `http.status_code=401` (find auth failures)
- Tags: `error=true` (find errors)

## Testing

### Verify Telemetry

1. Start the proxy with telemetry enabled
2. Make test requests
3. Check collector logs for received spans/metrics:

   ```bash
   docker logs otel-collector
   ```

### Local Testing

Use the provided Docker Compose for local testing:

```bash
docker-compose up -d jaeger prometheus grafana otel-collector
```

## Troubleshooting

### No traces appearing

1. Check OTLP endpoint is reachable: `telnet localhost 4318`
2. Verify `telemetry.enabled: true` in config
3. Check collector logs for errors
4. Ensure firewall allows OTLP traffic

### High cardinality metrics

Avoid high-cardinality labels (e.g., full URLs, user IDs in labels). Current implementation uses:

- HTTP methods (low cardinality)
- HTTP paths (controlled cardinality)
- Status codes (low cardinality)

### Performance impact

Typical overhead: 1-3% CPU, <50MB memory. If higher:

1. Reduce sampling rate
2. Increase batch intervals
3. Disable metrics if only traces are needed

## References

- [OpenTelemetry Go SDK](https://opentelemetry.io/docs/instrumentation/go/)
- [OTLP Specification](https://opentelemetry.io/docs/specs/otlp/)
- [Semantic Conventions](https://opentelemetry.io/docs/specs/semconv/)
- [MCP Authorization Spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
