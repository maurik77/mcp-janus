# mcp-janus Helm Chart

Deploys the **MCP Janus** OAuth 2.1 proxy server on Kubernetes.

MCP Janus sits between MCP clients and protected MCP servers. It manages the full OAuth 2.1 + PKCE authorization flow with an external Identity Provider, issues opaque AES-256-GCM encrypted bearer tokens to clients, and forwards authenticated requests upstream with the real IdP token — the client never sees IdP tokens directly.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.10+
- An OAuth 2.1-capable Identity Provider (Entra ID, Keycloak, Auth0, etc.)
- A Kubernetes Secret containing `MCP_IDP_CLIENT_SECRET` created before install (see [Secrets](#secrets))

## Install

```bash
helm install mcp-janus .helm/ \
  --set proxy.baseUrl=https://mcp.example.com \
  --set idp.clientId=<client-id> \
  --set idp.openidConfigurationUrl=https://login.microsoftonline.com/<tenant>/v2.0/.well-known/openid-configuration \
  --set 'idp.scopes={openid,offline_access,profile}' \
  --set upstream.baseUrl=http://mcp-server:8081 \
  --set upstream.resource=http://mcp-server:8081 \
  --set upstream.name=my-mcp-server \
  --set encryption.masterKey=<64-char-hex-key> \
  --set 'env[0].name=MCP_IDP_CLIENT_SECRET' \
  --set 'env[0].valueFrom.secretKeyRef.name=mcp-janus-secrets' \
  --set 'env[0].valueFrom.secretKeyRef.key=idp-client-secret'
```

Or with a values override file:

```bash
helm install mcp-janus .helm/ -f my-values.yaml
```

## Secrets

The IdP client secret (and optionally the encryption master key) must exist in the cluster before installing the chart. Create the secret manually:

```bash
kubectl create secret generic mcp-janus-secrets \
  --from-literal=idp-client-secret=<your-idp-client-secret>
```

Then reference it in your values:

```yaml
env:
  - name: MCP_IDP_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: mcp-janus-secrets
        key: idp-client-secret
```

## Configuration

| Parameter | Description | Default |
| --- | --- | --- |
| `replicaCount` | Number of pod replicas | `1` |
| `image.repository` | Container image repository | `mcp-proxy` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `service.type` | Kubernetes Service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `proxy.baseUrl` | Externally reachable base URL (used in OAuth redirect URIs) | `http://mcp-janus:8080` |
| `proxy.listenAddr` | Proxy HTTP bind address | `:8080` |
| `proxy.probeAddr` | Liveness/readiness probe bind address | `:2113` |
| `proxy.logLevel` | Log level: `debug`, `info`, `warn`, `error` | `info` |
| `proxy.logFormat` | Log format: `json`, `text` | `json` |
| `proxy.tls` | Enable TLS on the proxy listener | `false` |
| `idp.clientId` | OAuth 2.1 client ID registered with the IdP | `""` |
| `idp.openidConfigurationUrl` | OpenID Connect discovery URL | `""` |
| `idp.jwtLeeway` | Allowed clock skew for JWT validation | `60s` |
| `idp.scopes` | OAuth scopes requested during authorization | `[]` |
| `idp.claimsMapping` | Map of JWT claim → upstream HTTP header | `{}` |
| `encryption.masterKey` | AES-256-GCM master key (hex, 64 chars) | `""` |
| `telemetry.enabled` | Enable OpenTelemetry export | `true` |
| `telemetry.serviceName` | Service name in traces/metrics | `mcp-proxy` |
| `telemetry.serviceVersion` | Service version in traces/metrics | `1.0.0` |
| `telemetry.otlpEndpoint` | OTLP gRPC collector endpoint | `localhost:4317` |
| `upstream.name` | Logical name of the upstream MCP server | `""` |
| `upstream.resource` | OAuth resource identifier of the upstream server | `""` |
| `upstream.baseUrl` | Base URL of the upstream MCP server | `""` |
| `upstream.pathPrefix` | Path prefix for proxied MCP requests | `/mcp` |
| `env` | Extra environment variables (supports `value` and `valueFrom`) | `[]` |

## Kubernetes Probes

The proxy exposes a dedicated probe server on port `2113` (configurable via `proxy.probeAddr`):

| Path | Type | Description |
| --- | --- | --- |
| `/health/live` | Liveness | Returns 200 when the process is running |
| `/health/ready` | Readiness | Returns 200 when the proxy is ready to serve traffic |

## Architecture

```text
MCP Client
    │  opaque bearer token
    ▼
MCP Janus Proxy  (port 8080)
    │  real IdP JWT
    ▼
Upstream MCP Server
```

The proxy never forwards client-issued tokens upstream, and the client never sees real IdP tokens. All issued tokens are AEAD-encrypted blobs.
