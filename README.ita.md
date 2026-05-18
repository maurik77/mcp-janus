# MCP Janus

Un proxy MCP conforme a OAuth 2.1 che cripta i token IdP in bearer opachi AES-256-GCM. Singolo binario Go, zero token passthrough.

## Perché Janus?

La [specifica di autorizzazione MCP](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) richiede che i proxy **non inoltrino mai token non emessi per loro stessi**. La maggior parte dei proxy MCP auth passa il JWT dell'IdP così com'è, violando questo requisito e rivelando dettagli dell'identity provider ai client.

Janus risolve questo problema crittografando ogni JWT dell'IdP in un **token bearer opaco** tramite AES-256-GCM prima di consegnarlo al client. Il client non vede, decodifica o replica mai il token reale. Ad ogni richiesta il proxy decripta, valida il JWT e inoltra il token reale upstream.

**Risultato**: piena conformità alla specifica MCP, zero perdita di token, e il server upstream riceve un JWT dell'IdP valido senza integrazioni aggiuntive.

## Funzionalità Principali

### Sicurezza

- **Token opachi crittografati** -- AES-256-GCM (AEAD) avvolge ogni JWT dell'IdP; i client vedono solo testo cifrato
- **Nessun token passthrough** -- il proxy emette i propri token, non inoltra mai i token dei client
- **Validazione JWT** -- validazione completa dei claim (scadenza, audience, issuer) con recupero chiavi JWKS
- **Mappatura claims-to-headers** -- iniezione configurabile dei claim IdP negli header HTTP upstream
- **Credenziali client crittografate** -- la registrazione dinamica restituisce `client_id` / `client_secret` crittografati con AEAD

### Conformità agli Standard

- **OAuth 2.1 + PKCE** -- flusso authorization code con code challenge S256; i client pubblici (senza `client_secret`) sono completamente supportati — PKCE è l'unico meccanismo di autenticazione
- **RFC 7591** -- registrazione dinamica dei client con risposta completa §3.2.1 (echo-back dei metadata, `client_id_issued_at`, `client_secret_expires_at`)
- **RFC 8414** -- Authorization Server Metadata OAuth 2.0 (`.well-known/oauth-authorization-server`)
- **RFC 9728** -- metadata delle risorse protette incluso `bearer_methods_supported: ["header"]`
- **OpenID Connect Discovery** -- endpoint `.well-known/openid-configuration`

### Operatività

- **OpenTelemetry** -- tracing distribuito e metriche business (auth, scambio token, proxy, errori upstream)
- **Docker Compose** -- stack proxy + osservabilità con un solo comando (Jaeger, Prometheus, Grafana)
- **Logging strutturato** -- log JSON, livello configurabile; il livello `debug` emette i dettagli completi del flusso auth inclusi token grezzi, segreti e claim JWT — usare solo per troubleshooting, mai in produzione
- **Shutdown graduale** -- drenaggio pulito delle connessioni su SIGTERM
- **Singolo binario** -- `go build` produce un unico binario statico, nessuna dipendenza runtime
- **Supporto CORS** -- opt-in per client MCP browser (es. MCP Inspector); origini, metodi e header configurabili; le preflight request bypassano il middleware di autenticazione

## Architettura

```text
MCP Client                        MCP Janus Proxy                    Upstream MCP Server
    │                                    │                                    │
    │  Authorization: Bearer <opaque>    │                                    │
    │ ──────────────────────────────────>│                                    │
    │                                    │ 1. Decripta token opaco (AES-GCM)  │
    │                                    │ 2. Valida JWT (exp, aud, iss)      │
    │                                    │ 3. Mappa claims → header HTTP      │
    │                                    │                                    │
    │                                    │  Authorization: Bearer <real JWT>  │
    │                                    │  X-Sub: user123                    │
    │                                    │ ──────────────────────────────────>│
    │                                    │                                    │
    │                                    │◄──────────────────────────────────│
    │◄──────────────────────────────────│                                    │
    │                                    │                                    │

    Il flusso OAuth 2.1 + PKCE (register → authorize → callback → scambio token)
    è gestito tra il client e il proxy, in coordinamento con l'IdP.
```

## Avvio Rapido

### Prerequisiti

- Go 1.24+ (oppure scaricare un [binario di release](https://github.com))
- Un identity provider OAuth 2.1 / OpenID Connect
- [Task](https://taskfile.dev/) runner (opzionale, per comandi rapidi)

### Compilazione e avvio

```bash
git clone https://github.com/user/mcp-janus.git
cd mcp-janus

# Installa dipendenze
go mod download

# Compila
go build -o bin/mcpproxy ./cmd/proxy

# Imposta il client secret dell'IdP (oppure inseriscilo in config.yaml)
export MCP_IDP_CLIENT_SECRET="your-idp-client-secret"

# Avvia
./bin/mcpproxy
```

Oppure usa le scorciatoie Task:

```bash
task install        # go mod download + verify
task build          # compila → ./bin/mcpproxy
task run            # compila + avvia (richiede MCP_IDP_CLIENT_SECRET)
```

### Verifica che sia in esecuzione

```bash
curl http://localhost:8080/health
# OK

curl http://localhost:8080/.well-known/oauth-protected-resource | jq .
```

### Server di test

Il repository include un server MCP meteo fittizio per test locali:

```bash
task build-testserver   # compila → ./bin/mcpserver
task run-testserver     # avvia su :8081
task start-all          # proxy + server di test insieme
```

Consulta [docs/testing-guide.md](docs/testing-guide.md) per la guida completa ai test end-to-end.

## Come Funziona

### Flusso dei token opachi

1. **Registrazione** -- il client chiama `POST /register` con gli URI di redirect. Il proxy restituisce un `client_id` e un `client_secret` crittografati con AEAD, più una risposta completa RFC 7591 §3.2.1 (echo-back dei metadata, `client_id_issued_at`, `client_secret_expires_at`).
2. **Autorizzazione** -- il client effettua il redirect a `GET /auth` con il `code_challenge` PKCE. Il proxy reindirizza verso l'IdP.
3. **Callback** -- l'IdP reindirizza a `GET /callback`. Il proxy riceve il codice di autorizzazione dall'IdP.
4. **Scambio token** -- il client chiama `POST /token` con il `code_verifier`. Il proxy scambia il codice con l'IdP, riceve un JWT reale, lo cripta con AES-256-GCM e restituisce il bearer opaco al client.
5. **Richieste autenticate** -- il client invia `Authorization: Bearer <opaque>` a `GET/POST /mcp/*`. Il proxy decripta, valida il JWT, mappa i claims negli header e inoltra con il token reale.
6. **Refresh** -- il client chiama `POST /refresh` con il refresh token crittografato. Il proxy decripta, effettua il refresh con l'IdP, ri-cripta e restituisce un nuovo bearer opaco.

### Dettaglio crittografia dei token

- **Algoritmo**: AES-256-GCM (AEAD -- crittografia autenticata con dati associati)
- **Processo**: JWT reale → crittografia con chiave master a 256 bit → nonce casuale per operazione → codifica base64url → stringa token opaco
- **Decrittografia**: estrazione bearer → decodifica base64url → decrittografia con chiave master → parsing JWT → validazione claims

### Mappatura dei claims

I claims del JWT dell'IdP vengono mappati ad header HTTP nelle richieste upstream:

```yaml
idp:
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
    upn: X-UPN
```

Il server upstream riceve questi header senza dover comprendere JWT o comunicare con l'IdP.

Per la documentazione dettagliata dell'architettura consulta [docs/design.md](docs/design.md) e [docs/auth-flow.md](docs/auth-flow.md).

## Configurazione

Crea un file `config.yaml` nella directory di lavoro (oppure imposta variabili d'ambiente con prefisso `MCP_`):

```yaml
proxy:
  base_url: http://localhost:8080        # URL canonico di questo proxy
  listen_addr: ":8080"                   # Indirizzo di ascolto
  log_level: info                        # trace|debug|info|warn|error|fatal|panic
  log_format: json                       # json
  cors:
    enabled: false                       # impostare a true per client browser (es. MCP Inspector)
    allowed_origins:
      - http://localhost:6274            # origin predefinita di MCP Inspector

idp:
  client_id: your-idp-client-id         # OAuth client ID presso l'IdP
  client_secret: ""                      # OAuth client secret (usa env var MCP_IDP_CLIENT_SECRET)
  openid_configuration_url: https://auth.example.com/.well-known/openid-configuration
  scopes:
    - openid
    - profile
    - email
  claims_mapping:                        # Claim JWT dell'IdP → header HTTP upstream
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
  jwt_leeway: 10s                        # Tolleranza clock skew per validazione JWT

encryption:
  # Chiave hex a 256 bit. Genera con: openssl rand -hex 32
  master_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

upstream:
  name: my-mcp-server                   # Nome visualizzato dell'upstream
  resource: https://mcp.example.com     # Identificatore risorsa per audience binding
  base_url: https://mcp.example.com     # URL base dell'upstream
  path_prefix: /mcp                     # Prefisso percorso per richieste proxied

telemetry:
  enabled: true                          # Abilita OpenTelemetry
  service_name: mcp-proxy                # Nome servizio in trace/metriche
  service_version: 1.0.0
  otlp_endpoint: localhost:4318          # Endpoint OTLP HTTP
```

Gli override tramite variabili d'ambiente usano il prefisso `MCP_` con underscore per la nidificazione:

```bash
export MCP_IDP_CLIENT_SECRET="your-secret"
export MCP_PROXY_BASE_URL="https://proxy.example.com"
export MCP_ENCRYPTION_MASTER_KEY="$(openssl rand -hex 32)"
export MCP_PROXY_CORS_ENABLED=true          # abilita CORS (configurare le origini in config.yaml)
```

Consulta [.env.example](.env.example) per tutte le variabili supportate.

## Endpoint API

| Metodo | Percorso | Descrizione |
|--------|----------|-------------|
| `GET` | `/.well-known/openid-configuration` | Discovery OpenID Connect |
| `GET` | `/.well-known/oauth-authorization-server` | Metadata authorization server (RFC 8414) |
| `GET` | `/.well-known/oauth-protected-resource` | Metadata risorsa protetta (RFC 9728) |
| `POST` | `/register` | Registrazione dinamica client (RFC 7591) |
| `GET` | `/auth` | Avvio autorizzazione OAuth (con PKCE) |
| `GET` | `/callback` | Callback OAuth dall'IdP |
| `POST` | `/token` | Scambio token (auth code → bearer opaco) |
| `POST` | `/refresh` | Scambio refresh token |
| `GET/POST` | `/mcp/*` | Proxy MCP autenticato verso upstream |
| `GET` | `/health` | Health check (restituisce `OK`) |

### Esempio: registrare un client

```bash
curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"]
  }' | jq .
```

Consulta [docs/testing-guide.md](docs/testing-guide.md) per la sequenza completa di curl (register → auth → token → chiamata proxy).

## Osservabilità

Avvia lo stack completo di osservabilità:

```bash
docker-compose -f docker-compose.observability.yaml up -d
```

Questo lancia Jaeger (trace), Prometheus (metriche), Grafana (dashboard) e l'OpenTelemetry Collector. Il proxy esporta trace e metriche automaticamente quando `telemetry.enabled: true`.

Metriche principali:

- `mcp.proxy.auth.requests.total` -- richieste di autenticazione per risultato
- `mcp.proxy.token.exchange.duration` -- istogramma latenza scambio token
- `mcp.proxy.requests.total` -- richieste proxy per metodo/percorso/stato
- `mcp.proxy.upstream.errors.total` -- contatore errori upstream

Consulta [docs/opentelemetry.md](docs/opentelemetry.md) per dettagli di configurazione, span personalizzati e setup delle dashboard.

## Docker

```bash
# Proxy + server di test
docker-compose up -d

# Stack completo di osservabilità (Jaeger, Prometheus, Grafana, OTel Collector)
docker-compose -f docker-compose.observability.yaml up -d

# Entrambi insieme
docker-compose -f docker-compose.yaml -f docker-compose.observability.yaml up -d
```

## Deployment

Lo script `deploy.sh` compila, etichetta e pubblica l'immagine Docker, aggiorna il file dei valori Helm e rilascia in un unico passaggio:

```bash
export REGISTRY=myregistry.azurecr.io   # obbligatorio
export HELM_NAMESPACE=my-namespace       # opzionale, default "default"
./deploy.sh <versione>                   # es. ./deploy.sh 1.0.21
```

Esegue nell'ordine:

1. `task docker:build` -- compila l'immagine `mcp-janus:latest`
2. Etichetta e pubblica `$REGISTRY/mcp-janus:<versione>`
3. Aggiorna `image.tag` in `deployment/values-dev.yaml`
4. `helm upgrade -i -f deployment/values-dev.yaml mcp-janus ./.helm --namespace $HELM_NAMESPACE`

## Contribuire

1. Effettua il fork del repository e crea un branch per la funzionalità
2. Esegui `task fmt` prima del commit
3. Aggiungi test per le nuove funzionalità (table-driven preferiti)
4. Assicurati che `task test` passi
5. Assicurati che `task lint` passi (se golangci-lint è installato)
6. Apri una pull request con una descrizione chiara

## Riferimenti

### Specifiche MCP

- [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

### Standard OAuth

- [OAuth 2.1 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 7591: Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 8414: Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [MCP Authorization (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)

### Documentazione del Progetto

- [Architettura e Design](docs/design.md)
- [Diagrammi del Flusso Auth](docs/auth-flow.md)
- [Guida ai Test](docs/testing-guide.md)
- [Setup OpenTelemetry](docs/opentelemetry.md)
- [Note sulla Specifica Auth MCP](docs/mcp-auth-notes.md)
