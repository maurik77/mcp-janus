# MCP Janus

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP Spec](https://img.shields.io/badge/MCP%20spec-2025--06--18-blueviolet)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
[![OAuth](https://img.shields.io/badge/OAuth-2.1%20%2B%20PKCE-orange)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
[![RFC 7591](https://img.shields.io/badge/RFC-7591%20DCR-blue)](https://datatracker.ietf.org/doc/html/rfc7591)

**Un proxy OAuth 2.1 che porta la sicurezza enterprise ai server MCP senza toccare una riga del codice del server.**

---

## Il Problema

La maggior parte dei proxy MCP risolve il problema dell'autenticazione nel modo sbagliato: ricevono il JWT reale dall'authorization server e lo consegnano direttamente al client MCP. Il client può ora decodificarlo, leggere ogni claim, riutilizzarlo contro l'IdP e scoprire i dettagli interni dell'identity provider — una violazione diretta della [specifica di autorizzazione MCP](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), che proibisce esplicitamente l'inoltro di token non emessi per il proxy stesso.

Le conseguenze di sicurezza sono concrete:

- Il client apprende l'URL dell'IdP, il tenant, l'audience e i claim utente
- Un token rubato è riutilizzabile sia contro il proxy **che** contro l'IdP upstream
- Non esiste alcun confine tra "token per il proxy" e "token per tutto il resto"

## Cosa Fa Janus

Janus si posiziona davanti a qualsiasi server MCP ed esegue il flusso completo OAuth 2.1 + PKCE per conto dei client. Dopo lo scambio del codice di autorizzazione con il vero IdP, **cripta il JWT dell'IdP con AES-256-GCM** e consegna al client un blob opaco. Ad ogni richiesta successiva decripta, valida e inoltra il JWT reale upstream — in modo trasparente.

**Il client non vede, decodifica o replica mai il token reale. Zero token passthrough. Piena conformità alla specifica MCP.**

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
```

## A Chi È Rivolto

- **Platform engineer** che deployano server MCP in produzione e hanno bisogno di sicurezza reale
- **Team enterprise** che integrano Claude o ChatGPT con strumenti interni protetti da un IdP (Azure AD B2C, Okta, Keycloak, Auth0)
- **Sviluppatori di server MCP** che vogliono la conformità OAuth 2.1 senza reimplementare l'autenticazione da zero
- **Team di sicurezza** che verificano le integrazioni AI per perdite di token e conformità alle specifiche

---

## Funzionalità Principali

### Sicurezza

- **Token opachi crittografati** — AES-256-GCM (AEAD) avvolge ogni JWT dell'IdP; i client vedono solo testo cifrato
- **Nessun token passthrough** — il proxy emette i propri token, non inoltra mai i token dei client
- **Validazione JWT** — validazione completa dei claim (scadenza, audience, issuer) con JWKS e rotazione automatica delle chiavi
- **Mappatura claims-to-headers** — iniezione configurabile dei claim IdP negli header HTTP upstream
- **Credenziali client crittografate** — la registrazione dinamica restituisce `client_id` / `client_secret` crittografati con AEAD
- **Modalità token self-issued** — Janus può emettere token propri a lunga durata per client MCP come Claude e ChatGPT che non supportano il refresh

### Conformità agli Standard

- **OAuth 2.1 + PKCE** — flusso authorization code con code challenge S256; client pubblici completamente supportati
- **RFC 7591** — registrazione dinamica dei client con risposta completa §3.2.1
- **RFC 8414** — Authorization Server Metadata (`/.well-known/oauth-authorization-server`)
- **RFC 9728** — metadata risorse protette con `bearer_methods_supported: ["header"]`
- **OpenID Connect Discovery** — `/.well-known/openid-configuration`
- **RFC 9207** — parametro `iss` nelle risposte di autorizzazione (protezione da AS mix-up)

### Operatività

- **Singolo binario** — `go build` produce un unico binario statico, zero dipendenze runtime
- **OpenTelemetry** — tracing distribuito e metriche (Jaeger, Prometheus, Grafana pronti all'uso)
- **Docker Compose** — stack proxy + osservabilità completa con un solo comando
- **Logging strutturato** — log JSON, livello configurabile
- **Shutdown graduale** — drenaggio pulito delle connessioni su SIGTERM
- **Supporto CORS** — opt-in per client MCP browser (es. MCP Inspector)

---

## Avvio Rapido

### Opzione A — Test locale con Keycloak (consigliato per il primo avvio)

```bash
git clone https://github.com/maurik77/mcp-janus.git
cd mcp-janus

# Avvia Keycloak + server MCP di test
docker compose -f docker-compose.keycloak.yaml up -d

# Crea realm, client e utente di test — scrive .env.keycloak-dev
./scripts/keycloak/setup-keycloak.sh        # Linux/macOS
# .\scripts\keycloak\setup-keycloak.ps1     # Windows (PowerShell)

# Compila e avvia il proxy
task build
cp config.keycloak-dev.yaml config.yaml
source .env.keycloak-dev && CONFIG_PATH=. ./bin/mcpproxy

# Esegui il test end-to-end completo (apre il browser per il login)
./scripts/keycloak/test-proxy-flow.sh
```

Consulta [docs/guide_keycloak.md](docs/guide_keycloak.md) per la guida completa al setup Keycloak, incluse le istruzioni Windows (PowerShell).

### Opzione B — Usa il tuo IdP

```bash
git clone https://github.com/maurik77/mcp-janus.git
cd mcp-janus

go mod download
go build -o bin/mcpproxy ./cmd/proxy

# Modifica config.yaml con l'URL OIDC discovery del tuo IdP e le credenziali client
export MCP_IDP_CLIENT_SECRET="your-idp-client-secret"
CONFIG_PATH=. ./bin/mcpproxy
```

Oppure usa le scorciatoie [Task](https://taskfile.dev/):

```bash
task install   # go mod download + verify
task build     # compila → ./bin/mcpproxy
task run       # compila + avvia (richiede MCP_IDP_CLIENT_SECRET)
```

### Verifica che sia in esecuzione

```bash
curl http://localhost:8080/health
# OK

curl http://localhost:8080/.well-known/oauth-protected-resource | jq .
```

---

## Come Funziona

### Flusso token opachi standard

1. **Registrazione** — il client chiama `POST /register` con gli URI di redirect. Il proxy restituisce `client_id` e `client_secret` crittografati con AEAD (RFC 7591 §3.2.1).
2. **Autorizzazione** — il client effettua il redirect a `GET /auth` con il `code_challenge` PKCE. Il proxy reindirizza al vero IdP.
3. **Callback** — l'IdP reindirizza a `GET /callback`. Il proxy riceve il codice di autorizzazione.
4. **Scambio token** — il client chiama `POST /token` con il `code_verifier`. Il proxy scambia con l'IdP, riceve il JWT reale, lo cripta con AES-256-GCM e restituisce un bearer opaco al client.
5. **Richieste autenticate** — il client invia `Authorization: Bearer <opaque>` a `/mcp/*`. Il proxy decripta, valida il JWT, mappa i claim negli header e inoltra con il token reale.
6. **Refresh** — il client chiama `POST /refresh` con il refresh token crittografato. Il proxy decripta, effettua il refresh con l'IdP, ri-cripta e restituisce un nuovo bearer opaco.

### Modalità token self-issued (`token_behavior: self_issued`)

Alcuni client MCP (Claude, ChatGPT) completano il flusso OAuth una sola volta e non chiamano mai `/refresh`. Con la modalità predefinita `proxy`, le sessioni scadono alla scadenza del token dell'IdP (tipicamente 1 ora). La modalità `self_issued` risolve questo problema:

1. Dopo lo scambio iniziale con l'IdP, il JWT viene validato **una sola volta** e i claim vengono estratti.
2. Janus emette un token opaco proprio con i **claim mappati cifrati** e una scadenza controllata da Janus (`token_ttl`).
3. Ad ogni richiesta successiva il proxy decripta il token, verifica la scadenza e inietta i claim come header — **nessuna chiamata JWKS, nessun contatto con l'IdP**.
4. Se `/refresh` viene chiamato, viene emesso un nuovo access token dagli stessi claim cifrati fino al limite `token_max_ttl`.

**Trade-off:**

| | `proxy` | `self_issued` |
|---|---|---|
| Durata token | Controllata dall'IdP (es. 1 h) | Controllata da Janus (es. 720 h) |
| Revoca IdP efficace entro | ~1 h | fino a `token_ttl` |
| Chiamata JWKS per richiesta | sì (con cache) | no |
| Freschezza dei claim | ad ogni richiesta | congelati al login |
| Client senza refresh | sessione scade ogni ora | durata intera di `token_ttl` |

### Crittografia dei token

- **Algoritmo**: AES-256-GCM (AEAD — crittografia autenticata con dati associati)
- **Processo**: JWT reale → crittografia con chiave master a 256 bit → nonce casuale per operazione → codifica base64url → stringa opaca
- **Decrittografia**: estrazione bearer → decodifica base64url → decrittografia → parsing JWT → validazione claim

### Mappatura dei claim

I claim del JWT dell'IdP vengono mappati ad header HTTP ad ogni richiesta proxied:

```yaml
idp:
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
    upn: X-UPN
```

Il server MCP upstream riceve header HTTP puliti — nessun parsing JWT, nessuna dipendenza dall'IdP.

---

## Configurazione

Crea `config.yaml` nella directory di lavoro (oppure usa variabili d'ambiente con prefisso `MCP_`):

```yaml
proxy:
  base_url: http://localhost:8080
  listen_addr: ":8080"
  log_level: info                        # trace|debug|info|warn|error
  log_format: json
  cors:
    enabled: false                       # true per client browser (es. MCP Inspector)
    allowed_origins:
      - http://localhost:6274
  token_behavior: proxy                  # proxy (default) | self_issued
  token_ttl: 24h                         # [self_issued] durata di ogni access token
  token_max_ttl: 168h                    # [self_issued] finestra massima dal login originale

idp:
  client_id: your-idp-client-id
  client_secret: ""                      # usa env var MCP_IDP_CLIENT_SECRET
  openid_configuration_url: https://auth.example.com/.well-known/openid-configuration
  scopes:
    - openid
    - profile
    - email
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
  jwt_leeway: 10s

encryption:
  # Genera con: openssl rand -hex 32
  master_key: "your-64-char-hex-key"

upstream:
  name: my-mcp-server
  resource: https://mcp.example.com
  base_url: https://mcp.example.com
  path_prefix: /mcp

telemetry:
  enabled: true
  service_name: mcp-proxy
  otlp_endpoint: localhost:4318
```

Override tramite variabili d'ambiente:

```bash
export MCP_IDP_CLIENT_SECRET="your-secret"
export MCP_PROXY_BASE_URL="https://proxy.example.com"
export MCP_ENCRYPTION_MASTER_KEY="$(openssl rand -hex 32)"
export MCP_PROXY_CORS_ENABLED=true
export MCP_TOKEN_BEHAVIOR=self_issued
export MCP_TOKEN_TTL=720h
```

Consulta [.env.example](.env.example) per la lista completa.

---

## Endpoint API

| Metodo | Percorso | Descrizione |
|--------|----------|-------------|
| `GET` | `/.well-known/openid-configuration` | Discovery OpenID Connect |
| `GET` | `/.well-known/oauth-authorization-server` | Metadata authorization server (RFC 8414) |
| `GET` | `/.well-known/oauth-protected-resource` | Metadata risorsa protetta (RFC 9728) |
| `POST` | `/register` | Registrazione dinamica client (RFC 7591) |
| `GET` | `/auth` | Autorizzazione OAuth con PKCE |
| `GET` | `/callback` | Callback OAuth dall'IdP |
| `POST` | `/token` | Authorization code → bearer opaco |
| `POST` | `/refresh` | Scambio refresh token |
| `GET/POST` | `/mcp/*` | Proxy MCP autenticato |
| `GET` | `/health` | Health check |

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

Consulta [docs/testing-guide.md](docs/testing-guide.md) per la sequenza completa.

---

## Osservabilità

```bash
docker compose -f docker-compose.observability.yaml up -d
```

Avvia Jaeger (trace), Prometheus (metriche), Grafana (dashboard) e l'OpenTelemetry Collector.

Metriche principali:

| Metrica | Descrizione |
|---------|-------------|
| `mcp.proxy.auth.requests.total` | Richieste di autenticazione per risultato |
| `mcp.proxy.token.exchange.duration` | Latenza scambio token |
| `mcp.proxy.requests.total` | Richieste proxy per metodo/percorso/stato |
| `mcp.proxy.upstream.errors.total` | Contatore errori upstream |

Consulta [docs/opentelemetry.md](docs/opentelemetry.md) per il setup delle dashboard.

---

## Docker

```bash
# Proxy + server MCP di test
docker compose up -d

# Stack completo di osservabilità
docker compose -f docker-compose.observability.yaml up -d

# Entrambi insieme
docker compose -f docker-compose.yaml -f docker-compose.observability.yaml up -d

# Ambiente dev Keycloak
docker compose -f docker-compose.keycloak.yaml up -d
```

---

## Deployment

Lo script `deploy.sh` compila, etichetta, pubblica e deploya via Helm in un unico passaggio:

```bash
export REGISTRY=myregistry.azurecr.io
./deploy.sh 1.0.0
```

Passi eseguiti: `docker build` → tag + push al registry → aggiornamento `deployment/values-dev.yaml` → `helm upgrade`.

---

## Contribuire

1. Effettua il fork del repository e crea un branch per la funzionalità
2. Esegui `task fmt` prima del commit
3. Aggiungi test per le nuove funzionalità (table-driven preferiti)
4. Assicurati che `task test` e `task lint` passino
5. Apri una pull request con una descrizione chiara

Per testare con un IdP reale, la [guida setup Keycloak](docs/guide_keycloak.md) ti fornisce un IdP locale in meno di 5 minuti.

---

## Riferimenti

### Specifiche MCP
- [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

### Standard OAuth
- [OAuth 2.1 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 7591: Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 8414: Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9207: AS Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)

### Documentazione del Progetto
- [Architettura e Design](docs/design.md)
- [Diagrammi del Flusso Auth](docs/auth-flow.md)
- [Guida Setup Keycloak](docs/guide_keycloak.md)
- [Guida ai Test](docs/testing-guide.md)
- [Setup OpenTelemetry](docs/opentelemetry.md)
- [Note sulla Specifica Auth MCP](docs/mcp-auth-notes.md)
