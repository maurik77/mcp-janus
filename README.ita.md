# MCP Janus Proxy Server

Un **server proxy MCP (Model Context Protocol) conforme a OAuth 2.1** sicuro scritto in Go che si posiziona tra i client MCP e i server MCP protetti, gestendo tutte le comunicazioni con robusti controlli di sicurezza.

## 🏛️ Perché Janus?

**Giano** (Janus), l'antico dio romano delle porte, dei cancelli, delle transizioni e dei passaggi, sta eterno con due volti—uno che guarda al passato, l'altro al futuro. Guardiano delle soglie e degli inizi, Giano vigila su tutto ciò che entra ed esce, presiedendo al cambiamento e alla dualità.

Questo proxy incarna lo spirito di Giano:

- **🚪 Guardiano dei Passaggi**: Come Giano sulla soglia, questo proxy monta la guardia tra client e server, controllando il passaggio con vigilanza incrollabile
- **👁️ Visione Bifronte**: Un volto valida le richieste in arrivo dai client, l'altro protegge la comunicazione con i server upstream—vedendo entrambi i mondi simultaneamente
- **🔄 Maestro delle Transizioni**: Trasforma i token dei client in credenziali sicure, mediando il passaggio tra domini di fiducia
- **⚖️ Custode dei Confini**: Fa rispettare il confine sacro tra regni pubblici e protetti, permettendo solo ai degni di passare
- **🌅 Araldo dei Nuovi Inizi**: Ogni richiesta è un nuovo inizio, ogni token un nuovo avvio, gestito con cerimonia crittografica

Proprio come gli antichi Romani invocavano Giano all'inizio di ogni impresa, questo proxy avvia ogni connessione MCP sicura, ergendosi come sentinella eterna al passaggio tra i mondi.

## 🎯 Obiettivo del Progetto

Implementare un proxy sicuro che:

- ✅ Emette **token bearer opachi** ai client MCP (non in passthrough)
- ✅ Implementa i flussi **OAuth 2.0 / OAuth 2.1** con PKCE
- ✅ Utilizza la **crittografia AEAD** (AES-256-GCM) per la sicurezza dei token
- ✅ Applica il **binding dell'audience** e la validazione delle risorse
- ✅ Supporta la **rotazione delle chiavi** con gestione basata su KID
- ✅ Fornisce **logging strutturato** senza esporre segreti

## 📋 Funzionalità

### Sicurezza

- **Nessun Passthrough dei Token**: Il proxy emette i propri token opachi, non inoltra mai i token dei client
- **Crittografia AEAD**: AES-256-GCM per la crittografia dei token opachi
- **Integrazione JWT**: Decripta i token opachi per validare i claim JWT
- **Mappatura dei Claim**: Mappatura configurabile dei claim IdP agli header HTTP
- **Registrazione Dinamica Client**: Credenziali client crittografate con ID client univoci
- **HTTPS Pronto**: Pronto per la produzione con supporto TLS (HTTP per lo sviluppo)

### Conformità OAuth 2.1

- **Authorization Code + PKCE**: Supporto completo per flussi di autorizzazione sicuri
- **Registrazione Dinamica Client**: Registrazione client conforme a RFC 7591
- **Metadata delle Risorse Protette**: Conformità RFC 9728 per il discovery delle risorse
- **Scambio Token**: Scambio sicuro di token con IdP upstream
- **Supporto Refresh Token**: Scambio refresh token implementato (handler HTTP da collegare)

### Architettura

- **Framework Gin**: Router HTTP ad alte prestazioni con supporto middleware
- **Servizi Modulari**: Separazione delle responsabilità con servizi auth, metadata e proxy
- **Configurazione Guidata**: Configurazione basata su YAML con override delle variabili d'ambiente
- **Testabile**: Suite di test completa con mock e test table-driven
- **Pronto per la Produzione**: Shutdown graduale, health check, logging strutturato
- **Integrazione OpenTelemetry**: Tracing distribuito completo e raccolta metriche

## 🏗️ Architettura

```text
┌─────────────┐
│ MCP Client  │ ← Riceve il token bearer opaco
└──────┬──────┘
       │ Authorization: Bearer <opaque>
       ▼
┌─────────────────────────────────┐
│     MCP Proxy Server (Go)       │
│  ┌──────────────────────────┐   │
│  │ Gin HTTP Router          │   │
│  │ - Auth Service           │   │
│  │ - Metadata Service       │   │
│  │ - Encryption Utility     │   │
│  │ - Config Management      │   │
│  └──────────────────────────┘   │
└──────┬─────────────┬────────────┘
       │             │ Authorization: Bearer <upstream>
       │             ▼
       │    ┌─────────────────┐
       │    │ Protected MCP   │
       │    │ Server          │
       │    └─────────────────┘
       │
       │ OAuth 2.1 flow
       ▼
┌──────────────────────┐
│   Identity Provider  │
│  (Server di Autor.)  │
└──────────────────────┘
```

## 🚀 Avvio Rapido

### Prerequisiti

- Go 1.21 o successivo
- Certificati TLS (per produzione)

### Installazione

```bash
git clone <repository-url>
cd mcp-janus
task install
task build
```

### Configurazione

Creare un file `config.yaml` o impostare variabili d'ambiente:

```yaml
proxy:
  base_url: http://localhost:8080
  listen_addr: ":8080"

idp:
  client_id: mcp-proxy-client
  client_secret: your-secret-here
  openid_configuration_url: https://auth.example.com/.well-known/openid-configuration
  scopes: ["openid", "profile", "email"]
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
  jwt_leeway: 10s

encryption:
  master_key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

telemetry:
  enabled: true
  service_name: mcp-proxy
  service_version: 1.0.0
  otlp_endpoint: localhost:4318

upstream:
  name: my-mcp-server
  resource: https://mcp.example.com
  base_url: https://mcp.example.com
  path_prefix: /mcp
```

Override delle variabili d'ambiente:

```bash
export MCP_PROXY_BASE_URL="https://proxy.example.com"
export MCP_IDP_CLIENT_SECRET="your-secret-here"
```

### Logging

Il logging si configura tramite `proxy.log_level` e `proxy.log_format` nel file di configurazione.

```yaml
proxy:
  log_level: info   # trace|debug|info|warn|error|fatal|panic
  log_format: json  # json (formato testuale potrebbe essere aggiunto in seguito)
```

Usare `debug` o `trace` solo in sviluppo, dato che possono essere registrati header e body delle richieste/risposte.

### Esecuzione

```bash
# Sviluppo (HTTP) - usando Task
task run

# Oppure eseguire direttamente con go
go run cmd/proxy/main.go

# Produzione - prima compilare
task build
./bin/mcpproxy
```

### Health Check

```bash
curl http://localhost:8080/health
# OK
```

## 📊 Osservabilità

Il Proxy MCP include un'integrazione completa **OpenTelemetry** per il tracing distribuito e le metriche.

### Avvio Rapido con Osservabilità

```bash
# Avvia lo stack di osservabilità (Jaeger, Prometheus, Grafana, OpenTelemetry Collector)
docker-compose -f docker-compose.observability.yaml up -d

# Avvia il proxy con telemetria abilitata (default)
task run

# Accedi agli strumenti di osservabilità
open http://localhost:16686  # Jaeger - Trace Distribuite
open http://localhost:9090   # Prometheus - Metriche
open http://localhost:3000   # Grafana - Dashboard (admin/admin)
```

### Cosa è Instrumentato

- **Tracing Distribuito**: Tracing HTTP automatico tramite middleware `otelgin` + span personalizzati per flussi auth, operazioni token e inoltro proxy
- **Metriche Business**: Contatori e istogrammi per autenticazione, scambio token, richieste proxy e chiamate upstream
- **Propagazione Contesto**: W3C Trace Context per tracing end-to-end

### Metriche Chiave

- `mcp.proxy.auth.requests.total` - Richieste di autenticazione
- `mcp.proxy.token.exchange.duration` - Latenza scambio token
- `mcp.proxy.requests.total` - Richieste proxy per metodo/percorso/stato
- `mcp.proxy.upstream.errors.total` - Errori upstream

Vedere [Documentazione OpenTelemetry](docs/opentelemetry.md) per configurazione dettagliata e utilizzo.

## 📖 Endpoint API

### Endpoint di Discovery

#### Metadata della Risorsa Protetta (RFC 9728)

```http
GET /.well-known/oauth-protected-resource
```

Restituisce i metadata della risorsa proxy con informazioni sul server di autorizzazione.

#### Configurazione OpenID

```http
GET /.well-known/openid-configuration
```

Restituisce il documento di discovery OpenID Connect.

### Registrazione Dinamica Client

```http
POST /register
Content-Type: application/json

{
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

Risposta: Credenziali client crittografate con `client_id` e `client_secret`.

### Flusso di Autorizzazione OAuth

#### Endpoint di Autorizzazione

```http
GET /auth?response_type=code&client_id=<encrypted_id>&redirect_uri=<uri>&state=<state>&code_challenge=<challenge>&code_challenge_method=S256
```

Avvia l'autorizzazione OAuth con l'IdP upstream.

#### Endpoint di Callback

```http
GET /callback?code=<auth_code>&state=<state>
```

Gestisce il callback OAuth dall'IdP upstream e restituisce il codice di autorizzazione crittografato al client.

#### Endpoint Token

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<encrypted_code>&redirect_uri=<uri>&client_id=<encrypted_id>&client_secret=<secret>&code_verifier=<verifier>
```

Risposta:

```json
{
  "access_token": "<opaque_encrypted_token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<encrypted_refresh_token>",
  "scope": "openid profile email"
}
```

#### Endpoint Refresh Token

```http
POST /refresh
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<encrypted_refresh_token>&client_id=<encrypted_id>&client_secret=<secret>
```

**Nota: Attualmente restituisce 501 Not Implemented.** L'endpoint esiste ed è instradato, ma l'handler HTTP non è ancora collegato al flusso di refresh. Il metodo `RefreshToken` nel servizio auth è implementato, ma l'endpoint deve ancora invocarlo.

### Proxy MCP

```http
GET /mcp/*
Authorization: Bearer <opaque_encrypted_token>
```

Inoltra le richieste autenticate al server MCP upstream con il token reale decrittografato.

## 🔐 Modello di Sicurezza

### Flusso dei Token Opachi

1. **Registrazione Client**: Il client si registra e riceve un `client_id` crittografato contenente gli URI di redirect e un segreto generato
2. **Autorizzazione**: Il client avvia il flusso OAuth, il proxy coordina con l'IdP upstream
3. **Scambio Token**: Il proxy scambia il codice di autorizzazione con l'IdP, riceve token JWT
4. **Crittografia**: Il proxy cripta i token JWT usando AES-256-GCM
5. **Token Opaco**: Il client riceve un token crittografato (opaco per il client, contiene il JWT reale)
6. **Inoltro Richieste**: Il proxy decripta il token, valida il JWT, inietta il token upstream nelle richieste inoltrate

### Struttura del Client ID Crittografato

Il `client_id` restituito durante la registrazione è un payload crittografato contenente:

- URI di redirect
- Segreto client generato
- Metadata di registrazione

Questo garantisce che le credenziali del client siano sicure e a prova di manomissione.

### Crittografia dei Token

**Metodo di Crittografia**: AES-256-GCM (AEAD)

**Processo**:

1. Il token JWT reale dall'IdP viene crittografato con la chiave master
2. Viene generato un nonce per ogni operazione di crittografia
3. Ciphertext + nonce codificato come base64url
4. Il client riceve la stringa del token opaco

**Decrittografia & Validazione**:

1. Estrazione del bearer token dall'header `Authorization`
2. Decrittografia usando la chiave master
3. Parsing e validazione dei claim JWT
4. Mappatura dei claim agli header HTTP secondo la configurazione
5. Inoltro della richiesta con il token reale

### Mappatura dei Claim

Il proxy supporta la mappatura dei claim JWT dell'IdP agli header HTTP per il consumo upstream:

```yaml
idp:
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
    upn: X-UPN
```

### Principi Chiave di Sicurezza

1. **Nessun Passthrough dei Token**: Il client non vede né usa mai i token IdP reali
2. **Archiviazione Crittografata**: Tutti i token sensibili crittografati a riposo e in transito
3. **Validazione JWT**: Validazione JWT completa prima di inoltrare le richieste
4. **Claim Configurabili**: Mappatura flessibile claim-to-header
5. **HTTPS Pronto**: Il deployment di produzione dovrebbe usare TLS
6. **Sicurezza della Chiave Master**: Memorizzare la chiave master in modo sicuro (variabili d'ambiente, secrets manager)

## 🧪 Testing

### Eseguire Tutti i Test

```bash
task test
# oppure
go test ./... -v
```

### Eseguire i Test con Copertura

```bash
task coverage
# Apre il report di copertura HTML nel browser
```

### Eseguire Test di Pacchetti Specifici

```bash
go test ./internal/service/auth/... -v
go test ./internal/utility/... -v
go test ./internal/infrastructure/wire/... -v
```

### Test di Integrazione con il Server di Test

Il progetto include un server MCP di test per il testing end-to-end:

```bash
# Terminale 1: Avviare il server MCP di test
task run-testserver

# Terminale 2: Avviare il proxy
task run

# Terminale 3: Eseguire i test di integrazione
task test-testserver
```

Vedere [Testing Guide](docs/testing-guide.md) per la documentazione dettagliata sui test.

## 📁 Struttura del Progetto

```text
mcp-janus/
├── cmd/
│   ├── proxy/
│   │   └── main.go              # Punto di ingresso del proxy server
│   └── mcpserver/
│       └── main.go              # Server MCP di test
├── internal/
│   ├── infrastructure/
│   │   ├── config/
│   │   │   └── config.go        # Configurazione basata su YAML
│   │   └── wire/
│   │       └── gin.go           # Setup router Gin & handler
│   ├── server/
│   │   └── proxy.go             # Middleware auth & logica proxy
│   ├── service/
│   │   ├── auth/
│   │   │   ├── service.go       # Interfaccia servizio auth
│   │   │   ├── impl.go          # Implementazione auth
│   │   │   └── types.go         # Tipi request/response auth
│   │   └── metadata/
│   │       └── metadata.go      # RFC 9728 & metadata OpenID
│   └── utility/
│       └── encryption.go        # Servizio crittografia AES-GCM
├── docs/
│   ├── mcp-auth-notes.md        # Riassunto specifiche MCP
│   ├── design.md                # Documentazione architettura
│   ├── auth-flow.md             # Diagrammi di flusso
│   └── testing-guide.md         # Documentazione testing
├── config.yaml                  # File di configurazione
├── Taskfile.yaml                # Comandi task runner
├── go.mod
├── go.sum
└── README.md                    # Questo file
```

## 🔧 Sviluppo

### Stile del Codice

Questo progetto segue le convenzioni idiomatiche di Go:

- `gofmt` per la formattazione
- `golangci-lint` per il linting (quando disponibile)
- Test table-driven
- Gestione strutturata degli errori
- Chiara separazione delle responsabilità

### Comandi Task Disponibili

Visualizzare tutti i comandi disponibili:

```bash
task --list
```

Comandi principali:

- `task build` - Compilare il proxy server
- `task run` - Eseguire il proxy in modalità sviluppo
- `task test` - Eseguire tutti i test
- `task coverage` - Generare report di copertura
- `task lint` - Eseguire il linter (se golangci-lint è installato)
- `task fmt` - Formattare il codice
- `task build-testserver` - Compilare il server MCP di test
- `task run-testserver` - Eseguire il server MCP di test
- `task start-all` - Avviare sia proxy che server di test
- `task build-all` - Compilare per piattaforme multiple

### Aggiunta di Nuove Funzionalità

1. Aggiornare la configurazione in `internal/infrastructure/config/config.go`
2. Definire le interfacce dei servizi in `internal/service/*/service.go`
3. Implementare i servizi in `internal/service/*/impl.go`
4. Collegare i servizi in `internal/infrastructure/wire/gin.go`
5. Aggiungere test completi con pattern table-driven
6. Aggiornare la documentazione

### Gestione delle Chiavi di Crittografia

Generare una nuova chiave master:

```bash
# Generare una chiave hex di 32 byte (256-bit)
openssl rand -hex 32
```

Configurare in `config.yaml` o tramite variabile d'ambiente `MCP_ENCRYPTION_MASTER_KEY`.

## 🛡️ Modello delle Minacce

### Protetto Contro

- ✅ Attacchi di passthrough dei token (il proxy emette i propri token)
- ✅ Manomissione dei token (crittografia AEAD con autenticazione)
- ✅ Accesso non autorizzato (OAuth 2.1 con PKCE)
- ✅ Esposizione delle credenziali (ID client e token crittografati)
- ✅ Man-in-the-middle (supporto HTTPS per produzione)
- ✅ Replay dei token (validazione scadenza JWT)

### Best Practice di Sicurezza

- Memorizzare la chiave master di crittografia in modo sicuro (secrets manager, variabili d'ambiente)
- Usare HTTPS in produzione
- Ruotare le chiavi di crittografia periodicamente
- Monitorare e registrare gli eventi di autenticazione
- Mantenere sicure le credenziali IdP
- Audit di sicurezza regolari delle dipendenze

Vedere la documentazione in `docs/` per informazioni dettagliate sulla sicurezza.

## 📚 Riferimenti

### Specifiche MCP

- [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

### Standard OAuth

- [OAuth 2.1 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591: OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)

## 🤝 Contribuire

1. Seguire le best practice di Go e le convenzioni del progetto
2. Usare `task fmt` per formattare il codice prima del commit
3. Aggiungere test per tutte le nuove funzionalità
4. Aggiornare la documentazione secondo necessità
5. Assicurarsi che tutti i test passino: `task test`

## 🙋 Supporto

Per problemi e domande:

- Controllare [docs/](./docs/) per la documentazione dettagliata
- Consultare [Testing Guide](docs/testing-guide.md) per aiuto sui test
- Aprire una issue per bug o richieste di funzionalità

## ✅ Stato di Implementazione

- [x] Modulo Go inizializzato
- [x] Configurazione basata su YAML con override delle variabili d'ambiente
- [x] Crittografia AEAD (AES-256-GCM)
- [x] Generazione token opachi con crittografia JWT
- [x] Registrazione dinamica client con credenziali crittografate
- [x] Flusso authorization code OAuth con PKCE
- [x] Scambio e validazione token
- [x] Inoltro richieste MCP con middleware auth
- [x] Mappatura claim agli header HTTP
- [x] Server HTTP basato su Gin con shutdown graduale
- [x] Suite di test completa
- [x] Documentazione (README, documenti design, diagrammi di flusso)
- [x] Task runner per operazioni comuni
- [x] Server MCP di test per testing di integrazione
- [x] Integrazione OpenTelemetry (tracing distribuito e metriche)
- [x] Stack di osservabilità (Jaeger, Prometheus, Grafana, OpenTelemetry Collector)
- [x] Endpoint refresh token (restituisce 501 Not Implemented)
- [x] Implementazione refresh token (logica del servizio)
- [ ] Rate limiting
- [ ] Specifica OpenAPI
