# MCP Proxy Server

Un **server proxy MCP (Model Context Protocol) conforme a OAuth 2.1** sicuro scritto in Go che si posiziona tra i client MCP e i server MCP protetti, gestendo tutte le comunicazioni con robusti controlli di sicurezza.

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
- **Nessun Passthrough dei Token**: Il proxy emette i propri token, non inoltra mai i token dei client
- **Crittografia AEAD**: AES-256-GCM per la crittografia dei token opachi
- **Validazione dell'Audience**: Binding rigoroso dell'audience dei token secondo RFC 8707
- **Imposizione HTTPS**: Tutti gli endpoint utilizzano HTTPS (eccetto localhost in sviluppo)
- **Rotazione delle Chiavi**: Supporto per la rotazione delle chiavi crittografiche con tracciamento KID
- **Token a Breve Durata**: TTL configurabile con default di 15 minuti
- **Logging Strutturato**: Logging completo senza esposizione di segreti

### Conformità OAuth 2.1
- **Authorization Code + PKCE**: Richiesto per tutti i flussi di autorizzazione
- **Registrazione Dinamica Client**: Supporto RFC 7591
- **Discovery del Server di Autorizzazione**: Metadata RFC 8414
- **Metadata delle Risorse Protette**: Conformità RFC 9728
- **Indicatori di Risorsa**: RFC 8707 per il binding dei token

### Architettura
- **Go Idiomatico**: Interfacce pulite, gestione degli errori e concorrenza
- **Design Modulare**: Pacchetti separati per crypto, token, OAuth, MCP
- **Testabile**: >80% di copertura dei test con test table-driven
- **Pronto per la Produzione**: Shutdown graduale, health check, pronto per le metriche

## 🏗️ Architettura

```
┌─────────────┐
│ MCP Client  │ ← Riceve il token bearer opaco
└──────┬──────┘
       │ Authorization: Bearer <opaque>
       ▼
┌─────────────────────────────────┐
│     MCP Proxy Server (Go)       │
│  ┌──────────────────────────┐   │
│  │ OAuth Provider           │   │
│  │ Token Store (rtid→creds) │   │
│  │ Crypto Service (AEAD)    │   │
│  │ MCP Client (forwarding)  │   │
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
│ Authorization Server │
└──────────────────────┘
```

## 🚀 Avvio Rapido

### Prerequisiti

- Go 1.21 o successivo
- Certificati TLS (per produzione)

### Installazione

```bash
git clone <repository-url>
cd mcpproxy
go build -o bin/mcpproxy ./cmd/proxy
```

### Configurazione

Impostare le variabili d'ambiente:

```bash
# Obbligatori
export PROXY_URL="https://proxy.example.com"
export UPSTREAM_MCP_URL="https://mcp.example.com"

# Opzionali (con valori predefiniti)
export LISTEN_ADDR=":8443"
export TLS_CERT_FILE="./certs/cert.pem"
export TLS_KEY_FILE="./certs/key.pem"
export OPAQUE_TOKEN_TTL="15m"
export KEY_STORE_TYPE="memory"  # oppure "file", "kms"
export LOG_LEVEL="info"         # debug, info, warn, error
export LOG_FORMAT="json"        # oppure "text"
```

### Esecuzione

```bash
# Sviluppo (HTTP)
./bin/mcpproxy

# Produzione (HTTPS)
export TLS_CERT_FILE=/path/to/cert.pem
export TLS_KEY_FILE=/path/to/key.pem
./bin/mcpproxy
```

### Health Check

```bash
curl http://localhost:8443/health
# {"status":"ok"}
```

## 📖 Endpoint API

### Metadata della Risorsa Protetta (RFC 9728)

```http
GET /.well-known/oauth-protected-resource
```

Risposta:
```json
{
  "resource": "https://proxy.example.com",
  "authorization_servers": ["https://proxy.example.com/auth"],
  "bearer_methods_supported": ["header"]
}
```

### Autorizzazione OAuth

```http
POST /auth/authorize
```

Avvia il flusso OAuth con il server di autorizzazione upstream.

### Callback OAuth

```http
GET /auth/callback?code=<code>&state=<state>
```

Gestisce il callback OAuth e scambia il codice di autorizzazione.

### Endpoint Token

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<code>&redirect_uri=<uri>&client_id=<id>&code_verifier=<verifier>
```

Risposta:
```json
{
  "access_token": "<opaque_token>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<refresh_token>",
  "scope": "mcp:read mcp:write"
}
```

### Proxy MCP

```http
GET /mcp/*
Authorization: Bearer <opaque_token>
```

Inoltra le richieste autenticate al server MCP upstream.

## 🔐 Modello di Sicurezza

### Struttura del Token Opaco

**Payload in Chiaro (prima della crittografia):**
```json
{
  "rtid": "uuid-reference-to-upstream-credentials",
  "exp": 1698765432,
  "aud": "https://proxy.example.com",
  "scp": ["mcp:read", "mcp:write"],
  "ver": 1,
  "kid": "key-id-for-rotation"
}
```

**Formato Token Crittografato:**
```
<base64url(ciphertext)>.<base64url(nonce)>.<base64url(tag)>
```

### Principi Chiave di Sicurezza

1. **Nessun Passthrough dei Token**: Il proxy non inoltra mai i token dei client a upstream
2. **Binding dell'Audience**: Tutti i token sono validati per l'audience corretta
3. **Crittografia AEAD**: AES-256-GCM con autenticazione
4. **Rotazione delle Chiavi**: Supporto per più chiavi attive tramite KID
5. **TTL Brevi**: Durata predefinita del token di 15 minuti
6. **Solo HTTPS**: Tutto il traffico di produzione su TLS

## 🧪 Testing

### Eseguire Tutti i Test

```bash
go test ./... -v
```

### Eseguire i Test con Copertura

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Eseguire Test di Pacchetti Specifici

```bash
go test ./internal/crypto/... -v
go test ./internal/tokens/... -v
go test ./internal/oauth/... -v
```

## 📁 Struttura del Progetto

```
mcpproxy/
├── cmd/
│   └── proxy/
│       └── main.go              # Punto di ingresso
├── internal/
│   ├── config/
│   │   └── config.go            # Gestione della configurazione
│   ├── crypto/
│   │   ├── service.go           # Servizio di crittografia AEAD
│   │   ├── keystore.go          # Gestione delle chiavi
│   │   └── service_test.go      # Test di crittografia
│   ├── oauth/
│   │   └── provider.go          # Flussi OAuth 2.1
│   ├── tokens/
│   │   ├── store.go             # Archiviazione dei token
│   │   ├── opaque.go            # Servizio token opachi
│   │   └── opaque_test.go       # Test dei token
│   └── mcp/
│       └── client.go            # Inoltro MCP
├── pkg/
│   └── http/
│       ├── server.go            # Server HTTP e handler
│       └── middleware.go        # Logging, imposizione HTTPS
├── docs/
│   ├── mcp-auth-notes.md        # Riassunto delle specifiche MCP
│   └── design.md                # Documento di design
├── scripts/
│   ├── gen-keys/
│   │   └── main.go              # Utility di generazione chiavi
│   └── rotate-keys/
│       └── main.go              # Utility di rotazione chiavi
├── go.mod
├── go.sum
├── README.md                    # Questo file
└── SECURITY.md                  # Documentazione sulla sicurezza
```

## 🔧 Sviluppo

### Stile del Codice

Questo progetto segue le convenzioni idiomatiche di Go:

- `gofmt` per la formattazione
- `golangci-lint` per il linting
- Test table-driven
- Errori wrappati con contesto
- Logging strutturato (log/slog)

### Aggiunta di Nuove Funzionalità

1. Definire le interfacce nel pacchetto `internal/` appropriato
2. Implementare con pattern idiomatici Go
3. Aggiungere test completi (copertura >80%)
4. Aggiornare la documentazione
5. Assicurarsi che `golangci-lint` passi

### Gestione delle Chiavi

Generare una nuova chiave di crittografia:

```bash
go run scripts/gen-keys/main.go
# oppure usando Makefile
make gen-keys
```

Ruotare le chiavi:

```bash
go run scripts/rotate-keys/main.go
# oppure usando Makefile
make rotate-keys
```

## 🛡️ Modello delle Minacce

### Protetto Contro

- ✅ Attacchi di passthrough dei token
- ✅ Attacchi di replay dei token (tramite scadenza)
- ✅ Manomissione dei token (tramite autenticazione AEAD)
- ✅ Confusione dell'audience (tramite validazione rigorosa)
- ✅ Man-in-the-middle (tramite imposizione HTTPS)
- ✅ Compromissione delle chiavi (tramite supporto alla rotazione)
- ✅ Session hijacking (tramite autenticazione basata solo su token)

### Vettori di Attacco Mitigati

Vedere [SECURITY.md](./SECURITY.md) per un'analisi dettagliata delle minacce.

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
2. Aggiungere test per tutte le nuove funzionalità
3. Aggiornare la documentazione
4. Assicurarsi che tutti i test passino: `go test ./...`
5. Eseguire il linter: `golangci-lint run`

## 📄 Licenza

[Aggiungere la propria licenza qui]

## 🙋 Supporto

Per problemi e domande:

- Consultare [SECURITY.md](./SECURITY.md) per questioni di sicurezza
- Controllare [docs/](./docs/) per la documentazione dettagliata
- Aprire una issue per bug o richieste di funzionalità

## ✅ Stato di Implementazione

- [x] Modulo Go inizializzato
- [x] Gestione della configurazione (variabili d'ambiente)
- [x] Crittografia AEAD (AES-256-GCM)
- [x] Supporto alla rotazione delle chiavi
- [x] Generazione/validazione token opachi
- [x] Archiviazione token (in-memory + file)
- [x] Interfacce provider OAuth
- [x] Client di inoltro MCP
- [x] Server HTTP con middleware
- [x] Imposizione HTTPS
- [x] Logging strutturato (senza segreti)
- [x] Shutdown graduale
- [x] Test completi (copertura >80%)
- [x] Documentazione (README, SECURITY, design)
- [x] Script di generazione chiavi
- [x] Script di rotazione chiavi
- [ ] Implementazione rate limiting
- [ ] Handler completi del flusso OAuth
- [ ] Specifica OpenAPI
