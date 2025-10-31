# Security Documentation

## Overview

This document explains the security architecture, cryptographic mechanisms, and threat mitigations implemented in the MCP Proxy Server.

## Table of Contents

1. [Opaque Token Cryptography](#opaque-token-cryptography)
2. [Key Rotation](#key-rotation)
3. [Audience Binding](#audience-binding)
4. [Threat Model](#threat-model)
5. [Security Best Practices](#security-best-practices)
6. [Incident Response](#incident-response)

---

## Opaque Token Cryptography

### Design Principle

The proxy **issues its own opaque bearer tokens** to MCP clients. These tokens are **NOT** passthroughs of upstream tokens. This design:

- Prevents token misuse across services
- Enables proxy-level access control
- Maintains audit trails
- Supports key rotation independently

### Token Structure

#### Plaintext Payload

Before encryption, the token payload contains:

```json
{
  "rtid": "reference-to-upstream-credentials",
  "exp": 1698765432,
  "aud": "https://proxy.example.com",
  "scp": ["mcp:read", "mcp:write"],
  "ver": 1,
  "kid": "key-identifier"
}
```

**Fields:**
- `rtid` (string): Internal reference ID that maps to upstream credentials in token store
- `exp` (int64): Unix timestamp for token expiry (default: 15 minutes from issuance)
- `aud` (string): Audience claim - the proxy's canonical URL
- `scp` ([]string): Granted scopes
- `ver` (int): Token format version (for future compatibility)
- `kid` (string): Key ID used for encryption (enables key rotation)

#### Encryption

**Algorithm:** AES-256-GCM (Authenticated Encryption with Associated Data)

**Why AES-GCM?**
- AEAD provides both confidentiality and authenticity
- Detects tampering via authentication tag
- NIST-approved and widely supported
- Constant-time operations resistant to timing attacks

**Process:**

1. **Plaintext**: JSON-marshaled payload
2. **Key**: 256-bit key retrieved by KID
3. **Nonce**: 12-byte random nonce (unique per encryption)
4. **Encryption**: `Seal(plaintext, nonce, additional_data=nil)`
5. **Output**: `ciphertext || tag` (tag is 16 bytes)

#### Encoded Format

```
<base64url(ciphertext)>.<base64url(nonce)>.<base64url(tag)>
```

**Example:**
```
eyJydGlkIjoiYWJjMTIzIiwiZXhwIjoxNjk4NzY1NDMyLCJhdWQiOiJodHRwczovL3Byb3h5LmV4YW1wbGUuY29tIiwic2NwIjpbIm1jcDpyZWFkIiwibWNwOndyaXRlIl0sInZlciI6MSwia2lkIjoiazEyMzQ1Njc4In0.MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.YWJjZGVmZ2hpamtsbW5vcA
```

### Validation Process

1. **Parse**: Split token on `.` delimiter
2. **Decode**: Base64-decode ciphertext, nonce, and tag
3. **Decrypt**: Use AES-GCM with stored key (identified by KID)
4. **Verify Authentication**: GCM automatically verifies tag during decryption
5. **Unmarshal**: Parse JSON payload
6. **Validate Expiry**: Check `exp` claim against current time
7. **Validate Audience**: Verify `aud` matches proxy URL
8. **Retrieve Credentials**: Fetch upstream credentials using `rtid`

**Failure Modes:**
- Invalid format → 401 Unauthorized
- Decryption failure (wrong key or tampered) → 401 Unauthorized
- Expired token → 401 Unauthorized
- Wrong audience → 401 Unauthorized
- RTID not found → 500 Internal Server Error

---

## Key Rotation

### Motivation

Key rotation limits the impact of key compromise:
- Old tokens become invalid after rotation
- Reduces window of vulnerability
- Enables cryptographic agility
- Supports compliance requirements

### Key Identifier (KID)

Each key is identified by a unique KID:
- **Format**: Base64url-encoded random bytes (16 bytes → 22 characters)
- **Generation**: Cryptographically secure random number generator
- **Storage**: Persistent key store (memory, file, or KMS)

### Rotation Process

1. **Generate New Key**:
   ```go
   key := make([]byte, 32) // 256 bits
   rand.Read(key)
   kid := base64url(rand.Read(16))
   ```

2. **Store New Key**:
   ```go
   keyStore.StoreKey(ctx, kid, key)
   ```

3. **Set as Current**:
   ```go
   keyStore.SetCurrentKID(ctx, kid)
   ```

4. **Retain Old Keys**:
   - Old keys remain available for decryption
   - New tokens use new key
   - Old tokens remain valid until expiry

### Key Storage

#### Memory Key Store

- **Use Case**: Development, testing, single-instance deployments
- **Persistence**: None (lost on restart)
- **Security**: Protected by process isolation

#### File Key Store

- **Use Case**: Single-server deployments
- **Persistence**: JSON file with 0600 permissions
- **Security**: OS file permissions, disk encryption recommended

**Format:**
```json
{
  "keys": {
    "kid-abc123": "base64-encoded-key",
    "kid-def456": "base64-encoded-key"
  },
  "current_kid": "kid-def456"
}
```

#### KMS Key Store (Future)

- **Use Case**: Production, multi-instance, compliance
- **Persistence**: Managed by KMS provider
- **Security**: Hardware security modules (HSM), audit logs, IAM policies

### Rotation Schedule

**Recommended:**
- **Automatic Rotation**: Every 30-90 days
- **Manual Rotation**: On suspected compromise
- **Key Retention**: Keep old keys for max token TTL (e.g., 24 hours)

**Implementation:**
```bash
# Manual rotation
go run scripts/rotate-keys.go

# Automated (cron)
0 0 1 * * /usr/local/bin/rotate-keys.sh
```

---

## Audience Binding

### RFC 8707 Resource Indicators

**Purpose:** Explicitly bind tokens to their intended resource (MCP server).

**Client Behavior:**
- Include `resource` parameter in authorization and token requests
- Value: Canonical URI of target MCP server (e.g., `https://mcp.example.com`)

**Server Behavior:**
- Validate `aud` claim in opaque token matches proxy URL
- Reject tokens with wrong audience
- Validate upstream tokens have correct `resource`

### Canonical URI Format

**Valid:**
```
https://proxy.example.com
https://proxy.example.com:8443
https://proxy.example.com/mcp
```

**Invalid:**
```
proxy.example.com              (missing scheme)
https://proxy.example.com#frag (fragment not allowed)
```

### Validation Logic

```go
func (s *OpaqueTokenService) Validate(ctx context.Context, token string) (*Payload, error) {
    payload, err := s.decrypt(token)
    if err != nil {
        return nil, err
    }
    
    if payload.Aud != s.proxyURL {
        return nil, ErrInvalidAudience
    }
    
    if payload.IsExpired() {
        return nil, ErrTokenExpired
    }
    
    return payload, nil
}
```

### Why Audience Binding Matters

**Without audience binding:**
- Tokens can be replayed across services
- Confused deputy attacks become possible
- No clear trust boundaries

**With audience binding:**
- Tokens are service-specific
- Replay attacks limited to intended service
- Clear security boundaries

---

## Threat Model

### Assets

1. **Upstream Credentials**: Access tokens for protected MCP servers
2. **Encryption Keys**: Used to secure opaque tokens
3. **User Data**: Information proxied through the server
4. **Client Credentials**: OAuth client IDs and secrets

### Threat Actors

1. **External Attackers**: Attempting to access protected resources
2. **Malicious Clients**: Compromised or rogue MCP clients
3. **Insider Threats**: Operators with system access

### Attack Vectors & Mitigations

#### 1. Token Passthrough Attack

**Attack:** Client obtains token for Service A, attempts to use at Proxy B.

**Mitigation:**
- ✅ Strict audience validation
- ✅ No token forwarding - proxy issues own tokens
- ✅ Upstream credentials isolated in token store

**Status:** PROTECTED

---

#### 2. Token Replay Attack

**Attack:** Attacker captures token and replays it.

**Mitigation:**
- ✅ Short-lived tokens (15-minute default)
- ✅ Refresh token rotation
- ✅ HTTPS enforcement (prevents capture)

**Residual Risk:** Within token TTL window

**Status:** MITIGATED

---

#### 3. Token Tampering Attack

**Attack:** Attacker modifies token payload (e.g., extend expiry, change scope).

**Mitigation:**
- ✅ AEAD (AES-GCM) provides authenticity
- ✅ Any modification invalidates authentication tag
- ✅ Decryption fails on tampered tokens

**Status:** PROTECTED

---

#### 4. Key Compromise

**Attack:** Attacker obtains encryption key.

**Mitigation:**
- ✅ Key rotation limits exposure window
- ✅ File permissions (0600) for file-based keys
- ✅ KMS option for production
- ✅ No keys in logs or version control

**Residual Risk:** Compromised keys decrypt tokens until expiry

**Recommended:** Rotate immediately on suspicion

**Status:** MITIGATED

---

#### 5. Man-in-the-Middle (MITM)

**Attack:** Attacker intercepts traffic between client and proxy.

**Mitigation:**
- ✅ HTTPS enforcement (TLS 1.2+)
- ✅ Tokens never in URL query strings
- ✅ Strict redirect URI validation

**Residual Risk:** Certificate pinning not implemented

**Status:** MITIGATED

---

#### 6. Session Hijacking

**Attack:** Attacker steals session ID to impersonate user.

**Mitigation:**
- ✅ No session-based authentication
- ✅ Token-based auth only
- ✅ Tokens in Authorization header only

**Status:** PROTECTED

---

#### 7. Authorization Code Interception

**Attack:** Attacker intercepts OAuth authorization code.

**Mitigation:**
- ✅ PKCE (Proof Key for Code Exchange) mandatory
- ✅ Code verifier required for token exchange
- ✅ State parameter validation

**Status:** PROTECTED

---

#### 8. Confused Deputy Attack

**Attack:** Proxy used as intermediary to access unintended resources.

**Mitigation:**
- ✅ Strict audience binding (RFC 8707)
- ✅ No token passthrough
- ✅ Per-client consent for dynamic registration

**Status:** PROTECTED

---

#### 9. Logging Secrets

**Attack:** Secrets exposed in logs, aiding other attacks.

**Mitigation:**
- ✅ Structured logging with explicit field control
- ✅ Only log RTIDs, KIDs, client IDs (never secrets)
- ✅ No token values in logs

**Status:** PROTECTED

---

#### 10. Denial of Service (DoS)

**Attack:** Overwhelm proxy with requests.

**Mitigation:**
- ⚠️ Rate limiting interface defined (not yet implemented)
- ✅ Timeouts on all HTTP operations
- ✅ Graceful shutdown to drain connections

**Status:** PARTIAL (implementation pending)

---

## Security Best Practices

### For Operators

1. **Use HTTPS in Production**
   ```bash
   export TLS_CERT_FILE=/path/to/cert.pem
   export TLS_KEY_FILE=/path/to/key.pem
   ```

2. **Rotate Keys Regularly**
   ```bash
   # Every 30-90 days
   ./scripts/rotate-keys.sh
   ```

3. **Use File or KMS Key Store (Not Memory)**
   ```bash
   export KEY_STORE_TYPE=file
   export KEY_STORE_PATH=/secure/keys.json
   ```

4. **Set Short Token TTLs**
   ```bash
   export OPAQUE_TOKEN_TTL=15m
   ```

5. **Monitor Logs for Anomalies**
   ```bash
   # Look for unusual token validation failures
   grep "token validation failed" /var/log/mcpproxy.log
   ```

6. **Restrict File Permissions**
   ```bash
   chmod 600 /secure/keys.json
   chown proxy:proxy /secure/keys.json
   ```

7. **Enable Structured Logging**
   ```bash
   export LOG_FORMAT=json
   export LOG_LEVEL=info
   ```

### For Developers

1. **Never Log Secrets**
   ```go
   // ✅ Good
   slog.Info("token issued", "rtid", rtid, "expires_in", ttl)
   
   // ❌ Bad
   slog.Info("token issued", "token", tokenValue)
   ```

2. **Always Validate Audience**
   ```go
   if payload.Aud != s.proxyURL {
       return ErrInvalidAudience
   }
   ```

3. **Use Context for Cancellation**
   ```go
   ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
   defer cancel()
   ```

4. **Handle Errors Properly**
   ```go
   if err != nil {
       return fmt.Errorf("failed to encrypt token: %w", err)
   }
   ```

5. **Write Tests for Security-Critical Code**
   ```go
   func TestValidateExpiredToken(t *testing.T) {
       // Test expiry validation
   }
   ```

---

## Incident Response

### Suspected Key Compromise

1. **Immediate Actions:**
   ```bash
   # Rotate keys immediately
   ./scripts/rotate-keys.sh --emergency
   
   # Invalidate all active tokens (requires restart)
   systemctl restart mcpproxy
   ```

2. **Investigation:**
   - Review logs for unauthorized access attempts
   - Check file access logs for key store
   - Audit recent token issuances

3. **Communication:**
   - Notify clients of forced re-authentication
   - Document incident in security log

### Unauthorized Access Detected

1. **Immediate Actions:**
   ```bash
   # Check for tokens with suspicious RTIDs
   grep "RTID" /var/log/mcpproxy.log | grep "unauthorized"
   
   # Revoke specific credentials (future feature)
   ./scripts/revoke-token.sh --rtid <rtid>
   ```

2. **Analysis:**
   - Determine attack vector (replay, stolen token, etc.)
   - Review token validation logs
   - Check for pattern of failures

### DoS Attack

1. **Immediate Actions:**
   ```bash
   # Check connection metrics
   netstat -an | grep :8443 | wc -l
   
   # Implement rate limiting (if not already)
   # Update firewall rules
   ```

2. **Mitigation:**
   - Enable rate limiting
   - Implement request filtering
   - Consider CDN or DDoS protection

---

## Compliance

### Data Protection

- **Encryption at Rest**: Keys stored with OS permissions
- **Encryption in Transit**: HTTPS/TLS for all communication
- **Data Minimization**: Only essential data in tokens
- **Audit Logging**: All authorization decisions logged

### Standards Alignment

- **OAuth 2.1**: IETF draft compliance
- **RFC 8707**: Resource Indicators
- **RFC 9728**: Protected Resource Metadata
- **MCP Spec**: Full compliance with 2025-06-18 version

---

## Security Contacts

**For security issues:**
- Review this document first
- Check logs for error messages
- Open a security-specific issue (not public)
- Contact maintainers directly for sensitive issues

**Emergency Response:**
- Rotate keys immediately if compromise suspected
- Review [Incident Response](#incident-response) section

---

## Version History

- **v1.0 (2025-10-30)**: Initial security documentation
  - Opaque token cryptography
  - Key rotation
  - Audience binding
  - Threat model with 10 attack vectors
