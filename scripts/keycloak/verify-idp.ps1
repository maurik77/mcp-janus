#Requires -Version 5.1
<#
.SYNOPSIS
    Verify Keycloak IdP connectivity for MCP Janus — no browser required.

.DESCRIPTION
    Uses Keycloak's Direct Grant (Resource Owner Password Credentials) to
    obtain a real JWT directly from Keycloak, decodes the token claims, checks
    the JWKS endpoint, and verifies the proxy's OIDC discovery document.

    Useful for quick sanity checks and CI pipelines.

    Prerequisite: dot-source .env.keycloak-dev.ps1 first, or set env vars:
        . .\.env.keycloak-dev.ps1
        .\scripts\keycloak\verify-idp.ps1

.PARAMETER KcBase
    Keycloak base URL. Default: $env:KC_BASE or http://localhost:8888

.PARAMETER KcRealm
    Keycloak realm name. Default: $env:KC_REALM or mcp-dev

.PARAMETER KcClientId
    Client ID. Default: $env:KC_CLIENT_ID or mcp-janus

.PARAMETER KcTestUser
    Test user username. Default: $env:KC_TEST_USER or testuser

.PARAMETER KcTestPass
    Test user password. Default: $env:KC_TEST_PASS or Password123!

.PARAMETER ClientSecret
    Keycloak client secret. Default: $env:MCP_IDP_CLIENT_SECRET

.PARAMETER Proxy
    Proxy base URL. Default: http://localhost:8080
#>
param(
    [string]$KcBase      = $env:KC_BASE               ?? "http://localhost:8888",
    [string]$KcRealm     = $env:KC_REALM              ?? "mcp-dev",
    [string]$KcClientId  = $env:KC_CLIENT_ID          ?? "mcp-janus",
    [string]$KcTestUser  = $env:KC_TEST_USER           ?? "testuser",
    [string]$KcTestPass  = $env:KC_TEST_PASS           ?? "Password123!",
    [string]$ClientSecret = $env:MCP_IDP_CLIENT_SECRET ?? "",
    [string]$Proxy       = $env:PROXY                 ?? "http://localhost:8080"
)

$ErrorActionPreference = "Stop"

# ── helpers ───────────────────────────────────────────────────────────────────
function Info([string]$msg)    { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Section([string]$msg) { Write-Host "`n-- $msg " -ForegroundColor Cyan }
function Warn([string]$msg)    { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Fail([string]$msg)    { Write-Host "  [FAIL] $msg" -ForegroundColor Red; exit 1 }

function Decode-JwtPayload([string]$token) {
    $part   = $token.Split('.')[1]
    # base64url → base64
    $base64 = $part.Replace('-', '+').Replace('_', '/')
    switch ($base64.Length % 4) {
        2 { $base64 += '==' }
        3 { $base64 += '=' }
    }
    $bytes = [System.Convert]::FromBase64String($base64)
    return [System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
}

# ── pre-flight ────────────────────────────────────────────────────────────────
if (-not $ClientSecret) {
    Fail "MCP_IDP_CLIENT_SECRET is not set.`n  Run: . .\.env.keycloak-dev.ps1"
}

$TokenEndpoint = "$KcBase/realms/$KcRealm/protocol/openid-connect/token"

# ── 1. OIDC discovery ─────────────────────────────────────────────────────────
Section "Fetching OIDC discovery document"
try {
    $disco = Invoke-RestMethod -Uri "$KcBase/realms/$KcRealm/.well-known/openid-configuration" -UseBasicParsing
} catch {
    Fail "Cannot reach Keycloak OIDC discovery at $KcBase`n  $($_.Exception.Message)"
}
Info "Issuer       : $($disco.issuer)"
Info "Token URL    : $($disco.token_endpoint)"
Info "JWKS URI     : $($disco.jwks_uri)"

# ── 2. JWKS reachable ─────────────────────────────────────────────────────────
Section "Checking JWKS endpoint"
try {
    $jwks = Invoke-RestMethod -Uri $disco.jwks_uri -UseBasicParsing
} catch {
    Fail "JWKS endpoint unreachable: $($_.Exception.Message)"
}
$keyCount = @($jwks.keys).Count
if ($keyCount -eq 0) { Fail "JWKS response contains no keys." }
Info "JWKS keys    : $keyCount"

# ── 3. Direct grant ───────────────────────────────────────────────────────────
Section "Obtaining token via Direct Grant (password flow)"
Write-Host "  NOTE: Direct access grants must be enabled on the client (setup-keycloak.ps1 does this)."
try {
    $tokenResp = Invoke-RestMethod -Method POST -Uri $TokenEndpoint `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "password"
            client_id     = $KcClientId
            client_secret = $ClientSecret
            username      = $KcTestUser
            password      = $KcTestPass
            scope         = "openid profile email offline_access"
        }
} catch {
    $detail = $_.ErrorDetails.Message
    Fail "Direct grant failed.`n  Is 'Direct access grants' enabled on the client?`n  $detail"
}

$AccessToken  = $tokenResp.access_token
$RefreshToken = $tokenResp.refresh_token
if (-not $AccessToken) { Fail "No access_token in response." }
Info "Access token  (truncated): $($AccessToken.Substring(0, [Math]::Min(40,$AccessToken.Length)))..."
Info "Refresh token (truncated): $($RefreshToken.Substring(0, [Math]::Min(20,$RefreshToken.Length)))..."

# ── 4. Decode JWT claims ──────────────────────────────────────────────────────
Section "Decoded access token claims"
try {
    $claims = Decode-JwtPayload $AccessToken
    $display = [ordered]@{
        sub                = $claims.sub
        preferred_username = $claims.preferred_username
        email              = $claims.email
        name               = $claims.name
        iss                = $claims.iss
        exp                = $claims.exp
        aud                = $claims.aud
    }
    $display.GetEnumerator() | ForEach-Object {
        Write-Host ("  {0,-22}: {1}" -f $_.Key, $_.Value)
    }
} catch {
    Warn "Could not decode JWT payload: $($_.Exception.Message)"
}

# ── 5. Proxy health ───────────────────────────────────────────────────────────
Section "Checking proxy health"
try {
    $null = Invoke-WebRequest -Uri "$Proxy/health" -UseBasicParsing -TimeoutSec 5
    Info "Proxy is reachable at $Proxy"
} catch {
    Warn "Proxy is not running at $Proxy (start it with: task keycloak-run)"
    Write-Host "  IdP verification still passed."
}

# ── 6. Proxy OIDC discovery ───────────────────────────────────────────────────
Section "Proxy OIDC discovery (proxy acting as AS)"
try {
    $proxyDisco = Invoke-RestMethod -Uri "$Proxy/.well-known/openid-configuration" -UseBasicParsing
    Info "Proxy issuer : $($proxyDisco.issuer)"
} catch {
    Warn "Proxy OIDC discovery not available (proxy may not be running)"
}

# ── summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  [OK] Keycloak IdP is correctly configured for MCP Janus" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Realm     : $KcRealm"
Write-Host "  Client    : $KcClientId"
Write-Host "  Test user : $KcTestUser"
Write-Host "  Token URL : $TokenEndpoint"
Write-Host ""
