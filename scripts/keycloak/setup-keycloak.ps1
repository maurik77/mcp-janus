#Requires -Version 5.1
<#
.SYNOPSIS
    Bootstrap a Keycloak dev realm for MCP Janus testing.

.DESCRIPTION
    Creates the following resources via the Keycloak Admin REST API:
      Realm  : mcp-dev
      Client : mcp-janus  (confidential, standard flow + offline_access)
      User   : testuser / Password123!

    Writes .env.keycloak-dev.ps1 with the generated client secret so you can
    dot-source it before running the proxy:
        . .\.env.keycloak-dev.ps1

    Run from the repository root:
        .\scripts\keycloak\setup-keycloak.ps1

.PARAMETER KcBase
    Keycloak base URL. Default: http://localhost:8888

.PARAMETER KcAdminUser
    Keycloak admin username. Default: admin

.PARAMETER KcAdminPass
    Keycloak admin password. Default: admin

.EXAMPLE
    .\scripts\keycloak\setup-keycloak.ps1
    .\scripts\keycloak\setup-keycloak.ps1 -KcBase http://localhost:9090
#>
param(
    [string]$KcBase      = $env:KC_BASE       ?? "http://localhost:8888",
    [string]$KcAdminUser = $env:KC_ADMIN_USER ?? "admin",
    [string]$KcAdminPass = $env:KC_ADMIN_PASS ?? "admin"
)

$ErrorActionPreference = "Stop"

# ── constants ─────────────────────────────────────────────────────────────────
$Realm       = "mcp-dev"
$ClientId    = "mcp-janus"
$TestUser    = "testuser"
$TestPass    = "Password123!"
$TestEmail   = "testuser@example.com"
$RedirectUri = "http://localhost:8080/callback"
$EnvOut      = ".env.keycloak-dev.ps1"

# ── helpers ───────────────────────────────────────────────────────────────────
function Info([string]$msg)    { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Section([string]$msg) { Write-Host "`n-- $msg " -ForegroundColor Cyan }
function Fail([string]$msg)    { Write-Host "  [FAIL] $msg" -ForegroundColor Red; exit 1 }

function Get-HttpStatusCode($exception) {
    try { return [int]$exception.Exception.Response.StatusCode } catch { return 0 }
}

function Invoke-KcAdmin {
    param(
        [string]$Method,
        [string]$Path,
        [object]$Body = $null,
        [switch]$AllowConflict
    )
    $uri     = "$KcBase/admin$Path"
    $headers = @{ Authorization = "Bearer $script:AdminToken" }
    $params  = @{ Method = $Method; Uri = $uri; Headers = $headers }
    if ($null -ne $Body) {
        $params.Body        = $Body | ConvertTo-Json -Depth 10 -Compress
        $params.ContentType = "application/json"
    }
    try {
        return Invoke-RestMethod @params
    } catch {
        $code = Get-HttpStatusCode $_
        if ($AllowConflict -and $code -eq 409) { return $null }
        $msg = $_.ErrorDetails.Message
        if (-not $msg) { $msg = $_.Exception.Message }
        Fail "Admin API call failed ($Method $Path): $msg"
    }
}

# ── wait for Keycloak ─────────────────────────────────────────────────────────
Section "Waiting for Keycloak at $KcBase"
$maxTries = 30
for ($i = 1; $i -le $maxTries; $i++) {
    try {
        $null = Invoke-WebRequest -Uri "$KcBase/health/ready" -UseBasicParsing -TimeoutSec 5
        Info "Keycloak is ready (attempt $i/$maxTries)"
        break
    } catch {
        if ($i -eq $maxTries) {
            Fail "Keycloak did not become ready after $maxTries attempts.`n  Is it running?  docker compose -f docker-compose.keycloak.yaml up -d"
        }
        Write-Host "  waiting... ($i/$maxTries)"
        Start-Sleep -Seconds 5
    }
}

# ── admin token ───────────────────────────────────────────────────────────────
Section "Authenticating as Keycloak admin"
try {
    $resp = Invoke-RestMethod -Method POST `
        -Uri "$KcBase/realms/master/protocol/openid-connect/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type = "password"
            client_id  = "admin-cli"
            username   = $KcAdminUser
            password   = $KcAdminPass
        }
    $script:AdminToken = $resp.access_token
} catch {
    Fail "Failed to obtain admin token. Check admin credentials: $($_.Exception.Message)"
}
if (-not $script:AdminToken) { Fail "Admin token is empty." }
Info "Admin token obtained"

# ── realm ─────────────────────────────────────────────────────────────────────
Section "Creating realm '$Realm'"
$existingRealms = Invoke-KcAdmin -Method GET -Path "/realms"
if ($existingRealms | Where-Object { $_.realm -eq $Realm }) {
    Info "Realm '$Realm' already exists – skipping"
} else {
    Invoke-KcAdmin -Method POST -Path "/realms" -Body @{
        realm                  = $Realm
        enabled                = $true
        displayName            = "MCP Dev"
        registrationAllowed    = $false
        accessTokenLifespan    = 300
        ssoSessionMaxLifespan  = 86400
    } | Out-Null
    Info "Realm '$Realm' created"
}

# ── client ────────────────────────────────────────────────────────────────────
Section "Creating client '$ClientId'"
$existing = Invoke-KcAdmin -Method GET -Path "/realms/$Realm/clients?clientId=$ClientId"
if ($existing -and $existing.Count -gt 0) {
    $ClientUuid = $existing[0].id
    Info "Client '$ClientId' already exists (uuid: $ClientUuid)"
} else {
    Invoke-KcAdmin -Method POST -Path "/realms/$Realm/clients" -Body @{
        clientId                = $ClientId
        name                    = "MCP Janus Proxy"
        description             = "OAuth 2.1 proxy client for MCP Janus dev testing"
        enabled                 = $true
        publicClient            = $false
        clientAuthenticatorType = "client-secret"
        standardFlowEnabled     = $true
        directAccessGrantsEnabled = $true
        implicitFlowEnabled     = $false
        serviceAccountsEnabled  = $false
        redirectUris            = [string[]]@($RedirectUri)
        webOrigins              = [string[]]@("http://localhost:8080")
        protocol                = "openid-connect"
        defaultClientScopes     = [string[]]@("openid", "profile", "email")
        optionalClientScopes    = [string[]]@("offline_access", "address", "phone")
    } -AllowConflict | Out-Null

    $created = Invoke-KcAdmin -Method GET -Path "/realms/$Realm/clients?clientId=$ClientId"
    $ClientUuid = $created[0].id
    Info "Client '$ClientId' created (uuid: $ClientUuid)"
}

# retrieve client secret
$secretResp   = Invoke-KcAdmin -Method GET -Path "/realms/$Realm/clients/$ClientUuid/client-secret"
$ClientSecret = $secretResp.value
if (-not $ClientSecret) { Fail "Client secret is empty. The client may not be confidential." }
Info "Client secret retrieved"

# ── test user ─────────────────────────────────────────────────────────────────
Section "Creating test user '$TestUser'"
$existingUser = Invoke-KcAdmin -Method GET -Path "/realms/$Realm/users?username=$TestUser&exact=true"
if ($existingUser -and $existingUser.Count -gt 0) {
    $UserUuid = $existingUser[0].id
    Info "User '$TestUser' already exists (uuid: $UserUuid) – resetting password"
} else {
    Invoke-KcAdmin -Method POST -Path "/realms/$Realm/users" -Body @{
        username      = $TestUser
        email         = $TestEmail
        firstName     = "Test"
        lastName      = "User"
        enabled       = $true
        emailVerified = $true
    } -AllowConflict | Out-Null

    $created  = Invoke-KcAdmin -Method GET -Path "/realms/$Realm/users?username=$TestUser&exact=true"
    $UserUuid = $created[0].id
    Info "User '$TestUser' created (uuid: $UserUuid)"
}

# set / reset password
Invoke-KcAdmin -Method PUT -Path "/realms/$Realm/users/$UserUuid/reset-password" -Body @{
    type      = "password"
    value     = $TestPass
    temporary = $false
} | Out-Null
Info "Password set for '$TestUser'"

# ── write env file ────────────────────────────────────────────────────────────
Section "Writing $EnvOut"
@"
# Generated by scripts/keycloak/setup-keycloak.ps1
# Dot-source this file before starting the proxy:
#   . .\.env.keycloak-dev.ps1

`$env:MCP_IDP_CLIENT_SECRET = "$ClientSecret"
`$env:CONFIG_PATH           = "."
`$env:KC_BASE               = "$KcBase"
`$env:KC_REALM              = "$Realm"
`$env:KC_CLIENT_ID          = "$ClientId"
`$env:KC_TEST_USER          = "$TestUser"
`$env:KC_TEST_PASS          = "$TestPass"
"@ | Set-Content -Encoding UTF8 -Path $EnvOut
Info "Written to $EnvOut"

# ── summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  Keycloak dev environment ready" -ForegroundColor Yellow
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  Admin console   : $KcBase"
Write-Host "  Admin login     : $KcAdminUser / $KcAdminPass"
Write-Host "  Realm           : $Realm"
Write-Host "  OIDC discovery  : $KcBase/realms/$Realm/.well-known/openid-configuration"
Write-Host "  Client ID       : $ClientId"
Write-Host "  Client secret   : $ClientSecret"
Write-Host "  Test user       : $TestUser / $TestPass"
Write-Host "  Test user email : $TestEmail"
Write-Host "================================================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host ""
Write-Host "  1. Copy Keycloak config over the default:"
Write-Host "     Copy-Item config.keycloak-dev.yaml config.yaml"
Write-Host ""
Write-Host "  2. Start the MCP test server (new terminal):"
Write-Host "     task run-testserver"
Write-Host ""
Write-Host "  3. Load env vars and start the proxy:"
Write-Host "     . .\.env.keycloak-dev.ps1"
Write-Host "     `$env:CONFIG_PATH = '.'; .\bin\mcpproxy.exe"
Write-Host ""
Write-Host "  4. Verify IdP connection (no browser):"
Write-Host "     . .\.env.keycloak-dev.ps1"
Write-Host "     .\scripts\keycloak\verify-idp.ps1"
Write-Host ""
Write-Host "  5. Run the full end-to-end test:"
Write-Host "     .\scripts\keycloak\test-proxy-flow.ps1"
Write-Host ""
