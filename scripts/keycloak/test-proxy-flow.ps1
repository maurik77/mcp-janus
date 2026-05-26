#Requires -Version 5.1
<#
.SYNOPSIS
    End-to-end OAuth 2.1 + PKCE flow test for MCP Janus (Windows / PowerShell).

.DESCRIPTION
    Exercises the complete proxy flow without any external dependencies beyond
    PowerShell itself (.NET is used for PKCE crypto and the callback listener):

      1. Health checks    — proxy + MCP test server
      2. PKCE setup       — code_verifier / code_challenge via .NET SHA-256
      3. DCR              — registers an ephemeral client with the proxy (POST /register)
      4. Callback server  — System.Net.HttpListener on port 3000
      5. Auth redirect    — opens browser at GET /auth → Keycloak login page
      6. Code capture     — listener captures the authorization code
      7. Token exchange   — POST /token with code_verifier
      8. MCP tool call    — POST /mcp (tools/list + get_weather)
      9. Token refresh    — POST /refresh

    Prerequisite: dot-source .env.keycloak-dev.ps1 first:
        . .\.env.keycloak-dev.ps1
        .\scripts\keycloak\test-proxy-flow.ps1

    The proxy must be running at http://localhost:8080
    The MCP test server must be running at http://localhost:8081

.PARAMETER Proxy
    Proxy base URL. Default: http://localhost:8080

.PARAMETER CallbackPort
    Local port for the OAuth callback listener. Default: 3000

.PARAMETER McpResource
    Resource indicator passed to the proxy. Default: http://localhost:8081
#>
param(
    [string]$Proxy        = $env:PROXY       ?? "http://localhost:8080",
    [int]   $CallbackPort = 3000,
    [string]$McpResource  = $env:MCP_RESOURCE ?? "http://localhost:8081"
)

$ErrorActionPreference = "Stop"

$CallbackUri = "http://localhost:$CallbackPort/callback"

# ── helpers ───────────────────────────────────────────────────────────────────
function Info([string]$msg)    { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Section([string]$msg) { Write-Host "`n-- $msg " -ForegroundColor Cyan }
function Fail([string]$msg)    { Write-Host "  [FAIL] $msg" -ForegroundColor Red; exit 1 }

function UrlEncode([string]$value) {
    return [System.Uri]::EscapeDataString($value)
}

function Parse-QueryString([string]$qs) {
    $result = @{}
    foreach ($pair in $qs.TrimStart('?').Split('&')) {
        $kv = $pair.Split('=', 2)
        if ($kv.Count -eq 2) {
            $result[[System.Uri]::UnescapeDataString($kv[0])] = `
                [System.Uri]::UnescapeDataString($kv[1].Replace('+', ' '))
        }
    }
    return $result
}

# ── 0. health checks ──────────────────────────────────────────────────────────
Section "Health checks"
try {
    $null = Invoke-WebRequest -Uri "$Proxy/health" -UseBasicParsing -TimeoutSec 5
    Info "Proxy is up at $Proxy"
} catch {
    Fail "Proxy not reachable at $Proxy`n  Start it with: task keycloak-run"
}
try {
    $null = Invoke-WebRequest -Uri "http://localhost:8081/health" -UseBasicParsing -TimeoutSec 5
    Info "MCP test server is up"
} catch {
    Fail "MCP test server not reachable at http://localhost:8081`n  Start it with: task run-testserver"
}

# ── 1. PKCE setup ─────────────────────────────────────────────────────────────
Section "Generating PKCE parameters"
$rng          = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$verifierBytes = [byte[]]::new(40)
$rng.GetBytes($verifierBytes)
$CodeVerifier = [System.Convert]::ToBase64String($verifierBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

$sha256         = [System.Security.Cryptography.SHA256]::Create()
$challengeBytes = $sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($CodeVerifier))
$CodeChallenge  = [System.Convert]::ToBase64String($challengeBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

$stateBytes = [byte[]]::new(8)
$rng.GetBytes($stateBytes)
$State = "test-" + [System.Convert]::ToBase64String($stateBytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')

Info "code_verifier  : $($CodeVerifier.Substring(0,20))..."
Info "code_challenge : $($CodeChallenge.Substring(0,20))..."
Info "state          : $State"

# ── 2. Dynamic client registration ────────────────────────────────────────────
Section "Registering a client with the proxy (RFC 7591 DCR)"
$regBody = @{
    client_name    = "mcp-janus-test-client"
    redirect_uris  = [string[]]@($CallbackUri)
    grant_types    = [string[]]@("authorization_code", "refresh_token")
    response_types = [string[]]@("code")
} | ConvertTo-Json -Compress

try {
    $regResp = Invoke-RestMethod -Method POST -Uri "$Proxy/register" `
        -ContentType "application/json" -Body $regBody
} catch {
    Fail "DCR failed: $($_.ErrorDetails.Message)"
}

$ClientId     = $regResp.client_id
$ClientSecret = $regResp.client_secret
if (-not $ClientId) { Fail "No client_id in DCR response." }
Info "client_id      : $($ClientId.Substring(0,[Math]::Min(30,$ClientId.Length)))..."
Info "client_secret  : $($ClientSecret.Substring(0,[Math]::Min(16,$ClientSecret.Length)))..."

# ── 3. Start callback listener ────────────────────────────────────────────────
Section "Starting callback listener on port $CallbackPort"

$prefix   = "http://localhost:$CallbackPort/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)
try {
    $listener.Start()
} catch {
    Fail "Could not start HTTP listener on port $CallbackPort.`n  Is something else using it?`n  $($_.Exception.Message)"
}
Info "Listener started on $prefix"

# ── 4. Build auth URL and open browser ────────────────────────────────────────
Section "Starting OAuth 2.1 authorization flow"
$authUrl = "$Proxy/auth" +
    "?response_type=code" +
    "&client_id=$(UrlEncode $ClientId)" +
    "&redirect_uri=$(UrlEncode $CallbackUri)" +
    "&state=$State" +
    "&code_challenge=$CodeChallenge" +
    "&code_challenge_method=S256" +
    "&resource=$(UrlEncode $McpResource)"

Write-Host ""
Write-Host "  Opening browser for Keycloak login..." -ForegroundColor White
Write-Host "  User: $($env:KC_TEST_USER ?? 'testuser')   Password: $($env:KC_TEST_PASS ?? 'Password123!')"
Write-Host ""
Write-Host "  If the browser does not open, paste this URL manually:"
Write-Host "  $authUrl" -ForegroundColor DarkGray
Write-Host ""

Start-Process $authUrl

# ── 5. Wait for callback ──────────────────────────────────────────────────────
Write-Host "  Waiting for browser callback (up to 120 s)..." -ForegroundColor White

$contextTask = $listener.GetContextAsync()
if (-not $contextTask.Wait(120000)) {
    $listener.Stop()
    Fail "No callback received within 120 s."
}
$ctx = $contextTask.Result

# Parse query string
$params = Parse-QueryString $ctx.Request.Url.Query

# Send a friendly response to the browser
$html = [System.Text.Encoding]::UTF8.GetBytes(
    '<html><body style="font-family:sans-serif;padding:2em">' +
    '<h2>&#x2714; Authorization complete</h2>' +
    '<p>You can close this window and return to the terminal.</p>' +
    '</body></html>')
$ctx.Response.StatusCode  = 200
$ctx.Response.ContentType = "text/html; charset=utf-8"
$ctx.Response.OutputStream.Write($html, 0, $html.Length)
$ctx.Response.Close()
$listener.Stop()

$AuthCode      = $params['code']
$ReturnedState = $params['state']
if (-not $AuthCode) { Fail "No 'code' in callback. Params: $($params | Out-String)" }
Info "Authorization code received: $($AuthCode.Substring(0,[Math]::Min(20,$AuthCode.Length)))..."
$stateOk = if ($ReturnedState -eq $State) { "OK" } else { "MISMATCH (got: $ReturnedState)" }
Info "State match: $stateOk"

# ── 6. Token exchange ─────────────────────────────────────────────────────────
Section "Exchanging code for tokens (POST /token)"
try {
    $tokenResp = Invoke-RestMethod -Method POST -Uri "$Proxy/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "authorization_code"
            code          = $AuthCode
            client_id     = $ClientId
            client_secret = $ClientSecret
            redirect_uri  = $CallbackUri
            code_verifier = $CodeVerifier
        }
} catch {
    Fail "Token exchange failed: $($_.ErrorDetails.Message)"
}

$AccessToken  = $tokenResp.access_token
$RefreshToken = $tokenResp.refresh_token
if (-not $AccessToken) { Fail "No access_token in response." }
Info "Opaque access token  : $($AccessToken.Substring(0,[Math]::Min(30,$AccessToken.Length)))..."
Info "Opaque refresh token : $($RefreshToken.Substring(0,[Math]::Min(30,$RefreshToken.Length)))..."

# ── 7. MCP tools/list ─────────────────────────────────────────────────────────
Section "Calling MCP proxy endpoint (tools/list)"
$mcpHeaders = @{ Authorization = "Bearer $AccessToken" }
try {
    $listResp = Invoke-RestMethod -Method POST -Uri "$Proxy/mcp" `
        -Headers $mcpHeaders `
        -ContentType "application/json" `
        -Body '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
    Info "MCP response:"
    $listResp | ConvertTo-Json -Depth 10 | Write-Host -ForegroundColor DarkGray
} catch {
    Fail "MCP tools/list call failed.`n  Check proxy logs.`n  $($_.ErrorDetails.Message)"
}

# ── 8. MCP tools/call ─────────────────────────────────────────────────────────
Section "Calling get_weather tool through proxy"
$weatherBody = @{
    jsonrpc = "2.0"
    id      = 2
    method  = "tools/call"
    params  = @{
        name      = "get_weather"
        arguments = @{ city = "Rome"; date = "2025-06-01" }
    }
} | ConvertTo-Json -Depth 5 -Compress

try {
    $weatherResp = Invoke-RestMethod -Method POST -Uri "$Proxy/mcp" `
        -Headers $mcpHeaders `
        -ContentType "application/json" `
        -Body $weatherBody
    Info "Weather response:"
    $weatherResp | ConvertTo-Json -Depth 10 | Write-Host -ForegroundColor DarkGray
} catch {
    Fail "MCP tools/call failed: $($_.ErrorDetails.Message)"
}

# ── 9. Token refresh ──────────────────────────────────────────────────────────
Section "Testing token refresh (POST /refresh)"
try {
    $refreshResp = Invoke-RestMethod -Method POST -Uri "$Proxy/refresh" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "refresh_token"
            refresh_token = $RefreshToken
        }
} catch {
    Fail "Token refresh failed: $($_.ErrorDetails.Message)"
}
$NewAccess = $refreshResp.access_token
if (-not $NewAccess) { Fail "No new access_token in refresh response." }
Info "New access token : $($NewAccess.Substring(0,[Math]::Min(30,$NewAccess.Length)))..."

# ── summary ───────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  [OK] All steps passed — MCP Janus + Keycloak flow works!" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
Write-Host ""
