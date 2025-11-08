@startuml
title MCP Proxy Server – Full Authorization and Communication Flow

actor "MCP Client" as Client
participant "MCP Proxy Server" as Proxy
participant "MCP Server" as MCP
participant "Real Authorization Server" as Auth

== Initial MCP Request ==

Client -> Proxy: GET /mcp/resources
activate Client
activate Proxy
Proxy -> Proxy: Check for Bearer Token
Proxy --> Client: 401 Unauthorized\nWWW-Authenticate: Bearer realm="mcp", resource_metadata="https://proxy.example.com/oauth_protected-resource"
deactivate Proxy

== Discover Protected Resource ==

Client -> Proxy: GET /protected-resource
activate Proxy
Proxy --> Client:
deactivate Proxy
note right
{
  "resource": "https://proxy.example.com/mcp",
  "authorization_servers": ["https://proxy.example.com/authorize"],
  "scopes_supported": ["mcp.read", "mcp.write"]
}
end note

== Dynamic Client Registration ==

Client -> Proxy: POST /register (client_metadata)
note left
{
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
end note
activate Proxy
Proxy -> Proxy:Concat Redirect Uris + create random Secret. Encrypt it -> proxy_client_id. \nSecret -> proxy_client_secret
Proxy --> Client: {proxy_client_id, proxy_client_secret}
note right
     {
      "client_id": "[encrypted info]",
      "client_secret": "cf136dc3c1fc93f31185e5885805d",
      "client_id_issued_at": 2893256800,
      "client_secret_expires_at": 2893276800
     }
end note
deactivate Proxy

== Authorization Request (PKCE) ==

Client -> Proxy: GET /authorize?response_type=code&code_challenge=XYZ&client_id=abc&redirect_uri=https://client/callback
activate Proxy
Proxy -> Client: Redirect /authorize?response_type=code&code_challenge=XYZ&client_id=proxy-client&redirect_uri=https://proxy/callback
deactivate Proxy
Client -> Auth: /authorize?response_type=code&code_challenge=XYZ&client_id=proxy-client&redirect_uri=https://proxy/callback
activate Auth
Auth -> Client: Redirect to proxy with authorization_code=AUTH_CODE
deactivate Auth
Client -> Proxy: Real Auth authorization_code=AUTH_CODE
activate Proxy
Proxy -> Proxy: Encrypt auth code
Proxy -> Client: Proxy authorization_code=crypt(AUTH_CODE)
deactivate Proxy

== Token Exchange ==

Client -> Proxy: POST /token (\n\tproxy authorization_code,\n\tcode_verifier,\n\tproxy client_id, proxy client_secret\n)
activate Proxy
Proxy -> Proxy: Decrypt: \n\tproxy authorization_code\n\tproxy client_id\n\tproxy client_secret
Proxy -> Auth: POST /token (authorization_code, client_secret, code_verifier)
activate Auth
Auth --> Proxy: {access_token, refresh_token, id_token}
deactivate Auth
Proxy -> Proxy: Encrypt {access_token, refresh_token}
Proxy --> Client: {opaque_access_token, opaque_refresh_token}
deactivate Proxy

== Authorized MCP Request ==

Client -> Proxy: GET /mcp/resources\nAuthorization: Bearer opaque_access_token
activate Proxy
Proxy -> Proxy: Decrypt opaque_access_token
Proxy -> MCP: GET /mcp/resources\nAuthorization: Bearer real_access_token
activate MCP
MCP --> Proxy: 200 OK + JSON Data
deactivate MCP
Proxy --> Client: 200 OK + JSON Data
deactivate Proxy
== Token Refresh ==

Client -> Proxy: POST /token\n(grant_type=refresh_token, opaque_refresh_token)
activate Proxy
Proxy -> Proxy: Decrypt opaque_refresh_token
Proxy -> Auth: POST /token\n(grant_type=refresh_token, real_refresh_token)
activate Auth
Auth --> Proxy: {new_access_token, new_refresh_token}
deactivate Auth
Proxy -> Proxy: Encrypt new tokens
Proxy --> Client: {new_opaque_access_token, new_opaque_refresh_token}
deactivate Proxy
deactivate Client
@enduml