# Canvas OAuth for the HTTP MCP endpoint

With `MCP_AUTH_MODE=canvas`, the public Streamable HTTP endpoint is protected
by OAuth 2.1 and **Canvas is the identity provider**. Each person connecting
from ChatGPT, Claude, or another OAuth-capable MCP client signs in with their
own Canvas account. Every tool call then runs with that person's Canvas token,
so they see and change only what Canvas already lets them.

```
MCP client ──OAuth 2.1 + PKCE──▶ Canvas MCP (FastMCP OAuthProxy) ──OAuth2──▶ Canvas
           ◀── MCP access token ─┘   stores Canvas tokens (encrypted)
tool call ──Bearer MCP token──▶ swap for user's Canvas token ──▶ Canvas API
```

- The MCP client only ever holds a server-issued token. Canvas access and
  refresh tokens never leave the server; they are encrypted at rest with a key
  derived from `MCP_JWT_SIGNING_KEY`.
- When the MCP client refreshes its token, the server refreshes the Canvas
  token as well (Canvas tokens last one hour).
- No shared `CANVAS_API_TOKEN` is used. The server refuses a Canvas call that
  has no signed-in user rather than falling back to a server account.

This replaces the earlier setup, which needed a separate OIDC provider, a
shared `CANVAS_REFRESH_TOKEN`, and `X-Canvas-Token` headers.

## 1. Create a Canvas Developer Key

A Canvas admin creates the key under **Admin → Developer Keys → + Developer
Key → + API Key**:

| Field | Value |
|---|---|
| Key Name | Canvas MCP |
| Redirect URIs | `https://canvas-lms-mcp-server.francoisdisubi.com/auth/callback` |
| Enforce Scopes | Off (simplest). If on, list the same scopes in `CANVAS_OAUTH_SCOPES`. |

Save the key, set its state to **ON**, and copy the **Client ID** (the
numeric ID) and the **Client Secret** (from **Show Key**).

## 2. Configure the server

Set these values in the server's protected `.env` file:

```
MCP_AUTH_MODE=canvas
CANVAS_API_URL=https://canvas.example.edu/api/v1
CANVAS_API_TOKEN=            # leave empty: users sign in with Canvas
MCP_PUBLIC_URL=https://canvas-lms-mcp-server.francoisdisubi.com
CANVAS_OAUTH_CLIENT_ID=...   # Developer Key client ID
CANVAS_OAUTH_CLIENT_SECRET=...
MCP_JWT_SIGNING_KEY=...      # openssl rand -hex 32 — keep it stable
MCP_ALLOWED_CLIENT_REDIRECT_URIS=https://chatgpt.com/connector_platform_oauth_redirect,https://chatgpt.com/connector/oauth/*,http://localhost:*,http://127.0.0.1:*
```

Optional settings:

| Variable | Purpose |
|---|---|
| `CANVAS_BASE_URL` | Canvas origin, if it is not `CANVAS_API_URL` minus `/api/v1` |
| `CANVAS_OAUTH_SCOPES` | Space-separated scopes, when the Developer Key enforces scopes |
| `CANVAS_OAUTH_PURPOSE` | Label shown in Canvas → Account → Settings → Approved Integrations |
| `CANVAS_OAUTH_FORWARD_PKCE` | `true` to forward PKCE to Canvas (only if your instance supports it) |
| `MCP_OAUTH_REDIRECT_PATH` | Callback path (default `/auth/callback`); must match the Developer Key |
| `MCP_REQUIRE_AUTHORIZATION_CONSENT` | Show the consent screen before redirecting to Canvas (default `true`) |

The settings `MCP_OIDC_*`, `CANVAS_REFRESH_TOKEN`, `CANVAS_CLIENT_ID`,
`CANVAS_CLIENT_SECRET`, and `CANVAS_OAUTH_REDIRECT_URI` are no longer read. The
server logs a warning if they are still set.

OAuth state (registered clients and encrypted Canvas tokens) is kept in
FastMCP's data directory, in `oauth-proxy/` under the platform user-data
directory (on Linux `~/.local/share/fastmcp/oauth-proxy`), or under
`FASTMCP_HOME` when set. Persist that directory across deployments so users stay
signed in.

Start the server:

```
canvas-mcp-server --transport streamable-http --host 127.0.0.1 --port 8000
```

## 3. Reverse proxy (Caddy)

Let FastMCP receive the whole public endpoint, including the `/.well-known/*`,
`/register`, `/authorize`, `/token`, `/auth/callback`, and `/consent` routes:

```caddyfile
canvas-lms-mcp-server.francoisdisubi.com {
	reverse_proxy 127.0.0.1:8000 {
		header_up Host {upstream_hostport}
	}
}
```

## 4. Connect a client

Enter this MCP URL in ChatGPT (or `claude mcp add --transport http canvas <url>`):

```
https://canvas-lms-mcp-server.francoisdisubi.com/mcp
```

The client discovers the OAuth metadata, registers itself, and opens a browser
window. After the consent screen, the user is sent to the Canvas login and
"Authorize" page, then returned to the client.

## Revoking access

A user can revoke the integration in **Canvas → Account → Settings → Approved
Integrations**. An admin can turn the Developer Key off to revoke every
token at once. Changing `MCP_JWT_SIGNING_KEY` signs every user out of the MCP
server.

## Local stdio mode

stdio is unchanged: it uses `CANVAS_API_TOKEN` from `.env` (a personal access
token from Canvas → Account → Settings → New Access Token).
