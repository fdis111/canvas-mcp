"""Per-request Canvas credential resolution.

Two credential sources exist:

* **stdio / unauthenticated HTTP**: the server-wide ``CANVAS_API_TOKEN`` from
  ``.env`` (the caller of ``make_canvas_request`` falls back to it when
  :func:`get_request_credentials` returns ``None``).
* **HTTP with Canvas OAuth** (``MCP_AUTH_MODE=canvas``): every MCP request is
  authenticated by FastMCP's OAuth proxy, which swaps the MCP client's token
  for the user's own Canvas access token.  That token is read from the MCP
  request context, so each tool call acts as the signed-in Canvas user.

When OAuth is required, the server-wide token must never be used as a
fallback; :func:`is_oauth_required` lets callers enforce that.

A ContextVar override is kept for scripts and tests that need to run tool code
with explicit credentials.
"""

from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True)
class RequestCredentials:
    """Canvas API credentials for a single request."""

    api_token: str
    api_url: str


_request_credentials: ContextVar[RequestCredentials | None] = ContextVar(
    "request_credentials", default=None
)

# Set by the server at startup when the HTTP endpoint uses Canvas OAuth.
_oauth_required = False


def set_oauth_required(required: bool) -> None:
    """Declare whether every Canvas call must use a per-user OAuth token."""
    global _oauth_required
    _oauth_required = required


def is_oauth_required() -> bool:
    """Return True when the server-wide Canvas token must not be used."""
    return _oauth_required


def _oauth_token_from_mcp_request() -> str | None:
    """Return the signed-in user's Canvas token for the current MCP request.

    The MCP SDK sets ``request_ctx`` for every message it handles, carrying
    the Starlette request whose ``user`` was populated by the bearer-auth
    middleware.  ``OAuthProxy.load_access_token`` returns the *upstream*
    (Canvas) access token there.  The SDK's ``auth_context_var`` is not used
    because, with stateful sessions, it can hold the value from the request
    that opened the session rather than the current one.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx

        ctx = request_ctx.get()
    except LookupError:
        return None

    request = getattr(ctx, "request", None)
    scope = getattr(request, "scope", None)
    if not isinstance(scope, dict):
        return None

    access_token = getattr(scope.get("user"), "access_token", None)
    token = getattr(access_token, "token", None)
    return token if isinstance(token, str) and token else None


def get_request_credentials() -> RequestCredentials | None:
    """Get the current request's Canvas credentials.

    Returns ``None`` when no per-request credential exists (stdio mode or an
    unauthenticated HTTP endpoint).
    """
    override = _request_credentials.get()
    if override is not None:
        return override

    token = _oauth_token_from_mcp_request()
    if token:
        from .config import get_config

        return RequestCredentials(api_token=token, api_url=get_config().canvas_api_url)
    return None


def resolve_canvas_credentials() -> RequestCredentials | None:
    """Return the credentials a Canvas call should use, or None if there are none.

    Per-request credentials win.  The server-wide ``.env`` token is used only
    when OAuth is not required.
    """
    creds = get_request_credentials()
    if creds is not None:
        return creds
    if is_oauth_required():
        return None

    from .config import get_config

    config = get_config()
    if not config.canvas_api_token:
        return None
    return RequestCredentials(api_token=config.canvas_api_token, api_url=config.canvas_api_url)


def set_request_credentials(creds: RequestCredentials) -> None:
    """Set explicit Canvas credentials for the current async context."""
    _request_credentials.set(creds)


def clear_request_credentials() -> None:
    """Clear explicitly set credentials."""
    _request_credentials.set(None)
