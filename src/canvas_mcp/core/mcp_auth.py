"""Canvas OAuth2 authentication for the streamable HTTP MCP endpoint.

MCP clients (ChatGPT, Claude, ...) run a standard OAuth 2.1 flow against this
server.  FastMCP's ``OAuthProxy`` handles Dynamic Client Registration and
PKCE locally, sends the human to Canvas's ``/login/oauth2/auth`` page, and
exchanges the Canvas authorization code for a Canvas access + refresh token.
Those Canvas tokens are stored encrypted server-side; the MCP client only ever
holds a FastMCP-issued reference token.  When the MCP client refreshes, the
proxy refreshes the Canvas token too.

On every MCP request the proxy swaps the client's token for the user's Canvas
token and validates it with :class:`CanvasTokenVerifier`.  Tools then call
Canvas with that token (see ``core.credentials``).
"""

import hashlib
import time
from dataclasses import dataclass
from typing import Any

import httpx
from fastmcp.server.auth import TokenVerifier
from fastmcp.server.auth.auth import AccessToken
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions

from .config import Config
from .logging import log_debug, log_warning

# Canvas only accepts client credentials in the token request body.
CANVAS_TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_post"


@dataclass(frozen=True)
class MCPAuthentication:
    """The SDK settings, OAuth provider, and extra OAuth callback routes."""

    settings: AuthSettings
    provider: Any
    extra_route_paths: frozenset[str]


class CanvasTokenVerifier(TokenVerifier):
    """Validate opaque Canvas access tokens by calling ``/users/self``.

    Canvas tokens are not JWTs, so the only way to check one is to use it.
    Successful results are cached briefly so each MCP message does not cost an
    extra Canvas request.
    """

    _MAX_CACHE_ENTRIES = 1024

    def __init__(
        self,
        *,
        api_url: str,
        required_scopes: list[str] | None = None,
        timeout_seconds: int = 10,
        cache_ttl_seconds: int = 60,
    ) -> None:
        super().__init__(required_scopes=required_scopes)
        self.api_url = api_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: dict[str, tuple[float, AccessToken]] = {}

    @staticmethod
    def _cache_key(token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _prune_cache(self, now: float) -> None:
        if len(self._cache) < self._MAX_CACHE_ENTRIES:
            return
        for key in [k for k, (expiry, _) in self._cache.items() if expiry <= now]:
            del self._cache[key]
        if len(self._cache) >= self._MAX_CACHE_ENTRIES:
            self._cache.clear()

    async def verify_token(self, token: str) -> AccessToken | None:
        """Return access info for a valid Canvas token, or None."""
        if not token:
            return None

        key = self._cache_key(token)
        now = time.monotonic()
        cached = self._cache.get(key)
        if cached is not None:
            expiry, access_token = cached
            if expiry > now:
                return access_token
            del self._cache[key]

        try:
            async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
                response = await client.get(
                    f"{self.api_url}/users/self",
                    headers={"Authorization": f"Bearer {token}"},
                )
        except httpx.HTTPError as exc:
            log_warning(
                "Canvas token verification request failed",
                error_type=type(exc).__name__,
            )
            return None

        if response.status_code != 200:
            log_debug(f"Canvas token verification failed: HTTP {response.status_code}")
            return None

        try:
            user = response.json()
        except ValueError:
            return None
        user_id = user.get("id") if isinstance(user, dict) else None
        if user_id is None:
            return None

        access_token = AccessToken(
            token=token,
            client_id=str(user_id),
            # Canvas does not report a token's scopes; it enforces them on
            # every API call.  A token that works was granted what we asked for.
            scopes=list(self.required_scopes or []),
            expires_at=None,
            claims={"sub": str(user_id), "name": user.get("name")},
        )
        if self.cache_ttl_seconds > 0:
            self._prune_cache(now)
            self._cache[key] = (now + self.cache_ttl_seconds, access_token)
        return access_token


def create_oauth_storage(jwt_signing_key: str) -> Any:
    """Create OAuthProxy's encrypted disk store, tolerant of stale entries.

    This matches FastMCP's default store (same directory and key derivation,
    so existing data stays readable), with one difference: a record that can
    no longer be decrypted, for example after ``MCP_JWT_SIGNING_KEY``
    changed, is treated as missing instead of raising.  A client holding a
    stale registration then gets ``invalid_client`` and registers again,
    rather than an HTTP 500.
    """
    from cryptography.fernet import Fernet
    from fastmcp import settings as fastmcp_settings
    from fastmcp.server.auth.jwt_issuer import derive_jwt_key
    from key_value.aio.stores.disk import DiskStore
    from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

    signing_key = derive_jwt_key(
        low_entropy_material=jwt_signing_key, salt="fastmcp-jwt-signing-key"
    )
    storage_key = derive_jwt_key(
        high_entropy_material=signing_key.decode(),
        salt="fastmcp-storage-encryption-key",
    )
    return FernetEncryptionWrapper(
        key_value=DiskStore(directory=fastmcp_settings.home / "oauth-proxy"),
        fernet=Fernet(key=storage_key),
        raise_on_decryption_error=False,
    )


def create_mcp_auth_provider(config: Config) -> MCPAuthentication | None:
    """Create the Canvas OAuth proxy, or None when authentication is disabled."""
    if config.mcp_auth_mode == "none":
        return None

    if config.mcp_auth_mode != "canvas":
        raise ValueError(f"Unsupported MCP_AUTH_MODE: {config.mcp_auth_mode}")

    from fastmcp.server.auth.oauth_proxy import OAuthProxy

    scopes = config.canvas_oauth_scopes or None
    verifier = CanvasTokenVerifier(
        api_url=config.canvas_api_url,
        required_scopes=scopes,
        timeout_seconds=config.api_timeout,
    )

    extra_authorize_params: dict[str, str] = {}
    if config.canvas_oauth_purpose:
        # Shown to the user in Canvas > Account > Settings > Approved Integrations.
        extra_authorize_params["purpose"] = config.canvas_oauth_purpose

    provider = OAuthProxy(
        upstream_authorization_endpoint=f"{config.canvas_base_url}/login/oauth2/auth",
        upstream_token_endpoint=f"{config.canvas_base_url}/login/oauth2/token",
        upstream_client_id=config.canvas_oauth_client_id,
        upstream_client_secret=config.canvas_oauth_client_secret,
        token_verifier=verifier,
        base_url=config.mcp_public_url,
        issuer_url=config.mcp_public_url,
        redirect_path=config.mcp_oauth_redirect_path or None,
        allowed_client_redirect_uris=config.mcp_allowed_client_redirect_uris,
        valid_scopes=scopes,
        forward_pkce=config.canvas_oauth_forward_pkce,
        token_endpoint_auth_method=CANVAS_TOKEN_ENDPOINT_AUTH_METHOD,
        extra_authorize_params=extra_authorize_params or None,
        client_storage=create_oauth_storage(config.mcp_jwt_signing_key),
        jwt_signing_key=config.mcp_jwt_signing_key,
        require_authorization_consent=config.mcp_require_authorization_consent,
    )

    # The repository uses the MCP SDK's FastMCP implementation.  It supplies
    # the standard OAuth and protected-resource routes when given these
    # settings; OAuthProxy supplies the Canvas login and token storage.
    settings = AuthSettings(
        issuer_url=config.mcp_public_url,
        resource_server_url=f"{config.mcp_public_url}/mcp",
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=scopes,
        ),
        required_scopes=scopes,
    )
    return MCPAuthentication(
        settings=settings,
        provider=provider,
        extra_route_paths=frozenset({config.mcp_oauth_redirect_path, "/consent"}),
    )


def register_mcp_auth_routes(mcp: Any, authentication: MCPAuthentication) -> None:
    """Register OAuthProxy's Canvas callback and consent routes on the MCP app."""
    for route in authentication.provider.get_routes("/mcp"):
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        endpoint = getattr(route, "endpoint", None)
        if (
            path in authentication.extra_route_paths
            and methods is not None
            and endpoint is not None
        ):
            mcp.custom_route(path, methods=list(methods))(endpoint)
