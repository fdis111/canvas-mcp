"""Tests for Canvas OAuth authentication of the HTTP MCP endpoint."""

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from canvas_mcp.core import config as config_module
from canvas_mcp.core.config import Config
from canvas_mcp.core.credentials import (
    clear_request_credentials,
    get_request_credentials,
    resolve_canvas_credentials,
    set_oauth_required,
)
from canvas_mcp.core.mcp_auth import CanvasTokenVerifier, create_mcp_auth_provider

CANVAS_OAUTH_ENV = {
    "MCP_AUTH_MODE": "canvas",
    "CANVAS_API_URL": "https://school.instructure.com/api/v1",
    "CANVAS_API_TOKEN": "",
    # Pin values a developer's .env might otherwise supply.
    "CANVAS_BASE_URL": "",
    "CANVAS_OAUTH_SCOPES": "",
    "CANVAS_OAUTH_PURPOSE": "Canvas MCP",
    "MCP_OAUTH_REDIRECT_PATH": "/auth/callback",
    "MCP_PUBLIC_URL": "https://mcp.example.com",
    "CANVAS_OAUTH_CLIENT_ID": "10000000000001",
    "CANVAS_OAUTH_CLIENT_SECRET": "developer-key-secret",
    "MCP_JWT_SIGNING_KEY": "independent-signing-key",
    "MCP_ALLOWED_CLIENT_REDIRECT_URIS": "https://chatgpt.com/connector_platform_oauth_redirect,http://localhost:*",
}


@pytest.fixture
def canvas_env():
    """Install a fresh Config built from the given environment overrides."""
    previous = config_module._config

    def apply(overrides: dict[str, str]):
        patcher = patch.dict(os.environ, overrides, clear=False)
        patcher.start()
        apply.patchers.append(patcher)
        config_module._config = Config()
        return config_module._config

    apply.patchers = []
    yield apply
    for patcher in apply.patchers:
        patcher.stop()
    config_module._config = previous


@pytest.fixture(autouse=True)
def reset_oauth_state():
    clear_request_credentials()
    set_oauth_required(False)
    yield
    clear_request_credentials()
    set_oauth_required(False)


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


def test_canvas_oauth_config_is_valid(canvas_env):
    canvas_env(CANVAS_OAUTH_ENV)
    assert config_module.validate_http_auth_config() is True


def test_canvas_oauth_config_does_not_need_server_token(canvas_env):
    config = canvas_env(CANVAS_OAUTH_ENV)
    assert config.canvas_api_token == ""
    assert config_module.validate_http_auth_config() is True


@pytest.mark.parametrize(
    "missing",
    ["CANVAS_OAUTH_CLIENT_ID", "CANVAS_OAUTH_CLIENT_SECRET", "MCP_PUBLIC_URL", "MCP_JWT_SIGNING_KEY"],
)
def test_canvas_oauth_config_requires_settings(canvas_env, missing):
    canvas_env({**CANVAS_OAUTH_ENV, missing: ""})
    assert config_module.validate_http_auth_config() is False


def test_canvas_oauth_config_requires_redirect_allowlist(canvas_env):
    canvas_env({**CANVAS_OAUTH_ENV, "MCP_ALLOWED_CLIENT_REDIRECT_URIS": ""})
    assert config_module.validate_http_auth_config() is False


def test_removed_oidc_mode_is_rejected(canvas_env):
    canvas_env({**CANVAS_OAUTH_ENV, "MCP_AUTH_MODE": "oidc"})
    assert config_module.validate_http_auth_config() is False


def test_unauthenticated_http_requires_server_token(canvas_env):
    canvas_env({**CANVAS_OAUTH_ENV, "MCP_AUTH_MODE": "none"})
    assert config_module.validate_http_auth_config() is False


def test_canvas_base_url_derived_from_api_url(canvas_env):
    config = canvas_env({**CANVAS_OAUTH_ENV, "CANVAS_BASE_URL": ""})
    assert config.canvas_base_url == "https://school.instructure.com"


def test_canvas_scopes_split_on_whitespace_only(canvas_env):
    config = canvas_env({
        **CANVAS_OAUTH_ENV,
        "CANVAS_OAUTH_SCOPES": "url:GET|/api/v1/courses url:GET|/api/v1/users/:user_id/profile",
    })
    assert config.canvas_oauth_scopes == [
        "url:GET|/api/v1/courses",
        "url:GET|/api/v1/users/:user_id/profile",
    ]


# ---------------------------------------------------------------------------
# Provider construction
# ---------------------------------------------------------------------------


def test_provider_is_disabled_in_none_mode(canvas_env):
    config = canvas_env({**CANVAS_OAUTH_ENV, "MCP_AUTH_MODE": "none"})
    assert create_mcp_auth_provider(config) is None


def test_provider_targets_canvas_oauth_endpoints(canvas_env, tmp_path):
    config = canvas_env(CANVAS_OAUTH_ENV)
    from fastmcp.server.auth import oauth_proxy

    with patch.object(oauth_proxy.settings, "home", tmp_path):
        auth = create_mcp_auth_provider(config)

    assert auth is not None
    provider = auth.provider
    assert provider._upstream_authorization_endpoint == (
        "https://school.instructure.com/login/oauth2/auth"
    )
    assert provider._upstream_token_endpoint == (
        "https://school.instructure.com/login/oauth2/token"
    )
    assert provider._upstream_client_id == "10000000000001"
    assert provider._extra_authorize_params == {"purpose": "Canvas MCP"}
    assert isinstance(provider._token_validator, CanvasTokenVerifier)
    assert str(auth.settings.resource_server_url) == "https://mcp.example.com/mcp"
    assert "/auth/callback" in auth.extra_route_paths


@pytest.mark.asyncio
async def test_storage_from_other_signing_key_reads_as_missing(tmp_path):
    from fastmcp.server.auth import oauth_proxy

    from canvas_mcp.core.mcp_auth import create_oauth_storage

    with patch.object(oauth_proxy.settings, "home", tmp_path):
        old = create_oauth_storage("first-signing-key-value")
        await old.put(key="client-1", value={"client_id": "client-1"})
        assert await old.get(key="client-1") == {"client_id": "client-1"}

        rotated = create_oauth_storage("second-signing-key-value")
        assert await rotated.get(key="client-1") is None


def test_unknown_auth_mode_raises(canvas_env):
    config = canvas_env({**CANVAS_OAUTH_ENV, "MCP_AUTH_MODE": "basic"})
    with pytest.raises(ValueError):
        create_mcp_auth_provider(config)


# ---------------------------------------------------------------------------
# Canvas token verification
# ---------------------------------------------------------------------------


def _mock_canvas_client(response=None, side_effect=None):
    client = AsyncMock()
    client.get = AsyncMock(return_value=response, side_effect=side_effect)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _response(status_code, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    return response


@pytest.mark.asyncio
async def test_verifier_accepts_valid_canvas_token():
    verifier = CanvasTokenVerifier(api_url="https://school.instructure.com/api/v1/")
    client = _mock_canvas_client(_response(200, {"id": 42, "name": "Ada"}))
    with patch("canvas_mcp.core.mcp_auth.httpx.AsyncClient", return_value=client):
        token = await verifier.verify_token("canvas-user-token")

    assert token is not None
    assert token.token == "canvas-user-token"
    assert token.claims["sub"] == "42"
    url = client.get.call_args[0][0]
    assert url == "https://school.instructure.com/api/v1/users/self"
    assert client.get.call_args[1]["headers"]["Authorization"] == "Bearer canvas-user-token"


@pytest.mark.asyncio
async def test_verifier_rejects_invalid_canvas_token():
    verifier = CanvasTokenVerifier(api_url="https://school.instructure.com/api/v1")
    client = _mock_canvas_client(_response(401, {"errors": []}))
    with patch("canvas_mcp.core.mcp_auth.httpx.AsyncClient", return_value=client):
        assert await verifier.verify_token("revoked") is None


@pytest.mark.asyncio
async def test_verifier_rejects_on_network_error():
    verifier = CanvasTokenVerifier(api_url="https://school.instructure.com/api/v1")
    client = _mock_canvas_client(side_effect=httpx.ConnectError("down"))
    with patch("canvas_mcp.core.mcp_auth.httpx.AsyncClient", return_value=client):
        assert await verifier.verify_token("tok") is None


@pytest.mark.asyncio
async def test_verifier_caches_successful_results():
    verifier = CanvasTokenVerifier(api_url="https://school.instructure.com/api/v1")
    client = _mock_canvas_client(_response(200, {"id": 7}))
    with patch("canvas_mcp.core.mcp_auth.httpx.AsyncClient", return_value=client):
        await verifier.verify_token("tok")
        await verifier.verify_token("tok")
    assert client.get.await_count == 1


@pytest.mark.asyncio
async def test_verifier_rejects_empty_token():
    verifier = CanvasTokenVerifier(api_url="https://school.instructure.com/api/v1")
    assert await verifier.verify_token("") is None


# ---------------------------------------------------------------------------
# Per-request credential resolution
# ---------------------------------------------------------------------------


def _mcp_request_context(token: str | None):
    """Build a fake MCP request context like the SDK's bearer-auth middleware."""
    scope: dict = {"type": "http"}
    if token is not None:
        scope["user"] = SimpleNamespace(access_token=SimpleNamespace(token=token))
    return SimpleNamespace(request=SimpleNamespace(scope=scope))


def test_credentials_come_from_signed_in_user(canvas_env):
    from mcp.server.lowlevel.server import request_ctx

    canvas_env(CANVAS_OAUTH_ENV)
    reset = request_ctx.set(_mcp_request_context("user-canvas-token"))
    try:
        creds = get_request_credentials()
    finally:
        request_ctx.reset(reset)

    assert creds is not None
    assert creds.api_token == "user-canvas-token"
    assert creds.api_url == "https://school.instructure.com/api/v1"


def test_no_server_token_fallback_when_oauth_required(canvas_env):
    canvas_env({**CANVAS_OAUTH_ENV, "CANVAS_API_TOKEN": "server-token"})
    set_oauth_required(True)
    assert resolve_canvas_credentials() is None


def test_server_token_fallback_when_oauth_not_required(canvas_env):
    canvas_env({**CANVAS_OAUTH_ENV, "MCP_AUTH_MODE": "none", "CANVAS_API_TOKEN": "server-token"})
    creds = resolve_canvas_credentials()
    assert creds is not None
    assert creds.api_token == "server-token"


def test_request_without_user_has_no_credentials(canvas_env):
    from mcp.server.lowlevel.server import request_ctx

    canvas_env(CANVAS_OAUTH_ENV)
    reset = request_ctx.set(_mcp_request_context(None))
    try:
        assert get_request_credentials() is None
    finally:
        request_ctx.reset(reset)


@pytest.mark.asyncio
async def test_make_canvas_request_refuses_server_token_in_oauth_mode(canvas_env):
    from canvas_mcp.core.client import OAUTH_REQUIRED_ERROR, make_canvas_request

    canvas_env({**CANVAS_OAUTH_ENV, "CANVAS_API_TOKEN": "server-token"})
    set_oauth_required(True)
    with patch("canvas_mcp.core.client._get_http_client") as global_client:
        result = await make_canvas_request("get", "/users/self")

    assert result == {"error": OAUTH_REQUIRED_ERROR}
    global_client.assert_not_called()


@pytest.mark.asyncio
async def test_make_canvas_request_uses_signed_in_user_token(canvas_env):
    from mcp.server.lowlevel.server import request_ctx

    from canvas_mcp.core.client import make_canvas_request

    canvas_env(CANVAS_OAUTH_ENV)
    set_oauth_required(True)

    response = MagicMock()
    response.json.return_value = {"id": 1}
    response.raise_for_status = MagicMock()
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)

    reset = request_ctx.set(_mcp_request_context("user-canvas-token"))
    try:
        with patch("canvas_mcp.core.client.httpx.AsyncClient", return_value=client) as factory:
            await make_canvas_request("get", "/users/self")
    finally:
        request_ctx.reset(reset)

    assert factory.call_args[1]["headers"]["Authorization"] == "Bearer user-canvas-token"
    client.aclose.assert_awaited_once()


@pytest.mark.asyncio
async def test_expired_user_token_returns_reauth_error(canvas_env):
    from mcp.server.lowlevel.server import request_ctx

    from canvas_mcp.core.client import make_canvas_request

    canvas_env(CANVAS_OAUTH_ENV)
    set_oauth_required(True)

    request = httpx.Request("GET", "https://school.instructure.com/api/v1/users/self")
    error_response = httpx.Response(401, request=request, headers={"WWW-Authenticate": "Bearer"})
    response = MagicMock()
    response.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError("401", request=request, response=error_response)
    )
    client = AsyncMock()
    client.get = AsyncMock(return_value=response)

    reset = request_ctx.set(_mcp_request_context("expired"))
    try:
        with patch("canvas_mcp.core.client.httpx.AsyncClient", return_value=client):
            result = await make_canvas_request("get", "/users/self")
    finally:
        request_ctx.reset(reset)

    assert "401" in result["error"]
    assert "sign in" in result["error"]
