"""Tests for mobile Home Assistant OAuth callback helpers."""

from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from custom_components.auth_oidc.tools.helpers import async_create_mobile_auth_callback


@pytest.mark.asyncio
async def test_create_mobile_auth_callback_mirrors_ha_authorization_checks():
    """The helper validates the client/redirect before creating the HA auth code."""
    hass = MagicMock()
    hass.auth.async_get_user_by_credentials = AsyncMock(return_value=None)
    request = MagicMock()
    credentials = MagicMock()
    authorize_url = (
        "https://ha.example/auth/authorize?response_type=code&"
        "client_id=https%3A%2F%2Fhome-assistant.io%2FAndroid&"
        "redirect_uri=https%3A%2F%2Fhome-assistant.io%2FAndroid&state=app-state"
    )

    with (
        patch(
            "custom_components.auth_oidc.tools.helpers.indieauth.verify_client_id",
            return_value=True,
        ),
        patch(
            "custom_components.auth_oidc.tools.helpers.indieauth.verify_redirect_uri",
            new=AsyncMock(return_value=True),
        ) as verify_redirect,
        patch(
            "custom_components.auth_oidc.tools.helpers.process_success_login"
        ) as process_success,
        patch(
            "custom_components.auth_oidc.tools.helpers.create_auth_code",
            return_value="ha-code",
        ) as create_code,
    ):
        result = await async_create_mobile_auth_callback(
            hass, request, authorize_url, credentials
        )

    assert result is not None
    parsed = urlparse(result)
    assert parsed.scheme == "https"
    assert parsed.netloc == "home-assistant.io"
    assert parsed.path == "/Android"
    assert parse_qs(parsed.query) == {"code": ["ha-code"], "state": ["app-state"]}
    verify_redirect.assert_awaited_once_with(
        hass,
        "https://home-assistant.io/Android",
        "https://home-assistant.io/Android",
    )
    process_success.assert_called_once_with(request)
    create_code.assert_called_once_with(
        hass, "https://home-assistant.io/Android", credentials
    )


@pytest.mark.asyncio
async def test_create_mobile_auth_callback_rejects_invalid_redirect():
    """No HA authorization code should be created for an unverified redirect URI."""
    hass = MagicMock()
    request = MagicMock()
    credentials = MagicMock()
    authorize_url = (
        "https://ha.example/auth/authorize?response_type=code&"
        "client_id=https%3A%2F%2Fhome-assistant.io%2FAndroid&"
        "redirect_uri=https%3A%2F%2Fevil.example%2Fcallback"
    )

    with (
        patch(
            "custom_components.auth_oidc.tools.helpers.indieauth.verify_client_id",
            return_value=True,
        ),
        patch(
            "custom_components.auth_oidc.tools.helpers.indieauth.verify_redirect_uri",
            new=AsyncMock(return_value=False),
        ),
        patch(
            "custom_components.auth_oidc.tools.helpers.create_auth_code"
        ) as create_code,
    ):
        result = await async_create_mobile_auth_callback(
            hass, request, authorize_url, credentials
        )

    assert result is None
    create_code.assert_not_called()
