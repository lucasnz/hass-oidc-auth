"""Helper functions for the integration."""

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, parse_qsl, urlencode, urlparse, urlunparse

from aiohttp import web
from homeassistant.auth.models import Credentials
from homeassistant.components import http
from homeassistant.components.auth import create_auth_code, indieauth
from homeassistant.components.http.auth import async_user_not_allowed_do_auth
from homeassistant.components.http.ban import process_success_login
from homeassistant.core import HomeAssistant

from ..config.const import REPO_ROOT_URL
from ..views.loader import AsyncTemplateRenderer

if TYPE_CHECKING:
    from ..provider import OpenIDAuthProvider

STATE_COOKIE_NAME = "auth_oidc_state"
NO_STORE_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
}


def get_url(path: str, force_https: bool) -> str:
    """Returns the requested path appended to the current request base URL."""
    if (req := http.current_request.get()) is None:
        raise RuntimeError("No current request in context")

    base_uri = str(req.url).split("/auth", 2)[0]
    if force_https:
        base_uri = base_uri.replace("http://", "https://")
    return f"{base_uri}{path}"


async def get_view(template: str, parameters: dict | None = None) -> str:
    """Returns the generated HTML of the requested view."""
    if parameters is None:
        parameters = {}

    renderer = AsyncTemplateRenderer()
    return await renderer.render_template(f"{template}.html", **parameters)


def get_state_id(request: web.Request) -> str | None:
    """Return the current OIDC state cookie, if present."""
    return request.cookies.get(STATE_COOKIE_NAME)


def reset_state_cookie() -> str:
    """Return a Set-Cookie header value to reset the state cookie."""
    return f"{STATE_COOKIE_NAME}=; Path=/auth/; SameSite=Lax; HttpOnly; Max-Age=0"


async def get_valid_state_id(
    request: web.Request, oidc_provider: "OpenIDAuthProvider"
) -> str | None:
    """Return state id only when cookie exists and state is still valid."""
    state_id = get_state_id(request)
    if not state_id:
        return None

    if not await oidc_provider.async_is_state_valid(state_id):
        return None

    return state_id


async def async_create_mobile_auth_callback(
    hass: HomeAssistant,
    request: web.Request,
    authorize_url: str,
    credentials: Credentials,
) -> str | None:
    """Create the final Home Assistant OAuth callback for a mobile client.

    Home Assistant does not expose a documented server-side API for converting
    already-resolved Credentials into an authorization code. Its login-flow HTTP
    API ultimately stores Credentials in the same auth-code store via
    homeassistant.components.auth.create_auth_code(). Keep that dependency
    isolated here and mirror the redirect/user validation performed by HA's
    login-flow endpoint before creating the code.
    """
    query = parse_qs(urlparse(authorize_url).query)
    client_id_values = query.get("client_id", [])
    redirect_uri_values = query.get("redirect_uri", [])
    response_type_values = query.get("response_type", [])
    client_state_values = query.get("state", [])

    if (
        len(client_id_values) != 1
        or len(redirect_uri_values) != 1
        or response_type_values != ["code"]
        or len(client_state_values) > 1
    ):
        return None

    client_id = client_id_values[0]
    redirect_uri = redirect_uri_values[0]
    if not indieauth.verify_client_id(client_id):
        return None
    if not await indieauth.verify_redirect_uri(hass, client_id, redirect_uri):
        return None

    user = await hass.auth.async_get_user_by_credentials(credentials)
    if user is not None and async_user_not_allowed_do_auth(hass, user):
        return None

    process_success_login(request)
    auth_code = create_auth_code(hass, client_id, credentials)
    callback = urlparse(redirect_uri)
    callback_query = [
        (key, value)
        for key, value in parse_qsl(callback.query, keep_blank_values=True)
        if key not in {"code", "state"}
    ]
    callback_query.append(("code", auth_code))
    if client_state_values:
        callback_query.append(("state", client_state_values[0]))

    return urlunparse(callback._replace(query=urlencode(callback_query)))


def no_store_response(response: web.Response) -> web.Response:
    """Add no-cache headers to an authentication response."""
    response.headers.update(NO_STORE_HEADERS)
    return response


def html_response(html: str, status: int = 200, headers=None) -> web.Response:
    """Return an HTML response with the standard content type."""
    return web.Response(
        text=html, content_type="text/html", status=status, headers=headers
    )


async def template_response(
    template: str, parameters: dict | None = None
) -> web.Response:
    """Render a template and return it as an HTML response."""
    if parameters is None:
        parameters = {}
    parameters["help_url"] = REPO_ROOT_URL
    return html_response(await get_view(template, parameters))


async def error_response(message: str, status: int = 400) -> web.Response:
    """Render the shared error view."""
    return html_response(
        await get_view("error", {"error": message, "help_url": REPO_ROOT_URL}),
        status=status,
        headers={
            "set-cookie": reset_state_cookie(),
        },
    )


def concat_url_query(base: str, new_query: str) -> str:
    """Concatenate a base URL with a new query string, handling existing queries."""
    separator = "?"
    if "?" in base:
        separator = "&"
    return f"{base}{separator}{new_query}"
