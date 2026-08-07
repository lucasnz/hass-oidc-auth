"""Redirect route to redirect the user to the external OIDC server,
can either be linked to directly or accessed through the welcome page."""

from urllib.parse import quote
from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..provider import OpenIDAuthProvider
from ..stores.mobile_session_store import MobileSessionStore
from ..tools.helpers import (
    error_response,
    get_url,
    get_valid_state_id,
    no_store_response,
    template_response,
)
from ..tools.oidc_client import OIDCClient

PATH = "/auth/oidc/redirect"


class OIDCRedirectView(HomeAssistantView):
    """OIDC Plugin Redirect View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:redirect"

    def __init__(
        self,
        oidc_client: OIDCClient,
        oidc_provider: OpenIDAuthProvider,
        force_https: bool,
        mobile_sessions: MobileSessionStore,
    ) -> None:
        self.oidc_client = oidc_client
        self.oidc_provider = oidc_provider
        self.force_https = force_https
        self.mobile_sessions = mobile_sessions

    async def get(self, req: web.Request) -> web.Response:
        """Receive response."""
        mobile_token = req.query.get("mobile_token")
        if mobile_token:
            state_id = await self.oidc_provider.async_claim_mobile_handoff(mobile_token)
            if not state_id:
                return no_store_response(
                    await error_response(
                        "Invalid or expired mobile sign-in link, please restart login."
                    )
                )
        else:
            state_id = await get_valid_state_id(req, self.oidc_provider)

        if not state_id:
            # Direct access to the redirect endpoint, go to welcome page instead
            welcome_url = get_url("/auth/oidc/welcome", self.force_https)
            raise web.HTTPFound(welcome_url)

        try:
            redirect_uri = get_url("/auth/oidc/callback", self.force_https)
            auth_url = await self.oidc_client.async_get_authorization_url(
                redirect_uri, state_id
            )

            if auth_url:
                if mobile_token:
                    poll_token = self.mobile_sessions.create(state_id)
                    return no_store_response(
                        await template_response(
                            "welcome",
                            {
                                "mobile_auth_url": quote(auth_url),
                                "poll_token": poll_token,
                            },
                        )
                    )

                return no_store_response(
                    await template_response("redirect", {"url": quote(auth_url)})
                )
        except RuntimeError:
            pass

        return no_store_response(
            await error_response(
                "Integration is misconfigured, discovery could not be obtained.",
                status=500,
            )
        )

    async def post(self, req: web.Request) -> web.Response:
        """POST"""
        return await self.get(req)
