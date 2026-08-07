"""Mobile authentication completion status endpoint."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..stores.mobile_session_store import MobileSessionStore
from ..tools.helpers import NO_STORE_HEADERS

PATH = "/auth/oidc/mobile-status"


class OIDCMobileStatusView(HomeAssistantView):
    """Return the final app callback once external-browser sign-in completes."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:mobile-status"

    def __init__(self, mobile_sessions: MobileSessionStore) -> None:
        self.mobile_sessions = mobile_sessions

    async def post(self, request: web.Request) -> web.Response:
        """Return pending/completed status for a high-entropy mobile poll token."""
        try:
            data = await request.json()
        except (ValueError, TypeError):
            return web.json_response(
                {"status": "error"},
                status=400,
                headers=NO_STORE_HEADERS,
            )

        token = data.get("token") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            return web.json_response(
                {"status": "error"},
                status=400,
                headers=NO_STORE_HEADERS,
            )

        status, callback_url = self.mobile_sessions.poll(token)
        if status == "invalid":
            return web.json_response(
                {"status": "expired"},
                status=410,
                headers=NO_STORE_HEADERS,
            )
        if status == "completed":
            return web.json_response(
                {"status": "completed", "callback_url": callback_url},
                headers=NO_STORE_HEADERS,
            )
        return web.json_response({"status": "pending"}, headers=NO_STORE_HEADERS)
