"""Callback route to return the user to after external OIDC interaction."""

from aiohttp import web
from homeassistant.components.http import HomeAssistantView

from ..provider import ExistingUserRequiredError, OpenIDAuthProvider
from ..stores.mobile_session_store import MobileSessionStore
from ..tools.helpers import (
    async_create_mobile_auth_callback,
    error_response,
    get_url,
    get_valid_state_id,
    no_store_response,
    template_response,
)
from ..tools.oidc_client import OIDCClient
from ..tools.types import UserDetails

PATH = "/auth/oidc/callback"


class OIDCCallbackView(HomeAssistantView):
    """OIDC Plugin Callback View."""

    requires_auth = False
    url = PATH
    name = "auth:oidc:callback"

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

    async def _resolve_callback_state(
        self, request: web.Request, state: str
    ) -> tuple[str | None, bool, str | None]:
        """Resolve the callback state for normal and mobile-browser flows."""
        # A successfully claimed one-time handoff transfers this state to the
        # external mobile browser. Check it before the app/browser cookie so a
        # shared cookie jar cannot accidentally classify the callback as desktop.
        if await self.oidc_provider.async_is_mobile_callback_state(state):
            return state, True, None

        state_id = await get_valid_state_id(request, self.oidc_provider)
        if state_id == state:
            return state_id, False, None

        if state_id is None:
            return None, False, "Missing state cookie, please restart login."

        return None, False, "State parameter does not match, possible CSRF attack."

    async def _complete_mobile_login(
        self,
        request: web.Request,
        state_id: str,
        user_details: UserDetails,
    ) -> web.Response:
        """Resolve credentials and prepare the final Companion App callback."""
        if not self.mobile_sessions.is_pending(state_id):
            return await error_response(
                "Mobile sign-in session expired. Please restart login.", status=400
            )

        try:
            mobile_login = await self.oidc_provider.async_get_mobile_login(
                state_id, user_details
            )
        except ExistingUserRequiredError:
            return await error_response(
                "This OIDC account is not linked to an existing Home Assistant user.",
                status=403,
            )

        if mobile_login is None:
            return await error_response(
                "Mobile sign-in session expired. Please restart login.", status=400
            )

        authorize_url, credentials = mobile_login
        callback_url = await async_create_mobile_auth_callback(
            self.oidc_provider.hass, request, authorize_url, credentials
        )
        if callback_url is None:
            return await error_response(
                "Failed to complete Home Assistant mobile authorization.", status=403
            )

        if not self.mobile_sessions.complete(state_id, callback_url):
            return await error_response(
                "Mobile sign-in session expired. Please restart login.", status=400
            )

        return no_store_response(await template_response("mobile_complete", {}))

    async def get(self, request: web.Request) -> web.Response:
        """Receive response."""
        params = request.rel_url.query
        code = params.get("code")
        state = params.get("state")

        if not (code and state):
            return await error_response("Missing code or state parameter.")

        state_id, is_mobile_browser, state_error = await self._resolve_callback_state(
            request, state
        )
        if state_error:
            return await error_response(state_error)

        assert state_id is not None

        redirect_uri = get_url("/auth/oidc/callback", self.force_https)
        user_details = await self.oidc_client.async_complete_token_flow(
            redirect_uri, code, state
        )
        if user_details is None:
            return await error_response(
                "Failed to get user details, see Home Assistant logs for more information.",
                status=500,
            )

        if user_details.get("role") == "invalid":
            return await error_response(
                "User is not in the correct group to access Home Assistant, "
                + "contact your administrator!",
                status=403,
            )

        if is_mobile_browser:
            return await self._complete_mobile_login(request, state_id, user_details)

        success = await self.oidc_provider.async_save_user_info(state_id, user_details)
        if not success:
            return await error_response(
                "Failed to save user information, session probably expired. Please sign in again.",
                status=500,
            )

        raise web.HTTPFound(get_url("/auth/oidc/finish", self.force_https))
