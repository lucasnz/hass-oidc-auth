"""State Store, store authentication states (redirect_uri)."""

import hashlib
import secrets
import string

from datetime import datetime, timedelta, timezone
from typing import cast, Optional
from homeassistant.helpers.storage import Store
from homeassistant.core import HomeAssistant

from ..tools.types import OIDCState, UserDetails

STORAGE_VERSION = 1
STORAGE_KEY = "auth_provider.auth_oidc.states"
MAX_DEVICE_CODE_ATTEMPTS = 10


class StateStore:
    """Holds the authentication states and associated data"""

    def __init__(self, hass: HomeAssistant) -> None:
        """Initialize the user data store."""
        self.hass = hass
        self._store = Store[dict[str, OIDCState]](
            hass, STORAGE_VERSION, STORAGE_KEY, private=True, atomic_writes=True
        )
        self._data: dict[str, OIDCState] | None = None

    async def async_load(self) -> None:
        """Load stored data."""
        if (data := await self._store.async_load()) is None:
            data = cast(dict[str, OIDCState], {})
        self._data = data

    async def _async_save(self) -> None:
        """Save data."""
        if self._data is not None:
            await self._store.async_save(self._data)

    def _generate_id(self) -> str:
        """Generate a random identifier."""
        return secrets.token_urlsafe(32)

    def _generate_code(self) -> str:
        """Generate a random six-digit code."""
        return "".join(secrets.choice(string.digits) for _ in range(6))

    def _is_expired(self, state: OIDCState) -> bool:
        """Check if a state is expired."""
        return datetime.fromisoformat(state["expiration"]) < datetime.now(timezone.utc)

    def _is_valid(self, state: OIDCState, ip: str | None) -> bool:
        """Check if a state is valid"""
        return (
            not self._is_expired(state)
            and bool(state["redirect_uri"])
            and ip is not None
            and state["ip_address"] == ip
        )

    async def async_create_state_from_url(
        self, redirect_uri: str, ip: str, is_mobile: bool = False
    ) -> str:
        """Generates a the OIDC state adds it to the database for 5 minutes."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state_id = self._generate_id()
        expiration = datetime.now(timezone.utc) + timedelta(minutes=5)

        self._data[state_id] = {
            "id": state_id,
            "redirect_uri": redirect_uri,
            "device_code": None,
            "device_code_attempts": 0,
            "user_details": None,
            "expiration": expiration.isoformat(),
            "ip_address": ip,
            "is_mobile": is_mobile,
            "mobile_handoff_digest": None,
            "mobile_handoff_claimed": False,
        }

        await self._async_save()
        return state_id

    async def async_generate_mobile_handoff_for_state(
        self, state_id: str
    ) -> Optional[str]:
        """Generate a short-lived one-time token for opening mobile sign-in."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state = self._data.get(state_id)
        if state is None or self._is_expired(state):
            return None
        if not state.get("is_mobile", False) or state.get(
            "mobile_handoff_claimed", False
        ):
            return None
        if state.get("mobile_handoff_digest") is not None:
            return None
        if state.get("user_details") is not None:
            return None

        token = self._generate_id()
        state["mobile_handoff_digest"] = hashlib.sha256(token.encode()).hexdigest()
        state["mobile_handoff_claimed"] = False
        await self._async_save()
        return token

    async def async_claim_mobile_handoff(self, token: str) -> Optional[str]:
        """Consume a mobile handoff token and return its state id once."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        token_digest = hashlib.sha256(token.encode()).hexdigest()
        for state_id, state in self._data.items():
            stored_digest = state.get("mobile_handoff_digest")
            if not stored_digest:
                continue
            if not secrets.compare_digest(stored_digest, token_digest):
                continue
            if not state.get("is_mobile", False) or self._is_expired(state):
                continue
            if not state.get("redirect_uri") or state.get("user_details") is not None:
                continue

            # Claim before the first await so concurrent requests cannot reuse it.
            state["mobile_handoff_digest"] = None
            state["mobile_handoff_claimed"] = True
            await self._async_save()
            return state_id

        return None

    async def async_is_mobile_callback_state(self, state_id: str) -> bool:
        """Validate a state presented by the separate mobile browser callback."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state = self._data.get(state_id)
        if state is None or self._is_expired(state):
            return False
        if not state.get("is_mobile", False):
            return False
        if not state.get("mobile_handoff_claimed", False):
            return False
        if state.get("mobile_handoff_digest") is not None:
            return False
        if state.get("user_details") is not None:
            return False

        return bool(state.get("redirect_uri"))

    async def async_generate_code_for_state(self, state_id: str) -> Optional[str]:
        """Generates a one time code for the state to link device clients."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        try:
            code = self._generate_code()
            self._data[state_id]["device_code"] = code
            await self._async_save()
            return code
        except KeyError:
            return None

    async def async_add_userinfo_to_state(
        self, state_id: str, user_info: UserDetails
    ) -> bool:
        """Add userinfo to existing state to complete login"""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        try:
            self._data[state_id]["user_details"] = user_info
            await self._async_save()
            return True
        except KeyError:
            return False

    async def async_get_redirect_uri_for_state(
        self, state_id: str, ip: str
    ) -> Optional[str]:
        """Get the redirect_uri for a given state_id."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state = self._data.get(state_id)
        if state and self._is_valid(state, ip):
            return state["redirect_uri"]

        return None

    async def async_is_state_ready(self, state_id: str, ip: str) -> bool:
        """Check if the state has received the user info from the OIDC callback."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state = self._data.get(state_id)
        return (
            state is not None
            and state["user_details"] is not None
            and self._is_valid(state, ip)
        )

    async def async_link_state_to_code(
        self, state_id: str, code: str, ip: str | None
    ) -> bool:
        """Link a state to a device code, used for mobile sign-in."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state_data = self._data.get(state_id)
        if (
            state_data
            and self._is_valid(state_data, ip)
            and state_data["user_details"] is not None
        ):
            attempts = state_data.get("device_code_attempts", 0)
            if attempts >= MAX_DEVICE_CODE_ATTEMPTS:
                return False

            matching_states = [
                state
                for state in self._data.values()
                if state["device_code"] == code and not self._is_expired(state)
            ]

            if len(matching_states) > 1:
                raise ValueError("Multiple states match the provided device code")

            if matching_states:
                state = matching_states[0]

                # Set user details on the device state to allow it to complete login
                state["user_details"] = state_data["user_details"]

                # Delete the 'donor' state as it's one time use
                self._data.pop(state_id)

                # Save and return true
                await self._async_save()
                return True

            state_data["device_code_attempts"] = attempts + 1
            await self._async_save()

        return False

    async def async_consume_mobile_state(self, state_id: str) -> str | None:
        """Consume a claimed mobile state without relying on the browser IP."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        state = self._data.get(state_id)
        if state is None or self._is_expired(state):
            return None
        if not state.get("is_mobile", False):
            return None
        if not state.get("mobile_handoff_claimed", False):
            return None
        if state.get("mobile_handoff_digest") is not None:
            return None

        redirect_uri = state.get("redirect_uri")
        if not redirect_uri:
            return None

        # The one-time handoff and OIDC state/PKCE checks have transferred this
        # login to the external browser. Do not require its IP to match the app
        # webview, since mobile networking can legitimately change mid-flow.
        self._data.pop(state_id)
        await self._async_save()
        return redirect_uri

    async def async_receive_userinfo_for_state(
        self, state_id: str, ip: str
    ) -> Optional[OIDCState]:
        """Retrieve user info based on the state_id."""
        if self._data is None:
            raise RuntimeError("Data not loaded")

        user_data = self._data.get(state_id)

        if user_data:
            # We should now wipe it from the database, as it's one time use
            self._data.pop(state_id)
            await self._async_save()

        if user_data and self._is_valid(user_data, ip):
            return user_data["user_details"]

        return None

    def get_data(self):
        """Get the internal data for testing purposes."""
        return self._data
