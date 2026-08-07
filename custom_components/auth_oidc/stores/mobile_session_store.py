"""Short-lived mobile authentication completion sessions."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
from typing import Literal

MOBILE_SESSION_LIFETIME = timedelta(minutes=5)
MobileSessionStatus = Literal["pending", "completed", "invalid"]


@dataclass(slots=True)
class _MobileSession:
    """Internal mobile session data."""

    poll_digest: str
    expires_at: datetime
    callback_url: str | None = None


class MobileSessionStore:
    """Correlate an app waiting page with a completed browser login."""

    def __init__(self) -> None:
        self._sessions: dict[str, _MobileSession] = {}

    def _purge_expired(self) -> None:
        now = datetime.now(timezone.utc)
        for state_id in [
            state_id
            for state_id, session in self._sessions.items()
            if session.expires_at <= now
        ]:
            self._sessions.pop(state_id, None)

    def create(self, state_id: str) -> str:
        """Create a high-entropy polling secret for a mobile state."""
        self._purge_expired()
        token = secrets.token_urlsafe(32)
        self._sessions[state_id] = _MobileSession(
            poll_digest=hashlib.sha256(token.encode()).hexdigest(),
            expires_at=datetime.now(timezone.utc) + MOBILE_SESSION_LIFETIME,
        )
        return token

    def is_pending(self, state_id: str) -> bool:
        """Return whether a mobile state still has a pending polling session."""
        self._purge_expired()
        session = self._sessions.get(state_id)
        return session is not None and session.callback_url is None

    def complete(self, state_id: str, callback_url: str) -> bool:
        """Store the final Home Assistant callback for a mobile state."""
        self._purge_expired()
        session = self._sessions.get(state_id)
        if session is None or session.callback_url is not None:
            return False
        session.callback_url = callback_url
        return True

    def poll(self, token: str) -> tuple[MobileSessionStatus, str | None]:
        """Poll a mobile session, consuming a completed result exactly once."""
        self._purge_expired()
        token_digest = hashlib.sha256(token.encode()).hexdigest()
        for state_id, session in tuple(self._sessions.items()):
            if not secrets.compare_digest(session.poll_digest, token_digest):
                continue
            if session.callback_url is None:
                return "pending", None
            callback_url = session.callback_url
            self._sessions.pop(state_id, None)
            return "completed", callback_url
        return "invalid", None
