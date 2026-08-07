"""Tests for short-lived mobile authentication sessions."""

from custom_components.auth_oidc.stores.mobile_session_store import MobileSessionStore


def test_mobile_session_is_secret_bound_and_one_time():
    """Only the generated polling secret can consume a completed callback once."""
    store = MobileSessionStore()
    token = store.create("state-one")

    assert store.poll("wrong-token") == ("invalid", None)
    assert store.poll(token) == ("pending", None)
    assert store.complete("state-one", "https://home-assistant.io/Android?code=abc")
    assert store.poll(token) == (
        "completed",
        "https://home-assistant.io/Android?code=abc",
    )
    assert store.poll(token) == ("invalid", None)


def test_mobile_session_cannot_be_completed_twice():
    """A state should publish at most one final callback URL."""
    store = MobileSessionStore()
    token = store.create("state-one")

    assert store.complete("state-one", "https://example.com/first")
    assert not store.complete("state-one", "https://example.com/second")
    assert store.poll(token) == ("completed", "https://example.com/first")
