"""OIDC security hardening tests (P0 #4/#6 + unverified id_token sub removal).

Covers the P0 fixes in ``sso.py`` / ``sso_registry.py``:

  - authorize URL built with ``urllib.parse.urlencode`` (#6) — special
    characters in scope/redirect_uri/state must survive round-tripping
  - empty ``state`` on callback rejected fail-closed (#4, CSRF)
  - unknown/consumed state rejected; state is single-use
  - ``sub`` is never derived from an unverified id_token (#3): missing
    claims degrade to ``"unknown"``, not a truncated JWT prefix
"""
from __future__ import annotations

import urllib.parse

import pytest

from maop.enterprise.sso import SSOConfig, SSOManager, SSOProvider
from maop.enterprise.sso_registry import SSOProviderRegistry
from maop.enterprise.sso_store import SSOProviderResponse

# ── helpers ─────────────────────────────────────────────────────────


class _FakeProviderStore:
    """Minimal stand-in for SSOProviderStore (registry only uses .get)."""

    def __init__(self, resp: SSOProviderResponse) -> None:
        self._resp = resp

    def get(self, provider_id: int):
        return self._resp if provider_id == self._resp.id else None


def _make_registry(pending_store=None) -> SSOProviderRegistry:
    resp = SSOProviderResponse(
        id=1,
        name="test-idp",
        protocol="oidc",
        enabled=True,
        config={
            "client_id": "cid",
            "client_secret": "sec",
            "authorize_url": "https://idp.example.com/authorize",
            # empty token_url: callback passes state validation first,
            # then fails at the token-exchange configuration check —
            # exactly the seam these CSRF tests need.
            "token_url": "",
            "redirect_uri": "https://app.example.com/cb",
        },
    )
    return SSOProviderRegistry(store=_FakeProviderStore(resp), pending_store=pending_store)


@pytest.fixture
def oidc_manager(enterprise_edition):
    config = SSOConfig(
        provider=SSOProvider.OIDC,
        client_id="test-client",
        authorize_url="https://idp.example.com/authorize",
        redirect_uri="https://app.example.com/cb?x=1&y=2",
        scopes=["openid", "profile", "email", "offline_access"],
    )
    return SSOManager(config=config)


# ── P0 #6: authorize URL encoding ───────────────────────────────────


def test_authorize_url_is_properly_encoded(oidc_manager):
    state = "state with spaces & special=chars"
    url = oidc_manager.get_authorize_url(state=state)
    parsed = urllib.parse.urlsplit(url)
    assert parsed.query  # non-empty query string
    qs = urllib.parse.parse_qs(parsed.query)
    assert qs["client_id"] == ["test-client"]
    # redirect_uri itself contains & and ? — must round-trip intact
    assert qs["redirect_uri"] == ["https://app.example.com/cb?x=1&y=2"]
    # scope is space-joined, then percent-encoded as a single value
    assert qs["scope"] == ["openid profile email offline_access"]
    assert qs["state"] == [state]
    assert qs["response_type"] == ["code"]


def test_authorize_url_pkce_params(oidc_manager):
    url = oidc_manager.get_authorize_url(state="s1", code_challenge="abc123")
    qs = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    assert qs["code_challenge"] == ["abc123"]
    assert qs["code_challenge_method"] == ["S256"]


# ── P0 #4: state fail-closed on callback ────────────────────────────


def test_callback_empty_state_rejected(enterprise_edition):
    registry = _make_registry()
    with pytest.raises(ValueError, match="state"):
        registry.handle_oidc_callback(1, code="authcode", state="")


def test_callback_unknown_state_rejected(enterprise_edition):
    registry = _make_registry()
    with pytest.raises(ValueError, match="mismatch or expired"):
        registry.handle_oidc_callback(1, code="authcode", state="bogus-state")


def test_callback_empty_code_rejected(enterprise_edition):
    registry = _make_registry()
    with pytest.raises(ValueError, match="code"):
        registry.handle_oidc_callback(1, code="", state="whatever")


def test_valid_state_passes_csrf_check(enterprise_edition):
    registry = _make_registry()
    url, state = registry.prepare_oidc_authorize(1)
    assert url.startswith("https://idp.example.com/authorize?")
    # Known state passes CSRF validation; the call then fails at the
    # token-exchange stage (token_url empty), proving state was accepted.
    with pytest.raises(ValueError, match="token_url"):
        registry.handle_oidc_callback(1, code="authcode", state=state)


def test_state_is_single_use(enterprise_edition):
    registry = _make_registry()
    _, state = registry.prepare_oidc_authorize(1)
    with pytest.raises(ValueError, match="token_url"):
        registry.handle_oidc_callback(1, code="c", state=state)
    # second use: state was consumed by the first callback
    with pytest.raises(ValueError, match="mismatch or expired"):
        registry.handle_oidc_callback(1, code="c", state=state)


def test_state_provider_mismatch_rejected(enterprise_edition):
    registry = _make_registry()
    _, state = registry.prepare_oidc_authorize(1)
    with pytest.raises(ValueError, match="provider mismatch"):
        registry.handle_oidc_callback(999, code="c", state=state)


# ── P0 #3: sub never derived from unverified id_token ───────────────


def test_sub_not_derived_from_unverified_id_token(oidc_manager):
    # No sub in claims but an id_token present: external_id must NOT be
    # a truncated JWT prefix (old behavior) — it degrades to "unknown".
    token_resp = {"id_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig"}
    user = oidc_manager._build_user_from_claims({}, token_resp)
    assert user.external_id == "oidc:unknown"


def test_sub_not_derived_from_id_token_with_mapping(oidc_manager):
    oidc_manager.config.attribute_mapping = {"external_id": "sub"}
    token_resp = {"id_token": "eyJhbGciOiJSUzI1NiJ9.payload.sig"}
    user = oidc_manager._build_user_from_claims({}, token_resp)
    assert user.external_id == "oidc:unknown"


def test_sub_from_claims_is_used(oidc_manager):
    user = oidc_manager._build_user_from_claims({"sub": "user-123"}, {})
    assert user.external_id == "oidc:user-123"
