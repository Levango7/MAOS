"""Tests for license issuance and validation (``maop.enterprise.license``).

These tests use the bundled test license key (``data/test_license.key``)
signed by ``scripts/test_signing_key.pem`` whose public counterpart lives
in ``maop/enterprise/keys/public_key.pem``.
"""
from __future__ import annotations

import pytest

# ── Happy path ──────────────────────────────────────────────────────

def test_license_validates(validator, license_key):
    """A valid test license key must validate without raising."""
    info = validator.validate(license_key)
    assert info is not None


def test_license_customer_is_test_enterprise(validator, license_key):
    """The bundled test license belongs to ``Test Enterprise``."""
    info = validator.validate(license_key)
    assert info.customer == "Test Enterprise"


def test_license_edition_is_enterprise(validator, license_key):
    """The bundled test license is for the ``enterprise`` edition."""
    info = validator.validate(license_key)
    assert info.edition == "enterprise"


def test_license_not_expired(validator, license_key):
    """The bundled test license must not be expired."""
    info = validator.validate(license_key)
    assert not info.is_expired, (
        f"Test license expired on {info.expires_at.isoformat()} — "
        f"regenerate via scripts/issue_test_license.py --write --days 365"
    )


def test_license_expires_in_the_future(validator, license_key):
    """Sanity: expiry is strictly in the future (not today, not past)."""
    from datetime import datetime, timezone

    info = validator.validate(license_key)
    now = datetime.now(timezone.utc)
    assert info.expires_at > now


# ── Error paths ─────────────────────────────────────────────────────

def test_invalid_license_raises(validator):
    """A malformed key string must raise ``LicenseError`` (or subclass)."""
    from maop.enterprise.license import LicenseError

    with pytest.raises(LicenseError):
        validator.validate("MAOP-ENT-invalid.invalid")


def test_empty_license_raises(validator):
    """An empty string must raise ``LicenseError`` (or subclass)."""
    from maop.enterprise.license import LicenseError

    with pytest.raises(LicenseError):
        validator.validate("")


def test_garbage_license_raises(validator):
    """A completely garbage string must raise ``LicenseError``."""
    from maop.enterprise.license import LicenseError

    with pytest.raises(LicenseError):
        validator.validate("not-a-license-key-at-all")


def test_tampered_license_raises(validator, license_key):
    """Tampering with the payload portion must raise a signature error."""
    from maop.enterprise.license import LicenseError

    # The key format is MAOP-ENT-{payload}.{signature}.  Flip one char in
    # the payload to break the signature without corrupting the format.
    prefix = "MAOP-ENT-"
    body = license_key[len(prefix):]
    dot = body.index(".")
    payload, signature = body[:dot], body[dot + 1:]
    # Flip first char of payload (keep it alphanumeric-ish)
    flipped = ("Z" if payload[0] != "Z" else "Y") + payload[1:]
    tampered = f"{prefix}{flipped}.{signature}"

    with pytest.raises(LicenseError):
        validator.validate(tampered)


# ── LicenseInfo model ───────────────────────────────────────────────

def test_license_info_fields(validator, license_key):
    """LicenseInfo exposes the expected fields."""
    info = validator.validate(license_key)
    assert hasattr(info, "customer")
    assert hasattr(info, "edition")
    assert hasattr(info, "issued_at")
    assert hasattr(info, "expires_at")
    assert hasattr(info, "is_expired")
    assert hasattr(info, "is_in_grace_period")


def test_license_error_hierarchy():
    """LicenseError is the base for all license exceptions."""
    from maop.enterprise.license import (
        LicenseError,
        LicenseExpiredError,
        LicenseFormatError,
        LicenseSignatureError,
    )

    assert issubclass(LicenseFormatError, LicenseError)
    assert issubclass(LicenseSignatureError, LicenseError)
    assert issubclass(LicenseExpiredError, LicenseError)