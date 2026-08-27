"""SAML security hardening tests (P0 #1/#2/#3 + StatusCode/SubjectConfirmation).

Builds genuinely signed SAML responses (self-signed IdP certificate,
RSA-SHA256 enveloped signature, exclusive c14n — mirroring what
``SAMLHandler._verify_signature`` expects) and verifies the fail-closed
behavior added in the P0 security pass:

  - Assertion replay prevention (#1)
  - Conditions / AudienceRestriction mandatory (#2)
  - empty/missing NameID rejected (#3)
  - non-Success StatusCode rejected
  - SubjectConfirmation Recipient / NotOnOrAfter validation
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import secrets

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

# sso-saml extra（lxml/defusedxml）未安装时整模块跳过而非收集报错；
# CI 已安装该 extra（见 .github/workflows/ci.yml），正常环境会执行。
pytest.importorskip("lxml", reason="requires sso-saml extra")
pytest.importorskip("defusedxml", reason="requires sso-saml extra")

from lxml import etree  # noqa: E402

from maop.enterprise.saml_handler import SAMLHandler  # noqa: E402
from maop.enterprise.sso import SSOConfig, SSOError, SSOProvider  # noqa: E402

SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
ACS_URL = "https://sp.example.com/acs"
ENTITY_ID = "maop-sp"
STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _fmt(dt: datetime.datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── fixtures ────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def idp_keypair():
    """Self-signed IdP RSA keypair (module-scoped: keygen is expensive)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_utcnow() - datetime.timedelta(days=1))
        .not_valid_after(_utcnow() + datetime.timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    cert_b64 = base64.b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode("ascii")
    return private_key, cert_b64


@pytest.fixture
def handler(idp_keypair):
    _, cert_b64 = idp_keypair
    config = SSOConfig(
        provider=SSOProvider.SAML,
        saml_entity_id=ENTITY_ID,
        saml_acs_url=ACS_URL,
        saml_idp_cert=cert_b64,
    )
    return SAMLHandler(config)


# ── SAML response builders ──────────────────────────────────────────


def _build_assertion(
    *,
    name_id: str = "user@example.com",
    include_nameid: bool = True,
    audience: str = ENTITY_ID,
    include_conditions: bool = True,
    include_audience: bool = True,
    cond_not_before: datetime.datetime | None = None,
    cond_not_after: datetime.datetime | None = None,
    sc_recipient: str | None = ACS_URL,
    sc_not_after: datetime.datetime | None = None,
) -> etree._Element:
    now = _utcnow()
    nb = cond_not_before or (now - datetime.timedelta(minutes=5))
    noa = cond_not_after or (now + datetime.timedelta(minutes=10))
    sc_noa = sc_not_after or noa

    assertion = etree.Element(
        f"{{{SAML_NS}}}Assertion",
        nsmap={"saml": SAML_NS},
        attrib={
            "ID": f"_aid{secrets.token_hex(8)}",
            "Version": "2.0",
            "IssueInstant": _fmt(now),
        },
    )
    issuer = etree.SubElement(assertion, f"{{{SAML_NS}}}Issuer")
    issuer.text = "https://idp.example.com"

    subject = etree.SubElement(assertion, f"{{{SAML_NS}}}Subject")
    if include_nameid:
        name_id_el = etree.SubElement(subject, f"{{{SAML_NS}}}NameID")
        name_id_el.text = name_id
    sc = etree.SubElement(subject, f"{{{SAML_NS}}}SubjectConfirmation")
    sc.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    sc_data = etree.SubElement(sc, f"{{{SAML_NS}}}SubjectConfirmationData")
    if sc_recipient is not None:
        sc_data.set("Recipient", sc_recipient)
    sc_data.set("NotOnOrAfter", _fmt(sc_noa))

    if include_conditions:
        conditions = etree.SubElement(assertion, f"{{{SAML_NS}}}Conditions")
        conditions.set("NotBefore", _fmt(nb))
        conditions.set("NotOnOrAfter", _fmt(noa))
        if include_audience:
            ar = etree.SubElement(conditions, f"{{{SAML_NS}}}AudienceRestriction")
            aud = etree.SubElement(ar, f"{{{SAML_NS}}}Audience")
            aud.text = audience
    return assertion


def _sign_assertion(assertion: etree._Element, private_key) -> None:
    """Add an enveloped XML signature (exclusive c14n + RSA-SHA256) in place.

    Mirrors ``SAMLHandler._verify_signature``: the digest is computed over
    the assertion *without* the Signature child (enveloped-signature
    transform), and SignatureValue covers the exclusive-c14n SignedInfo.
    """
    assertion_id = assertion.get("ID")
    digest_c14n = etree.tostring(
        assertion, method="c14n", exclusive=True, with_comments=False
    )
    digest_b64 = base64.b64encode(hashlib.sha256(digest_c14n).digest()).decode()

    signed_info = etree.Element(f"{{{DS_NS}}}SignedInfo", nsmap={"ds": DS_NS})
    c14n_method = etree.SubElement(signed_info, f"{{{DS_NS}}}CanonicalizationMethod")
    c14n_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
    sig_method = etree.SubElement(signed_info, f"{{{DS_NS}}}SignatureMethod")
    sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
    reference = etree.SubElement(
        signed_info, f"{{{DS_NS}}}Reference", attrib={"URI": f"#{assertion_id}"}
    )
    transforms = etree.SubElement(reference, f"{{{DS_NS}}}Transforms")
    t_enveloped = etree.SubElement(transforms, f"{{{DS_NS}}}Transform")
    t_enveloped.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
    t_exc = etree.SubElement(transforms, f"{{{DS_NS}}}Transform")
    t_exc.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")
    digest_method = etree.SubElement(reference, f"{{{DS_NS}}}DigestMethod")
    digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
    digest_value = etree.SubElement(reference, f"{{{DS_NS}}}DigestValue")
    digest_value.text = digest_b64

    si_c14n = etree.tostring(
        signed_info, method="c14n", exclusive=True, with_comments=False
    )
    signature_value = private_key.sign(si_c14n, padding.PKCS1v15(), hashes.SHA256())

    signature = etree.Element(f"{{{DS_NS}}}Signature", nsmap={"ds": DS_NS})
    signature.append(signed_info)
    sv = etree.SubElement(signature, f"{{{DS_NS}}}SignatureValue")
    sv.text = base64.b64encode(signature_value).decode()
    assertion.insert(1, signature)  # after Issuer, per SAML schema order


def _response_b64(
    assertion: etree._Element,
    *,
    status: str = STATUS_SUCCESS,
    status_message: str = "",
) -> str:
    response = etree.Element(
        f"{{{SAMLP_NS}}}Response",
        nsmap={"samlp": SAMLP_NS, "saml": SAML_NS},
        attrib={
            "ID": f"_rid{secrets.token_hex(8)}",
            "Version": "2.0",
            "IssueInstant": _fmt(_utcnow()),
        },
    )
    status_el = etree.SubElement(response, f"{{{SAMLP_NS}}}Status")
    status_code = etree.SubElement(status_el, f"{{{SAMLP_NS}}}StatusCode")
    status_code.set("Value", status)
    if status_message:
        msg = etree.SubElement(status_el, f"{{{SAMLP_NS}}}StatusMessage")
        msg.text = status_message
    response.append(assertion)
    xml_bytes = etree.tostring(response, xml_declaration=False, encoding="utf-8")
    return base64.b64encode(xml_bytes).decode("ascii")


def _signed_response_b64(private_key, **assertion_kwargs) -> str:
    assertion = _build_assertion(**assertion_kwargs)
    _sign_assertion(assertion, private_key)
    return _response_b64(assertion)


# ── happy path ──────────────────────────────────────────────────────


def test_valid_response_creates_session(handler, idp_keypair):
    private_key, _ = idp_keypair
    session = handler.handle_response(_signed_response_b64(private_key))
    assert session.user.external_id == "saml:user@example.com"
    assert session.session_id
    assert session.expires_at > session.created_at


# ── P0 #1: assertion replay ─────────────────────────────────────────


def test_assertion_replay_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(private_key)
    handler.handle_response(b64)
    with pytest.raises(SSOError, match="[Rr]eplay"):
        handler.handle_response(b64)


def test_distinct_assertions_both_accepted(handler, idp_keypair):
    private_key, _ = idp_keypair
    handler.handle_response(_signed_response_b64(private_key))
    # a different assertion ID is not a replay
    session = handler.handle_response(_signed_response_b64(private_key))
    assert session.user.external_id == "saml:user@example.com"


# ── P0 #2: Conditions mandatory ─────────────────────────────────────


def test_missing_conditions_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(private_key, include_conditions=False)
    with pytest.raises(SSOError, match="Conditions"):
        handler.handle_response(b64)


def test_missing_audience_restriction_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(private_key, include_audience=False)
    with pytest.raises(SSOError, match="AudienceRestriction"):
        handler.handle_response(b64)


def test_audience_mismatch_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(private_key, audience="https://evil.example.com")
    with pytest.raises(SSOError, match="[Aa]udience"):
        handler.handle_response(b64)


def test_expired_conditions_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(
        private_key,
        cond_not_after=_utcnow() - datetime.timedelta(minutes=1),
        # keep SubjectConfirmation valid so the failure is attributed to
        # Conditions, not SubjectConfirmationData
        sc_not_after=_utcnow() + datetime.timedelta(minutes=10),
    )
    with pytest.raises(SSOError, match="NotOnOrAfter"):
        handler.handle_response(b64)


# ── StatusCode must be Success ──────────────────────────────────────


def test_non_success_status_rejected(handler, idp_keypair):
    # Status is checked before signature verification, so an unsigned
    # response with a failure status is sufficient.
    assertion = _build_assertion()
    b64 = _response_b64(
        assertion, status=STATUS_REQUESTER, status_message="blocked by policy"
    )
    with pytest.raises(SSOError, match="not Success"):
        handler.handle_response(b64)


def test_status_message_surfaced_in_error(handler, idp_keypair):
    assertion = _build_assertion()
    b64 = _response_b64(assertion, status=STATUS_REQUESTER, status_message="denied")
    with pytest.raises(SSOError, match="denied"):
        handler.handle_response(b64)


# ── P0 #3: NameID fail-closed ───────────────────────────────────────


def test_missing_nameid_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(private_key, include_nameid=False)
    with pytest.raises(SSOError, match="NameID"):
        handler.handle_response(b64)


def test_empty_nameid_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(private_key, name_id="")
    with pytest.raises(SSOError, match="NameID"):
        handler.handle_response(b64)


# ── SubjectConfirmation validation ──────────────────────────────────


def test_subject_confirmation_recipient_mismatch_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(private_key, sc_recipient="https://evil.example.com/acs")
    with pytest.raises(SSOError, match="Recipient"):
        handler.handle_response(b64)


def test_subject_confirmation_expired_rejected(handler, idp_keypair):
    private_key, _ = idp_keypair
    b64 = _signed_response_b64(
        private_key,
        sc_not_after=_utcnow() - datetime.timedelta(minutes=1),
        # keep Conditions valid so the failure is attributed to
        # SubjectConfirmationData, not Conditions
        cond_not_after=_utcnow() + datetime.timedelta(minutes=10),
    )
    with pytest.raises(SSOError, match="NotOnOrAfter"):
        handler.handle_response(b64)
