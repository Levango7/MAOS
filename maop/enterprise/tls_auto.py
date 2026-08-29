"""MAOP Enterprise TLS Auto-Configuration.

When MAOP_EDITION=enterprise, TLS is auto-enabled with sensible defaults:
  - Auto-generate self-signed certs for development
  - Enforce TLSv1.2+ minimum
  - Cert/key pair match validation before SSL context creation (P1 #25)
  - Fail-closed: any config problem raises :class:`TLSAutoConfigError`
    (caller uvicorn fails to start rather than silently serving plaintext)

TODO(P1 #25): 以下能力在旧文档中声称存在但实际未实现：
  - HSTS headers（需中间件支持，当前无）
  - Certificate rotation hooks（无轮换调度/ACME 集成）
"""

from __future__ import annotations

import datetime
import logging
import os
from typing import Any

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)


class TLSAutoConfigError(Exception):
    """TLS cannot be configured with valid certificates.

    不再静默降级为无 TLS 明文服务：抛异常让调用方（uvicorn 启动）明确失败，
    与 sso_store / notification.store 的 fail-closed 修复一致。
    """


def auto_configure_tls() -> dict[str, Any]:
    """Auto-configure TLS settings for enterprise edition.

    Returns SSL context kwargs for uvicorn. Raises :class:`TLSAutoConfigError`
    if no usable certificates are available — fail-closed (no silent
    plaintext fallback). Self-signed certificates are only generated in
    non-production environments; in production missing certs abort startup.
    """
    require_feature(FeatureFlag.TLS_AUTO)

    cert_file = os.getenv("MAOP_TLS_CERT", "")
    key_file = os.getenv("MAOP_TLS_KEY", "")

    if cert_file and key_file and os.path.isfile(cert_file) and os.path.isfile(key_file):
        logger.info("[tls-auto] Using provided certificates: cert=%s", cert_file)
        return _build_ssl_kwargs(cert_file, key_file)

    env = os.getenv("MAOP_ENV", "development").lower()
    if env == "production":
        # 生产环境禁止自签蒙混：缺证书直接抛异常，uvicorn 启动失败而不是
        # 静默退回明文 HTTP。
        raise TLSAutoConfigError(
            "MAOP_TLS_CERT/MAOP_TLS_KEY not set or unreadable — refusing to "
            "start without TLS in production (self-signed fallback disabled)"
        )

    dev_cert, dev_key = _ensure_dev_certs()
    if not (dev_cert and dev_key):
        raise TLSAutoConfigError(
            "No TLS certificates available and auto-generation failed"
        )
    logger.error(
        "[tls-auto] Using auto-generated DEVELOPMENT certificates — DO NOT use in production"
    )
    return _build_ssl_kwargs(dev_cert, dev_key)


def _ensure_dev_certs() -> tuple[str, str]:
    cert_dir = os.path.join(os.getenv("MAOP_DATA_DIR", "data"), "tls")
    cert_path = os.path.join(cert_dir, "dev-cert.pem")
    key_path = os.path.join(cert_dir, "dev-key.pem")

    if os.path.isfile(cert_path) and os.path.isfile(key_path):
        # 复用已有证书前先校验有效期：证书过期必须重新生成（P1）。
        if _cert_is_valid(cert_path):
            return cert_path, key_path
        logger.error(
            "[tls-auto] Existing dev certificate at %s has expired — regenerating",
            cert_path,
        )

    try:
        os.makedirs(cert_dir, exist_ok=True)

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "MAOP Dev"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MAOP"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256())
        )

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        # 私钥文件权限收紧到仅属主可读写（Windows 无 POSIX 权限位，跳过）
        if os.name != "nt":
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass

        logger.info("[tls-auto] Generated development certificates in %s", cert_dir)
        return cert_path, key_path
    except ImportError:
        logger.error("[tls-auto] cryptography package not installed — cannot auto-generate dev certs")
        return "", ""
    except Exception as e:
        logger.error("[tls-auto] Failed to generate dev certs: %s", e)
        return "", ""


def _cert_is_valid(cert_file: str) -> bool:
    """Check a PEM certificate is currently inside its validity window.

    解析失败（文件损坏/非证书）视为无效（fail-closed），由调用方重新生成。
    """
    try:
        from cryptography import x509
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        now = datetime.datetime.now(datetime.timezone.utc)
        # 兼容新旧 cryptography：新版本提供 UTC-aware 属性，旧版本为 naive UTC
        not_after = getattr(cert, "not_valid_after_utc", None)
        not_before = getattr(cert, "not_valid_before_utc", None)
        if not_after is None:  # 旧版 cryptography
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
            not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        return not_before <= now < not_after
    except Exception as e:
        logger.warning("[tls-auto] Failed to parse certificate %s: %s", cert_file, e)
        return False


def _cert_key_pair_matches(cert_file: str, key_file: str) -> bool:
    """校验证书与私钥匹配（P1 #25）。

    比较 ``cert.public_key()`` 与私钥派生的公钥的 PEM 编码。
    读取/解析失败返回 False（fail-closed，由调用方拒绝启动 TLS）。
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509 import load_pem_x509_certificate

        cert_pem = open(cert_file, "rb").read()  # noqa: SIM115
        key_pem = open(key_file, "rb").read()  # noqa: SIM115
        cert = load_pem_x509_certificate(cert_pem)
        private_key = serialization.load_pem_private_key(key_pem, password=None)
        cert_pub = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_pub = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return cert_pub == key_pub
    except Exception as e:
        logger.error("[tls-auto] cert/key match validation failed: %s", e)
        return False


def _build_ssl_kwargs(cert_file: str, key_file: str) -> dict[str, Any]:
    # P1 #25: 证书/私钥不匹配时拒绝构造 SSL context（fail-closed，抛异常
    # 而非返回 {}，避免调用方静默降级为明文 HTTP）
    if not _cert_key_pair_matches(cert_file, key_file):
        raise TLSAutoConfigError(
            f"Certificate {cert_file} does not match private key {key_file} — "
            "refusing to build SSL context"
        )
    try:
        from maop.core.security.tls import TLSSettings, create_ssl_context
        min_ver = os.getenv("MAOP_TLS_MIN_VERSION", "TLSv1_2")
        ssl_ctx = create_ssl_context(TLSSettings(
            enabled=True, cert_file=cert_file, key_file=key_file, min_version=min_ver,
        ))
        if not ssl_ctx:
            raise TLSAutoConfigError(
                "create_ssl_context returned no context (TLS disabled?)"
            )
        return {"ssl": ssl_ctx}
    except TLSAutoConfigError:
        raise
    except Exception as e:
        raise TLSAutoConfigError(f"Failed to create SSL context: {e}") from e
