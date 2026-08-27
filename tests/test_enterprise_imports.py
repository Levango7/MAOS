"""Tests that all enterprise modules are importable.

These tests verify the MAOS package surface area — every module that the
MAOP main package (or MAOS itself) references must be importable.  They do
*not* require ENTERPRISE edition to be active; importing a module should
not raise ``FeatureNotAvailable`` (only *instantiating* managers does).
"""
from __future__ import annotations


def test_import_rbac():
    """``maop.enterprise.rbac`` exposes ``RBACManager``."""
    from maop.enterprise.rbac import RBACManager  # noqa: F401


def test_import_tenant():
    """``maop.enterprise.tenant`` exposes ``TenantManager``."""
    from maop.enterprise.tenant import TenantManager  # noqa: F401


def test_import_sso():
    """``maop.enterprise.sso`` exposes ``SSOManager``."""
    from maop.enterprise.sso import SSOManager  # noqa: F401


def test_import_quota():
    """``maop.enterprise.quota`` exposes ``QuotaManager``."""
    from maop.enterprise.quota import QuotaManager  # noqa: F401


def test_import_audit():
    """``maop.enterprise.audit`` exposes ``EnterpriseAuditLogger``."""
    from maop.enterprise.audit import EnterpriseAuditLogger  # noqa: F401


def test_import_license():
    """``maop.enterprise.license`` exposes ``LicenseValidator`` + ``LicenseInfo``."""
    from maop.enterprise.license import LicenseInfo, LicenseValidator  # noqa: F401


def test_import_license_manager():
    """``maop.enterprise.license_manager`` module is importable."""
    import maop.enterprise.license_manager  # noqa: F401


def test_import_notification():
    """``maop.enterprise.notification`` sub-package is importable."""
    import maop.enterprise.notification  # noqa: F401


def test_import_notification_event_bus():
    """``maop.enterprise.notification.event_bus`` exposes ``EventBus``."""
    from maop.enterprise.notification.event_bus import EventBus  # noqa: F401


def test_import_ha():
    """``maop.enterprise.ha`` exposes ``HAManager``."""
    from maop.enterprise.ha import HAManager  # noqa: F401


def test_import_sso_registry():
    """``maop.enterprise.sso_registry`` exposes ``SSOProviderRegistry``."""
    from maop.enterprise.sso_registry import SSOProviderRegistry  # noqa: F401


def test_import_sso_store():
    """``maop.enterprise.sso_store`` exposes ``SSOProviderStore``."""
    from maop.enterprise.sso_store import SSOProviderStore  # noqa: F401


def test_import_audit_enhanced():
    """``maop.enterprise.audit_enhanced`` module is importable."""
    import maop.enterprise.audit_enhanced  # noqa: F401


def test_import_pg_persist():
    """``maop.enterprise.pg_persist`` module is importable."""
    import maop.enterprise.pg_persist  # noqa: F401


def test_import_container():
    """``maop.enterprise.container`` module is importable."""
    import maop.enterprise.container  # noqa: F401


def test_import_tls_auto():
    """``maop.enterprise.tls_auto`` module is importable."""
    import maop.enterprise.tls_auto  # noqa: F401


def test_import_n8n():
    """``maop.enterprise.n8n`` exposes ``N8nClient``."""
    from maop.enterprise.n8n import N8nClient  # noqa: F401


def test_import_crl():
    """``maop.enterprise.crl`` exposes ``CRLChecker``."""
    from maop.enterprise.crl import CRLChecker  # noqa: F401


def test_import_quota_middleware():
    """``maop.enterprise.quota_middleware`` module is importable."""
    import maop.enterprise.quota_middleware  # noqa: F401