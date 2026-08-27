"""Basic functional tests for ``RBACManager`` (``maop.enterprise.rbac``).

Covers role granting, revocation, permission checking, and the role
hierarchy (superadmin > admin > operator > viewer).  All tests run with
ENTERPRISE edition activated via the ``enterprise_edition`` fixture.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def rbac(enterprise_edition):
    """A fresh ``RBACManager`` instance (no PG persistence in tests)."""
    from maop.enterprise.rbac import RBACManager

    return RBACManager()


# ── Role / Permission enums ─────────────────────────────────────────

def test_role_enum_has_expected_members():
    from maop.enterprise.rbac import Role

    assert Role.SUPERADMIN.value == "superadmin"
    assert Role.ADMIN.value == "admin"
    assert Role.OPERATOR.value == "operator"
    assert Role.VIEWER.value == "viewer"


def test_permission_enum_has_expected_members():
    from maop.enterprise.rbac import Permission

    assert Permission.AGENTS_READ.value == "agents:read"
    assert Permission.CONFIG_WRITE.value == "config:write"
    assert Permission.TENANT_ADMIN.value == "tenant:admin"


# ── Grant / revoke ──────────────────────────────────────────────────

def test_grant_role_returns_grant(rbac):
    from maop.enterprise.rbac import Role

    grant = rbac.grant_role("user1", Role.ADMIN, granted_by="admin")
    assert grant.user_id == "user1"
    assert grant.role == Role.ADMIN
    assert grant.granted_by == "admin"


def test_user_roles_after_grant(rbac):
    from maop.enterprise.rbac import Role

    rbac.grant_role("user1", Role.OPERATOR)
    roles = rbac.user_roles("user1")
    assert Role.OPERATOR in roles


def test_revoke_role(rbac):
    from maop.enterprise.rbac import Role

    rbac.grant_role("user1", Role.VIEWER)
    assert rbac.revoke_role("user1", Role.VIEWER)
    assert Role.VIEWER not in rbac.user_roles("user1")


def test_revoke_nonexistent_role_returns_false(rbac):
    from maop.enterprise.rbac import Role

    assert not rbac.revoke_role("ghost", Role.ADMIN)


# ── Permission checking ─────────────────────────────────────────────

def test_admin_has_agents_write(rbac):
    from maop.enterprise.rbac import Permission, Role

    rbac.grant_role("admin1", Role.ADMIN)
    assert rbac.has_permission("admin1", Permission.AGENTS_WRITE)


def test_viewer_lacks_agents_write(rbac):
    from maop.enterprise.rbac import Permission, Role

    rbac.grant_role("viewer1", Role.VIEWER)
    assert not rbac.has_permission("viewer1", Permission.AGENTS_WRITE)


def test_viewer_has_agents_read(rbac):
    from maop.enterprise.rbac import Permission, Role

    rbac.grant_role("viewer1", Role.VIEWER)
    assert rbac.has_permission("viewer1", Permission.AGENTS_READ)


def test_superadmin_has_all_permissions(rbac):
    from maop.enterprise.rbac import Permission, Role

    rbac.grant_role("root", Role.SUPERADMIN)
    for perm in Permission:
        assert rbac.has_permission("root", perm), f"superadmin lacks {perm}"


def test_require_permission_raises_when_missing(rbac):
    from maop.enterprise.rbac import Permission, Role
    from maop.enterprise.rbac import PermissionDenied

    rbac.grant_role("viewer1", Role.VIEWER)
    with pytest.raises(PermissionDenied):
        rbac.require_permission("viewer1", Permission.AGENTS_WRITE)


def test_require_permission_passes_when_present(rbac):
    from maop.enterprise.rbac import Permission, Role

    rbac.grant_role("viewer1", Role.VIEWER)
    # Should not raise
    rbac.require_permission("viewer1", Permission.AGENTS_READ)


# ── Tenant isolation ────────────────────────────────────────────────

def test_grant_is_tenant_scoped(rbac):
    from maop.enterprise.rbac import Role

    rbac.grant_role("user1", Role.ADMIN, tenant_id="tenantA")
    # Role visible in tenantA
    assert Role.ADMIN in rbac.user_roles("user1", tenant_id="tenantA")
    # Role NOT visible in tenantB
    assert Role.ADMIN not in rbac.user_roles("user1", tenant_id="tenantB")


# ── List grants ─────────────────────────────────────────────────────

def test_list_grants_empty(rbac):
    assert rbac.list_grants() == []


def test_list_grants_after_grant(rbac):
    from maop.enterprise.rbac import Role

    rbac.grant_role("user1", Role.ADMIN)
    rbac.grant_role("user2", Role.VIEWER)
    grants = rbac.list_grants()
    assert len(grants) == 2


def test_list_grants_filtered_by_user(rbac):
    from maop.enterprise.rbac import Role

    rbac.grant_role("user1", Role.ADMIN)
    rbac.grant_role("user2", Role.VIEWER)
    grants = rbac.list_grants(user_id="user1")
    assert len(grants) == 1
    assert grants[0].user_id == "user1"