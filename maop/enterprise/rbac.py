"""MAOP Enterprise RBAC — Role-Based Access Control.

Extends core/auth.py with hierarchical roles, permission grants,
and resource-level access control for multi-user environments.

Role hierarchy:
  superadmin > admin > operator > viewer

Permission model:
  resource:action  (e.g. "agents:read", "config:write", "tenant:admin")
"""

from __future__ import annotations

import logging
from enum import Enum

from pydantic import BaseModel

from maop.config.edition import FeatureFlag, require_feature

logger = logging.getLogger(__name__)


class Role(str, Enum):
    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(str, Enum):
    AGENTS_READ = "agents:read"
    AGENTS_WRITE = "agents:write"
    AGENTS_EXECUTE = "agents:execute"
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    MEMORY_READ = "memory:read"
    MEMORY_WRITE = "memory:write"
    MODELS_READ = "models:read"
    MODELS_WRITE = "models:write"
    COST_READ = "cost:read"
    TENANT_READ = "tenant:read"
    TENANT_WRITE = "tenant:write"
    TENANT_ADMIN = "tenant:admin"
    AUDIT_READ = "audit:read"
    RBAC_READ = "rbac:read"
    RBAC_WRITE = "rbac:write"
    SYSTEM_ADMIN = "system:admin"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.SUPERADMIN: frozenset(Permission),
    Role.ADMIN: frozenset(set(Permission) - {Permission.TENANT_ADMIN, Permission.SYSTEM_ADMIN}),
    Role.OPERATOR: frozenset({
        Permission.AGENTS_READ, Permission.AGENTS_WRITE, Permission.AGENTS_EXECUTE,
        Permission.CONFIG_READ, Permission.MEMORY_READ, Permission.MEMORY_WRITE,
        Permission.MODELS_READ, Permission.COST_READ,
    }),
    Role.VIEWER: frozenset({
        Permission.AGENTS_READ, Permission.CONFIG_READ, Permission.MEMORY_READ,
        Permission.MODELS_READ, Permission.COST_READ,
    }),
}


class RoleGrant(BaseModel):
    user_id: str
    role: Role
    tenant_id: str = ""
    granted_by: str = ""
    granted_at: float = 0.0
    expires_at: float | None = None


class RBACManager:
    """Enterprise RBAC permission checker with optional PG persistence."""

    def __init__(self) -> None:
        require_feature(FeatureFlag.RBAC)
        self._grants: list[RoleGrant] = []
        self._pg: PgRBACStore | None = None
        try:
            from maop.enterprise.pg_persist import PgRBACStore
            pg = PgRBACStore()
            if pg.available:
                self._pg = pg
                self._load_from_pg()
        except Exception as e:
            logger.debug("ignored: %s", e, exc_info=True)

    def _load_from_pg(self) -> None:
        if not self._pg:
            return
        for row in self._pg.load_grants():
            self._grants.append(RoleGrant(
                user_id=row.get("user_id", ""),
                role=Role(row.get("role", "viewer")),
                tenant_id=row.get("tenant_id", ""),
                granted_by=row.get("granted_by", ""),
                granted_at=row.get("granted_at", 0.0),
                expires_at=row.get("expires_at"),
            ))

    def grant_role(
        self,
        user_id: str,
        role: Role,
        *,
        granted_by: str = "",
        tenant_id: str = "",
        expires_at: float | None = None,
    ) -> RoleGrant:
        """Grant a role to a user.

        C8 note: authorization is enforced at the HTTP layer
        (dashboard/routers/rbac.py require_admin). Callers invoking this
        method directly MUST perform their own authorization check.
        """
        import time as _time
        now = _time.time()
        # C8 fix: expires_at was accepted by the model but never settable
        # here nor persisted — temporary grants silently became permanent.
        grant = RoleGrant(
            user_id=user_id, role=role, tenant_id=tenant_id,
            granted_by=granted_by, granted_at=now, expires_at=expires_at,
        )
        self._grants.append(grant)
        if self._pg:
            self._pg.save_grant(user_id, role.value, tenant_id, granted_by, now, expires_at)
        logger.info("[rbac] Granted %s to user=%s tenant=%s by=%s expires_at=%s",
                    role.value, user_id, tenant_id, granted_by, expires_at)
        return grant

    def revoke_role(self, user_id: str, role: Role, tenant_id: str = "") -> bool:
        before = len(self._grants)
        self._grants = [
            g for g in self._grants
            if not (g.user_id == user_id and g.role == role and g.tenant_id == tenant_id)
        ]
        removed = before - len(self._grants)
        if removed:
            if self._pg:
                self._pg.delete_grant(user_id, role.value, tenant_id)
            logger.info("[rbac] Revoked %s from user=%s tenant=%s", role.value, user_id, tenant_id)
        return removed > 0

    @staticmethod
    def _is_active(grant: RoleGrant) -> bool:
        """C8 fix: expired grants must not confer roles/permissions."""
        if grant.expires_at is None:
            return True
        import time as _time
        return grant.expires_at > _time.time()

    def user_roles(self, user_id: str, tenant_id: str = "") -> list[Role]:
        return [
            g.role for g in self._grants
            if g.user_id == user_id
            and (not tenant_id or g.tenant_id in ("", tenant_id))
            and self._is_active(g)
        ]

    def user_permissions(self, user_id: str, tenant_id: str = "") -> frozenset[Permission]:
        roles = self.user_roles(user_id, tenant_id)
        perms: set[Permission] = set()
        for r in roles:
            perms |= ROLE_PERMISSIONS.get(r, frozenset())
        return frozenset(perms)

    def has_permission(self, user_id: str, permission: Permission, tenant_id: str = "") -> bool:
        return permission in self.user_permissions(user_id, tenant_id)

    def require_permission(self, user_id: str, permission: Permission, tenant_id: str = "") -> None:
        if not self.has_permission(user_id, permission, tenant_id):
            raise PermissionDenied(user_id, permission, tenant_id)

    def list_grants(self, user_id: str = "", tenant_id: str = "") -> list[RoleGrant]:
        # C8 fix: filter out expired grants so admin views reflect reality.
        result = [g for g in self._grants if self._is_active(g)]
        if user_id:
            result = [g for g in result if g.user_id == user_id]
        if tenant_id:
            result = [g for g in result if g.tenant_id in ("", tenant_id)]
        return result


class PermissionDenied(Exception):
    def __init__(self, user_id: str, permission: Permission, tenant_id: str) -> None:
        self.user_id = user_id
        self.permission = permission
        self.tenant_id = tenant_id
        super().__init__(f"User '{user_id}' lacks permission '{permission.value}' on tenant '{tenant_id}'")
