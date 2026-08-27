# Changelog

## [5.1.0] - 2026-08-27

### Added
- Initial enterprise extension package
- RBAC (Role-Based Access Control) with Role/Permission system
- Multi-tenant isolation with TenantManager
- SSO support (SAML + OIDC) with SSOManager
- Quota management with QuotaManager
- Enterprise audit logging with EnterpriseAuditLogger
- Enhanced audit with alert engine, event filtering, and statistics
- License validation with Ed25519 signature verification
- CRL (Certificate Revocation List) online revocation support
- Module integrity self-verification (anti-tamper)
- HA (High Availability) cluster management
- PostgreSQL persistence backends
- Notification system with multi-channel support
- n8n workflow integration
- TLS auto-cert management
- Container orchestration support

### Security
- Ed25519 license signing (not honor-system)
- Module integrity manifest verification
- CRL-based online license revocation
- Grace period after license expiry (7 days)
- Degrade to personal edition on invalid/expired license

### Infrastructure
- Hatchling build system (dual-wheel model, ADR-018)
- Test suite with 86 tests (RBAC, Tenant, Quota, License, Imports)
- CI workflow for Python 3.10-3.13
- Contract tests in MAOP main repository (37 tests)