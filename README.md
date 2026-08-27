# MAOS — MAOP Enterprise Extension

> **Private repository. Commercial license.**
> 
> MAOS provides enterprise capabilities for MAOP (Multi-Agent Orchestration Platform):
> RBAC, multi-tenant isolation, SSO (OIDC + SAML), audit logging, HA, 
> license management, CRL, n8n integration, and cloud backends.

## Installation

See [Installation Guide](docs/installation-guide.md) for detailed setup instructions.

## Architecture

See ADR-016 and ADR-017 in the MAOP repository.

## License

Commercial. See LICENSE file.

## Quick Start

1. Install MAOP: `pip install maop>=5.1.0`
2. Install MAOP Enterprise: `pip install maop_enterprise-5.1.0-py3-none-any.whl`
3. Configure license: `export MAOP_LICENSE_KEY="your-license-key"`
4. Verify: `python -c "from maop.enterprise.license import LicenseValidator; print(LicenseValidator().validate_from_env())"`