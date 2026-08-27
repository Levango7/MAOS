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

1. Install MAOP: `pip install maop-orchestrator>=5.1.0`
2. Install MAOP Enterprise: `pip install maop_enterprise-5.2.0-py3-none-any.whl`
3. Configure license: `export MAOP_LICENSE_KEY="your-license-key"`
4. Verify: `python -c "from maop.enterprise.license import LicenseValidator; print(LicenseValidator().validate_from_env())"`

## Known Limitations（已知限制，v5.2.0）

以下限制为当前版本的已知事实，部署前请评估（详见 `docs/security-audit-license.md` 与 CHANGELOG）：

1. **OIDC id_token 签名不验证**：callback 流程不校验 id_token 的 JWT 签名（未集成 JWKS），
   用户身份依赖 userinfo 端点 + 到 IdP 的 TLS。sub 缺失时 external_id 降级为 `oidc:unknown`，
   不会从未验签的 id_token 截取。
2. **SAML 严格验证**：v5.2.0 起强制要求 `Conditions`/`AudienceRestriction`、Success StatusCode、
   SubjectConfirmation 校验与断言重放防护。不符合 SAML2 规范的 IdP 响应会被拒绝。
3. **CRL 宽松模式离线降级**：默认（非严格）模式下，CRL 服务不可达且无本地缓存时
   license 仍被接受（跳过撤销检查）。高敏感部署请设置 `MAOP_CRL_STRICT=1`。
   无签名的旧格式 CRL 仍被接受（记录警告）。
4. **公钥文件可替换**：拥有文件系统写权限的攻击者可替换
   `maop/enterprise/keys/public_key.pem`。建议部署时将该目录设为只读，
   并评估 PyArmor 混淆（审计 6.1，尚未根治）。
5. **完整性校验逃生舱**：`MAOP_SKIP_INTEGRITY=1` 会跳过模块完整性校验，
   生产环境严禁设置。生产环境（`MAOP_ENV=production`）manifest 缺失或被篡改将阻断启动。
6. **License 指纹绑定需调用方配合**：`validate()` 仅在调用方传入 `expected_fingerprint`
   或 license 携带指纹时校验；业务层需显式调用 `enforce_max_users` / `feature_allowed`。
7. **SSO 会话 SQLite 后端为单节点**：`sso_session_store.py` 的 SQLite 持久化不支持
   多副本共享，跨副本部署需要共享存储或 Redis 后端（未实现）。
8. **系统时钟回拨无防护**：license 过期判断依赖本机时钟，无在线时间戳/回拨检测。