# MAOS — MAOP Enterprise Extension

> **Commercial license — proprietary code.**
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

> 安装源说明：MAOP 主包与 MAOS 企业扩展均**未发布到 PyPI**，通过
> GitHub 直接安装 / GitHub Releases 分发（无需 PyPI 账号，无需代理）。

1. Install MAOP (from GitHub, subdirectory `py`):
   `pip install "maop-orchestrator @ git+https://github.com/Levango7/MAOP.git@master#subdirectory=py"`
2. Install MAOP Enterprise: 从 GitHub Releases 页面下载
   `maop_enterprise-5.2.1-py3-none-any.whl` 后
   `pip install ./maop_enterprise-5.2.1-py3-none-any.whl`
3. Configure license: `export MAOP_LICENSE_KEY="your-license-key"`
4. Verify: `python -c "from maop.enterprise.license import LicenseValidator; print(LicenseValidator().validate_from_env())"`

## Known Limitations（已知限制，v5.2.1）

以下限制为当前版本的已知事实，部署前请评估（详见 `docs/security-audit-license.md` 与 CHANGELOG）：

1. **OIDC id_token 签名不验证**：callback 流程不校验 id_token 的 JWT 签名（未集成 JWKS），
   用户身份依赖 userinfo 端点 + 到 IdP 的 TLS。**userinfo 获取失败或缺失 sub 时
   登录被拒绝（fail-closed）**——不会降级为 `oidc:unknown`（v5.2.0 曾降级
   unknown，会把多个用户合并为同一身份，属认证缺陷，已改为拒绝登录）。
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
9. **license 吊销依赖 CRL 服务端**：`LicenseManager.revoke_license` 只更新管理端
   本地状态；要让客户运行实例真正失效，需将吊销条目发布到 `MAOP_CRL_URL`
   指向的 CRL 服务（license 已携带 `license_id`，CRL 条目含 `license_id`
   即可精确吊销）。