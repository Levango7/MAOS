# Changelog

## [5.2.0] - 2026-08-28

安全审计（25 项：10 P0 + 15 P1）修复版本。所有安全类缺失按严格 fail-closed 策略修复；
测试从 86 个增至 156 个，覆盖率 33.91% → 52.03%（CI 门禁 35%）。

### Breaking Changes

- **SAML 严格验证**：Response 必须包含 `Conditions` 与 `AudienceRestriction`（缺失即拒绝）；
  `StatusCode` 非 Success 拒绝；`SubjectConfirmationData` 的 `Recipient`/`NotOnOrAfter` 强制校验；
  新增 Assertion ID 重放防护（内存 TTL 去重）。不规范的 IdP 响应将被拒绝。
- **OIDC state 必填**：callback 缺少 `state` 参数直接拒绝（CSRF fail-closed），不再静默通过。
- **OIDC external_id 语义变化**：移除从未验签 id_token 截取 sub 的回退逻辑；
  sub 缺失时 external_id 降级为 `oidc:unknown`（此前是 id_token 前 16 字符）。
  依赖旧回退值关联用户的部署需要数据核对。
- **delete_license 改为软删除**：license 行标记 `status='deleted'` + `deleted_at`，
  审计日志不再删除（合规证据保留）；默认列表排除已删除 license。
- **SSO store 不再明文降级**：`cryptography` 缺失时直接报错而非明文存储；
  `cryptography`、`httpx` 升级为核心依赖。
- **issue_test_license.py 生产防护**：`MAOP_ENV=production` 时拒绝用测试密钥签发（`--force` 可覆盖）。

### Security (P0)

- SAML 断言重放防护：消费过的 Assertion ID 在 TTL 窗口内拒绝（#1）
- SAML `Conditions`/`AudienceRestriction` 缺失 fail-closed（#2）
- SAML `NameID` 缺失/为空拒绝，不再返回空字符串（#3）
- OIDC callback `state` 参数必填（#4）；authorize URL 改用 `urlencode` 正确编码（#6）
- OIDC id_token 未验签限制在 docstring 明确标注（依赖 TLS + userinfo，JWKS 待实现）（#5）
- 模块完整性校验接通启动路径：`maop.enterprise` 导入时执行 `verify_module_integrity`，
  生产环境（`MAOP_ENV=production`）manifest 缺失/校验失败抛 `ModuleTamperError` 阻断（#7）
- License `fingerprint`/`max_users`/`features` 字段强制执行：
  `validate(key, expected_fingerprint=...)`、`enforce_max_users`、`feature_allowed`（#8）
- CI 修复：MAOP 基础仓库 editable install（替代不存在的 PyPI `maop` 包）、
  CI 内动态生成临时签名密钥对（不再依赖入库密钥）、覆盖率门禁调整为 35%（#9）
- 配额中间件规则遮蔽修复：`concurrent_tasks` 规则先于 `api_calls` 匹配（#10）

### Fixed (P1)

- 审计日志 SQLite 兜底：PG 不可用/写入失败降级 SQLite（WAL），`event_id` 改用 UUID（#11）
- RBAC SQLite 持久化兜底 + `grant_role` 去重（ON CONFLICT DO NOTHING）（#12）
- SSO 会话/pending state 可选 SQLite 持久化（`sso_session_store.py`，跨进程重启存活）（#13）
- `delete_license` 软删除 + 审计日志保留（#14）
- `LicenseManager` 无签名私钥时拒绝构造（移除临时密钥对自动生成），签发/验证密钥隔离（#15）
- CRL 支持按 `license_id` 精确吊销（customer 回退兼容）；CRL JSON 支持 Ed25519 签名，
  验签失败拒绝缓存与使用（#17）
- 配额原子扣减：`check_quota` 单条 SQL 条件更新消除 TOCTOU；`update_usage` 结果钳制 ≥0
  （修复负增量被 `excluded.used` 钳制值吞掉导致释放语义失效的 bug）（#20）
- n8n 触发端点修正为 POST `/webhook/{path}` 与 `/webhook-test/{path}`（#21）
- notification `manager.stats()` 取 total 而非 rows 长度，返回 int 计数（#22）
- `tenant.update_tenant` 字段白名单（未知/只读字段如 `created_at` 不再被覆盖）（#23）
- HA `register_node` 增加鉴权钩子（callback 拒绝/异常 → PermissionError fail-closed）；
  移除 docstring 中未实现的 Redis pub/sub 描述（#24）
- TLS 证书/私钥加载后校验匹配（公钥比对）；移除 docstring 中未实现的 HSTS/轮换描述（#25）
- SSO store 移除对 `vault._fernet` 私有成员的访问；`cryptography` 缺失不再降级明文（#19）
- `saml_handler.py` docstring 修正：不再宣称"优先使用 xmlsec"（实际为 lxml 自研实现）（#18）

### Added

- `scripts/sign_enterprise_modules.py`：企业模块 SHA-256 manifest 签名工具
- `scripts/ci_generate_test_key.py`：CI 临时 Ed25519 密钥对生成器
- `maop/enterprise/sso_session_store.py`：SSO 会话/pending state SQLite 存储
- 新增测试文件：`test_saml_security.py`（14）、`test_oidc_security.py`（11）、
  `test_quota_middleware.py`（7）、`test_integrity.py`（7）、`test_p1_fixes.py`（31）

### Infrastructure

- 依赖声明修正：基础包 PyPI 名 `maop` → `maop-orchestrator`；`cryptography`/`httpx`
  移入核心依赖；`sso-saml` extra 由 `python3-saml` 改为实际使用的 `lxml` + `defusedxml`
- 测试套件 86 → 156 个测试；覆盖率 52.03%（门禁 35%）

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