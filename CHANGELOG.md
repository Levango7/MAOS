# Changelog

## [5.2.1] - 2026-08-29

全量代码审计（问题清单驱动）修复版。核心目标：激活"声称已修但实际是死代码"的安全
防护、修复商业链路断裂、统一分发产物。测试从 156 增至 164（新增 8 个真实路径
回归测试），覆盖率 52.03% → 53.40%。

### Security（死代码激活 / fail-closed）

- **SAML 重放防护激活**（P0）：`SSOManager` 改为进程内复用同一 `SAMLHandler`
  实例——此前每次回调新建 handler，`InResponseTo` 校验与 Assertion 重放表
  恒空，防护全部失效（v5.2.0 声称已修实为死代码）
- **OIDC userinfo fail-closed**（P0，**Breaking**）：userinfo 获取失败或缺失
  `sub` 时拒绝登录，不再降级 `oidc:unknown`（降级会把多个用户合并为同一身份，
  属认证缺陷）；README 已知限制同步更新
- **SAML XSW 防护补全**：签名元素既非 Assertion 也非 Response 时拒绝（补
  else 分支）；校验 `Reference URI` 与 signed element ID 一致
- **CRL 缓存读取路径验签**：带签名的缓存读取时验签、失败拒绝（此前仅拉取路径
  验签，本地缓存回滚/伪造存在绕过窗口）
- **n8n webhook fail-closed**：未配置 `N8N_WEBHOOK_SECRET` 时默认拒绝请求
  （旧实现静默放行），显式 `N8N_ALLOW_UNSIGNED=1` 为测试逃生舱
- **TLS 自动配置 fail-closed**：证书缺失/不匹配/创建失败不再静默降级明文
  HTTP，改抛 `TLSAutoConfigError`；`MAOP_ENV=production` 禁止自签蒙混
- **通知密钥存储 fail-closed**：移除 `plain:` 明文降级；兼容 cryptography 50
  移除 `Fernet.is_valid_key` 的兼容层
- **审计日志不可覆盖**：SQLite 保存改 `INSERT OR IGNORE`（原 `OR REPLACE`
  允许以相同 event_id 覆盖审计证据）

### Fixed（功能缺陷）

- **license_id 全链贯通**：`issue_license.py` / `issue_test_license.py` /
  `license_manager.create_license` 签发 payload 携带 `license_id`（此前缺失，
  CRL 只能退化按 customer 宽松匹配）；`renew` 保留 license_id；`update_license`
  修改授权字段（max_users/fingerprint/features/customer）时重签 license key
  （此前管理面与运行时授权值漂移）
- **RBAC 租户隔离**：`user_roles` 未显式传 tenant_id 时只匹配全局授权，
  不再合并用户在所有租户下的角色（跨租户权限泄漏入口）
- **tenant 校验**：`update_tenant` 对 status/quota 做类型校验（非法值拒绝）；
  `check_quota` 未知资源 fail-closed（此前拼错资源名即永久放行）
- **配额真实生效**：中间件由只读 `check_quota` 改为原子 `consume`（检查+扣减），
  配合 60s 读缓存不再让硬限制形同虚设；`consume` 内告警记录移出 SQLite 事务
  （消除嵌套写连接锁冲突）
- **告警引擎接线**：`EnterpriseAuditLogger` 支持注入 `AuditAlertEngine` 并在
  `log()` 后评估（此前引擎全仓库零调用点，规则永不触发）；新增 60s 同规则
  告警去重防风暴
- **审计查询 tags 过滤**：PG/SQLite 分支同步生效（此前仅内存分支过滤）
- **HA 修复**：抢主条件改为"无 leader 或 leader 失联"（此前每 tick 抢主导致
  抖动）；`release_leadership` 消除 check-then-act 竞态；`_nodes` 增加 TTL
  清理（此前无界增长）
- **n8n**：`list_workflows` 兼容 `{"data":[...]}` 与裸 list 两种响应（此前
  非 dict 响应抛 AttributeError）
- **notification**：`_deliver` 任务引用保存防 GC（投递从未执行的隐患）；
  EventBus sync handler 改 `asyncio.to_thread`（此前阻塞事件循环）

### Infrastructure / Docs

- **wheel 重建为 5.2.0**（此前 dist/ 是过期的 5.1.0）：含 `cryptography`/
  `httpx` 核心依赖、`sso-saml` extra 修正为 `lxml`+`defusedxml`、含
  `sso_session_store.py` 与 `_integrity_manifest.json`（force-include，
  生产 strict 模式启动校验依赖）；旧 5.1.0 wheel 保留于 dist/
- 完整性 manifest 用打包公钥配对私钥重签（仓库内自洽、校验通过）；
  发布说明：生产发行前必须用生产私钥重新签名 manifest
- 安装文档修正：包名 `maop` → `maop-orchestrator`、wheel 版本 5.2.0、
  分支 `@main` → `@master`、FAQ 版本查询包名
- `conftest.py` 移除硬编码 `F:\Nexus\MAOP\py` 绝对路径（改用 env 覆盖 +
  importlib 探测 + 相对探测）
- 完整性测试重构为 tmp 隔离（不再直接读写/删除仓库内真实 manifest 与模块，
  兼容沙箱/CI 安全删除策略）；`verify_module_integrity` 增加 `manifest_path`
  参数
- 失实 docstring 修正：`maop/enterprise/__init__.py`（backends 位于主包而非
  本包）、`quota.py`（无 ALTER 迁移，如实描述）
- `issue_license.py`：`--key` 改为必填并拒绝测试密钥（此前默认测试私钥，生产
  会静默产出无效 license）；新增 `--quiet`

### 未解决项（交付前评估）

- MAOP 主包尚未发布 PyPI（`maop-orchestrator`），按 README 安装需先发布
- SAML 仅支持 RSA-SHA256（RSA-PSS/ECDSA 待支持）；metadata 拉取无 HTTPS
  强制/SSRF 防护（可配 `https://` 规避）
- pg_persist 层错误处理与连接复用（无 PG 测试环境，留待有 PG CI 后处理）
- 租户用量双轨（PG 汇总列 vs SQLite 配额用量表）已文档化边界，未重构

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