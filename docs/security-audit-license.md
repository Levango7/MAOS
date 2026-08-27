# MAOP Enterprise License 防破解机制安全审计报告

- **审计日期**：2026-08-27
- **审计范围**：`maop/enterprise/license.py`、`maop/enterprise/crl.py`、`scripts/issue_license.py`
- **审计人员**：P2-5 子代理（自动化安全评审）
- **License 格式**：`MAOP-ENT-{base64url(payload_json)}.{base64url(signature)}`
- **签名算法**：Ed25519（RFC 8032）
- **公钥路径**：`maop/enterprise/keys/public_key.pem`
- **总体结论**：当前 license 防破解机制在**签名强度**与**降级安全**两个核心维度达到生产可用水平；**模块完整性**与**CRL 撤销**提供了纵深防御；主要残余风险集中在**公钥文件可替换**与**Python 源码可打补丁**两类本地攻击，需配合 PyArmor 混淆与文件系统权限管控进一步收敛。

---

## 整改跟踪（2026-08-28 更新，v5.2.0）

本审计报告中提出的部分建议已在 v5.2.0 落地，状态更新如下：

| 审计项 | 原状态 | 现状（2026-08-28） |
|---|---|---|
| 硬件指纹字段仅解析不校验（7.1 表） | ⚠️ 仅字段支持 | ✅ **已强制执行**（P0 #8）：`validate(key, expected_fingerprint=...)` 比对失败即拒绝；`enforce_max_users` / `feature_allowed` 供业务层消费 |
| 模块完整性校验为死代码，无调用点 | ⚠️ 已实现未接通 | ✅ **已接通启动路径**（P0 #7）：`maop.enterprise` 导入时执行 `verify_module_integrity()`；生产环境失败抛 `ModuleTamperError` 阻断；新增签名工具 `scripts/sign_enterprise_modules.py` |
| CRL 自身签名缺失（3.5 / 7.2.5） | ⚠️ 建议项 | ✅ **客户端验证已实现**（P1 #17）：带 `signature` 字段的 CRL 用打包 Ed25519 公钥验签，失败拒绝缓存与使用；无签名的旧格式 CRL 仍接受（记录 WARNING，向后兼容）。**服务端签名仍需部署方配合** |
| CRL 仅按 customer 字符串吊销 | ⚠️ 粒度不足 | ✅ **已支持 `license_id` 精确吊销**（P1 #17）：条目含 `license_id` 时精确匹配，否则回退 customer 匹配 |
| 测试密钥与生产密钥隔离（8.3 项 1） | ⚠️ 仅 .gitignore | ✅ **已加固**（P1 #15/#16）：`LicenseManager` 无签名私钥拒绝构造（不再自动生成临时密钥对）；`issue_test_license.py` 在 `MAOP_ENV=production` 时拒绝用测试密钥签发 |

**仍未解决项**（维持原报告结论）：6.1 公钥替换攻击面、6.3 时钟回拨、PyArmor 混淆（7.2.1）、在线激活（7.2.3）、密钥轮换（7.2.4）。

---

## 第1章 签名验证机制

### 1.1 算法强度

- **算法**：Ed25519（ Edwards-curve Digital Signature Algorithm over Curve25519）
- **公钥长度**：32 字节（256 bit）
- **签名长度**：64 字节（512 bit）
- **安全等级**：约 128 bit 等效对称强度
- **实现库**：`cryptography.hazmat.primitives.asymmetric.ed25519`

**结论**：Ed25519 是当前公认的高性能、高安全签名算法，抗侧信道攻击设计良好，签名长度短、验证快。在私钥不泄露的前提下，签名伪造在计算上不可行（约 2^128 次运算）。

**证据出处**：`license.py` 第 145-146 行导入 `Ed25519PublicKey`；第 295-298 行强制签名长度为 64 字节。

### 1.2 公钥加载与保护

公钥从 `maop/enterprise/keys/public_key.pem` 加载，路径硬编码于 `_PUBLIC_KEY_PATH`（`license.py` 第 65 行）。

加载流程（`_load_public_key`，第 142-163 行）：

1. 检查文件存在性，不存在抛 `LicenseError`
2. 调用 `serialization.load_pem_public_key` 解析 PEM
3. **类型校验**：`isinstance(public_key, Ed25519PublicKey)`，非 Ed25519 直接拒绝
4. 异常全部包装为 `LicenseError`

**结论**：加载流程具备类型校验，能拒绝被替换为其他算法（如 RSA）的公钥。但公钥文件本身**未做完整性校验**（无 manifest 签名覆盖 `public_key.pem` 自身），这是当前最大单一攻击面（详见第6章）。

### 1.3 签名验证流程

`_verify_signature`（第 302-310 行）调用 `self._public_key.verify(signature, payload)`，失败抛 `LicenseSignatureError`。

验证顺序（`validate` 方法，第 188-220 行）：

1. `_parse_key`：格式解析 + base64 解码 + 签名长度校验
2. `_verify_signature`：Ed25519 签名验证
3. `_parse_payload`：JSON 解析 + 必填字段校验 + 时区规范化
4. `_check_expiry`：过期 + 宽限期检查
5. `_check_revocation`：CRL 撤销检查

**结论**：验证顺序正确——先验签再解析 payload，避免对未签名数据做业务校验。签名验证在常量时间内完成（Ed25519 实现），无时序侧信道。

### 1.4 Payload 编码一致性

签发端（`issue_license.py`）与验证端（`license.py`）均使用 `json.dumps(payload, separators=(",", ":"))` 生成紧凑 JSON，并使用 `base64.urlsafe_b64encode(...).rstrip(b"=")` 去除 padding。

验证端 `_parse_key` 第 290-291 行使用 `base64.urlsafe_b64decode(payload_b64 + "==")` 容忍缺失 padding。

**结论**：编解码双向一致，无格式漂移风险。

---

## 第2章 过期检查机制

### 2.1 宽限期设计

- **宽限期**：7 天（`_GRACE_PERIOD_DAYS = 7`，第 62 行）
- **语义**：过期后 7 天内仍可用（`is_in_grace_period`，第 85-89 行），超过 7 天抛 `LicenseExpiredError`

**结论**：7 天宽限期对客户续费运维友好，但意味着过期后仍有 7 天攻击窗口。建议对高敏感场景可配置缩短为 0。

### 2.2 时区处理

- `issued_at` / `expires_at` 使用 `datetime.now(timezone.utc).isoformat()` 生成（UTC 带偏移）
- 验证端 `_parse_payload`（第 327-344 行）支持：
  - `Z` 后缀转换为 `+00:00`
  - naive datetime 补 UTC 时区
  - 已带时区的 datetime 直接使用
- `is_expired` / `is_in_grace_period` 均与 `datetime.now(timezone.utc)` 比较

**结论**：时区处理完备，无 naive vs aware 比较异常风险。客户机器时区设置不影响过期判断（全部归一化为 UTC）。

### 2.3 系统时钟篡改风险

**残余风险**：客户可篡改系统时钟回拨以延长 license 有效期。当前**无时钟防篡改机制**（如在线时间戳服务、最大回拨阈值）。

**缓解建议**：

- 短期：CRL 在线检查时附带服务器时间，检测时钟偏差超过阈值时拒绝
- 长期：在线激活时绑定服务器签发时间

---

## 第3章 CRL 撤销机制

### 3.1 架构

CRL（Certificate Revocation List）模块位于 `maop/enterprise/crl.py`，提供在线撤销能力。启用条件：环境变量 `MAOP_CRL_URL` 非空（`license.py` 第 171 行）。

检查时机：签名验证 + 过期检查通过后，`_check_revocation`（第 362-365 行）调用 `CRLChecker.check_license`。

### 3.2 数据流

```
validate() → _check_revocation() → CRLChecker.check_license()
                                        → _find_revocation(customer)
                                        → _get_crl()
                                            1. _load_cached_crl()    # 新鲜缓存（未过 TTL）
                                            2. _fetch_crl()          # HTTP 拉取
                                            3. _load_cached_crl_raw() # 过期缓存降级
```

### 3.3 缓存策略

- **缓存路径**：`data/crl_cache.json`（默认，第 104 行）
- **TTL**：3600 秒（默认，可由 `MAOP_CRL_CACHE_TTL_S` 覆盖）
- **原子写入**：先写 `.tmp` 再 `os.replace`（第 262-270 行），避免半写状态
- **最大过期**：7 天（`_DEFAULT_MAX_CACHE_AGE_S`，超过后即使宽松模式也 WARNING）

**结论**：缓存设计合理，原子写入避免竞态。TTL 可运维调参。

### 3.4 离线降级

| 场景 | 严格模式（`MAOP_CRL_STRICT=1`） | 宽松模式（默认） |
|---|---|---|
| 新鲜缓存可用 | 用缓存 | 用缓存 |
| 缓存过期 + 拉取成功 | 用新拉取 | 用新拉取 |
| 缓存过期 + 拉取失败 | 用过期缓存（>7天则抛 `CRLError`） | 用过期缓存（>7天 WARNING） |
| 无缓存 + 拉取失败 | **抛 `CRLError` 拒绝 license** | **允许 license**（仅依赖签名+过期） |

**结论**：宽松模式下离线降级会**绕过撤销检查**——已撤销客户在断网时仍可使用。这是可用性优先于安全性的权衡。高敏感部署应启用严格模式。

### 3.5 残余风险

- **回滚攻击**：攻击者保留旧版有效 CRL 缓存（未含撤销条目），断网时降级使用。`_load_cached_crl_raw` 仅按 mtime 判断新鲜度，未对 CRL 自身签名验证。
- **建议**：CRL 服务端应对 CRL JSON 做 Ed25519 签名，客户端用同一公钥验签，防止缓存被注入伪造撤销列表。
- **整改状态（2026-08-28）**：客户端验签已实现（P1 #17，`_verify_crl_signature`）——拉取到的 CRL 若带 `signature` 字段则验签，失败即拒绝（不缓存、不使用）。**残余窗口**：本地缓存文件本身仍可被回滚为旧版有效 CRL（mtime 检查可被同时篡改），且旧格式无签名 CRL 仍被接受；彻底收敛需服务端强制签名 + 严格模式。

---

## 第4章 模块完整性校验

### 4.1 机制概述

`verify_module_integrity`（`license.py` 第 377-508 行）对 enterprise 模块文件做 SHA-256 哈希校验 + manifest 签名验证。

- **Manifest 路径**：`maop/enterprise/_integrity_manifest.json`
- **Manifest 内容**：`{files: {rel_path: sha256}, signed_at, version, signature}`
- **签名**：manifest 自身被 Ed25519 签名（用同一公钥），防止攻击者篡改 manifest 适配修改后的文件

### 4.2 验证流程

1. **跳过开关**：`MAOP_SKIP_INTEGRITY=1` 时直接返回 `(True, "skipped")`（第 433-434 行）——测试逃生舱，生产不应设置
2. **Manifest 存在性**：缺失则 `_fail`（第 445-446 行）
3. **Manifest 签名验证**：重建 canonical payload（`sort_keys=True`），用 `LicenseValidator()._public_key` 验签（第 462-484 行）
4. **逐文件哈希校验**：对 manifest 中每个文件计算 SHA-256 比对（第 491-505 行）
5. **缺失文件检测**：文件不存在记为 `tampered`（第 497-498 行）

### 4.3 安全模型（引自代码 docstring 第 401-417 行）

**能检测**：
- 直接编辑 `rbac.py` / `audit.py` 等业务模块
- Manifest 删除（strict 模式抛 `ModuleTamperError`）
- Manifest 签名伪造（无私钥则验签失败）

**不能检测**：
- 直接 patch 掉 `verify_module_integrity` 函数本身（攻击者需同时替换公钥，但替换公钥会破坏正常 license 验证——形成相互制约）
- 内存 patch（import 后运行时修改）

**结论**：这是**抬高门槛（raising-the-bar）**控制，非绝对保护。与 PyArmor 混淆配合可显著提升逆向难度。

### 4.4 严格模式默认值

`strict` 默认值由 `MAOP_ENV` 决定（第 428 行）：`production` → True，其他 → False。

**结论**：开发环境宽松、生产环境严格，默认值合理。但 `MAOP_ENV` 可被攻击者环境变量覆盖——需配合部署时固化环境变量。

---

## 第5章 降级策略

### 5.1 降级矩阵

| 场景 | 行为 | 安全性 |
|---|---|---|
| 无 license key 配置 | → PERSONAL edition | ✅ 安全（不再 honor-system） |
| License key 存在但签名无效 | → PERSONAL + log error | ✅ 安全 |
| License key 存在但已过期（超宽限期） | 抛 `LicenseExpiredError` → 调用方降级 PERSONAL | ✅ 安全 |
| License key 有效但模块被篡改 | → PERSONAL（`verify_module_integrity` 失败） | ✅ 安全 |
| License key 有效 + 模块完整 | → ENTERPRISE | ✅ 正常 |
| CRL 严格模式 + 无法获取 CRL | 抛 `CRLError` → 调用方降级 PERSONAL | ✅ 安全 |
| CRL 宽松模式 + 无法获取 CRL | → ENTERPRISE（跳过撤销检查） | ⚠️ 可用性优先 |

### 5.2 Honor-System 移除

代码 docstring 第 24-30 行明确记载：2026-08-11 加固移除了 honor-system 机制（此前无 license 即授予 enterprise，属平凡绕过）。

**结论**：降级策略已加固，无 license 一律降级 PERSONAL，不存在"无 license 即 enterprise"的绕过路径。

---

## 第6章 攻击面分析

### 6.1 公钥替换攻击

- **攻击路径**：攻击者获取文件系统写权限，替换 `maop/enterprise/keys/public_key.pem` 为攻击者自签的公钥，随后用对应私钥签发任意 license
- **前置条件**：文件系统写权限（root / 同用户 / 进程权限）
- **当前防御**：无（公钥文件未纳入完整性 manifest 自校验）
- **残余风险**：**高**——这是当前最大单一攻击面
- **缓解建议**：
  1. 将 `public_key.pem` 纳入 `_integrity_manifest.json` 哈希清单（但 manifest 签名又依赖公钥——需引入二级根公钥或离线根公钥）
  2. 部署时将 `maop/enterprise/keys/` 目录设为只读 + chattr +i（Linux）/ ACL 只读（Windows）
  3. 长期：公钥硬编码到编译后的二进制扩展中（PyArmor 可选）

### 6.2 签名伪造攻击

- **攻击路径**：在不知道私钥的前提下，构造合法 (payload, signature) 对
- **前置条件**：破解 Ed25519
- **当前防御**：Ed25519 算法本身（128 bit 等效强度）
- **残余风险**：**可忽略**——计算上不可行（约 2^128 次运算）

### 6.3 回滚攻击

- **攻击路径**：攻击者保留一份历史有效 license（未过期、未撤销），替换当前 license 文件
- **前置条件**：文件系统写权限 + 持有历史有效 license
- **当前防御**：CRL 撤销机制（`MAOP_CRL_URL` 配置后生效）
- **残余风险**：**中**——CRL 宽松模式离线时降级，回滚 license 仍可用
- **缓解建议**：
  1. 在 payload 中加入 `issued_at` 单调性检查（新 license 必须晚于上次记录的 issued_at）
  2. 启用 CRL 严格模式
  3. CRL 缓存自身签名验证（防缓存回滚）

### 6.4 模块篡改攻击

- **攻击路径**：直接修改 `rbac.py` / `audit.py` 等业务模块，绕过权限/审计逻辑
- **前置条件**：文件系统写权限
- **当前防御**：`verify_module_integrity` SHA-256 哈希校验 + manifest 签名
- **残余风险**：**中**——能检测但依赖调用方正确降级；攻击者若同时 patch 掉 `verify_module_integrity` 则绕过（但需同时替换公钥，见 6.1）
- **缓解建议**：PyArmor 混淆 + 部署时模块目录只读

### 6.5 环境变量绕过

- **攻击路径**：设置 `MAOP_EDITION=enterprise` 试图绕过 license 检查
- **当前防御**：`LicenseValidator` 不读取 `MAOP_EDITION`，edition 由 license payload 决定
- **残余风险**：**无**——环境变量不影响 license 验证结果

**验证**：`license.py` 全文搜索无 `MAOP_EDITION` 读取；edition 字段来自 payload 第 322 行必填校验 + 第 346 行 `LicenseInfo(**data)`。

### 6.6 完整性跳过开关滥用

- **攻击路径**：设置 `MAOP_SKIP_INTEGRITY=1` 跳过模块完整性校验
- **前置条件**：进程环境变量控制权
- **当前防御**：无（设计为测试逃生舱，silent by design）
- **残余风险**：**中**——生产环境若误设或被注入则完整性校验失效
- **缓解建议**：
  1. 生产构建中通过编译期常量移除该开关（PyArmor 可配置）
  2. 部署时固化环境变量，禁止非白名单变量

### 6.7 Payload 可读性

- **特性**：License 是签名而非加密，客户可 base64 解码 payload 看到客户名、过期时间、features 等
- **风险**：信息泄露（客户名、授权范围可见）
- **评估**：**可接受**——这是业界 license 文件的常见设计（签名防篡改 ≠ 加密防泄露）。若需保密可叠加 AES 加密层，但会增加密钥管理复杂度。

---

## 第7章 改进建议

### 7.1 已具备基础

| 能力 | 状态 | 证据 |
|---|---|---|
| Ed25519 强签名 | ✅ 已实现 | `license.py` 第 145-146、302-310 行 |
| 过期 + 宽限期 | ✅ 已实现 | `_GRACE_PERIOD_DAYS = 7` |
| CRL 在线撤销 | ✅ 已实现 | `crl.py` 全模块 |
| CRL 缓存 + 离线降级 | ✅ 已实现 | `crl.py` 第 161-258 行 |
| 模块完整性校验 | ✅ 已实现 | `license.py` 第 377-508 行 |
| 无 license → PERSONAL 降级 | ✅ 已实现 | docstring 第 24-30 行 |
| 硬件指纹绑定字段 | ✅ 已强制执行（2026-08-28） | `validate(expected_fingerprint=...)` + `compute_machine_fingerprint`（P0 #8） |
| 生产级签发 CLI | ✅ 已实现 | `scripts/issue_license.py` |

### 7.2 建议增强项

#### 7.2.1 PyArmor 混淆（优先级：高）

- **目标**：提高 `license.py` / `crl.py` 逆向难度，防止 `verify_module_integrity` 被 patch
- **方案**：PyArmor 8+ 对 enterprise 模块做 RFT 模式混淆 + 虚拟化保护关键函数
- **收益**：将 patch 攻击从"文本编辑"提升到"二进制逆向 + 虚拟机破解"

#### 7.2.2 公钥完整性保护（优先级：高）

- **目标**：收敛公钥替换攻击面（6.1）
- **方案**：
  - 方案 A：引入离线根公钥（编译进扩展），二级公钥（`public_key.pem`）由根私钥签发，运行时验证二级公钥签名
  - 方案 B：部署时 `chattr +i` 锁定公钥文件 + 启动时校验公钥 SHA-256 与编译期常量一致
- **收益**：公钥替换需同时突破离线根密钥或文件系统不可变属性

#### 7.2.3 在线激活（优先级：中）

- **目标**：防系统时钟篡改 + 首次激活绑定硬件指纹
- **方案**：首次启动时向激活服务发送 `{license_key, machine_fingerprint}`，服务端返回 `{activation_token, server_time}`，本地缓存激活令牌
- **收益**：时钟篡改可由 `server_time` 检测；硬件绑定由服务端强制

#### 7.2.4 定期密钥轮换（优先级：中）

- **目标**：限制私钥泄露的爆炸半径
- **方案**：
  - License payload 增加 `key_id` 字段，公钥文件支持多 key（`public_key.{key_id}.pem`）
  - 每 2 年轮换一次，旧 key 签发的 license 在过期前继续有效，新签发用新 key
  - CRL 同时支持多 key 撤销
- **收益**：单 key 泄露不影响其他 key 签发的 license

#### 7.2.5 CRL 自身签名（优先级：中）——✅ 客户端验证已实现（2026-08-28，P1 #17）

- **目标**：防 CRL 缓存被注入伪造撤销列表 / 缓存回滚
- **方案**：CRL JSON 增加 `signature` 字段，服务端用同一 Ed25519 私钥签名，客户端验签
- **收益**：即使攻击者写入伪造 `data/crl_cache.json`，验签失败被拒绝
- **现状**：客户端 `_verify_crl_signature` 已实现（签名对象为去除 `signature` 字段的规范化 JSON，base64url 编码，用打包公钥验证）。待办：CRL 服务端上线签名 + 停止接受无签名 CRL

#### 7.2.6 License Payload 加密（优先级：低）

- **目标**：防客户名 / 授权范围信息泄露（6.7）
- **方案**：payload 用 AES-256-GCM 加密（密钥派生自 Ed25519 公钥 ECDH），signature 仍为 Ed25519
- **代价**：增加密钥管理复杂度，业界非主流
- **评估**：当前信息泄露风险可接受，**暂不推荐**

#### 7.2.7 issued_at 单调性检查（优先级：低）

- **目标**：防回滚攻击（6.3）
- **方案**：本地持久化最近一次有效 license 的 `issued_at`，新 license 必须满足 `issued_at >= last_issued_at`
- **代价**：需可靠本地存储（防攻击者删除记录文件）

---

## 第8章 审计结论

### 8.1 安全性评级

| 维度 | 评级 | 说明 |
|---|---|---|
| 签名强度 | ⭐⭐⭐⭐⭐ | Ed25519，128 bit，计算上不可伪造 |
| 降级安全 | ⭐⭐⭐⭐⭐ | 无 license → PERSONAL，honor-system 已移除 |
| 过期检查 | ⭐⭐⭐⭐ | UTC 归一化 + 宽限期，缺时钟防篡改 |
| 撤销能力 | ⭐⭐⭐⭐ | CRL 完整，宽松模式离线降级有窗口 |
| 模块完整性 | ⭐⭐⭐⭐ | SHA-256 + manifest 签名，缺公钥自保护 |
| 防本地攻击 | ⭐⭐⭐ | 公钥可替换 + Python 可 patch，需 PyArmor |
| 防远程攻击 | ⭐⭐⭐⭐⭐ | 无远程攻击面（CRL 仅出站 HTTP） |

### 8.2 总体评级

**生产可用（B+）**——核心签名与降级机制扎实，残余风险集中在本地文件系统攻击，需配合 PyArmor 混淆与部署时文件权限管控收敛至 A 级。

### 8.3 上线前必做项

1. ✅ 生产私钥存入 HSM/KMS，**绝不**入库（已 `.gitignore` `scripts/test_signing_key.pem`）
2. ⬜ 部署时 `maop/enterprise/keys/` 目录设只读 + 不可变属性
3. ⬜ 生产环境不设置 `MAOP_SKIP_INTEGRITY`
4. ⬜ 高敏感部署启用 `MAOP_CRL_STRICT=1`
5. ⬜ 评估 PyArmor 混淆 enterprise 模块

### 8.4 审计边界声明

本审计基于静态代码审查（`license.py` 508 行 + `crl.py` 302 行 + `issue_license.py`），**未**包含：

- 动态渗透测试
- PyArmor 混淆后的逆向分析
- 部署环境文件权限审计
- CRL 服务端安全审计

建议上述项在后续安全周期中补充。