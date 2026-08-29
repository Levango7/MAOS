# MAOP Enterprise 安装指南

> 安装源说明：MAOP 主包（`maop-orchestrator`）与企业扩展（`maop-enterprise`）
> 均**未发布到 PyPI**，以下安装方式均基于 GitHub（无需 PyPI 账号，无需代理）。
> 将来若发布到 PyPI，可切回 `pip install maop-orchestrator>=5.1.0`。

## 前置条件

- Python 3.10 或更高版本
- MAOP 个人版 5.1.0+（从 GitHub 安装，见步骤 1）
- 有效的 MAOP Enterprise license key

## 安装步骤

### 1. 安装 MAOP 个人版（从 GitHub）

主包源码位于 MAOP 仓库的 `py/` 子目录（pip 需 `subdirectory=py`）：

```bash
pip install "maop-orchestrator @ git+https://github.com/Levango7/MAOP.git@master#subdirectory=py"
```

### 2. 安装 MAOP Enterprise 扩展

#### 方式 A：从 GitHub Releases 下载 wheel（推荐）

1. 打开 https://github.com/Levango7/MAOS/releases 下载
   `maop_enterprise-5.2.1-py3-none-any.whl`
2. 本地安装：

```bash
pip install ./maop_enterprise-5.2.1-py3-none-any.whl
```

#### 方式 B：从 Git 仓库直接安装

```bash
pip install git+ssh://git@github.com/Levango7/MAOS.git@master
```

### 3. 配置 License Key

#### 方式 A：环境变量（推荐）

```bash
export MAOP_LICENSE_KEY="MAOP-ENT-xxxxx.yyyy"
```

Windows PowerShell:
```powershell
$env:MAOP_LICENSE_KEY = "MAOP-ENT-xxxxx.yyyy"
```

#### 方式 B：License 文件

将 license key 写入 `data/license.key` 文件：

```bash
mkdir -p data
echo "MAOP-ENT-xxxxx.yyyy" > data/license.key
```

### 4. 安装可选依赖

根据需要安装可选依赖：

```bash
# PostgreSQL 后端
pip install maop-enterprise[postgresql]

# Redis 缓存/队列
pip install maop-enterprise[redis]

# RabbitMQ 消息队列
pip install maop-enterprise[rabbitmq]

# HashiCorp Vault 密钥管理
pip install maop-enterprise[vault]

# SAML SSO
pip install maop-enterprise[sso-saml]

# OIDC SSO
pip install maop-enterprise[sso-oidc]

# 所有可选依赖
pip install maop-enterprise[all]
```

### 5. 验证安装

```bash
python -c "
from maop.enterprise.license import LicenseValidator
v = LicenseValidator()
info = v.validate_from_env()
if info:
    print(f'License valid: {info.customer}, edition={info.edition}, expires={info.expires_at}')
else:
    print('No valid license found — running in personal edition')
"
```

## 升级

```bash
pip install --upgrade maop-enterprise
```

## 卸载

```bash
pip uninstall maop-enterprise
```

卸载后，MAOP 将自动降级为个人版（enterprise 路由返回 404）。

## 常见问题

### Q: 安装后 `import maop.enterprise` 失败
A: 确保 MAOP 个人版已安装（`pip install "maop-orchestrator @ git+https://github.com/Levango7/MAOP.git@master#subdirectory=py"`），且两个包安装在同一个 Python 环境中。

### Q: License 验证失败
A: 检查：
1. `MAOP_LICENSE_KEY` 环境变量是否设置正确
2. License key 是否过期
3. 系统时间是否正确

### Q: 如何获取 license key
A: 联系 MAOP 商务团队获取商业 license key。

### Q: 安装后 `maop.__version__` 丢失
A: 这是 namespace package 的已知行为。使用 `importlib.metadata.version("maop-orchestrator")` 获取版本号。