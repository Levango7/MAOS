#!/usr/bin/env python3
"""Generate an ephemeral Ed25519 test signing keypair (CI only).

CI 专用：测试签名密钥 ``scripts/test_signing_key.pem`` 被 gitignore，
从不入库；CI 中在签发测试 license 之前运行本脚本动态生成一对临时密钥：

  - 私钥 → ``scripts/test_signing_key.pem``（供 issue_test_license.py 使用）
  - 公钥 → ``maop/enterprise/keys/public_key.pem``（覆盖打包公钥，
    使 LicenseValidator 能验证 CI 签发的测试 license）

**严禁用于生产**：生产 license 由商务团队用离线生产私钥签发，
生产私钥不在任何仓库/CI 中出现。

Usage:
    python scripts/ci_generate_test_key.py
"""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    repo_root = Path(__file__).resolve().parent.parent

    key = Ed25519PrivateKey.generate()

    private_path = repo_root / "scripts" / "test_signing_key.pem"
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )

    public_path = repo_root / "maop" / "enterprise" / "keys" / "public_key.pem"
    public_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    print(f"ephemeral test keypair generated: {private_path} + {public_path}")


if __name__ == "__main__":
    main()
