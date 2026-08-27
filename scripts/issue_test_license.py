#!/usr/bin/env python3
"""Issue a test license for MAOP Enterprise.

Usage:
    python scripts/issue_test_license.py [--customer NAME] [--days N]

Output:
    Prints the license key string to stdout.
    Also writes it to data/test_license.key if --write is specified.

This script is for **testing only**. It uses the test signing key
(``scripts/test_signing_key.pem``) whose corresponding public key is
bundled in ``maop/enterprise/keys/public_key.pem``. In production,
licenses are signed by the MAOP commercial team with the production
private key (which is NOT in this repository).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def issue_license(
    private_key_path: Path,
    customer: str = "Test Customer",
    days: int = 365,
    max_users: int | None = None,
    features: list[str] | None = None,
) -> str:
    """Issue a test license key.

    Parameters
    ----------
    private_key_path : Path
        Path to the Ed25519 private key (PEM, PKCS8, unencrypted).
    customer : str
        Customer / organization name embedded in the license payload.
    days : int
        License validity in days from now.
    max_users : int | None
        Optional max concurrent users limit.
    features : list[str] | None
        Optional feature scope list.

    Returns
    -------
    str
        The license key string in format ``MAOP-ENT-{payload}.{signature}``.
    """
    # Load private key
    key_data = private_key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(
            f"Expected an Ed25519 private key, got {type(private_key).__name__}"
        )

    # Build payload
    now = datetime.now(timezone.utc)
    payload: dict[str, object] = {
        "customer": customer,
        "edition": "enterprise",
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat(),
    }
    if max_users is not None:
        payload["max_users"] = max_users
    if features is not None:
        payload["features"] = features

    # Sign — compact JSON (separators match LicenseValidator parsing)
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(payload_bytes)

    # Encode (URL-safe base64, strip padding — LicenseValidator tolerates this)
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    return f"MAOP-ENT-{payload_b64}.{sig_b64}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue test MAOP Enterprise license")
    parser.add_argument("--customer", default="Test Customer", help="Customer name")
    parser.add_argument("--days", type=int, default=365, help="License validity in days")
    parser.add_argument("--max-users", type=int, default=None, help="Max concurrent users")
    parser.add_argument(
        "--features",
        nargs="*",
        default=None,
        help="Feature scope (space-separated list)",
    )
    parser.add_argument(
        "--write", action="store_true", help="Write to data/test_license.key"
    )
    parser.add_argument(
        "--key",
        default="scripts/test_signing_key.pem",
        help="Private key path (relative to repo root)",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    key_path = repo_root / args.key
    if not key_path.exists():
        print(f"ERROR: private key not found at {key_path}", file=sys.stderr)
        sys.exit(1)

    license_key = issue_license(
        key_path, args.customer, args.days, args.max_users, args.features
    )

    if args.write:
        out_dir = repo_root / "data"
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / "test_license.key"
        out_path.write_text(license_key, encoding="utf-8")
        print(f"License written to {out_path}", file=sys.stderr)

    print(license_key)


if __name__ == "__main__":
    main()