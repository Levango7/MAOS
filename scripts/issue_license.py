#!/usr/bin/env python3
"""Production license issuer for MAOP Enterprise.

This tool signs MAOP Enterprise license keys using an Ed25519 private key.
The private key MUST be kept secure and never committed to git.

Usage:
    # Issue a 1-year license
    python scripts/issue_license.py --customer "Acme Corp" --days 365 --key /path/to/private_key.pem

    # Issue with max users
    python scripts/issue_license.py --customer "Acme Corp" --days 365 --max-users 50 --key /path/to/private_key.pem

    # Issue with feature scope
    python scripts/issue_license.py --customer "Acme Corp" --days 365 --features rbac,audit,sso --key /path/to/private_key.pem

    # Issue with machine fingerprint
    python scripts/issue_license.py --customer "Acme Corp" --days 365 --fingerprint "ABCD-1234" --key /path/to/private_key.pem

    # Generate a new key pair
    python scripts/issue_license.py --gen-keys --public-out maop/enterprise/keys/public_key.pem --private-out /secure/path/private_key.pem

Security notes:
    - The private key must be stored in a secure location (HSM, KMS, or encrypted at rest)
    - Never commit the private key to git
    - License keys are signed, not encrypted — customers can decode the payload
    - Tamper protection comes from the Ed25519 signature verification
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# License key prefix and edition (must match LicenseValidator parsing)
_LICENSE_PREFIX = "MAOP-ENT-"
_LICENSE_EDITION = "enterprise"


def generate_keypair(public_out: Path, private_out: Path) -> None:
    """Generate a new Ed25519 key pair for license signing.

    Parameters
    ----------
    public_out : Path
        Destination path for the PEM-encoded public key
        (SubjectPublicKeyInfo format). Parent directories are created
        automatically.
    private_out : Path
        Destination path for the PEM-encoded private key (PKCS8,
        unencrypted). Parent directories are created automatically.
        Restrictive file permissions (0o600) are applied on POSIX
        systems; on Windows the chmod call is a no-op.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Write public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_out.parent.mkdir(parents=True, exist_ok=True)
    public_out.write_bytes(public_pem)
    print(f"Public key written to: {public_out}")

    # Write private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_out.parent.mkdir(parents=True, exist_ok=True)
    private_out.write_bytes(private_pem)
    # Set restrictive permissions on private key (POSIX only)
    try:
        os.chmod(private_out, 0o600)
    except OSError:
        # Windows doesn't support chmod the same way — rely on ACLs
        pass
    print(f"Private key written to: {private_out} (permissions: 600)")


def issue_license(
    private_key_path: Path,
    customer: str,
    days: int,
    max_users: int | None = None,
    fingerprint: str | None = None,
    features: list[str] | None = None,
) -> str:
    """Issue a signed MAOP Enterprise license key.

    Parameters
    ----------
    private_key_path : Path
        Path to the Ed25519 private key (PEM, PKCS8, unencrypted).
    customer : str
        Customer / organization name embedded in the license payload.
    days : int
        License validity in days from now (must be positive).
    max_users : int | None
        Optional max concurrent users limit. Omitted from payload when
        ``None`` (interpreted as unlimited by the validator).
    fingerprint : str | None
        Optional machine fingerprint binding. When set, the license is
        only valid on the machine whose fingerprint matches.
    features : list[str] | None
        Optional feature scope list (e.g. ``["rbac", "audit", "sso"]``).
        Omitted from payload when ``None`` (all features enabled).

    Returns
    -------
    str
        The license key string in format
        ``MAOP-ENT-{base64url(payload)}.{base64url(signature)}``.

    Raises
    ------
    FileNotFoundError
        If ``private_key_path`` does not exist.
    ValueError
        If the loaded key is not an Ed25519 private key, or ``days`` is
        non-positive, or ``customer`` is empty.
    """
    if not customer.strip():
        raise ValueError("customer name must not be empty")
    if days <= 0:
        raise ValueError(f"days must be positive, got {days}")

    # Load private key
    if not private_key_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_key_path}")
    key_data = private_key_path.read_bytes()
    private_key = serialization.load_pem_private_key(key_data, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError(
            f"Expected an Ed25519 private key, got {type(private_key).__name__}"
        )

    # Build payload (field order matters: must match LicenseValidator parsing)
    now = datetime.now(timezone.utc)
    payload: dict[str, object] = {
        "customer": customer,
        "edition": _LICENSE_EDITION,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat(),
    }
    if max_users is not None:
        if max_users <= 0:
            raise ValueError(f"max_users must be positive, got {max_users}")
        payload["max_users"] = max_users
    if fingerprint:
        payload["fingerprint"] = fingerprint
    if features:
        # Strip whitespace and drop empty entries
        cleaned = [f.strip() for f in features if f.strip()]
        if cleaned:
            payload["features"] = cleaned

    # Sign — compact JSON (separators match LicenseValidator parsing)
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(payload_bytes)

    # Encode (URL-safe base64, strip padding — LicenseValidator tolerates this)
    payload_b64 = base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii")
    sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

    return f"{_LICENSE_PREFIX}{payload_b64}.{sig_b64}"


def _parse_features(features_arg: str | None) -> list[str] | None:
    """Parse a comma-separated feature list into a list of feature names."""
    if not features_arg:
        return None
    return [f.strip() for f in features_arg.split(",") if f.strip()] or None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Production license issuer for MAOP Enterprise",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--gen-keys",
        action="store_true",
        help="Generate a new Ed25519 key pair",
    )
    parser.add_argument(
        "--public-out",
        type=Path,
        help="Output path for public key (required with --gen-keys)",
    )
    parser.add_argument(
        "--private-out",
        type=Path,
        help="Output path for private key (required with --gen-keys)",
    )
    parser.add_argument("--customer", help="Customer/organization name")
    parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="License validity in days (default: 365)",
    )
    parser.add_argument(
        "--max-users",
        type=int,
        default=None,
        help="Max concurrent users",
    )
    parser.add_argument(
        "--fingerprint",
        default=None,
        help="Machine fingerprint binding",
    )
    parser.add_argument(
        "--features",
        default=None,
        help="Comma-separated feature scope (e.g., rbac,audit,sso)",
    )
    parser.add_argument(
        "--key",
        default="scripts/test_signing_key.pem",
        help="Private key path (relative to repo root or absolute)",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write license to data/license.key",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        default=True,
        help="Print license to stdout (default: on)",
    )
    args = parser.parse_args()

    if args.gen_keys:
        if not args.public_out or not args.private_out:
            parser.error("--gen-keys requires --public-out and --private-out")
        generate_keypair(args.public_out, args.private_out)
        return

    if not args.customer:
        parser.error("--customer is required for license issuance")

    repo_root = Path(__file__).resolve().parent.parent
    key_path = Path(args.key)
    if not key_path.is_absolute():
        key_path = repo_root / key_path

    features_list = _parse_features(args.features)

    try:
        license_key = issue_license(
            key_path,
            args.customer,
            args.days,
            args.max_users,
            args.fingerprint,
            features_list,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.write:
        out_dir = repo_root / "data"
        out_dir.mkdir(exist_ok=True)
        out_path = out_dir / "license.key"
        out_path.write_text(license_key, encoding="utf-8")
        print(f"License written to {out_path}", file=sys.stderr)

    if args.stdout:
        print(license_key)


if __name__ == "__main__":
    main()