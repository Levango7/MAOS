"""Shared test fixtures for MAOS enterprise tests.

This conftest ensures both the MAOS enterprise package (``maop.enterprise``)
and the MAOP main package (``maop.config``, ``maop.core``, …) are importable.
MAOS uses a namespace package (``pkgutil.extend_path``) so the ``maop``
package is split across two repos:

  - ``F:\\Nexus\\MAOS\\maop\\``         → ``maop.enterprise.*``
  - ``F:\\Nexus\\MAOP\\py\\maop\\``     → ``maop.config.*``, ``maop.core.*``

We insert the MAOS repo root first so its namespace ``__init__.py`` runs
``pkgutil.extend_path`` and merges both directories into ``maop.__path__``.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

# ── Path setup ──────────────────────────────────────────────────────
# MAOS repo root (where this conftest lives: <root>/tests/conftest.py)
REPO_ROOT = Path(__file__).resolve().parent.parent

# Ensure maop.enterprise is importable (MAOS namespace package first).
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Locate the MAOP main package so maop.config / maop.core are importable.
# Try: env override (MAOP_REPO_PATH) → editable-installed distribution →
# sibling repo (../MAOP/py). 不再硬编码开发者机器绝对路径（旧实现写了
# F:\\Nexus\\MAOP\\py，换机器/CI 即失效）。
_maop_candidates: list[Path] = []
_env_maop = os.getenv("MAOP_REPO_PATH")
if _env_maop:
    _maop_candidates.append(Path(_env_maop))
# editable install 的主包（pip install -e maop-base/py 后 importlib 可解析）
try:
    import importlib.util as _ilu
    _spec = _ilu.find_spec("maop")
    if _spec and _spec.submodule_search_locations:
        for _loc in _spec.submodule_search_locations:
            _p = Path(_loc)
            if (_p / "config" / "edition.py").exists():
                _maop_candidates.append(_p.parent)
                break
except Exception:
    pass
_maop_candidates.append(REPO_ROOT.parent / "MAOP" / "py")  # ../MAOP/py

for _candidate in _maop_candidates:
    if (_candidate / "maop" / "config" / "edition.py").exists():
        if str(_candidate) not in sys.path:
            sys.path.append(str(_candidate))
        break

# ── Environment flags ───────────────────────────────────────────────
# Skip module integrity check in tests (dev escape hatch).
os.environ.setdefault("MAOP_SKIP_INTEGRITY", "1")
# Force test environment (non-production, no auth gate).
os.environ.setdefault("MAOP_ENV", "test")


# ── Fixtures ────────────────────────────────────────────────────────

@pytest.fixture
def license_key() -> str:
    """Load the test license key from ``data/test_license.key``.

    Skips the test if the file is missing (caller must run
    ``scripts/issue_test_license.py --write`` first).
    """
    key_file = REPO_ROOT / "data" / "test_license.key"
    if not key_file.exists():
        pytest.skip(
            "test_license.key not found — run "
            "scripts/issue_test_license.py --write first"
        )
    return key_file.read_text(encoding="utf-8").strip()


@pytest.fixture
def validator():
    """A :class:`LicenseValidator` instance (loads bundled public key)."""
    from maop.enterprise.license import LicenseValidator

    return LicenseValidator()


@pytest.fixture
def enterprise_edition():
    """Activate ENTERPRISE edition for the duration of a test.

    Uses ``set_edition`` (programmatic override) so tests don't depend on
    a valid license key being present in the environment.  The edition is
    reset to auto-detect after the test.
    """
    from maop.config.edition import Edition, reset_edition, set_edition

    set_edition(Edition.ENTERPRISE)
    yield
    reset_edition()