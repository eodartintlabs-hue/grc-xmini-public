#!/usr/bin/env python3
"""
grc_common.py - Shared Standard-Library Utilities for GRC-xMINI Engines
=======================================================================

Classification: Internal Compliance & Engineering Specification
Target Frameworks: NIST SP 800-53 Rev. 5, FedRAMP High, DISA STIG
Zero External Dependencies: 100% Python 3 Standard Library.

Provides cross-engine utilities for:
  - Cryptographic SHA-256 file hashing (`sha256_file`)
  - Canonical UTC timestamps (`utc_now_iso`, `utc_now_str`)
  - Guarded workspace teardown (`safe_rmtree`) preventing accidental deletion
    of root, $HOME, repository root, or unverified directories
  - Numeric tuple version parsing & segment-safe EOL prefix matching
    (`parse_version`, `version_lt`, `version_matches_prefix`)
  - Unified FedRAMP ConMon severity & SLA policy constants
"""

import datetime
import hashlib
import os
import re
import shutil
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple, Union

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

# Unified FedRAMP Continuous Monitoring (ConMon) SLA Policy (in calendar days)
SLA_DAYS_POLICY: Dict[str, int] = {
    "CRITICAL": 30,
    "CAT I": 30,
    "HIGH": 30,
    "CAT II": 30,
    "MEDIUM": 90,
    "MODERATE": 90,
    "CAT III": 90,
    "LOW": 180,
    "INFORMATIONAL": 180,
    "INFO": 180,
}

# Numeric rank for sorting severities from highest risk (0) to lowest (5)
SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 0,
    "CAT I": 0,
    "HIGH": 1,
    "CAT II": 1,
    "MEDIUM": 2,
    "MODERATE": 2,
    "CAT III": 2,
    "UNVERIFIED": 2,
    "LOW": 3,
    "INFORMATIONAL": 4,
    "INFO": 4,
    "UNKNOWN": 5,
}


def sha256_file(file_path: Union[Path, str], block_size: int = 65536) -> str:
    """Computes the hex-encoded SHA-256 digest of a file."""
    path = Path(file_path)
    with open(path, "rb") as f:
        if hasattr(hashlib, "file_digest"):
            return hashlib.file_digest(f, "sha256").hexdigest()
        h = hashlib.sha256()
        while chunk := f.read(block_size):
            h.update(chunk)
        return h.hexdigest()


def utc_now_iso() -> str:
    """Returns current UTC timestamp in ISO-8601 format."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def utc_now_str(fmt: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    """Returns current UTC timestamp formatted with `fmt`."""
    return datetime.datetime.now(datetime.timezone.utc).strftime(fmt)


def utc_today() -> datetime.date:
    """Returns current UTC calendar date."""
    return datetime.datetime.now(datetime.timezone.utc).date()


def safe_rmtree(
    target_path: Union[Path, str],
    marker: Optional[str] = None,
    allowed_markers: Sequence[str] = ("bundle_provenance.json", "ami_provenance.json"),
) -> None:
    """
    Safely removes an ephemeral workspace directory after verifying:
      1. It is not `/`, `$HOME`, `REPO_ROOT`, `SCRIPT_DIR`, or an ancestor of `REPO_ROOT`.
      2. If `marker` is required (or `allowed_markers` provided for non-empty directories),
         at least one expected provenance/workspace marker exists inside `target_path`.
    """
    resolved = Path(target_path).resolve()
    home_dir = Path.home().resolve()

    forbidden = {
        Path("/").resolve(),
        home_dir,
        REPO_ROOT,
        SCRIPT_DIR,
        REPO_ROOT / "scripts",
        REPO_ROOT / "rules",
        REPO_ROOT / "templates",
        REPO_ROOT / "testing",
    }

    if resolved in forbidden or REPO_ROOT in resolved.parents and resolved == REPO_ROOT:
        raise ValueError(f"Refusing to delete protected directory: {resolved}")

    # Never allow deleting an ancestor of REPO_ROOT or HOME
    if resolved in REPO_ROOT.parents or resolved in home_dir.parents:
        raise ValueError(f"Refusing to delete ancestor directory: {resolved}")

    if not resolved.exists():
        return

    # If the directory is non-empty and marker enforcement is requested, verify marker presence
    if any(resolved.iterdir()):
        markers_to_check = [marker] if marker else list(allowed_markers)
        has_marker = any((resolved / m).exists() for m in markers_to_check if m)
        if not has_marker:
            raise ValueError(
                f"Refusing to delete directory '{resolved}': missing expected ephemeral workspace "
                f"marker ({', '.join(m for m in markers_to_check if m)})."
            )

    shutil.rmtree(resolved)


def parse_version(version_str: str) -> Tuple[int, ...]:
    """
    Extracts numeric segments from a version string as a tuple of integers
    for accurate semantic/numeric comparison (e.g., '9.0' -> (9, 0) < '41.0.0' -> (41, 0, 0)).
    Returns an empty tuple if no numeric segments are present.
    """
    if not version_str or version_str.strip().lower() in ("unknown", "n/a", "none"):
        return ()
    parts = re.findall(r"\d+", version_str)
    return tuple(int(p) for p in parts)


def version_lt(version_a: str, version_b: str) -> bool:
    """
    Returns True if `version_a` is strictly less than `version_b` using numeric segment tuples.
    Pads shorter tuples with trailing zeros so (1, 7) == (1, 7, 0).
    Returns False if either version cannot be parsed into numbers.
    """
    ta = parse_version(version_a)
    tb = parse_version(version_b)
    if not ta or not tb:
        return False
    max_len = max(len(ta), len(tb))
    ta_pad = ta + (0,) * (max_len - len(ta))
    tb_pad = tb + (0,) * (max_len - len(tb))
    return ta_pad < tb_pad


def version_matches_prefix(version_str: str, prefix_str: str) -> bool:
    """
    Returns True if `version_str` matches `prefix_str` on segment boundaries.
    For example, prefix '1.1.1' matches '1.1.1', '1.1.1k', '1.1.1.2',
    but does NOT match '1.1.10'.
    """
    v = version_str.strip()
    p = prefix_str.strip()
    if not v or not p:
        return False
    if v == p:
        return True
    if v.startswith(p):
        next_char = v[len(p)]
        return not next_char.isdigit()
    return False
