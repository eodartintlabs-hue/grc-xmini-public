#!/usr/bin/env python3
"""
grc_common.py - Shared Standard-Library Utilities & Policy Loaders for GRC-xMINI
================================================================================

Classification: Internal Compliance & Engineering Specification
Target Frameworks: NIST SP 800-53 Rev. 5, FedRAMP High, DISA STIG
Zero External Dependencies: 100% Python 3 Standard Library.

Provides cross-engine utilities for:
  - Cryptographic SHA-256 file hashing (`sha256_file`)
  - Canonical UTC timestamps (`utc_now_iso`, `utc_now_str`, `utc_today`)
  - Guarded workspace teardown (`safe_rmtree`) preventing accidental deletion
    of root, $HOME, repository root, or unverified directories
  - Numeric tuple version parsing & segment-safe EOL prefix matching
    (`parse_version`, `version_lt`, `version_matches_prefix`)
  - Unified FedRAMP ConMon severity & SLA policy loader (`rules/severity_policy.json`)
  - Unified DISA STIG & SRG catalog loader (`rules/stig_catalog.json`)
  - Standardized output writer (`write_output`)
"""

import datetime
import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RULES_DIR = REPO_ROOT / "rules"
SEVERITY_POLICY_PATH = RULES_DIR / "severity_policy.json"
STIG_CATALOG_PATH = RULES_DIR / "stig_catalog.json"
FINDING_SCHEMA_PATH = RULES_DIR / "finding_schema.json"
FIPS_ALGORITHM_POLICY_PATH = RULES_DIR / "fips_algorithm_policy.json"
CMVP_CATALOG_PATH = RULES_DIR / "cmvp_catalog.json"

# Built-in fallback severity policy if rules/severity_policy.json is unavailable
_FALLBACK_SEVERITY_POLICY: Dict[str, Tuple[str, int]] = {
    "CRITICAL": ("CAT I", 30),
    "HIGH": ("CAT II", 30),
    "MEDIUM": ("CAT II", 90),
    "LOW": ("CAT III", 180),
    "INFO": ("CAT III", 180),
}

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


def load_severity_policy(path: Optional[Path] = None) -> Dict[str, Tuple[str, int]]:
    """
    Loads the canonical severity -> (DISA CAT level, FedRAMP SLA days) table from
    `rules/severity_policy.json` (with safe fallback to built-in policy).
    """
    target = Path(path) if path else SEVERITY_POLICY_PATH
    if target.is_file():
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            sev_block = data.get("severities", {})
            if isinstance(sev_block, dict) and sev_block:
                policy: Dict[str, Tuple[str, int]] = {}
                for k, v in sev_block.items():
                    cat = str(v.get("cat_level", "CAT II"))
                    sla = int(v.get("sla_days", 90))
                    policy[k.upper()] = (cat, sla)
                    for alias in v.get("aliases", []):
                        SLA_DAYS_POLICY[str(alias).upper()] = sla
                return policy
        except Exception:
            pass
    return dict(_FALLBACK_SEVERITY_POLICY)


SEVERITY_POLICY: Dict[str, Tuple[str, int]] = load_severity_policy()


def normalize_severity(raw_severity: Optional[str], default: str = "MEDIUM") -> str:
    """
    Normalizes heterogeneous scanner severity strings ('Critical', 'ERROR', 'MODERATE',
    'Negligible', 'CAT I', etc.) to canonical ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO').
    """
    if not raw_severity:
        return default
    s = str(raw_severity).strip().upper()
    if s in ("CRITICAL", "CRIT", "VERY HIGH", "CAT I", "CAT 1", "CAT-I"):
        return "CRITICAL"
    if s in ("HIGH", "ERROR", "IMPORTANT", "CAT II", "CAT 2", "CAT-II"):
        return "HIGH"
    if s in ("MEDIUM", "MODERATE", "MOD", "MED", "WARNING", "WARN", "UNVERIFIED", "CAT III", "CAT 3", "CAT-III"):
        return "MEDIUM"
    if s in ("LOW", "MINOR", "NEGLIGIBLE"):
        return "LOW"
    if s in ("INFO", "INFORMATIONAL", "NONE", "UNKNOWN"):
        return "INFO"
    return default


def get_severity_policy(raw_severity: Optional[str]) -> Tuple[str, str, int]:
    """
    Returns `(canonical_severity, cat_level, sla_days)` for any raw severity label.
    """
    canon = normalize_severity(raw_severity)
    cat_level, sla_days = SEVERITY_POLICY.get(canon, ("CAT II", 90))
    return canon, cat_level, sla_days


def load_stig_catalog(path: Optional[Path] = None) -> Dict[str, Dict[str, Any]]:
    """Loads the `catalog` section of `rules/stig_catalog.json`."""
    target = Path(path) if path else STIG_CATALOG_PATH
    if target.is_file():
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            catalog = data.get("catalog", {})
            if isinstance(catalog, dict) and catalog:
                return catalog
        except Exception:
            pass
    return {}


def load_os_stig_mapping(path: Optional[Path] = None) -> Dict[str, Dict[str, str]]:
    """Loads the `os_stig_mapping` section of `rules/stig_catalog.json`."""
    target = Path(path) if path else STIG_CATALOG_PATH
    if target.is_file():
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            mapping = data.get("os_stig_mapping", {})
            if isinstance(mapping, dict) and mapping:
                return mapping
        except Exception:
            pass
    return {}


def write_output(text: str, output_path: Optional[Union[Path, str]] = None) -> None:
    """
    Writes formatted output `text` to `output_path` (creating parent directories if needed),
    or prints to stdout when `output_path` is None.
    """
    if output_path:
        out = Path(output_path).resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
        print(f"[SUCCESS] Report written to: {out}")
    else:
        print(text)


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


def _restore_write_and_retry(func: Any, path: str, _exc_info: Any) -> None:
    """Restores owner write permission on read-only workspace files/dirs during teardown."""
    try:
        p = Path(path)
        if not p.is_symlink():
            mode = stat.S_IRWXU if p.is_dir() else (stat.S_IRUSR | stat.S_IWUSR)
            os.chmod(path, mode)
    except OSError:
        pass
    func(path)


def safe_rmtree(
    target_path: Union[Path, str],
    marker: Optional[str] = None,
    allowed_markers: Sequence[str] = (
        "bundle_provenance.json",
        "ami_provenance.json",
        "fips_provenance.json",
    ),
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

    shutil.rmtree(resolved, onerror=_restore_write_and_retry)


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


# ==============================================================================
# NORMALIZED FINDING ENVELOPE (v1.0.0) HELPERS & STDLIB VALIDATOR
# ==============================================================================

_SCHEMA_VER_RE = re.compile(r"^1\.\d+\.\d+$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_CONTROL_ID_RE = re.compile(r"^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$")
_AOC_ID_RE = re.compile(r"^AOC-\d{2,3}$")
_FINDING_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
_DET_DETAIL_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_CMVP_CERT_RE = re.compile(r"^\d{1,5}$")

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_DETERMINATIONS = {"FAIL", "WARN", "NEEDS_REVIEW", "CANNOT_DETERMINE_STATICALLY", "PASS"}
VALID_SUBJECT_KINDS = {
    "algorithm",
    "protocol",
    "package",
    "module",
    "config_setting",
    "secret",
    "vulnerability",
    "iac_resource",
    "code_pattern",
}
VALID_PURPOSES = {
    "signature",
    "hashing",
    "hmac",
    "encryption",
    "key_agreement",
    "kdf",
    "rng",
    "non_security",
    "unknown",
}
VALID_LOCATION_KINDS = {"file", "manifest", "package", "host", "image"}
VALID_DETECTION_METHODS = {"ast", "lexical", "manifest", "lockfile", "config", "binary", "external_tool"}
VALID_CONFIDENCES = {"HIGH", "MEDIUM", "LOW"}
VALID_FIPS_STATUSES = {"VALIDATED_MODULE", "CAPABLE_IF_CONFIGURED", "NOT_VALIDATED", "UNKNOWN"}
VALID_CERT_STANDARDS = {"FIPS 140-2", "FIPS 140-3"}
VALID_CERT_STATUSES = {"Active", "Historical", "Revoked", "Unknown"}


def make_finding_id(
    engine_prefix: str,
    rule_id: str,
    location_path: str = "",
    line_start: Optional[int] = None,
    subject_name: str = "",
) -> str:
    """
    Generates a deterministic schema finding_id:
    `<prefix>-<first 16 hex of sha256(engine|rule_id|path|line_start|subject.name)>`.
    """
    prefix = re.sub(r"[^a-z0-9]", "", engine_prefix.lower()) or "finding"
    raw = f"{prefix}|{rule_id}|{location_path}|{line_start or ''}|{subject_name.lower()}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}-{digest}"


def split_aoc(raw_aoc: str, default_id: str = "AOC-09") -> Dict[str, str]:
    """Splits 'AOC-09: Crypto Dependencies...' into {'id': 'AOC-09', 'title': '...'}."""
    text = str(raw_aoc or "").strip()
    if ":" in text:
        left, right = text.split(":", 1)
        cand = left.strip().upper().replace(" ", "-")
        if _AOC_ID_RE.match(cand):
            res: Dict[str, str] = {"id": cand}
            if right.strip():
                res["title"] = right.strip()
            return res
    m = re.search(r"AOC[-\s]?(\d{2,3})", text, re.IGNORECASE)
    if m:
        aoc_id = f"AOC-{m.group(1)}"
        return {"id": aoc_id, "title": text}
    return {"id": default_id, "title": text or "Security Policy Check"}


def get_catalog_descriptor(catalog_path: Union[Path, str], rel_label: Optional[str] = None) -> Dict[str, str]:
    """Builds an `engine.catalogs[]` descriptor with version, sha256, and last_updated."""
    p = Path(catalog_path)
    desc: Dict[str, str] = {"path": p.name, "version": "1.0.0"}
    if rel_label:
        desc["path"] = rel_label
    elif p.is_absolute() and REPO_ROOT in p.resolve().parents:
        desc["path"] = str(p.resolve().relative_to(REPO_ROOT)).replace("\\", "/")
    else:
        desc["path"] = str(p).replace("\\", "/")

    if p.is_file():
        desc["sha256"] = sha256_file(p)
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            meta = data.get("catalog_metadata", {}) if isinstance(data, dict) else {}
            if isinstance(meta, dict):
                if meta.get("version"):
                    desc["version"] = str(meta["version"])
                last_upd = meta.get("last_updated") or meta.get("retrieved_at")
                if isinstance(last_upd, str) and len(last_upd) >= 10:
                    desc["last_updated"] = last_upd[:10]
        except Exception:
            pass
    return desc


def validate_finding_envelope(payload: Any) -> List[str]:
    """
    Validates a Normalized Finding Envelope dictionary against `rules/finding_schema.json`
    using 100% Python 3 stdlib. Returns a list of validation error messages (empty if valid).
    """
    errors: List[str] = []
    if not isinstance(payload, dict):
        return ["Root payload must be a JSON object."]

    allowed_top = {"schema_version", "engine", "generated_at", "target", "scope", "findings"}
    req_top = {"schema_version", "engine", "generated_at", "scope", "findings"}
    for k in req_top - set(payload.keys()):
        errors.append(f"Missing required root field: '{k}'")
    for k in set(payload.keys()) - allowed_top:
        errors.append(f"Unexpected root field: '{k}'")

    sv = payload.get("schema_version")
    if sv is not None and (not isinstance(sv, str) or not _SCHEMA_VER_RE.match(sv)):
        errors.append(f"Invalid schema_version: {sv!r}")

    eng = payload.get("engine")
    if isinstance(eng, dict):
        for rk in ("name", "version"):
            if not isinstance(eng.get(rk), str) or not eng.get(rk):
                errors.append(f"engine.{rk} must be a non-empty string")
        for uk in set(eng.keys()) - {"name", "version", "catalogs"}:
            errors.append(f"Unexpected engine field: '{uk}'")
        cats = eng.get("catalogs")
        if cats is not None:
            if not isinstance(cats, list):
                errors.append("engine.catalogs must be an array")
            else:
                for idx, c in enumerate(cats):
                    if not isinstance(c, dict):
                        errors.append(f"engine.catalogs[{idx}] must be an object")
                        continue
                    for rk in ("path", "version"):
                        if not isinstance(c.get(rk), str) or not c.get(rk):
                            errors.append(f"engine.catalogs[{idx}].{rk} required")
                    for uk in set(c.keys()) - {"path", "version", "sha256", "last_updated"}:
                        errors.append(f"Unexpected engine.catalogs[{idx}] field: '{uk}'")
                    if "sha256" in c and (not isinstance(c["sha256"], str) or not _SHA256_RE.match(c["sha256"])):
                        errors.append(f"Invalid engine.catalogs[{idx}].sha256")
    elif eng is not None:
        errors.append("engine must be an object")

    if "generated_at" in payload and not isinstance(payload.get("generated_at"), str):
        errors.append("generated_at must be an ISO-8601 string")

    tgt = payload.get("target")
    if tgt is not None:
        if not isinstance(tgt, dict):
            errors.append("target must be an object")
        else:
            for uk in set(tgt.keys()) - {"identifier", "provenance_file", "commit"}:
                errors.append(f"Unexpected target field: '{uk}'")

    scope = payload.get("scope")
    if isinstance(scope, dict):
        if "assessed_controls" not in scope or not isinstance(scope.get("assessed_controls"), list):
            errors.append("scope.assessed_controls must be an array")
        else:
            for ctl in scope["assessed_controls"]:
                if not isinstance(ctl, str) or not _CONTROL_ID_RE.match(ctl):
                    errors.append(f"Invalid scope.assessed_controls entry: {ctl!r}")
        for aoc_item in scope.get("assessed_aocs", []) or []:
            if not isinstance(aoc_item, str) or not _AOC_ID_RE.match(aoc_item):
                errors.append(f"Invalid scope.assessed_aocs entry: {aoc_item!r}")
        for uk in set(scope.keys()) - {"assessed_controls", "assessed_aocs", "ecosystems", "limitations"}:
            errors.append(f"Unexpected scope field: '{uk}'")
    elif scope is not None:
        errors.append("scope must be an object")

    findings = payload.get("findings")
    if not isinstance(findings, list):
        errors.append("findings must be an array")
        return errors

    req_finding = {
        "finding_id",
        "rule_id",
        "aoc",
        "controls",
        "determination",
        "subject",
        "location",
        "detection",
        "title",
        "message",
    }
    allowed_finding = req_finding | {
        "determination_detail",
        "severity",
        "remediation",
        "evidence",
        "extensions",
    }

    for i, f in enumerate(findings):
        pfx = f"findings[{i}]"
        if not isinstance(f, dict):
            errors.append(f"{pfx} must be an object")
            continue
        for rk in req_finding - set(f.keys()):
            errors.append(f"{pfx}: missing required field '{rk}'")
        for uk in set(f.keys()) - allowed_finding:
            errors.append(f"{pfx}: unexpected field '{uk}'")

        fid = f.get("finding_id")
        if fid is not None and (not isinstance(fid, str) or not _FINDING_ID_RE.match(fid)):
            errors.append(f"{pfx}.finding_id invalid: {fid!r}")

        aoc = f.get("aoc")
        if isinstance(aoc, dict):
            if not isinstance(aoc.get("id"), str) or not _AOC_ID_RE.match(aoc["id"]):
                errors.append(f"{pfx}.aoc.id invalid: {aoc.get('id')!r}")
            for uk in set(aoc.keys()) - {"id", "title"}:
                errors.append(f"{pfx}.aoc unexpected field '{uk}'")
        else:
            errors.append(f"{pfx}.aoc must be an object")

        ctls = f.get("controls")
        if not isinstance(ctls, list) or len(ctls) < 1:
            errors.append(f"{pfx}.controls must be a non-empty array")
        else:
            if len(ctls) != len(set(ctls)):
                errors.append(f"{pfx}.controls must have unique items")
            for c in ctls:
                if not isinstance(c, str) or not _CONTROL_ID_RE.match(c):
                    errors.append(f"{pfx}.controls invalid control_id: {c!r}")

        det = f.get("determination")
        if det not in VALID_DETERMINATIONS:
            errors.append(f"{pfx}.determination invalid: {det!r}")

        det_detail = f.get("determination_detail")
        if det_detail is not None and (not isinstance(det_detail, str) or not _DET_DETAIL_RE.match(det_detail)):
            errors.append(f"{pfx}.determination_detail invalid: {det_detail!r}")

        sev = f.get("severity")
        if sev is not None and sev not in VALID_SEVERITIES:
            errors.append(f"{pfx}.severity invalid: {sev!r}")

        if det in ("FAIL", "WARN"):
            if not sev:
                errors.append(f"{pfx}: severity is required when determination is {det}")
            if not f.get("remediation"):
                errors.append(f"{pfx}: remediation is required when determination is {det}")

        subj = f.get("subject")
        if isinstance(subj, dict):
            if subj.get("kind") not in VALID_SUBJECT_KINDS:
                errors.append(f"{pfx}.subject.kind invalid: {subj.get('kind')!r}")
            if not isinstance(subj.get("name"), str) or not subj.get("name"):
                errors.append(f"{pfx}.subject.name required")
            for uk in set(subj.keys()) - {"kind", "name", "version", "ecosystem", "parameters"}:
                errors.append(f"{pfx}.subject unexpected field '{uk}'")
            params = subj.get("parameters")
            if params is not None:
                if not isinstance(params, dict):
                    errors.append(f"{pfx}.subject.parameters must be an object")
                else:
                    for uk in set(params.keys()) - {"mode", "key_bits", "curve", "purpose"}:
                        errors.append(f"{pfx}.subject.parameters unexpected field '{uk}'")
                    if "purpose" in params and params["purpose"] not in VALID_PURPOSES:
                        errors.append(f"{pfx}.subject.parameters.purpose invalid: {params['purpose']!r}")
                    if "key_bits" in params and (not isinstance(params["key_bits"], int) or params["key_bits"] < 0):
                        errors.append(f"{pfx}.subject.parameters.key_bits invalid")
        else:
            errors.append(f"{pfx}.subject must be an object")

        loc = f.get("location")
        if isinstance(loc, dict):
            lkind = loc.get("kind")
            if lkind not in VALID_LOCATION_KINDS:
                errors.append(f"{pfx}.location.kind invalid: {lkind!r}")
            if lkind in ("file", "manifest") and (not isinstance(loc.get("path"), str) or not loc.get("path")):
                errors.append(f"{pfx}.location.path is required when location.kind is {lkind}")
            for uk in set(loc.keys()) - {"kind", "path", "line_start", "line_end", "column"}:
                errors.append(f"{pfx}.location unexpected field '{uk}'")
            for lk in ("line_start", "line_end", "column"):
                if lk in loc and (not isinstance(loc[lk], int) or loc[lk] < 1):
                    errors.append(f"{pfx}.location.{lk} must be integer >= 1")
        else:
            errors.append(f"{pfx}.location must be an object")

        det_obj = f.get("detection")
        if isinstance(det_obj, dict):
            if det_obj.get("method") not in VALID_DETECTION_METHODS:
                errors.append(f"{pfx}.detection.method invalid: {det_obj.get('method')!r}")
            if det_obj.get("confidence") not in VALID_CONFIDENCES:
                errors.append(f"{pfx}.detection.confidence invalid: {det_obj.get('confidence')!r}")
            for uk in set(det_obj.keys()) - {"method", "confidence"}:
                errors.append(f"{pfx}.detection unexpected field '{uk}'")
        else:
            errors.append(f"{pfx}.detection must be an object")

        title = f.get("title")
        if not isinstance(title, str) or not title or len(title) > 200:
            errors.append(f"{pfx}.title must be 1..200 chars")

        ev = f.get("evidence")
        if ev is not None:
            if not isinstance(ev, dict):
                errors.append(f"{pfx}.evidence must be an object")
            else:
                for uk in set(ev.keys()) - {"snippet", "references"}:
                    errors.append(f"{pfx}.evidence unexpected field '{uk}'")
                if "snippet" in ev and (not isinstance(ev["snippet"], str) or len(ev["snippet"]) > 500):
                    errors.append(f"{pfx}.evidence.snippet must be string <= 500 chars")

        ext = f.get("extensions")
        if ext is not None:
            if not isinstance(ext, dict):
                errors.append(f"{pfx}.extensions must be an object")
            else:
                fips_ext = ext.get("fips")
                if fips_ext is not None:
                    if not isinstance(fips_ext, dict):
                        errors.append(f"{pfx}.extensions.fips must be an object")
                    else:
                        allowed_fips = {
                            "fips_status",
                            "module_name",
                            "cmvp_cert",
                            "cert_standard",
                            "cert_status",
                            "operational_environment",
                            "approved_mode_evidence",
                        }
                        for uk in set(fips_ext.keys()) - allowed_fips:
                            errors.append(f"{pfx}.extensions.fips unexpected field '{uk}'")
                        if "fips_status" in fips_ext and fips_ext["fips_status"] not in VALID_FIPS_STATUSES:
                            errors.append(f"{pfx}.extensions.fips.fips_status invalid")
                        if "cmvp_cert" in fips_ext and (
                            not isinstance(fips_ext["cmvp_cert"], str) or not _CMVP_CERT_RE.match(fips_ext["cmvp_cert"])
                        ):
                            errors.append(f"{pfx}.extensions.fips.cmvp_cert invalid")
                        if "cert_standard" in fips_ext and fips_ext["cert_standard"] not in VALID_CERT_STANDARDS:
                            errors.append(f"{pfx}.extensions.fips.cert_standard invalid")
                        if "cert_status" in fips_ext and fips_ext["cert_status"] not in VALID_CERT_STATUSES:
                            errors.append(f"{pfx}.extensions.fips.cert_status invalid")

    return errors
