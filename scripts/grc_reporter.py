#!/usr/bin/env python3
"""
grc_reporter.py - GRC Compliance Report & SCR/SCN Package Synthesizer
====================================================================

Classification: Internal Compliance & Security Audit Deliverable Generator
Pipeline Role: Phase 4 (Evidence & SCR/SCN Package Consolidation)
Target Frameworks: NIST SP 800-53 Rev. 5, DISA STIG, FedRAMP High, DoD Cloud Computing SRG
Operational Pattern: Out-of-Band (OOB), Zero Untrusted Execution, Fail-Open

Purpose:
  Aggregates, normalizes, and synthesizes multi-engine scanner findings
  (Semgrep, Checkov, Grype, Trivy, Gitleaks, CryptoScan)
  and provenance metadata into formal, audit-ready compliance deliverables:
    1. poam_data.md          - Structured Plan of Action & Milestones (FedRAMP/DoD)
    2. controls.md           - NIST SP 800-53 Rev. 5 Comprehensive Traceability Matrix
    3. ruleset_validation.md - Custom 37-Rule Semgrep Baseline Audit Log
    4. scr_scn_package.json  - Consolidated Machine-Readable SCR/SCN Evidence Payload
    5. sha256sum             - Cryptographic Integrity Manifest Sealing Deliverables

Zero External Dependencies:
  Uses exclusively Python 3 standard library.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from grc_common import (
        SEVERITY_POLICY,
        SEVERITY_RANK,
        SLA_DAYS_POLICY,
        get_severity_policy,
        sha256_file,
        utc_now_iso,
        utc_now_str,
        utc_today,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from grc_common import (
        SEVERITY_POLICY,
        SEVERITY_RANK,
        SLA_DAYS_POLICY,
        get_severity_policy,
        sha256_file,
        utc_now_iso,
        utc_now_str,
        utc_today,
    )


# ==============================================================================
# NIST SP 800-53 REV. 5 CONTROL DEFINITIONS
# ==============================================================================

NIST_CONTROLS_CATALOG: Dict[str, Dict[str, Any]] = {
    "IA-2": {
        "title": "Identification and Authentication (Organizational Users)",
        "family": "Identification and Authentication (IA)",
        "description": "Uniquely identify and authenticate organizational users (or processes acting on their behalf). Prohibits hardcoded static credentials, default passwords, and unmanaged API tokens.",
        "stig_cat": "CAT I",
        "assessed_by": ["Semgrep", "Gitleaks", "Checkov"],
    },
    "IA-7": {
        "title": "Cryptographic Module Authentication",
        "family": "Identification and Authentication (IA)",
        "description": "Authenticate to cryptographic modules using mechanisms meeting applicable federal laws, regulations, and standards.",
        "stig_cat": "CAT II",
        "assessed_by": ["CryptoScan", "Semgrep"],
    },
    "SI-2": {
        "title": "Flaw Remediation",
        "family": "System and Information Integrity (SI)",
        "description": "Identify, report, and correct system flaws (vulnerabilities and CVEs) within defined remediation timeframes.",
        "stig_cat": "CAT I",
        "assessed_by": ["Grype", "Trivy", "Semgrep"],
    },
    "SI-4": {
        "title": "Information System Monitoring",
        "family": "System and Information Integrity (SI)",
        "description": "Monitor system execution to detect attacks and indicators of potential compromise. Prohibits unsanitized runtime shell execution (command injection).",
        "stig_cat": "CAT I",
        "assessed_by": ["Semgrep"],
    },
    "SI-7": {
        "title": "Software, Firmware, and Information Integrity",
        "family": "System and Information Integrity (SI)",
        "description": "Employ integrity verification tools to detect unauthorized changes and prohibit use of unsupported, unmaintained, or EOL libraries and providers.",
        "stig_cat": "CAT I",
        "assessed_by": ["CryptoScan", "Semgrep"],
    },
    "SI-10": {
        "title": "Information Input Validation",
        "family": "System and Information Integrity (SI)",
        "description": "Validate information inputs to syntax rules, character sets, and payload limits before runtime interpretation.",
        "stig_cat": "CAT I",
        "assessed_by": ["Semgrep"],
    },
    "SI-16": {
        "title": "Memory Protection / Cryptographic Hash Integrity",
        "family": "System and Information Integrity (SI)",
        "description": "Protect memory integrity and enforce strong cryptographic hash algorithms. Prohibits MD5, SHA-1, DES, and RC4.",
        "stig_cat": "CAT I",
        "assessed_by": ["Semgrep", "CryptoScan"],
    },
    "SI-17": {
        "title": "Fail-Secure / Secure Communications Initiation",
        "family": "System and Information Integrity (SI)",
        "description": "Ensure the system fails to a secure state. Prohibits disabled TLS certificate validation and deprecated TLS 1.0/1.1 protocols.",
        "stig_cat": "CAT I",
        "assessed_by": ["Semgrep", "Checkov"],
    },
    "SC-8": {
        "title": "Transmission Confidentiality and Integrity",
        "family": "System and Communications Protection (SC)",
        "description": "Protect the confidentiality and integrity of transmitted information using strong cryptography (TLS 1.2+ / 1.3).",
        "stig_cat": "CAT I",
        "assessed_by": ["Semgrep", "Checkov"],
    },
    "SC-12": {
        "title": "Cryptographic Key Establishment and Management",
        "family": "System and Communications Protection (SC)",
        "description": "Establish and manage cryptographic keys in accordance with NIST SP 800-56A/B and applicable FIPS guidelines.",
        "stig_cat": "CAT I",
        "assessed_by": ["CryptoScan", "Gitleaks", "Semgrep"],
    },
    "SC-13": {
        "title": "Cryptographic Protection (FIPS 140 Validation)",
        "family": "System and Communications Protection (SC)",
        "description": "Implement cryptographic modules validated under FIPS 140-2 / 140-3. Enforce OS kernel FIPS mode and validated security providers.",
        "stig_cat": "CAT I",
        "assessed_by": ["CryptoScan", "Semgrep", "Checkov"],
    },
    "SC-28": {
        "title": "Protection of Information at Rest",
        "family": "System and Communications Protection (SC)",
        "description": "Protect the confidentiality and integrity of information at rest (e.g., EBS volume encryption, S3 SSE-KMS).",
        "stig_cat": "CAT I",
        "assessed_by": ["Checkov", "Semgrep"],
    },
    "AC-3": {
        "title": "Access Enforcement",
        "family": "Access Control (AC)",
        "description": "Enforce approved authorizations for logical access to information and system resources (e.g. security group ingress rules).",
        "stig_cat": "CAT I",
        "assessed_by": ["Checkov", "Semgrep"],
    },
    "AC-6": {
        "title": "Least Privilege",
        "family": "Access Control (AC)",
        "description": "Employ the principle of least privilege, allowing only authorized accesses necessary for accomplishing assigned tasks (e.g., prohibiting public cloud buckets).",
        "stig_cat": "CAT I",
        "assessed_by": ["Checkov", "Semgrep"],
    },
    "CM-6": {
        "title": "Configuration Settings",
        "family": "Configuration Management (CM)",
        "description": "Establish and document mandatory configuration settings for IT products using hardened baselines (DISA STIG / CIS).",
        "stig_cat": "CAT II",
        "assessed_by": ["Checkov", "Semgrep"],
    },
    "CM-8": {
        "title": "Information System Component Inventory",
        "family": "Configuration Management (CM)",
        "description": "Develop and document an inventory of information system components (SBOM) detailing name, version, and license.",
        "stig_cat": "CAT II",
        "assessed_by": ["Grype", "Trivy", "SBOM"],
    },
    "RA-5": {
        "title": "Vulnerability Monitoring and Scanning",
        "family": "Risk Assessment (RA)",
        "description": "Monitor and scan for vulnerabilities in the system and hosted applications, prioritizing remediation of critical CVEs.",
        "stig_cat": "CAT I",
        "assessed_by": ["Grype", "Trivy"],
    },
}

# Unified FedRAMP ConMon SLA rules (30d Critical/High, 90d Medium, 180d Low/Info)
SLA_DAYS_MAP: Dict[str, int] = dict(SLA_DAYS_POLICY)


def normalize_severity_and_cat(raw_sev: str) -> Tuple[str, str]:
    """
    Canonical severity -> (Normalized Severity, DISA STIG CAT) mapping across all tools,
    backed by `rules/severity_policy.json` (`grc_common.get_severity_policy`):
      - CRITICAL -> ("CRITICAL", "CAT I")
      - HIGH     -> ("HIGH", "CAT II")
      - MEDIUM   -> ("MEDIUM", "CAT III")
      - LOW / NEGLIGIBLE / INFO / INFORMATIONAL / UNKNOWN -> ("LOW" / "INFO", "CAT III")
    """
    s = (raw_sev or "MEDIUM").strip().upper()
    if s in ("INFO", "INFORMATIONAL"):
        return "INFO", str(SEVERITY_POLICY.get("LOW", ("CAT III", 180))[0])
    canonical, cat_level, _ = get_severity_policy(s)
    if canonical == "MEDIUM":
        cat_level = "CAT III"
    return canonical, str(cat_level)


# ==============================================================================
# NORMALIZED FINDING DATA STRUCTURE
# ==============================================================================

class NormalizedFinding:
    """Represents a unified security finding across any scanning engine."""

    def __init__(
        self,
        finding_id: str,
        source_tool: str,
        rule_or_cve_id: str,
        title: str,
        severity: str,
        cat_level: str,
        file_path: str,
        line_number: Optional[int],
        message: str,
        aoc: str,
        nist_controls: List[str],
        remediation: str,
        raw_data: Optional[Dict[str, Any]] = None,
        anchor_date: Optional[datetime.date] = None,
    ):
        self.finding_id = finding_id
        self.source_tool = source_tool
        self.rule_or_cve_id = rule_or_cve_id
        self.title = title
        self.severity = severity.upper()
        self.cat_level = cat_level.upper()
        self.file_path = file_path
        self.line_number = line_number
        self.message = message
        self.aoc = aoc
        self.nist_controls = nist_controls if nist_controls else ["CM-6"]
        self.remediation = remediation
        self.raw_data = raw_data or {}

        # Calculate FedRAMP SLA days using unified 30/30/90/180 policy
        self.sla_days = SLA_DAYS_MAP.get(self.severity, 90)
        base_date = anchor_date if anchor_date else utc_today()
        self.target_date = (base_date + datetime.timedelta(days=self.sla_days)).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "source_tool": self.source_tool,
            "rule_or_cve_id": self.rule_or_cve_id,
            "title": self.title,
            "severity": self.severity,
            "cat_level": self.cat_level,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "message": self.message,
            "aoc": self.aoc,
            "nist_controls": self.nist_controls,
            "remediation": self.remediation,
            "sla_days": self.sla_days,
            "target_completion_date": self.target_date,
            "status": "Open (Identified Out-of-Band)",
        }


# ==============================================================================
# GRC COMPLIANCE REPORT SYNTHESIZER
# ==============================================================================

class GRCComplianceReporter:
    """
    Parses all scanner deliverables and synthesizes Phase 4 SCR/SCN packages.
    """

    def __init__(
        self,
        evidence_dir: Path,
        workspace_dir: Optional[Path] = None,
        ruleset_path: Optional[Path] = None,
    ):
        self.evidence_dir = Path(evidence_dir).resolve()
        self.workspace_dir = Path(workspace_dir).resolve() if workspace_dir else None
        self.ruleset_path = Path(ruleset_path).resolve() if ruleset_path else None

        self.findings: List[NormalizedFinding] = []
        self.provenance: Dict[str, Any] = {}
        self.baseline_rules: List[Dict[str, Any]] = []
        self.loaded_scanners: Set[str] = set()
        self.sbom_stig_evidence: Optional[Dict[str, Any]] = None
        self._seen_vuln_keys: Set[Tuple[str, str]] = set()
        self._finding_counter = 1

    def _load_json(self, filename: str, label: str = "JSON") -> Optional[Any]:
        """Loads and parses a JSON file in `self.evidence_dir` if it exists and is non-empty."""
        path = self.evidence_dir / filename
        if not path.exists() or path.stat().st_size == 0:
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[!] Warning: Error loading {label} JSON ({filename}): {e}", file=sys.stderr)
            return None

    def _anchor_date(self) -> datetime.date:
        """Resolves a stable anchor date from provenance if available, otherwise UTC today."""
        for key in ("restored_at", "verified_at"):
            ts = self.provenance.get(key)
            if isinstance(ts, str) and len(ts) >= 10:
                try:
                    return datetime.date.fromisoformat(ts[:10])
                except ValueError:
                    pass
        return utc_today()

    def _make_finding_id(self, tool: str, rule_id: str, location: str) -> str:
        """Generates a deterministic finding ID combining sequence number and stable content hash."""
        seq = self._finding_counter
        self._finding_counter += 1
        fingerprint = hashlib.sha256(f"{tool}|{rule_id}|{location}".encode("utf-8")).hexdigest()[:6].upper()
        return f"POAM-{seq:03d}-{fingerprint}"

    def clean_path(self, path_str: str) -> str:
        """Strips leading `/workspace/` prefix only (never mid-string occurrences)."""
        if not path_str:
            return "N/A"
        clean = re.sub(r"^/+workspace/+", "", str(path_str).strip())
        if clean.startswith("/"):
            clean = clean.lstrip("/")
        return clean or "N/A"

    _clean_path = clean_path

    # --------------------------------------------------------------------------
    # INGESTION & PARSING
    # --------------------------------------------------------------------------

    def load_provenance(self) -> None:
        """Loads bundle or AMI provenance record."""
        prov_file = self.evidence_dir / "bundle_provenance.json"
        if not prov_file.exists():
            prov_file = self.evidence_dir / "ami_provenance.json"

        if not prov_file.exists() and self.workspace_dir:
            prov_file = self.workspace_dir / "bundle_provenance.json"
            if not prov_file.exists():
                prov_file = self.workspace_dir / "ami_provenance.json"

        if prov_file.exists():
            try:
                with open(prov_file, "r", encoding="utf-8") as f:
                    self.provenance = json.load(f)
                dest_prov = self.evidence_dir / prov_file.name
                if not dest_prov.exists():
                    with open(dest_prov, "w", encoding="utf-8") as f:
                        json.dump(self.provenance, f, indent=2)
            except Exception as e:
                print(f"[!] Warning: Failed to parse provenance file {prov_file}: {e}", file=sys.stderr)

    def load_baseline_rules(self) -> None:
        """Loads rule definitions from custom-baseline-ruleset.yaml."""
        if not self.ruleset_path or not self.ruleset_path.exists():
            candidate = Path(__file__).resolve().parent.parent / "rules" / "custom-baseline-ruleset.yaml"
            if candidate.exists():
                self.ruleset_path = candidate

        if self.ruleset_path and self.ruleset_path.exists():
            try:
                with open(self.ruleset_path, "r", encoding="utf-8") as f:
                    content = f.read()

                rule_chunks = re.findall(
                    r"  - id:\s*([^\n]+).*?severity:\s*([^\n]+).*?message:\s*\"([^\"]+)\".*?aoc:\s*\"([^\"]+)\".*?nist_control:\s*\"([^\"]+)\"",
                    content,
                    re.DOTALL,
                )
                for chunk in rule_chunks:
                    r_id, r_sev, r_msg, r_aoc, r_nist = chunk
                    ctl_match = re.search(r"([A-Z]{2}-\d+)", r_nist)
                    ctl_id = ctl_match.group(1) if ctl_match else "CM-6"

                    self.baseline_rules.append({
                        "id": r_id.strip(),
                        "severity": r_sev.strip(),
                        "message": r_msg.strip(),
                        "aoc": r_aoc.strip(),
                        "nist_control": ctl_id,
                    })
            except Exception as e:
                print(f"[!] Warning: Failed to parse baseline ruleset: {e}", file=sys.stderr)

    def parse_semgrep(self) -> None:
        """Parses semgrep_findings.json with per-record error isolation."""
        s_file = self.evidence_dir / "semgrep_findings.json"
        if not s_file.exists() or s_file.stat().st_size == 0:
            return

        try:
            with open(s_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Error loading Semgrep JSON: {e}", file=sys.stderr)
            return

        self.loaded_scanners.add("Semgrep")
        anchor = self._anchor_date()
        results = data.get("results", []) if isinstance(data, dict) else []

        for r in results:
            try:
                if not isinstance(r, dict):
                    continue
                check_id = str(r.get("check_id") or "semgrep-rule")
                path = self.clean_path(r.get("path", ""))
                line = r.get("start", {}).get("line") if isinstance(r.get("start"), dict) else None
                extra = r.get("extra", {}) if isinstance(r.get("extra"), dict) else {}
                message = str(extra.get("message") or "Semgrep security finding")
                meta = extra.get("metadata", {}) if isinstance(extra.get("metadata"), dict) else {}

                raw_sev = str(extra.get("severity") or "WARNING").upper()
                severity, cat_level = normalize_severity_and_cat(raw_sev)

                aoc = str(meta.get("aoc") or "General Security Policy")
                if "AOC-04" in aoc or "AOC-10" in aoc:
                    severity, cat_level = "CRITICAL", "CAT I"

                nist_raw = str(meta.get("nist_control") or "CM-6")
                ctl_match = re.search(r"([A-Z]{2}-\d+)", nist_raw)
                ctl_id = ctl_match.group(1) if ctl_match else "CM-6"

                title = message.split(":")[0] if ":" in message else check_id
                remediation = "Remediate source code according to the secure coding baseline; eliminate static credentials, legacy ciphers, or shell execution."
                if "AOC-02" in aoc:
                    remediation = "Externalize credentials into a secret management vault or protected environment variable."
                elif "AOC-03" in aoc:
                    remediation = "Migrate cryptographic algorithms to approved AES-256-GCM or SHA-256/384."
                elif "AOC-04" in aoc:
                    remediation = "Replace shell execution with parameterized runtime APIs; avoid shell=True."
                elif "AOC-05" in aoc:
                    remediation = "Enable strict TLS certificate validation and enforce minimum TLS 1.2 or 1.3."

                loc = f"{path}:{line}" if line else path
                self.findings.append(
                    NormalizedFinding(
                        finding_id=self._make_finding_id("Semgrep", check_id, loc),
                        source_tool="Semgrep",
                        rule_or_cve_id=check_id,
                        title=title,
                        severity=severity,
                        cat_level=cat_level,
                        file_path=loc,
                        line_number=line,
                        message=message,
                        aoc=aoc,
                        nist_controls=[ctl_id],
                        remediation=remediation,
                        raw_data=r,
                        anchor_date=anchor,
                    )
                )
            except Exception as rec_err:
                print(f"[!] Warning: Skipping malformed Semgrep record: {rec_err}", file=sys.stderr)

    def parse_checkov(self) -> None:
        """Parses checkov_findings.json with word-boundary classification and per-record isolation."""
        c_file = self.evidence_dir / "checkov_findings.json"
        if not c_file.exists() or c_file.stat().st_size == 0:
            return

        try:
            with open(c_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Error loading Checkov JSON: {e}", file=sys.stderr)
            return

        self.loaded_scanners.add("Checkov")
        anchor = self._anchor_date()
        reports = data if isinstance(data, list) else [data]

        for report in reports:
            if not isinstance(report, dict):
                continue
            results = report.get("results", {})
            if not isinstance(results, dict):
                continue
            failed = results.get("failed_checks", []) or []
            for check in failed:
                try:
                    if not isinstance(check, dict):
                        continue
                    cid = str(check.get("check_id") or "CKV_POLICY")
                    cname = str(check.get("check_name") or "IaC Configuration Check Failed")
                    fpath = self.clean_path(check.get("file_path", ""))
                    lines = check.get("file_line_range") or []
                    line_num = lines[0] if (isinstance(lines, list) and lines) else None
                    line_str = f":{line_num}" if line_num else ""
                    res = str(check.get("resource") or "Unknown Resource")
                    guideline = str(
                        check.get("guideline")
                        or "Harden Infrastructure-as-Code template according to CIS / DISA STIG benchmarks."
                    )

                    nist_ctls = ["CM-6"]
                    aoc = "AOC-07: Infrastructure-as-Code Misconfiguration"
                    sev = "HIGH"
                    cat = "CAT II"

                    cname_lc = cname.lower()
                    cid_lc = cid.lower()

                    # Evaluate secrets/passwords first so "Ensure secrets are encrypted" maps to IA-2
                    if re.search(r"\b(secret|secrets|password|passwords|credential|credentials)\b", f"{cid_lc} {cname_lc}"):
                        nist_ctls = ["IA-2", "SC-12"]
                        aoc = "AOC-02: Password Hygiene"
                        sev, cat = "CRITICAL", "CAT I"
                    elif re.search(r"\b(public|s3)\b", cname_lc):
                        nist_ctls = ["AC-6", "CM-6", "SC-28"]
                        sev, cat = "CRITICAL", "CAT I"
                    elif re.search(r"(\bsecurity group\b|0\.0\.0\.0|\bport\b|\bingress\b)", cname_lc):
                        nist_ctls = ["AC-3", "CM-6"]
                        sev, cat = "CRITICAL", "CAT I"
                    elif re.search(r"\b(encryption|encrypted|ebs|kms|at rest)\b", cname_lc):
                        nist_ctls = ["SC-13", "SC-28"]
                        sev, cat = "HIGH", "CAT II"

                    loc = f"{fpath}{line_str} (Resource: {res})"
                    self.findings.append(
                        NormalizedFinding(
                            finding_id=self._make_finding_id("Checkov", cid, loc),
                            source_tool="Checkov",
                            rule_or_cve_id=cid,
                            title=cname,
                            severity=sev,
                            cat_level=cat,
                            file_path=loc,
                            line_number=line_num,
                            message=f"IaC policy violation on resource '{res}': {cname}",
                            aoc=aoc,
                            nist_controls=nist_ctls,
                            remediation=guideline,
                            raw_data=check,
                            anchor_date=anchor,
                        )
                    )
                except Exception as rec_err:
                    print(f"[!] Warning: Skipping malformed Checkov record: {rec_err}", file=sys.stderr)

    def parse_crypto_scan(self) -> None:
        """
        Parses crypto_findings.json.
        CRITICAL FIX (P0 #3): Skips `compliance_status == "PASS"` findings so compliant
        libraries are never ingested as POA&M items, and preserves `manifest_file`.
        """
        c_file = self.evidence_dir / "crypto_findings.json"
        if not c_file.exists() or c_file.stat().st_size == 0:
            return

        try:
            with open(c_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Error loading CryptoScan JSON: {e}", file=sys.stderr)
            return

        self.loaded_scanners.add("CryptoScan")
        anchor = self._anchor_date()
        findings_list = data.get("findings", []) if isinstance(data, dict) else []

        for item in findings_list:
            try:
                if not isinstance(item, dict):
                    continue
                status = str(item.get("compliance_status") or "FAIL").strip().upper()
                # Never ingest compliant PASS items as POA&M findings
                if status == "PASS":
                    continue

                lib = str(item.get("library_name") or "Unknown Crypto Library")
                ver = str(item.get("detected_version") or "N/A")
                raw_sev = str(item.get("severity") or "CRITICAL").upper()
                sev, cat = normalize_severity_and_cat(raw_sev)
                aoc = str(item.get("area_of_concern") or "AOC-09: Crypto Dependencies on Unsupported Libraries")
                remediation = str(
                    item.get("remediation") or f"Upgrade '{lib}' to a supported, active FIPS-capable version."
                )
                ctls = item.get("nist_controls") or ["SI-7", "SC-12", "SC-13"]
                manifest_path = self.clean_path(
                    item.get("manifest_file") or "Dependency Manifest / System Libraries"
                )
                rule_id = f"CRYPTO-{lib.upper()}-{status}"

                self.findings.append(
                    NormalizedFinding(
                        finding_id=self._make_finding_id("CryptoScan", rule_id, manifest_path),
                        source_tool="CryptoScan",
                        rule_or_cve_id=rule_id,
                        title=f"Unsupported/Deprecated Cryptographic Library: {lib} ({ver})",
                        severity=sev,
                        cat_level=cat,
                        file_path=manifest_path,
                        line_number=None,
                        message=f"Detected cryptographic library '{lib}' version '{ver}' with status '{status}'.",
                        aoc=aoc,
                        nist_controls=list(ctls),
                        remediation=remediation,
                        raw_data=item,
                        anchor_date=anchor,
                    )
                )
            except Exception as rec_err:
                print(f"[!] Warning: Skipping malformed CryptoScan record: {rec_err}", file=sys.stderr)

    def parse_grype(self) -> None:
        """Parses grype_findings.json with unified severity mapping and deduplication."""
        g_file = self.evidence_dir / "grype_findings.json"
        if not g_file.exists() or g_file.stat().st_size == 0:
            return

        try:
            with open(g_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Error loading Grype JSON: {e}", file=sys.stderr)
            return

        self.loaded_scanners.add("Grype")
        anchor = self._anchor_date()
        matches = data.get("matches", []) if isinstance(data, dict) else []

        for match in matches:
            try:
                if not isinstance(match, dict):
                    continue
                vuln = match.get("vulnerability", {}) or {}
                art = match.get("artifact", {}) or {}
                cve_id = str(vuln.get("id") or "CVE-UNKNOWN")
                raw_sev = str(vuln.get("severity") or "Medium").upper()
                pkg_name = str(art.get("name") or "Unknown Package")
                pkg_ver = str(art.get("version") or "Unknown Version")

                sev, cat = normalize_severity_and_cat(raw_sev)
                dedup_key = (cve_id.upper(), f"{pkg_name.lower()}:{pkg_ver.lower()}")
                if dedup_key in self._seen_vuln_keys:
                    continue
                self._seen_vuln_keys.add(dedup_key)

                fix_versions = vuln.get("fix", {}).get("versions", []) if isinstance(vuln.get("fix"), dict) else []
                fix_text = (
                    f"Upgrade '{pkg_name}' to version {', '.join(fix_versions)}."
                    if fix_versions
                    else f"Upgrade or apply vendor patch for '{pkg_name}'."
                )
                loc = f"Package: {pkg_name}:{pkg_ver}"

                self.findings.append(
                    NormalizedFinding(
                        finding_id=self._make_finding_id("Grype", cve_id, loc),
                        source_tool="Grype",
                        rule_or_cve_id=cve_id,
                        title=f"Published Vulnerability: {cve_id} in {pkg_name} ({pkg_ver})",
                        severity=sev,
                        cat_level=cat,
                        file_path=loc,
                        line_number=None,
                        message=f"{cve_id} detected in dependency {pkg_name} version {pkg_ver}. Severity: {raw_sev}.",
                        aoc="AOC-10: CRITICAL Severity Findings" if sev == "CRITICAL" else "AOC-08: Software Supply Chain & CVE Remediation",
                        nist_controls=["RA-5", "SI-2"],
                        remediation=fix_text,
                        raw_data=match,
                        anchor_date=anchor,
                    )
                )
            except Exception as rec_err:
                print(f"[!] Warning: Skipping malformed Grype record: {rec_err}", file=sys.stderr)

    def parse_trivy(self) -> None:
        """Parses trivy_findings.json with unified severity mapping and Grype deduplication."""
        t_file = self.evidence_dir / "trivy_findings.json"
        if not t_file.exists() or t_file.stat().st_size == 0:
            return

        try:
            with open(t_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Error loading Trivy JSON: {e}", file=sys.stderr)
            return

        self.loaded_scanners.add("Trivy")
        anchor = self._anchor_date()
        results = data.get("Results", []) if isinstance(data, dict) else []

        for res in results:
            if not isinstance(res, dict):
                continue
            target = self.clean_path(res.get("Target", "Workspace"))
            vulns = res.get("Vulnerabilities") or []
            for v in vulns:
                try:
                    if not isinstance(v, dict):
                        continue
                    cve_id = str(v.get("VulnerabilityID") or "CVE-UNKNOWN")
                    pkg = str(v.get("PkgName") or "package")
                    ver = str(v.get("InstalledVersion") or "")
                    raw_sev = str(v.get("Severity") or "MEDIUM").upper()
                    fix_ver = str(v.get("FixedVersion") or "")
                    title = str(v.get("Title") or f"Vulnerability in {pkg}")

                    sev, cat = normalize_severity_and_cat(raw_sev)
                    dedup_key = (cve_id.upper(), f"{pkg.lower()}:{ver.lower()}")
                    if dedup_key in self._seen_vuln_keys:
                        continue
                    self._seen_vuln_keys.add(dedup_key)

                    fix_text = f"Upgrade {pkg} to {fix_ver}." if fix_ver else f"Patch {pkg}."
                    loc = f"{target} ({pkg}:{ver})"

                    self.findings.append(
                        NormalizedFinding(
                            finding_id=self._make_finding_id("Trivy", cve_id, loc),
                            source_tool="Trivy",
                            rule_or_cve_id=cve_id,
                            title=f"{cve_id}: {title}",
                            severity=sev,
                            cat_level=cat,
                            file_path=loc,
                            line_number=None,
                            message=f"{cve_id} affecting {pkg} ({ver}) in {target}",
                            aoc="AOC-10: CRITICAL Severity Findings" if sev == "CRITICAL" else "AOC-08: Software Supply Chain & CVE Remediation",
                            nist_controls=["RA-5", "SI-2"],
                            remediation=fix_text,
                            raw_data=v,
                            anchor_date=anchor,
                        )
                    )
                except Exception as rec_err:
                    print(f"[!] Warning: Skipping malformed Trivy record: {rec_err}", file=sys.stderr)

    def parse_gitleaks(self) -> None:
        """Parses gitleaks_findings.json with per-record isolation."""
        g_file = self.evidence_dir / "gitleaks_findings.json"
        if not g_file.exists() or g_file.stat().st_size == 0:
            return

        try:
            with open(g_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Warning: Error loading Gitleaks JSON: {e}", file=sys.stderr)
            return

        self.loaded_scanners.add("Gitleaks")
        anchor = self._anchor_date()

        if isinstance(data, list):
            for leak in data:
                try:
                    if not isinstance(leak, dict):
                        continue
                    rule = str(leak.get("RuleID") or "hardcoded-secret")
                    desc = str(leak.get("Description") or "Detected exposed secret or credential")
                    fpath = self.clean_path(leak.get("File", ""))
                    line = leak.get("StartLine")
                    loc = f"{fpath}:{line}" if line else fpath

                    self.findings.append(
                        NormalizedFinding(
                            finding_id=self._make_finding_id("Gitleaks", rule, loc),
                            source_tool="Gitleaks",
                            rule_or_cve_id=rule,
                            title=f"Hardcoded Secret Detected: {desc}",
                            severity="CRITICAL",
                            cat_level="CAT I",
                            file_path=loc,
                            line_number=line,
                            message=f"Exposed secret ({rule}) in {fpath}. Credentials must not be stored in source code.",
                            aoc="AOC-02: Password Hygiene",
                            nist_controls=["IA-2", "SC-12"],
                            remediation="Rotate exposed credential immediately and inject secrets via environment or vault.",
                            raw_data=leak,
                            anchor_date=anchor,
                        )
                    )
                except Exception as rec_err:
                    print(f"[!] Warning: Skipping malformed Gitleaks record: {rec_err}", file=sys.stderr)

    def parse_sbom_stig(self) -> None:
        """Ingests SBOM STIG applicability outputs (`stig_applicability.json` or `sbom_stig_map.json`) if present."""
        for fname in ("stig_applicability.json", "sbom_stig_map.json"):
            data = self._load_json(fname, label="SBOM STIG")
            if isinstance(data, dict):
                self.sbom_stig_evidence = data
                self.loaded_scanners.add("SBOM")
                return
        if (self.evidence_dir / "stig_matrix.md").exists():
            self.loaded_scanners.add("SBOM")

    PARSERS = {
        "semgrep_findings.json": parse_semgrep,
        "checkov_findings.json": parse_checkov,
        "crypto_findings.json": parse_crypto_scan,
        "grype_findings.json": parse_grype,
        "trivy_findings.json": parse_trivy,
        "gitleaks_findings.json": parse_gitleaks,
        "stig_applicability.json": parse_sbom_stig,
    }

    # --------------------------------------------------------------------------
    # SYNTHESIS & REPORT GENERATION
    # --------------------------------------------------------------------------

    def _target_id(self) -> str:
        return (
            self.provenance.get("bundle_identifier")
            or self.provenance.get("ami_identifier")
            or self.evidence_dir.name
        )

    def _md_header(
        self,
        title: str,
        classification: str,
        extra_lines: Optional[List[str]] = None,
    ) -> List[str]:
        """Generates a standardized Markdown compliance deliverable header block."""
        header = [
            f"# {title}",
            "",
            f"> **Classification / Use**: {classification}  ",
            f"> **Audit Target Identifier**: `{self._target_id()}`  ",
        ]
        if extra_lines:
            header.extend(extra_lines)
        header.extend(["", "---", ""])
        return header

    def _control_was_assessed(self, ctl_id: str) -> bool:
        """Returns True if at least one scanner mapping to `ctl_id` was present in the evidence directory."""
        meta = NIST_CONTROLS_CATALOG.get(ctl_id, {})
        assessors = set(meta.get("assessed_by", []))
        if (
            (self.evidence_dir / "stig_applicability.json").exists()
            or (self.evidence_dir / "sbom_stig_map.json").exists()
            or (self.evidence_dir / "stig_matrix.md").exists()
        ):
            self.loaded_scanners.add("SBOM")
        return bool(assessors & self.loaded_scanners)

    def generate_poam_markdown(self) -> str:
        """Generates poam_data.md in formal FedRAMP High / DoD format."""
        now = utc_now_str()
        bundle_id = self._target_id()
        source_path = (
            self.provenance.get("bundle_source_path")
            or self.provenance.get("image_metadata", {}).get("name")
            or "Local Audit Evidence"
        )
        sha256 = (
            self.provenance.get("bundle_sha256")
            or self.provenance.get("image_metadata", {}).get("image_id")
            or "N/A"
        )
        session_id = self.provenance.get("session_id", "N/A")

        crit_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        med_count = sum(1 for f in self.findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in self.findings if f.severity in ("LOW", "INFORMATIONAL", "INFO"))
        total_count = len(self.findings)

        if total_count > 0:
            overall_posture = "NON-COMPLIANT (Active Findings Identified)"
        elif not self.loaded_scanners:
            overall_posture = "NOT ASSESSED (No Scanner Evidence Present)"
        else:
            overall_posture = "COMPLIANT (Clean Out-of-Band Audit)"

        md = [
            "# Plan of Action and Milestones (POA&M) Datapoints",
            "",
            "> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD CC SRG / SCR-SCN)  ",
            f"> **Audit Target Identifier**: `{bundle_id}`  ",
            f"> **Source Subject**: `{source_path}`  ",
            f"> **Cryptographic Hash (SHA-256)**: `{sha256}`  ",
            f"> **Review Session ID**: `{session_id}`  ",
            f"> **Evaluation Timestamp**: `{now}`  ",
            f"> **Overall Audit Posture**: **{overall_posture}**  ",
            "",
            "---",
            "",
            "## 1. Executive Vulnerability & Risk Summary",
            "",
            "The following risk rollup aggregates all findings detected across static AST analysis (Semgrep), dependency scanning (Grype/Trivy), secret scanning (Gitleaks), Infrastructure-as-Code policy validation (Checkov), and cryptographic library audits:",
            "",
            "| Severity Level | DISA STIG Impact Category | Active Findings Count | Mandatory Remediation SLA | Compliance Status |",
            "| :--- | :--- | :--- | :--- | :--- |",
            f"| **CRITICAL** | **Category I (CAT I)** | **{crit_count}** | **30 Calendar Days** | {'❌ Non-Compliant' if crit_count > 0 else ('⚪ Not Assessed' if not self.loaded_scanners else '✅ Clear')} |",
            f"| **HIGH** | **Category II (CAT II)** | **{high_count}** | **30 Calendar Days** | {'❌ Non-Compliant' if high_count > 0 else ('⚪ Not Assessed' if not self.loaded_scanners else '✅ Clear')} |",
            f"| **MEDIUM** | **Category III (CAT III)** | **{med_count}** | **90 Calendar Days** | {'⚠️ Warning' if med_count > 0 else ('⚪ Not Assessed' if not self.loaded_scanners else '✅ Clear')} |",
            f"| **LOW / INFO** | Informational | **{low_count}** | 180 Calendar Days | {'⚪ Not Assessed' if not self.loaded_scanners else '✅ Monitored'} |",
            f"| **TOTAL** | — | **{total_count}** | — | **{overall_posture}** |",
            "",
            "---",
            "",
            "## 2. Standardized POA&M Itemization Table",
            "",
            "All line items below are structured for automated ingestion into formal Enterprise POA&M tracking systems (eMASS, Archer, ServiceNow GRC, Jira Security):",
            "",
            "| POAM ID | Primary NIST Control | Weakness / Finding Name | Severity / CAT | Source Engine | Affected Asset / File | Target Completion | Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        if not self.findings:
            empty_status = "**Not Assessed**" if not self.loaded_scanners else "**Compliant**"
            empty_msg = (
                "No scanner evidence files were present in the evidence directory."
                if not self.loaded_scanners
                else "No unmitigated vulnerabilities detected in release."
            )
            md.append(f"| *None* | — | {empty_msg} | — | — | — | — | {empty_status} |")
        else:
            for f in self.findings:
                ctls_str = ", ".join(f.nist_controls)
                clean_title = f.title.replace("|", "/")
                clean_file = f.file_path.replace("|", "/")
                md.append(
                    f"| **{f.finding_id}** | `{ctls_str}` | {clean_title} | **{f.severity} / {f.cat_level}** | `{f.source_tool}` | `{clean_file}` | `{f.target_date}` | Open |"
                )

        md.extend([
            "",
            "---",
            "",
            "## 3. Remediation & Corrective Action Plans",
            "",
        ])

        if not self.findings:
            if not self.loaded_scanners:
                md.append("No scanner evidence files were found to evaluate remediation requirements.")
            else:
                md.append("No remediation actions required. The audited release bundle conforms to baseline compliance rules.")
        else:
            for idx, f in enumerate(self.findings, start=1):
                md.extend([
                    f"### 3.{idx} [{f.finding_id}] {f.title}",
                    f"* **Affected Asset**: `{f.file_path}`",
                    f"* **Governing Controls**: `{', '.join(f.nist_controls)}` | **Area of Concern**: `{f.aoc}`",
                    f"* **Detection Identifier**: `{f.rule_or_cve_id}` ({f.source_tool})",
                    f"* **Detailed Finding**: {f.message}",
                    f"* **Prescribed Action / Fix**: {f.remediation}",
                    f"* **Scheduled Completion SLA**: `{f.target_date}` ({f.sla_days} days)",
                    "",
                ])

        return "\n".join(md) + "\n"

    def generate_controls_markdown(self) -> str:
        """
        Generates controls.md NIST SP 800-53 Rev. 5 Traceability Matrix.
        CRITICAL FIX (P0 #4): Reports `⚪ NOT ASSESSED` when the assessing scanner
        evidence was not present instead of falsely claiming `✅ COMPLIANT`.
        """
        now = utc_now_str()
        bundle_id = self._target_id()

        findings_by_control: Dict[str, List[NormalizedFinding]] = {
            ctl: [] for ctl in NIST_CONTROLS_CATALOG.keys()
        }
        for f in self.findings:
            for ctl in f.nist_controls:
                findings_by_control.setdefault(ctl, []).append(f)

        md = [
            "# NIST SP 800-53 Rev. 5 Controls Traceability Matrix",
            "",
            "> **Classification / Use**: Internal Compliance & Security Audit Deliverable (FedRAMP High / DoD RMF / SCR-SCN)  ",
            f"> **Audit Target Identifier**: `{bundle_id}`  ",
            f"> **Evaluation Timestamp**: `{now}`  ",
            "",
            "---",
            "",
            "## 1. Compliance Status by Control Family",
            "",
            "| Control ID | Control Name | Control Family | DISA STIG Impact | Audit Findings Count | Compliance Status |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for ctl_id, meta in sorted(NIST_CONTROLS_CATALOG.items()):
            c_findings = findings_by_control.get(ctl_id, [])
            count = len(c_findings)
            assessed = self._control_was_assessed(ctl_id)
            if count > 0:
                status = f"❌ **NON-COMPLIANT ({count})**"
            elif not assessed:
                status = "⚪ **NOT ASSESSED**"
            else:
                status = "✅ **COMPLIANT**"
            md.append(
                f"| **{ctl_id}** | {meta['title']} | {meta['family']} | `{meta['stig_cat']}` | {count} | {status} |"
            )

        md.extend([
            "",
            "---",
            "",
            "## 2. Detailed Control Breakdown & Evidence Mapping",
            "",
        ])

        for ctl_id, meta in sorted(NIST_CONTROLS_CATALOG.items()):
            c_findings = findings_by_control.get(ctl_id, [])
            count = len(c_findings)
            assessed = self._control_was_assessed(ctl_id)

            if count > 0:
                status_badge = "❌ NON-COMPLIANT"
                outcome_text = "Deficiencies detected out-of-band requiring remediation."
            elif not assessed:
                status_badge = "⚪ NOT ASSESSED"
                outcome_text = f"No evidence file present from assessing scanner(s) ({', '.join(meta.get('assessed_by', []))})."
            else:
                status_badge = "✅ COMPLIANT"
                outcome_text = "No policy violations or vulnerabilities detected. Conforms to baseline."

            md.extend([
                f"### {ctl_id}: {meta['title']} — {status_badge}",
                f"* **Control Family**: {meta['family']}",
                f"* **DISA STIG Baseline**: `{meta['stig_cat']}`",
                f"* **Control Objective**: {meta['description']}",
                f"* **Evaluation Outcome**: {outcome_text}",
                "",
            ])

            if count > 0:
                md.extend([
                    "| Finding ID | Source Engine | Rule / CVE ID | Affected Location | Severity |",
                    "| :--- | :--- | :--- | :--- | :--- |",
                ])
                for f in c_findings:
                    md.append(
                        f"| **{f.finding_id}** | `{f.source_tool}` | `{f.rule_or_cve_id}` | `{f.file_path}` | **{f.severity}** |"
                    )
                md.append("")

        return "\n".join(md) + "\n"

    def generate_ruleset_validation_markdown(self) -> str:
        """
        Generates ruleset_validation.md itemizing Semgrep custom baseline execution.
        CRITICAL FIX (P0 #4): When `semgrep_findings.json` is absent (`"Semgrep"` not in
        `self.loaded_scanners`), rules report `⚪ NOT ASSESSED (NO EVIDENCE)` instead of
        `✅ PASSED (CLEAN)`.
        """
        now = utc_now_str()
        bundle_id = self._target_id()
        semgrep_ran = "Semgrep" in self.loaded_scanners

        def norm_id(rid: str) -> str:
            # Match by trailing rule identifier suffix so path-prefixed Semgrep IDs always match
            return rid.strip().split(".")[-1]

        semgrep_findings = [f for f in self.findings if f.source_tool == "Semgrep"]
        triggered_norm_ids = {norm_id(f.rule_or_cve_id): f for f in semgrep_findings}

        total_rules = len(self.baseline_rules)
        triggered_rules_count = sum(1 for r in self.baseline_rules if norm_id(r["id"]) in triggered_norm_ids)
        clean_rules_count = (total_rules - triggered_rules_count) if semgrep_ran else 0

        md = [
            "# Custom Baseline Ruleset Validation Audit Log",
            "",
            "> **Classification / Use**: Internal Compliance & Security Audit Deliverable (Ruleset Verification Log)  ",
            f"> **Audit Target Identifier**: `{bundle_id}`  ",
            f"> **Ruleset File**: `rules/custom-baseline-ruleset.yaml`  ",
            f"> **Evaluation Timestamp**: `{now}`  ",
            f"> **Semgrep Evidence Status**: `{'ASSESSED (semgrep_findings.json loaded)' if semgrep_ran else 'NOT ASSESSED (semgrep_findings.json missing)'}`  ",
            "",
            "---",
            "",
            "## 1. Execution Summary",
            "",
            f"The custom Semgrep baseline defines **{total_rules} high-assurance security rules** spanning password hygiene, cryptography, command injection, TLS validation, and infrastructure hardening across Go, Java, Python, and JavaScript.",
            "",
            "| Metric | Value | Audit Significance |",
            "| :--- | :--- | :--- |",
            f"| **Total Evaluated Rules** | **{total_rules if semgrep_ran else 0} / {total_rules}** | Complete baseline coverage |",
            f"| **Triggered Rules (Violations Detected)** | **{triggered_rules_count}** | Active findings requiring engineering triage |",
            f"| **Clean Rules (Passed Checks)** | **{clean_rules_count}** | {'Controls verified without violation' if semgrep_ran else 'Not assessed — Semgrep output file was not provided'} |",
            f"| **Total Discovered Code Defects** | **{len(semgrep_findings)}** | Raw AST match instances |",
            "",
            "---",
            "",
            "## 2. Itemized Rule Evaluation Audit Trail",
            "",
            "| Rule Identifier | Target AOC | Governing NIST Control | Severity | Audit Status | Triggered Matches |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ]

        for rule in self.baseline_rules:
            rid = norm_id(rule["id"])
            matched_findings = [f for f in semgrep_findings if norm_id(f.rule_or_cve_id) == rid]
            match_count = len(matched_findings)

            if match_count > 0:
                status = "❌ **TRIGGERED**"
            elif not semgrep_ran:
                status = "⚪ **NOT ASSESSED (NO EVIDENCE)**"
            else:
                status = "✅ **PASSED (CLEAN)**"

            md.append(
                f"| `{rid}` | {rule['aoc']} | `{rule['nist_control']}` | `{rule['severity']}` | {status} | **{match_count}** |"
            )

        md.extend([
            "",
            "---",
            "",
            "## 3. Discovered Violation Code Locations",
            "",
        ])

        if not semgrep_ran:
            md.append("Semgrep AST analysis was not executed or `semgrep_findings.json` was not present in the evidence directory.")
        elif not semgrep_findings:
            md.append("No AST policy violations detected. All source files conform to baseline rules.")
        else:
            for f in semgrep_findings:
                md.extend([
                    f"* **Rule**: `{f.rule_or_cve_id}` ({f.aoc})",
                    f"  * **Location**: `{f.file_path}`",
                    f"  * **Message**: {f.message}",
                ])

        return "\n".join(md) + "\n"

    def generate_scr_scn_package_json(self) -> Dict[str, Any]:
        """Generates scr_scn_package.json machine-readable deliverable."""
        now = utc_now_iso()
        bundle_id = self._target_id()

        crit_count = sum(1 for f in self.findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in self.findings if f.severity == "HIGH")
        med_count = sum(1 for f in self.findings if f.severity == "MEDIUM")
        low_count = sum(1 for f in self.findings if f.severity in ("LOW", "INFORMATIONAL", "INFO"))

        controls_rollup: Dict[str, Any] = {}
        for ctl_id, meta in NIST_CONTROLS_CATALOG.items():
            matching = [f.to_dict() for f in self.findings if ctl_id in f.nist_controls]
            assessed = self._control_was_assessed(ctl_id)
            if matching:
                ctl_status = "FAIL"
            elif not assessed:
                ctl_status = "NOT_ASSESSED"
            else:
                ctl_status = "PASS"
            controls_rollup[ctl_id] = {
                "title": meta["title"],
                "family": meta["family"],
                "status": ctl_status,
                "findings_count": len(matching),
                "findings": matching,
            }

        if self.findings:
            overall_status = "NON_COMPLIANT"
        elif not self.loaded_scanners:
            overall_status = "NOT_ASSESSED"
        else:
            overall_status = "COMPLIANT"

        pkg: Dict[str, Any] = {
            "$schema": "https://specs.grc.internal/schemas/scr-scn-package-v1.json",
            "package_schema": "grc-scr-scn-package-v1",
            "session_id": self.provenance.get("session_id", "local-session"),
            "target_identifier": bundle_id,
            "generated_at": now,
            "assessed_scanners": sorted(list(self.loaded_scanners)),
            "provenance": self.provenance,
            "summary": {
                "total_findings": len(self.findings),
                "critical_cat1": crit_count,
                "high_cat2": high_count,
                "medium_cat3": med_count,
                "low_cat4": low_count,
                "overall_status": overall_status,
            },
            "controls_rollup": controls_rollup,
            "findings": [f.to_dict() for f in self.findings],
        }
        if self.sbom_stig_evidence is not None:
            pkg["sbom_stig_applicability"] = self.sbom_stig_evidence
        return pkg

    def seal_evidence_manifest(self) -> str:
        """
        Computes SHA-256 checksums across all files in evidence_dir
        and writes evidence_dir/sha256sum as an integrity manifest.
        """
        manifest_lines: List[str] = []
        target_file = self.evidence_dir / "sha256sum"

        evidence_files = sorted([
            p for p in self.evidence_dir.iterdir()
            if p.is_file() and p.name != "sha256sum" and not p.name.startswith(".")
        ])

        for p in evidence_files:
            sha = sha256_file(p)
            manifest_lines.append(f"{sha}  {p.name}")

        manifest_content = "\n".join(manifest_lines) + "\n"
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(manifest_content)

        return manifest_content

    # --------------------------------------------------------------------------
    # EXECUTE FULL REPORTING PIPELINE
    # --------------------------------------------------------------------------

    def run(self, write_files: bool = True) -> Dict[str, Any]:
        """Executes all ingestion and generation steps."""
        self.load_provenance()
        self.load_baseline_rules()

        for parser_fn in self.PARSERS.values():
            parser_fn(self)

        # Sort findings deterministically by severity rank then finding_id
        self.findings.sort(key=lambda x: (SEVERITY_RANK.get(x.severity, 99), x.rule_or_cve_id, x.file_path))

        poam_md = self.generate_poam_markdown()
        controls_md = self.generate_controls_markdown()
        ruleset_md = self.generate_ruleset_validation_markdown()
        package_json = self.generate_scr_scn_package_json()

        if write_files:
            deliverable_map = {
                "poam_data.md": poam_md,
                "controls.md": controls_md,
                "ruleset_validation.md": ruleset_md,
                "scr_scn_package.json": json.dumps(package_json, indent=2) + "\n",
            }
            for fname, content in deliverable_map.items():
                with open(self.evidence_dir / fname, "w", encoding="utf-8") as f:
                    f.write(content)

            self.seal_evidence_manifest()

        return {
            "findings_count": len(self.findings),
            "assessed_scanners": sorted(list(self.loaded_scanners)),
            "evidence_dir": str(self.evidence_dir),
            "deliverables": [
                "poam_data.md",
                "controls.md",
                "ruleset_validation.md",
                "scr_scn_package.json",
                "sha256sum",
            ],
        }


# ==============================================================================
# CLI DISPATCHER
# ==============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="GRC-xMINI Phase 4 Compliance Deliverable & SCR/SCN Package Synthesizer"
    )
    parser.add_argument(
        "--evidence", "-e",
        required=True,
        type=Path,
        help="Target directory containing scanner JSON files (e.g. evidence/aoc-02-weak-passwords/)",
    )
    parser.add_argument(
        "--workspace", "-w",
        type=Path,
        default=None,
        help="Optional path to ephemeral workspace for provenance fallback",
    )
    parser.add_argument(
        "--ruleset",
        type=Path,
        default=None,
        help="Optional path to custom-baseline-ruleset.yaml",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output synthesis summary as JSON",
    )

    args = parser.parse_args()

    if not args.evidence.exists():
        print(f"[ERROR] Evidence directory not found: {args.evidence}", file=sys.stderr)
        sys.exit(1)

    reporter = GRCComplianceReporter(
        evidence_dir=args.evidence,
        workspace_dir=args.workspace,
        ruleset_path=args.ruleset,
    )

    result = reporter.run(write_files=True)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print("==========================================================")
        print("  GRC Phase 4 Compliance Deliverables Generated")
        print("==========================================================")
        print(f"[*] Target Evidence:    {result['evidence_dir']}")
        print(f"[*] Assessed Scanners:  {', '.join(result['assessed_scanners']) or 'None'}")
        print(f"[*] Total Discovered:   {result['findings_count']} finding(s)")
        print("[*] Generated Deliverables:")
        for d in result["deliverables"]:
            print(f"    - {d}")
        print("==========================================================")


if __name__ == "__main__":
    main()
