#!/usr/bin/env python3
"""
crypto_lib_scan.py - Static Cryptographic Provider & Dependency Scanner
========================================================================

Classification: Internal Compliance & Engineering Specification
Pipeline Role: Phase 3 (Analyze) & Phase 4 (Evidence) Deliverable Generator
Target Frameworks: NIST SP 800-53 (SI-7, SC-12, SC-13, IA-7), DISA STIG ASD V5R1

Purpose:
  Statically inspects an extracted repository or workspace to identify and enumerate
  cryptographic libraries, providers, and shared dependencies across:
    - Python (requirements.txt, pyproject.toml)
    - JavaScript / Node.js (package.json)
    - Java (pom.xml)
    - Go (go.mod)
    - Native System Libraries (libcrypto.*, libssl.*, openssl binaries)

  Evaluates detected libraries against policy rules defined in `crypto_catalog.json`
  to directly satisfy:
    - AOC 09: Crypto Dependencies on Unsupported Libraries (e.g. OpenSSL 1.1.1, PyCrypto)
    - AOC 03: Weak Encryption Check (insecure provider identification)
    - FIPS 140 Cryptographic Module baseline traceability

Outputs:
  - Terminal Compliance Audit Summary
  - Structured JSON Evidence Deliverable (`crypto_findings.json`)
  - Markdown Audit Traceability Table (`crypto_matrix.md`)
"""

import argparse
import dataclasses
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import tomllib  # Python 3.11+ stdlib
except ImportError:
    tomllib = None  # type: ignore

try:
    from grc_common import (
        SEVERITY_RANK,
        utc_now_iso,
        utc_now_str,
        version_lt,
        version_matches_prefix,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from grc_common import (
        SEVERITY_RANK,
        utc_now_iso,
        utc_now_str,
        version_lt,
        version_matches_prefix,
    )

SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv"}


# ==============================================================================
# DEFAULT EMBEDDED POLICY CATALOG (Fallback if JSON not present)
# ==============================================================================

DEFAULT_CRYPTO_CATALOG: Dict[str, Any] = {
    "openssl": {
        "display_name": "OpenSSL Cryptographic Library",
        "ecosystems": ["system", "c_cpp", "deb", "rpm", "alpine"],
        "patterns": [r"^openssl$", r"^libssl.*", r"^libcrypto.*"],
        "min_supported_version": "3.0.0",
        "status": "ACTIVE",
        "fips_capable": True,
        "eol_versions": [
            {"version": "1.1.1", "eol_date": "2023-09-11", "severity": "CRITICAL"},
            {"version": "1.1.0", "eol_date": "2019-09-11", "severity": "CRITICAL"},
            {"version": "1.0.2", "eol_date": "2019-12-31", "severity": "CRITICAL"},
        ],
        "remediation": "Upgrade OpenSSL to supported 3.0.x LTS or 3.2.x+ branch.",
        "nist_controls": ["SI-7", "SC-12", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "pycrypto": {
        "display_name": "Python PyCrypto",
        "ecosystems": ["pypi", "python"],
        "patterns": [r"^pycrypto$"],
        "status": "DEPRECATED_UNMAINTAINED",
        "severity": "CRITICAL",
        "description": "PyCrypto has been unmaintained since 2013 and contains unpatched vulnerabilities.",
        "remediation": "Migrate all cryptographic operations to 'cryptography' or 'pycryptodome'.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "cryptography": {
        "display_name": "PyCA Cryptography",
        "ecosystems": ["pypi", "python"],
        "patterns": [r"^cryptography$"],
        "min_supported_version": "41.0.0",
        "status": "APPROVED",
        "fips_capable": True,
        "remediation": "Ensure version >= 41.0.0 for modern memory-safe OpenSSL bindings.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "bouncycastle": {
        "display_name": "Bouncy Castle Crypto Provider",
        "ecosystems": ["maven", "gradle", "java"],
        "patterns": [r"^bcprov-.*", r"^bcpkix-.*", r"^bcutil-.*", r"^bouncycastle.*"],
        "min_supported_version": "1.70",
        "status": "ACTIVE",
        "fips_capable": True,
        "eol_versions": [
            {"version": "<1.70", "eol_date": "2021-11-01", "severity": "HIGH"}
        ],
        "remediation": "Upgrade org.bouncycastle dependencies to >= 1.70 (or bc-fips 1.0.2+).",
        "nist_controls": ["SI-7", "SC-12", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "crypto-js": {
        "display_name": "Node.js crypto-js",
        "ecosystems": ["npm", "yarn", "javascript", "typescript"],
        "patterns": [r"^crypto-js$"],
        "status": "UNRECOMMENDED",
        "severity": "MEDIUM",
        "description": "crypto-js lacks constant-time security and hardware acceleration.",
        "remediation": "Migrate to native Node.js 'crypto' module or Web Cryptography API.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "node-forge": {
        "display_name": "Node-Forge Cryptographic Provider",
        "ecosystems": ["npm", "yarn", "javascript", "typescript"],
        "patterns": [r"^node-forge$"],
        "min_supported_version": "1.3.1",
        "status": "ACTIVE",
        "remediation": "Ensure version >= 1.3.1 to avoid known signature bypass vulnerabilities.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "golang-x-crypto": {
        "display_name": "Go Supplementary Cryptography Libraries",
        "ecosystems": ["golang", "go"],
        "patterns": [r"^golang\.org/x/crypto.*"],
        "status": "APPROVED",
        "remediation": "Review specific subpackage usage. Ensure standard crypto/aes is preferred.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
}


# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclasses.dataclass
class CryptoFinding:
    """Represents a discovered cryptographic dependency and its compliance status."""

    name: str
    version: str
    source_file: str
    ecosystem: str
    status: str       # "PASS", "WARN_OUTDATED", "WARN_UNVERIFIED", "FAIL_EOL", "FAIL_DEPRECATED"
    severity: str     # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    remediation: str
    nist_controls: List[str]
    aoc: str
    rule_key: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "library_name": self.name,
            "detected_version": self.version,
            "manifest_file": self.source_file,
            "ecosystem": self.ecosystem,
            "compliance_status": self.status,
            "severity": self.severity,
            "description": self.description,
            "remediation": self.remediation,
            "nist_controls": self.nist_controls,
            "area_of_concern": self.aoc,
            "matched_rule": self.rule_key,
        }


# ==============================================================================
# MANIFEST PARSERS
# ==============================================================================

class DependencyExtractor:
    """Parses standard language manifests and extracts packages with versions."""

    @staticmethod
    def extract_from_workspace(workspace_root: Path) -> List[Tuple[str, str, str, str]]:
        """
        Traverses workspace and extracts (package_name, version, manifest_relpath, ecosystem).
        Prunes SKIP_DIRS by exact directory segment name rather than full-path substring matching.
        """
        extracted: List[Tuple[str, str, str, str]] = []
        ws_resolved = Path(workspace_root).resolve()

        for root, dirs, files in os.walk(ws_resolved):
            # In-place prune of skipped directory names (never checks parent path substrings)
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

            r_path = Path(root)
            for f in files:
                f_path = r_path / f
                rel_path = str(f_path.relative_to(ws_resolved))

                if f == "requirements.txt":
                    extracted.extend(DependencyExtractor._parse_requirements(f_path, rel_path))
                elif f == "pyproject.toml":
                    extracted.extend(DependencyExtractor._parse_pyproject(f_path, rel_path))
                elif f == "package.json":
                    extracted.extend(DependencyExtractor._parse_package_json(f_path, rel_path))
                elif f == "pom.xml":
                    extracted.extend(DependencyExtractor._parse_pom_xml(f_path, rel_path))
                elif f == "go.mod":
                    extracted.extend(DependencyExtractor._parse_go_mod(f_path, rel_path))
                elif f.startswith("libcrypto.") or f.startswith("libssl.") or f == "openssl":
                    so_ver = DependencyExtractor._extract_soname_version(f)
                    extracted.append((f, so_ver, rel_path, "system"))

        return extracted

    @staticmethod
    def _extract_soname_version(filename: str) -> str:
        """
        Extracts version string from shared object filenames such as:
          - `libssl.so.1.1`     -> `1.1`
          - `libcrypto.so.3`    -> `3`
          - `libssl.1.1.dylib`  -> `1.1`
          - `libcrypto-1.0.2.so`-> `1.0.2`
        Returns 'Unknown' if no version suffix is embedded in the filename.
        """
        m_so = re.search(r"\.so\.([0-9][0-9a-zA-Z\.\-]*)$", filename)
        if m_so:
            return m_so.group(1)
        m_dylib = re.search(r"\.([0-9][0-9a-zA-Z\.\-]*)\.dylib$", filename)
        if m_dylib:
            return m_dylib.group(1)
        m_dash = re.search(r"-([0-9][0-9a-zA-Z\.\-]*)\.so$", filename)
        if m_dash:
            return m_dash.group(1)
        return "Unknown"

    @staticmethod
    def _parse_req_spec(spec_str: str) -> Optional[Tuple[str, str]]:
        """Parses a PEP 508 / requirements dependency string into (name, version)."""
        cleaned = spec_str.strip().split("#")[0].split(";")[0].strip()
        if not cleaned or cleaned.startswith("-"):
            return None
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]*\])?\s*(?:[=><~^!]+([0-9a-zA-Z_\.\-]+))?", cleaned)
        if m:
            return (m.group(1), m.group(2) or "Unknown")
        return None

    @staticmethod
    def _parse_requirements(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parsed = DependencyExtractor._parse_req_spec(line)
                    if parsed:
                        results.append((parsed[0], parsed[1], rel_path, "python"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_pyproject(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            if tomllib is not None:
                with open(path, "rb") as f:
                    data = tomllib.load(f)
                # PEP 621 project.dependencies & optional-dependencies
                proj = data.get("project", {})
                for dep_str in proj.get("dependencies", []):
                    parsed = DependencyExtractor._parse_req_spec(str(dep_str))
                    if parsed:
                        results.append((parsed[0], parsed[1], rel_path, "python"))
                for group_deps in proj.get("optional-dependencies", {}).values():
                    for dep_str in group_deps:
                        parsed = DependencyExtractor._parse_req_spec(str(dep_str))
                        if parsed:
                            results.append((parsed[0], parsed[1], rel_path, "python"))
                # Poetry dependencies
                poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                for pkg, spec in poetry_deps.items():
                    if pkg.lower() == "python":
                        continue
                    ver_str = spec.get("version", "") if isinstance(spec, dict) else str(spec)
                    clean_ver = re.sub(r"^[\^~>=<!\s]+", "", ver_str).strip() or "Unknown"
                    results.append((pkg, clean_ver, rel_path, "python"))
                return results
        except Exception:
            pass

        # Fallback regex if tomllib unavailable or file malformed
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                deps = re.findall(r'["\']([a-zA-Z0-9_\-\.]+)(?:[=><~^!]+([0-9a-zA-Z_\.\-]+))["\']', content)
                for name, ver in deps:
                    results.append((name, ver or "Unknown", rel_path, "python"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_package_json(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                for section in ("dependencies", "devDependencies"):
                    for pkg, ver in data.get(section, {}).items():
                        clean_ver = re.sub(r"[^0-9\.]", "", str(ver)).strip(".") or "Unknown"
                        results.append((pkg, clean_ver, rel_path, "javascript"))
        except Exception:
            pass
        return results

    @staticmethod
    def _parse_pom_xml(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        """
        Parses Maven `pom.xml` using `xml.etree.ElementTree` per `<dependency>` element
        so dependencies without `<version>` (BOM-managed) never consume a subsequent
        dependency's `<version>`.
        """
        results = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            for elem in root.iter():
                tag_local = elem.tag.split("}", 1)[-1] if "}" in elem.tag else elem.tag
                if tag_local != "dependency":
                    continue
                art_id = ""
                ver = "Unknown"
                for child in elem:
                    c_local = child.tag.split("}", 1)[-1] if "}" in child.tag else child.tag
                    if c_local == "artifactId" and child.text:
                        art_id = child.text.strip()
                    elif c_local == "version" and child.text:
                        raw_v = child.text.strip()
                        # Ignore unresolved Maven property placeholders like ${bc.version}
                        ver = "Unknown" if raw_v.startswith("${") else raw_v
                if art_id:
                    results.append((art_id, ver, rel_path, "java"))
        except Exception:
            pass
        return results

    @staticmethod
    def _parse_go_mod(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    m = re.match(r"^require\s+([^\s]+)\s+([^\s]+)", line)
                    if m:
                        results.append((m.group(1), m.group(2).lstrip("v"), rel_path, "go"))
                    else:
                        m2 = re.match(r"^([^\s]+)\s+v([^\s]+)", line)
                        if m2 and "/" in m2.group(1):
                            results.append((m2.group(1), m2.group(2), rel_path, "go"))
        except OSError:
            pass
        return results


# ==============================================================================
# CRYPTO POLICY ENGINE
# ==============================================================================

class CryptoScanner:
    """Evaluates extracted dependencies against cryptographic policy catalog."""

    def __init__(self, catalog: Dict[str, Any]):
        self.catalog = catalog
        # Pre-compile regex patterns once
        self._compiled_rules: List[Tuple[str, List[re.Pattern], Dict[str, Any]]] = []
        for key, rule in self.catalog.items():
            patterns = [re.compile(pat, re.IGNORECASE) for pat in rule.get("patterns", [])]
            self._compiled_rules.append((key, patterns, rule))

    def evaluate(self, dependencies: List[Tuple[str, str, str, str]]) -> List[CryptoFinding]:
        findings = []
        for name, version, source_file, ecosystem in dependencies:
            matched_key, rule = self._match_rule(name)
            if not rule or not matched_key:
                continue
            finding = self._audit_dependency(name, version, source_file, ecosystem, matched_key, rule)
            findings.append(finding)
        return findings

    def _match_rule(self, name: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        for key, patterns, rule in self._compiled_rules:
            for pat in patterns:
                if pat.match(name):
                    return key, rule
        return None, None

    def _audit_dependency(
        self,
        name: str,
        version: str,
        source_file: str,
        ecosystem: str,
        rule_key: str,
        rule: Dict[str, Any],
    ) -> CryptoFinding:
        status_flag = rule.get("status", "ACTIVE")
        base = CryptoFinding(
            name=name,
            version=version,
            source_file=source_file,
            ecosystem=ecosystem,
            status="PASS",
            severity="INFO",
            description="",
            remediation=rule.get("remediation", "Migrate to supported crypto provider."),
            nist_controls=rule.get("nist_controls", ["SI-7", "SC-13"]),
            aoc=rule.get("aoc", "AOC-09: Crypto Dependencies on Unsupported Libraries"),
            rule_key=rule_key,
        )

        # 1. Check explicitly deprecated/unmaintained libraries (AOC 09)
        if status_flag == "DEPRECATED_UNMAINTAINED":
            return dataclasses.replace(
                base,
                status="FAIL_DEPRECATED",
                severity=rule.get("severity", "CRITICAL"),
                description=rule.get("description", "Deprecated and unmaintained cryptographic package."),
            )

        # 2. Check unrecommended libraries (e.g. crypto-js)
        if status_flag == "UNRECOMMENDED":
            return dataclasses.replace(
                base,
                status="WARN_UNRECOMMENDED",
                severity=rule.get("severity", "MEDIUM"),
                description=rule.get("description", "Unrecommended cryptographic package."),
            )

        # 3. Check EOL versions using numeric tuple comparison & segment-safe prefix matching
        for eol in rule.get("eol_versions", []):
            eol_ver = eol.get("version", "").strip()
            if not eol_ver or version == "Unknown":
                continue
            if eol_ver.startswith("<"):
                threshold = eol_ver.lstrip("<").strip()
                if version_lt(version, threshold):
                    return dataclasses.replace(
                        base,
                        status="FAIL_EOL",
                        severity=eol.get("severity", "CRITICAL"),
                        description=f"Version '{version}' is End-of-Life (EOL since {eol.get('eol_date')}).",
                        nist_controls=rule.get("nist_controls", ["SI-7"]),
                    )
            elif version_matches_prefix(version, eol_ver) or (
                ecosystem == "system" and version in ("1.1", "1.0") and eol_ver.startswith(f"{version}.")
            ):
                return dataclasses.replace(
                    base,
                    status="FAIL_EOL",
                    severity=eol.get("severity", "CRITICAL"),
                    description=f"Version branch '{version}' is End-of-Life (EOL since {eol.get('eol_date')}).",
                    nist_controls=rule.get("nist_controls", ["SI-7"]),
                )

        # 4. Check Minimum Supported Version using numeric tuple comparison
        min_ver = rule.get("min_supported_version")
        if min_ver and version != "Unknown" and version_lt(version, min_ver):
            return dataclasses.replace(
                base,
                status="WARN_OUTDATED",
                severity="HIGH",
                description=f"Detected version '{version}' is below baseline minimum '{min_ver}'.",
                remediation=rule.get("remediation", f"Upgrade to >= {min_ver}."),
            )

        # 5. If version is Unknown and the rule enforces version constraints, report UNVERIFIED instead of PASS
        if version == "Unknown" and (min_ver or rule.get("eol_versions")):
            return dataclasses.replace(
                base,
                status="WARN_UNVERIFIED",
                severity="MEDIUM",
                description=(
                    f"Cryptographic library '{name}' detected without a pinned or parseable version; "
                    f"minimum supported version is '{min_ver or 'active release'}'."
                ),
                remediation=rule.get("remediation", "Pin and verify cryptographic library version."),
            )

        # 6. Approved / Compliant Provider
        return dataclasses.replace(
            base,
            status="PASS",
            severity="INFO",
            description=f"Supported cryptographic library. FIPS Capable: {rule.get('fips_capable', False)}.",
            remediation="None required. Maintain automated dependency patch cadence.",
            nist_controls=rule.get("nist_controls", ["SC-13"]),
        )


# ==============================================================================
# REPORT GENERATORS
# ==============================================================================

def _escape_md_cell(val: str) -> str:
    return str(val).replace("|", "\\|").replace("\n", " ")


class CryptoReporter:
    """Formats findings into Markdown, JSON, and terminal deliverables."""

    @staticmethod
    def to_markdown(findings: List[CryptoFinding], workspace: str) -> str:
        now = utc_now_str()
        fails = sum(1 for f in findings if f.status.startswith("FAIL"))
        warns = sum(1 for f in findings if f.status.startswith("WARN"))
        passes = sum(1 for f in findings if f.status == "PASS")

        md = [
            "# Cryptographic Provider & Dependency Audit Matrix",
            f"> **Generated**: {now}  ",
            f"> **Workspace**: `{workspace}`  ",
            "> **Framework Reference**: NIST SP 800-53 (SI-7, SC-12, SC-13) / AOC-09 & AOC-03  ",
            "",
            "---",
            "",
            "## 1. Compliance Summary",
            "",
            f"* **Total Cryptographic Libraries Evaluated**: `{len(findings)}`",
            f"* **Failed / EOL / Unsupported**: `{fails}` (Requires immediate POA&M remediation)",
            f"* **Warnings / Below Baseline / Unverified**: `{warns}`",
            f"* **Approved / Supported**: `{passes}`",
            "",
            "---",
            "",
            "## 2. Findings Detail Matrix",
            "",
            "| Library | Detected Version | Manifest Source | Status | Severity | NIST Controls | Remediation Guidance |",
            "| :--- | :---: | :--- | :---: | :---: | :--- | :--- |",
        ]

        for f in sorted(findings, key=lambda x: (SEVERITY_RANK.get(x.severity.upper(), 99), x.name)):
            status_chip = f"`{_escape_md_cell(f.status)}`"
            sev_chip = f"**`{f.severity}`**" if f.severity in ("CRITICAL", "HIGH") else f"`{f.severity}`"
            controls = ", ".join(f.nist_controls)
            md.append(
                f"| **{_escape_md_cell(f.name)}** | `{_escape_md_cell(f.version)}` | "
                f"`{_escape_md_cell(f.source_file)}` | {status_chip} | {sev_chip} | "
                f"`{_escape_md_cell(controls)}` | {_escape_md_cell(f.remediation)} |"
            )

        md.append("")
        md.append("---")
        md.append("*Generated by GRC-xMINI Review Pipeline (`crypto_lib_scan.py`)*")
        return "\n".join(md)

    @staticmethod
    def to_json(findings: List[CryptoFinding], workspace: str) -> str:
        payload = {
            "metadata": {
                "scan_time": utc_now_iso(),
                "workspace": workspace,
                "tool": "crypto_lib_scan.py",
                "framework": "NIST SP 800-53 Rev. 5 (SI-7, SC-12, SC-13)",
                "aoc_coverage": ["AOC-09", "AOC-03"],
            },
            "summary": {
                "total_crypto_libraries": len(findings),
                "critical_eol_count": sum(1 for f in findings if f.severity == "CRITICAL"),
                "high_severity_count": sum(1 for f in findings if f.severity == "HIGH"),
                "warning_count": sum(1 for f in findings if f.status.startswith("WARN")),
                "compliant_count": sum(1 for f in findings if f.status == "PASS"),
            },
            "findings": [
                f.to_dict()
                for f in sorted(findings, key=lambda x: (SEVERITY_RANK.get(x.severity.upper(), 99), x.name))
            ],
        }
        return json.dumps(payload, indent=2)


# ==============================================================================
# CLI ENTRY POINT
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Static Cryptographic Provider & Dependency Auditor (GRC-xMINI Review Pipeline)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 crypto_lib_scan.py --workspace ./ephemeral_workspace
  python3 crypto_lib_scan.py --workspace ./ephemeral_workspace --format markdown -o crypto_matrix.md
  python3 crypto_lib_scan.py --workspace ./ephemeral_workspace --format json -o crypto_findings.json
  python3 crypto_lib_scan.py --catalog rules/crypto_catalog.json --workspace ./ephemeral_workspace
        """,
    )
    parser.add_argument(
        "--workspace",
        "-w",
        default=".",
        help="Path to the extracted workspace or code tree to scan (default: current directory).",
    )
    parser.add_argument(
        "--catalog",
        "-c",
        help="Path to custom crypto_catalog.json policy file (defaults to rules/crypto_catalog.json if present).",
    )
    parser.add_argument(
        "--format",
        "-f",
        choices=["terminal", "markdown", "json"],
        default="terminal",
        help="Output presentation format (default: terminal).",
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output file path. If omitted, results are emitted to stdout.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    workspace_path = Path(args.workspace).resolve()
    if not workspace_path.exists():
        print(f"[FATAL] Workspace path does not exist: {workspace_path}", file=sys.stderr)
        sys.exit(1)

    # Load Catalog
    catalog = DEFAULT_CRYPTO_CATALOG
    catalog_path = (
        Path(args.catalog)
        if args.catalog
        else Path(__file__).resolve().parent.parent / "rules" / "crypto_catalog.json"
    )
    if catalog_path.exists():
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and "rules" in data and isinstance(data["rules"], dict):
                    catalog = data["rules"]
                elif isinstance(data, dict) and data:
                    catalog = data
        except Exception as e:
            print(f"[WARN] Failed to load catalog from {catalog_path}: {e}. Using embedded defaults.", file=sys.stderr)

    # 1. Discover dependencies across manifests
    deps = DependencyExtractor.extract_from_workspace(workspace_path)

    # 2. Audit against crypto policy
    scanner = CryptoScanner(catalog)
    findings = scanner.evaluate(deps)

    # If --output ends with .json and --format wasn't explicitly set to markdown, emit JSON automatically
    fmt = args.format
    if args.output and fmt == "terminal":
        if str(args.output).lower().endswith(".json"):
            fmt = "json"
        elif str(args.output).lower().endswith(".md"):
            fmt = "markdown"

    # 3. Format Output
    if fmt == "json":
        out = CryptoReporter.to_json(findings, str(workspace_path))
    elif fmt == "markdown":
        out = CryptoReporter.to_markdown(findings, str(workspace_path))
    else:
        lines = [
            "=======================================================================",
            "  Cryptographic Provider & Dependency Audit Report",
            "=======================================================================",
            f"Workspace: {workspace_path}",
            f"Crypto Packages Detected: {len(findings)}",
            "-----------------------------------------------------------------------",
        ]
        for f in sorted(findings, key=lambda x: (SEVERITY_RANK.get(x.severity.upper(), 99), x.name)):
            tag = f"[{f.severity}]"
            lines.append(f"{tag:<10} {f.name:<20} Ver: {f.version:<10} Status: {f.status}")
            lines.append(f"           Source: {f.source_file}")
            lines.append(f"           NIST: {', '.join(f.nist_controls)} | AOC: {f.aoc}")
            lines.append(f"           Action: {f.remediation}")
            lines.append("-----------------------------------------------------------------------")
        out = "\n".join(lines)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"[SUCCESS] Crypto audit report written to: {args.output}")
        except IOError as e:
            print(f"[ERROR] Failed to write output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(out)


if __name__ == "__main__":
    main()
