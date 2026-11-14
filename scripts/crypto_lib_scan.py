#!/usr/bin/env python3
"""
crypto_lib_scan.py - Static Cryptographic Provider & Dependency Scanner
========================================================================

Classification: Internal Compliance & Engineering Specification
Pipeline Role: Phase 3 (Analyze) & Phase 4 (Evidence) Deliverable Generator
Target Frameworks: NIST SP 800-53 (SI-7, SC-12, SC-13), DISA STIG ASD V5R1, NIST FIPS 140-3

Purpose:
  Statically inspects an extracted repository or workspace to identify and enumerate
  cryptographic libraries, providers, and shared dependencies across:
    - Python (requirements.txt, pyproject.toml)
    - JavaScript / Node.js (package.json)
    - Java (pom.xml)
    - Go (go.mod)
    - Native System Libraries (libcrypto.*, libssl.*, openssl binaries)

  Evaluates detected libraries against policy rules defined in `crypto_catalog.json`
  for:
    - AOC 09: Crypto Dependencies on Unsupported/EOL Libraries (SI-7)
    - Static FIPS 140-3 capability & validation-status inventory (SC-13)
    - Surfacing CAPABLE_IF_CONFIGURED modules as requiring runtime/host verification

Outputs:
  - Terminal Audit Inventory Summary
  - Structured JSON Evidence Deliverable (`crypto_findings.json`)
  - Markdown Audit Traceability Table (`crypto_matrix.md`)
"""

import argparse
import copy
import dataclasses
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
# EMBEDDED FALLBACK POLICY CATALOG (Kept in sync with rules/crypto_catalog.json)
# ==============================================================================

_CATALOG_FILE = Path(__file__).resolve().parent.parent / "rules" / "crypto_catalog.json"

EMBEDDED_CRYPTO_CATALOG: Dict[str, Any] = {
    "openssl": {
        "display_name": "OpenSSL Cryptographic Library",
        "ecosystems": ["c_cpp", "python", "pypi", "system", "deb", "rpm", "alpine"],
        "patterns": ["^openssl$", "^libssl.*", "^libcrypto.*", "^pyopenssl$"],
        "min_supported_version": "3.0.14",
        "status": "ACTIVE",
        "fips_status": "CAPABLE_IF_CONFIGURED",
        "fips_note": (
            "OpenSSL 3.x requires an explicitly configured and activated CMVP-validated FIPS "
            "provider (e.g., openssl.cnf [fips_sect] activate = 1); library version alone does not prove FIPS mode."
        ),
        "eol_versions": [
            {"version": "1.1.1", "eol_date": "2023-09-11", "severity": "CRITICAL"},
            {"version": "1.1.0", "eol_date": "2019-09-11", "severity": "CRITICAL"},
            {"version": "1.0.2", "eol_date": "2019-12-31", "severity": "CRITICAL"},
            {"version": "0.9.8", "eol_date": "2015-12-31", "severity": "CRITICAL"},
        ],
        "remediation": (
            "Upgrade OpenSSL to >= 3.0.14 LTS (or 3.2+) and configure/activate a CMVP-validated "
            "FIPS 140-3 provider for SC-13 workloads."
        ),
        "nist_controls": ["SI-7", "SC-12", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "pycrypto": {
        "display_name": "Python PyCrypto",
        "ecosystems": ["pypi", "python"],
        "patterns": ["^pycrypto$"],
        "status": "DEPRECATED_UNMAINTAINED",
        "fips_status": "NOT_VALIDATED",
        "eol_since": "2013-10-18",
        "severity": "CRITICAL",
        "description": (
            "PyCrypto has been unmaintained since 2013, contains unpatched vulnerabilities, "
            "and is not FIPS 140-3 validated."
        ),
        "fips_note": "PyCrypto is unmaintained and holds no NIST CMVP FIPS 140 validation.",
        "remediation": (
            "Migrate all cryptographic operations to 'cryptography' (pyca/cryptography >= 41.0.0) "
            "linked against a CMVP-validated OpenSSL 3 FIPS provider."
        ),
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "pycryptodome": {
        "display_name": "Python PyCryptodome / PyCryptodomex",
        "ecosystems": ["pypi", "python"],
        "patterns": ["^pycryptodome$", "^pycryptodomex$"],
        "min_supported_version": "3.19.1",
        "status": "ACTIVE",
        "fips_status": "NOT_VALIDATED",
        "fips_note": (
            "PyCryptodome and PyCryptodomex are actively maintained Python packages, "
            "but neither holds a NIST CMVP FIPS 140-2/140-3 module validation certificate."
        ),
        "remediation": (
            "For FIPS 140-3 / SC-13 regulated workloads, migrate to 'cryptography' "
            "(pyca/cryptography) dynamically linked against a CMVP-validated OpenSSL FIPS provider."
        ),
        "nist_controls": ["SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "cryptography": {
        "display_name": "PyCA Cryptography",
        "ecosystems": ["pypi", "python"],
        "patterns": ["^cryptography$"],
        "min_supported_version": "41.0.0",
        "status": "ACTIVE",
        "fips_status": "CAPABLE_IF_CONFIGURED",
        "fips_note": (
            "Standard PyPI manylinux/macOS/Windows wheels statically bundle a non-validated "
            "OpenSSL build. FIPS 140-3 use requires building or dynamically linking against the "
            "host platform's CMVP-validated OpenSSL FIPS provider with FIPS mode enabled."
        ),
        "eol_versions": [
            {"version": "36.", "eol_date": "2023-03-01", "severity": "HIGH"},
            {"version": "3.", "eol_date": "2021-11-01", "severity": "CRITICAL"},
            {"version": "2.", "eol_date": "2020-07-01", "severity": "CRITICAL"},
        ],
        "remediation": (
            "Ensure version >= 41.0.0 (Rust memory-safety bindings) and verify dynamic linkage "
            "against a CMVP-validated OpenSSL 3 FIPS provider rather than default static PyPI wheels."
        ),
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "bouncycastle": {
        "display_name": "Bouncy Castle Standard Provider (Non-FIPS)",
        "ecosystems": ["maven", "gradle", "java"],
        "patterns": [
            "^bcprov-.*",
            "^bcpkix-(?!fips).*",
            "^bcutil-.*",
            "^bctls-(?!fips).*",
            "^bouncycastle.*",
        ],
        "min_supported_version": "1.77",
        "status": "ACTIVE",
        "fips_status": "NOT_VALIDATED",
        "fips_note": (
            "Standard Bouncy Castle (bcprov-jdk18on / bcprov-jdk15on) is not FIPS 140 validated; "
            "use Bouncy Castle FIPS (bc-fips / bctls-fips) in approved-only mode for SC-13 workloads."
        ),
        "eol_versions": [
            {"version": "<1.70", "eol_date": "2021-11-01", "severity": "HIGH"}
        ],
        "remediation": (
            "Upgrade org.bouncycastle dependencies to >= 1.77, and replace standard bcprov-* with "
            "CMVP-validated bc-fips (>= 1.0.2.4) in approved mode for FIPS 140-3 / SC-13 workloads."
        ),
        "nist_controls": ["SI-7", "SC-12", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "bouncycastle-fips": {
        "display_name": "Bouncy Castle FIPS Provider (bc-fips)",
        "ecosystems": ["maven", "gradle", "java"],
        "patterns": ["^bc-fips.*", "^bctls-fips.*", "^bcpkix-fips.*"],
        "min_supported_version": "1.0.2",
        "status": "ACTIVE",
        "fips_status": "CAPABLE_IF_CONFIGURED",
        "fips_note": (
            "Bouncy Castle FIPS (bc-fips) holds CMVP validation on specific certified versions "
            "when JVM provider configuration and CryptoServicesRegistrar.setApprovedOnlyMode(true) enforce approved mode."
        ),
        "remediation": (
            "Verify exact bc-fips version against active NIST CMVP certificate and confirm "
            "JVM/application approved-only mode enforcement."
        ),
        "nist_controls": ["SI-7", "SC-12", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "crypto-js": {
        "display_name": "Node.js crypto-js",
        "ecosystems": ["npm", "yarn", "javascript", "typescript"],
        "patterns": ["^crypto-js$"],
        "min_supported_version": "4.2.0",
        "status": "UNRECOMMENDED",
        "fips_status": "NOT_VALIDATED",
        "severity": "MEDIUM",
        "description": (
            "Active development of crypto-js has been discontinued; pure JS crypto lacks constant-time "
            "side-channel resistance and has no FIPS 140-3 validation."
        ),
        "fips_note": "crypto-js is a pure JavaScript implementation with no NIST CMVP FIPS 140 validation.",
        "remediation": (
            "Migrate to Node.js built-in 'node:crypto' (compiled against a FIPS-validated OpenSSL "
            "provider) or Web Crypto API (SubtleCrypto)."
        ),
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "node-forge": {
        "display_name": "Node-Forge Cryptographic Provider",
        "ecosystems": ["npm", "yarn", "javascript", "typescript"],
        "patterns": ["^node-forge$"],
        "min_supported_version": "1.3.1",
        "status": "ACTIVE",
        "fips_status": "NOT_VALIDATED",
        "fips_note": "Pure-JavaScript node-forge is not a CMVP FIPS 140-3 validated cryptographic module.",
        "remediation": (
            "Upgrade node-forge >= 1.3.1 to remediate ASN.1 and signature verification bypass CVEs, "
            "and migrate SC-13 regulated crypto operations to Node.js 'node:crypto' backed by a FIPS-validated OpenSSL provider."
        ),
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "golang-x-crypto": {
        "display_name": "Go Supplementary Cryptography Libraries",
        "ecosystems": ["golang", "go"],
        "patterns": ["^golang\\.org/x/crypto($|/.*)"],
        "min_supported_version": "0.17.0",
        "status": "ACTIVE",
        "fips_status": "NOT_VALIDATED",
        "description": "Go supplementary cryptography packages outside the Go standard library cryptographic module boundary.",
        "fips_note": (
            "Packages under golang.org/x/crypto lie outside the Go Cryptographic Module boundary "
            "(GODEBUG=fips140=on / BoringCrypto) and are not FIPS 140-3 validated."
        ),
        "remediation": (
            "Update golang.org/x/crypto >= v0.17.0 (mitigating Terrapin SSH CVE-2023-48795), and ensure "
            "FIPS-regulated primitives use Go standard library 'crypto/*' with GODEBUG=fips140=only "
            "(Go 1.24+) or BoringCrypto rather than golang.org/x/crypto."
        ),
        "nist_controls": ["SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
}


def load_crypto_catalog(catalog_path: Optional[Path] = None) -> Dict[str, Any]:
    """
    Loads rules from `catalog_path` (or `rules/crypto_catalog.json`), falling back to a
    deep copy of `EMBEDDED_CRYPTO_CATALOG` so the embedded constant is never mutated.
    """
    target = Path(catalog_path) if catalog_path else _CATALOG_FILE
    if target.is_file():
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("rules"), dict):
                return data["rules"]
            if isinstance(data, dict) and data:
                return data
        except Exception as exc:
            print(
                f"[WARN] Failed to load catalog from {target}: {exc}. Using embedded defaults.",
                file=sys.stderr,
            )
    return copy.deepcopy(EMBEDDED_CRYPTO_CATALOG)


DEFAULT_CRYPTO_CATALOG: Dict[str, Any] = load_crypto_catalog()


# ==============================================================================
# DATA MODELS
# ==============================================================================

@dataclasses.dataclass
class CryptoFinding:
    """Represents a discovered cryptographic dependency and its inventory/compliance status."""

    name: str
    version: str
    source_file: str
    ecosystem: str
    status: str       # "NOT_VALIDATED", "CANNOT_DETERMINE_STATICALLY", "CONFORMANT_INDICATOR", "WARN_OUTDATED", "WARN_UNRECOMMENDED", "WARN_UNVERIFIED", "FAIL_EOL", "FAIL_DEPRECATED"
    severity: str     # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str
    remediation: str
    nist_controls: List[str]
    aoc: str
    rule_key: str
    fips_status: str = "UNKNOWN"  # "VALIDATED_MODULE", "CAPABLE_IF_CONFIGURED", "NOT_VALIDATED", "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "library_name": self.name,
            "detected_version": self.version,
            "manifest_file": self.source_file,
            "ecosystem": self.ecosystem,
            "compliance_status": self.status,
            "fips_status": self.fips_status,
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

                parser_fn = DependencyExtractor.PARSERS.get(f)
                if parser_fn is not None:
                    extracted.extend(parser_fn(f_path, rel_path))
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


DependencyExtractor.PARSERS = {
    "requirements.txt": DependencyExtractor._parse_requirements,
    "pyproject.toml": DependencyExtractor._parse_pyproject,
    "package.json": DependencyExtractor._parse_package_json,
    "pom.xml": DependencyExtractor._parse_pom_xml,
    "go.mod": DependencyExtractor._parse_go_mod,
}


# ==============================================================================
# CRYPTO POLICY ENGINE
# ==============================================================================

class CryptoScanner:
    """Evaluates extracted dependencies against cryptographic policy catalog."""

    _ECOSYSTEM_ALIASES: Dict[str, Set[str]] = {
        "python": {"python", "pypi"},
        "pypi": {"python", "pypi"},
        "java": {"java", "maven", "gradle"},
        "maven": {"java", "maven", "gradle"},
        "gradle": {"java", "maven", "gradle"},
        "javascript": {"javascript", "typescript", "npm", "yarn"},
        "typescript": {"javascript", "typescript", "npm", "yarn"},
        "npm": {"javascript", "typescript", "npm", "yarn"},
        "yarn": {"javascript", "typescript", "npm", "yarn"},
        "go": {"go", "golang"},
        "golang": {"go", "golang"},
        "system": {"system", "c_cpp", "deb", "rpm", "alpine"},
        "c_cpp": {"system", "c_cpp", "deb", "rpm", "alpine"},
        "deb": {"system", "c_cpp", "deb", "rpm", "alpine"},
        "rpm": {"system", "c_cpp", "deb", "rpm", "alpine"},
        "alpine": {"system", "c_cpp", "deb", "rpm", "alpine"},
        "rust": {"rust", "cargo", "crates"},
        "cargo": {"rust", "cargo", "crates"},
        "crates": {"rust", "cargo", "crates"},
    }

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
            matched_key, rule = self._match_rule(name, ecosystem)
            if not rule or not matched_key:
                continue
            finding = self._audit_dependency(name, version, source_file, ecosystem, matched_key, rule)
            findings.append(finding)
        return findings

    def _match_rule(
        self, name: str, ecosystem: str = ""
    ) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        eco_lc = (ecosystem or "").strip().lower()
        eco_group = self._ECOSYSTEM_ALIASES.get(eco_lc, {eco_lc}) if eco_lc else set()
        for key, patterns, rule in self._compiled_rules:
            rule_ecos = {str(e).lower() for e in rule.get("ecosystems", []) if e}
            if eco_group and rule_ecos and not (eco_group & rule_ecos):
                continue
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
        fips_status = rule.get("fips_status", "UNKNOWN")
        fips_note = rule.get("fips_note", "")
        base = CryptoFinding(
            name=name,
            version=version,
            source_file=source_file,
            ecosystem=ecosystem,
            status="CANNOT_DETERMINE_STATICALLY",
            severity="INFO",
            description="",
            remediation=rule.get("remediation", "Migrate to supported crypto provider."),
            nist_controls=rule.get("nist_controls", ["SI-7", "SC-13"]),
            aoc=rule.get("aoc", "AOC-09: Crypto Dependencies on Unsupported Libraries"),
            rule_key=rule_key,
            fips_status=fips_status,
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

        # 6. Maintained version baseline met (SI-7); evaluate SC-13 FIPS 140-3 status explicitly.
        # No library reaches PASS for SC-13 from dependency manifest checks alone.
        if fips_status == "NOT_VALIDATED":
            desc = (
                f"Version '{version}' meets maintenance minimums, but '{name}' is not a "
                "NIST CMVP FIPS 140-3 validated cryptographic module."
            )
            if fips_note:
                desc = f"{desc} {fips_note}"
            return dataclasses.replace(
                base,
                status="NOT_VALIDATED",
                severity="MEDIUM",
                description=desc,
                remediation=rule.get(
                    "remediation",
                    "Migrate SC-13 regulated cryptographic operations to a CMVP-validated module.",
                ),
                nist_controls=["SC-13"],
            )

        if fips_status == "CAPABLE_IF_CONFIGURED":
            desc = (
                f"Version '{version}' meets maintenance baseline, but FIPS 140-3 module linkage and "
                "approved-mode activation cannot be determined from dependency manifests alone."
            )
            if fips_note:
                desc = f"{desc} {fips_note}"
            return dataclasses.replace(
                base,
                status="CANNOT_DETERMINE_STATICALLY",
                severity="INFO",
                description=desc,
                remediation=rule.get(
                    "remediation",
                    "Verify runtime FIPS provider linkage and approved-mode configuration on the deployed host.",
                ),
                nist_controls=["SC-13"],
            )

        if fips_status == "VALIDATED_MODULE":
            desc = (
                f"Version '{version}' matches a validated module entry; confirm operational "
                "environment and approved-mode execution against the CMVP Security Policy."
            )
            if fips_note:
                desc = f"{desc} {fips_note}"
            return dataclasses.replace(
                base,
                status="CONFORMANT_INDICATOR",
                severity="INFO",
                description=desc,
                remediation=rule.get(
                    "remediation",
                    "Confirm operational environment matches CMVP Security Policy.",
                ),
                nist_controls=["SC-13"],
            )

        return dataclasses.replace(
            base,
            status="CANNOT_DETERMINE_STATICALLY",
            severity="INFO",
            description=f"Version '{version}' detected; FIPS 140-3 validation status cannot be determined statically.",
            remediation="Perform manual/runtime FIPS 140-3 module verification for SC-13.",
            nist_controls=["SC-13"],
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
        not_validated = sum(1 for f in findings if f.status == "NOT_VALIDATED")
        needs_review = sum(1 for f in findings if f.status == "CANNOT_DETERMINE_STATICALLY")

        md = [
            "# Cryptographic Library EOL & FIPS Validation-Status Inventory",
            f"> **Generated**: {now}  ",
            f"> **Workspace**: `{workspace}`  ",
            "> **Framework Reference**: NIST SP 800-53 (SI-7, SC-12, SC-13) / NIST FIPS 140-3 / AOC-09  ",
            "",
            "---",
            "",
            "## 1. Inventory & Validation-Status Summary",
            "",
            f"* **Total Cryptographic Libraries Evaluated**: `{len(findings)}`",
            f"* **Failed / EOL / Unsupported (`FAIL_*`)**: `{fails}` (Requires immediate POA&M remediation)",
            f"* **Warnings / Below Baseline / Unverified (`WARN_*`)**: `{warns}`",
            f"* **Unvalidated Modules (`NOT_VALIDATED`)**: `{not_validated}` (No CMVP FIPS 140-3 certificate)",
            f"* **Needs Human or Runtime Verification (`CANNOT_DETERMINE_STATICALLY`)**: `{needs_review}`",
            "",
            "---",
            "",
            "## 2. Findings Detail Matrix",
            "",
            "| Library | Detected Version | Manifest Source | Status | FIPS Status | Severity | NIST Controls | Remediation / Verification Guidance |",
            "| :--- | :---: | :--- | :---: | :---: | :---: | :--- | :--- |",
        ]

        for f in sorted(findings, key=lambda x: (SEVERITY_RANK.get(x.severity.upper(), 99), x.name)):
            status_chip = f"`{_escape_md_cell(f.status)}`"
            fips_chip = f"`{_escape_md_cell(f.fips_status)}`"
            sev_chip = f"**`{f.severity}`**" if f.severity in ("CRITICAL", "HIGH") else f"`{f.severity}`"
            controls = ", ".join(f.nist_controls)
            md.append(
                f"| **{_escape_md_cell(f.name)}** | `{_escape_md_cell(f.version)}` | "
                f"`{_escape_md_cell(f.source_file)}` | {status_chip} | {fips_chip} | {sev_chip} | "
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
                "framework": "NIST SP 800-53 Rev. 5 (SI-7, SC-12, SC-13) / NIST FIPS 140-3",
                "aoc_coverage": ["AOC-09"],
            },
            "summary": {
                "total_crypto_libraries": len(findings),
                "critical_eol_count": sum(1 for f in findings if f.severity == "CRITICAL"),
                "eol_count": sum(1 for f in findings if f.status == "FAIL_EOL"),
                "deprecated_count": sum(1 for f in findings if f.status == "FAIL_DEPRECATED"),
                "unverified_count": sum(1 for f in findings if f.status == "WARN_UNVERIFIED"),
                "high_severity_count": sum(1 for f in findings if f.severity == "HIGH"),
                "warning_count": sum(1 for f in findings if f.status.startswith("WARN")),
                "not_validated_count": sum(1 for f in findings if f.status == "NOT_VALIDATED"),
                "cannot_determine_statically_count": sum(
                    1 for f in findings if f.status == "CANNOT_DETERMINE_STATICALLY"
                ),
                "compliant_count": sum(
                    1 for f in findings if f.status in ("PASS", "CONFORMANT_INDICATOR")
                ),
            },
            "findings": [
                f.to_dict()
                for f in sorted(findings, key=lambda x: (SEVERITY_RANK.get(x.severity.upper(), 99), x.name))
            ],
        }
        return json.dumps(payload, indent=2)

    @staticmethod
    def to_terminal(findings: List[CryptoFinding], workspace: str) -> str:
        lines = [
            "=======================================================================",
            "  Cryptographic Library EOL & FIPS Validation-Status Inventory",
            "=======================================================================",
            f"Workspace: {workspace}",
            f"Crypto Packages Detected: {len(findings)}",
            "-----------------------------------------------------------------------",
        ]
        for f in sorted(findings, key=lambda x: (SEVERITY_RANK.get(x.severity.upper(), 99), x.name)):
            tag = f"[{f.severity}]"
            lines.append(
                f"{tag:<10} {f.name:<20} Ver: {f.version:<10} Status: {f.status} (FIPS: {f.fips_status})"
            )
            lines.append(f"           Source: {f.source_file}")
            lines.append(f"           NIST: {', '.join(f.nist_controls)} | AOC: {f.aoc}")
            lines.append(f"           Action: {f.remediation}")
            lines.append("-----------------------------------------------------------------------")
        return "\n".join(lines)


FORMATTERS = {
    "json": CryptoReporter.to_json,
    "markdown": CryptoReporter.to_markdown,
    "terminal": CryptoReporter.to_terminal,
}


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
    catalog = load_crypto_catalog(Path(args.catalog) if args.catalog else None)

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

    # 3. Format Output via FORMATTERS dispatch dict
    formatter = FORMATTERS.get(fmt, CryptoReporter.to_terminal)
    out = formatter(findings, str(workspace_path))

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
