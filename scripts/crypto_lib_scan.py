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
    - Python (requirements*.txt, pyproject.toml, poetry.lock)
    - JavaScript / Node.js (package.json, package-lock.json)
    - Java / Kotlin (pom.xml, build.gradle, build.gradle.kts)
    - Go (go.mod, go.sum)
    - Rust (Cargo.toml, Cargo.lock)
    - .NET / C# (*.csproj, packages.lock.json)
    - Native System Libraries (libcrypto.*, libssl.*, openssl binaries)

  Evaluates detected libraries against policy rules defined in `crypto_catalog.json`
  and emits Normalized Finding Schema v1.0.0 (`crypto_findings.json`).
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
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import tomllib  # Python 3.11+ stdlib
except ImportError:
    tomllib = None  # type: ignore

try:
    from grc_common import (
        SEVERITY_RANK,
        get_catalog_descriptor,
        make_finding_id,
        split_aoc,
        utc_now_iso,
        utc_now_str,
        version_lt,
        version_matches_prefix,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from grc_common import (
        SEVERITY_RANK,
        get_catalog_descriptor,
        make_finding_id,
        split_aoc,
        utc_now_iso,
        utc_now_str,
        version_lt,
        version_matches_prefix,
    )

ENGINE_VERSION = "1.5.3"
SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "target", "bin", "obj"}


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
        "fips_remediation": (
            "Configure and activate a CMVP-validated OpenSSL 3 FIPS provider (e.g., openssl.cnf "
            "[fips_sect] activate = 1) for SC-13 workloads; run './grc fips' to inspect configuration."
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
        "fips_remediation": (
            "Verify dynamic linkage against a CMVP-validated OpenSSL 3 FIPS provider rather than "
            "default static PyPI wheels; run './grc fips' to evaluate container/OS linkage."
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
            "CMVP-validated bc-fips (>= 2.0.0) in approved mode for FIPS 140-3 / SC-13 workloads."
        ),
        "fips_remediation": (
            "Replace standard non-FIPS bcprov-* with CMVP-validated bc-fips (>= 2.0.0, cert #4743) "
            "in approved-only mode for FIPS 140-3 / SC-13 workloads."
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
        "historical_fips_versions": [
            {
                "version": "<2.0.0",
                "cert_number": "3673",
                "standard": "FIPS 140-2",
                "sunset_date": "2026-09-21",
                "severity": "MEDIUM",
                "note": (
                    "BC-FJA 1.0.2.x holds only FIPS 140-2 certificate #3673, which moved to Historical status on "
                    "2026-09-21; upgrade to bc-fips >= 2.0.0 (FIPS 140-3 cert #4743)."
                ),
            }
        ],
        "fips_note": (
            "Bouncy Castle FIPS (bc-fips) holds CMVP FIPS 140-3 validation on 2.0.x (cert #4743; "
            "1.0.2.x cert #3673 moved to Historical status on 2026-09-21) when JVM provider "
            "configuration and CryptoServicesRegistrar.setApprovedOnlyMode(true) enforce approved mode."
        ),
        "remediation": (
            "Upgrade bc-fips to >= 2.0.0 (FIPS 140-3 cert #4743) and confirm "
            "JVM/application approved-only mode enforcement."
        ),
        "fips_remediation": (
            "Confirm JVM security.provider priority and CryptoServicesRegistrar.setApprovedOnlyMode(true) enforce "
            "FIPS 140-3 approved-only mode (cert #4743); run './grc fips' to inspect provider configuration."
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
        "fips_remediation": (
            "Migrate SC-13 regulated cryptographic operations from pure-JavaScript node-forge to Node.js "
            "built-in 'node:crypto' backed by a FIPS-validated OpenSSL provider."
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
        "fips_remediation": (
            "Ensure FIPS-regulated primitives use Go standard library 'crypto/*' with GODEBUG=fips140=only "
            "(Go 1.24+) or BoringCrypto rather than unvalidated golang.org/x/crypto packages."
        ),
        "nist_controls": ["SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "rust-ring": {
        "display_name": "Rust ring Cryptography Crate",
        "ecosystems": ["rust", "cargo", "crates"],
        "patterns": ["^ring$"],
        "min_supported_version": "0.17.0",
        "status": "ACTIVE",
        "fips_status": "NOT_VALIDATED",
        "fips_note": "The 'ring' crate does not hold a NIST CMVP FIPS 140-3 validation certificate.",
        "remediation": (
            "For FIPS 140-3 / SC-13 workloads in Rust (including rustls), migrate from 'ring' "
            "to 'aws-lc-rs' with the 'fips' Cargo feature enabled."
        ),
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "rust-aws-lc": {
        "display_name": "AWS-LC Rust Cryptographic Bindings",
        "ecosystems": ["rust", "cargo", "crates"],
        "patterns": ["^aws-lc-rs$", "^aws-lc-fips-sys$"],
        "min_supported_version": "1.6.0",
        "status": "ACTIVE",
        "fips_status": "CAPABLE_IF_CONFIGURED",
        "fips_note": (
            "aws-lc-rs links the CMVP-validated AWS-LC FIPS module (cert #4759) only when compiled "
            "with the 'fips' feature (aws-lc-fips-sys)."
        ),
        "remediation": "Enable the 'fips' Cargo feature on aws-lc-rs / rustls and verify tested Operational Environment alignment.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "rustcrypto-crates": {
        "display_name": "RustCrypto Pure-Rust Algorithm Crates",
        "ecosystems": ["rust", "cargo", "crates"],
        "patterns": ["^md-5$", "^sha-1$", "^sha1$", "^des$", "^chacha20poly1305$", "^salsa20$", "^blowfish$", "^rc4$"],
        "status": "ACTIVE",
        "fips_status": "NOT_VALIDATED",
        "fips_note": "Pure-Rust RustCrypto algorithm crates hold no NIST CMVP FIPS 140-3 validation certificate.",
        "remediation": (
            "Route FIPS-scoped cryptographic operations through 'aws-lc-rs' (with 'fips' feature) "
            "or 'openssl' crate linked to an OpenSSL 3 FIPS provider."
        ),
        "nist_controls": ["SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "rust-openssl": {
        "display_name": "Rust OpenSSL Bindings",
        "ecosystems": ["rust", "cargo", "crates"],
        "patterns": ["^openssl$", "^openssl-sys$"],
        "min_supported_version": "0.10.55",
        "status": "ACTIVE",
        "fips_status": "CAPABLE_IF_CONFIGURED",
        "fips_note": (
            "Rust 'openssl' crate delegates to the linked OpenSSL library; avoid 'vendored' builds "
            "unless explicitly building and activating the CMVP-validated FIPS provider."
        ),
        "remediation": "Ensure openssl crate >= 0.10.55 dynamically links against a host OpenSSL 3.x installation with the FIPS provider activated.",
        "fips_remediation": "Confirm the openssl crate dynamically links against a host OpenSSL 3.x installation with the FIPS provider activated.",
        "nist_controls": ["SI-7", "SC-13"],
        "aoc": "AOC-09: Crypto Dependencies on Unsupported Libraries",
    },
    "dotnet-bouncycastle": {
        "display_name": ".NET BouncyCastle Standard Package (Non-FIPS)",
        "ecosystems": ["nuget", "dotnet", "csharp"],
        "patterns": [
            "^BouncyCastle\\.Cryptography$",
            "^Portable\\.BouncyCastle$",
            "^BouncyCastle\\.NetCore$",
            "^BouncyCastle$",
        ],
        "min_supported_version": "2.3.0",
        "status": "ACTIVE",
        "fips_status": "NOT_VALIDATED",
        "eol_versions": [
            {"version": "1.8.", "eol_date": "2022-12-01", "severity": "HIGH"}
        ],
        "fips_note": (
            "Standard NuGet BouncyCastle packages are not FIPS 140-3 validated; .NET "
            "System.Security.Cryptography delegates to the OS validated module (CNG / OpenSSL FIPS)."
        ),
        "remediation": (
            "Use .NET built-in System.Security.Cryptography APIs backed by OS FIPS mode "
            "(Windows CNG FIPS policy or Linux OpenSSL 3 FIPS provider), or BC-FNA FIPS."
        ),
        "nist_controls": ["SI-7", "SC-13"],
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
# MANIFEST & LOCKFILE PARSERS
# ==============================================================================

_LOCKFILE_BASENAMES = {
    "package-lock.json",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "packages.lock.json",
}

_CANONICAL_SCHEMA_ECOSYSTEM = {
    "python": "pypi",
    "pypi": "pypi",
    "javascript": "npm",
    "typescript": "npm",
    "npm": "npm",
    "yarn": "npm",
    "java": "maven",
    "maven": "maven",
    "gradle": "gradle",
    "go": "go",
    "golang": "go",
    "rust": "cargo",
    "cargo": "cargo",
    "crates": "cargo",
    "nuget": "nuget",
    "dotnet": "nuget",
    "csharp": "nuget",
    "system": "system",
}


class DependencyExtractor:
    """Parses language manifests and lockfiles across Python, JS, Java/Gradle, Go, Rust, .NET, and C/system."""

    PARSERS: Dict[str, Callable[[Path, str], List[Tuple[str, str, str, str]]]] = {}

    @staticmethod
    def _clean_version_spec(raw_spec: str) -> str:
        """
        Extracts the lowest / primary version token from a version specifier or range
        without concatenating separate range clauses (fixes '>=1.3.1 <2.0.0' -> '1.3.1').
        """
        if not raw_spec:
            return "Unknown"
        s = str(raw_spec).strip()
        if not s or s in ("*", "latest", "workspace:*"):
            return "Unknown"
        # Take the first alternative in '1.2.x || 1.3.x' so the lowest allowed bound is evaluated
        first_alt = s.split("||")[0].strip()
        # Extract the first numeric semver-like token (supporting suffix letters like 1.1.1k)
        m = re.search(r"(\d+(?:\.\d+)*(?:[a-zA-Z0-9_\-\.]*)?)", first_alt)
        if not m:
            return "Unknown"
        cand = m.group(1).rstrip(".")
        # Strip wildcard '.x' or '.*'
        cand = re.sub(r"\.[xX\*]+$", "", cand)
        return cand if re.search(r"\d", cand) else "Unknown"

    @staticmethod
    def extract_from_workspace(workspace_root: Path) -> List[Tuple[str, str, str, str]]:
        """
        Traverses workspace and extracts `(package_name, version, manifest_relpath, ecosystem)`.
        Prefers lockfile-pinned versions over manifest ranges within the same directory.
        """
        manifest_items: List[Tuple[str, str, str, str]] = []
        lockfile_items: List[Tuple[str, str, str, str]] = []
        system_items: List[Tuple[str, str, str, str]] = []
        ws_resolved = Path(workspace_root).resolve()

        for root, dirs, files in os.walk(ws_resolved):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            r_path = Path(root)
            for f in sorted(files):
                f_path = r_path / f
                rel_path = str(f_path.relative_to(ws_resolved)).replace("\\", "/")

                parser_fn = DependencyExtractor._resolve_parser(f)
                if parser_fn is not None:
                    parsed = parser_fn(f_path, rel_path)
                    if f in _LOCKFILE_BASENAMES:
                        lockfile_items.extend(parsed)
                    else:
                        manifest_items.extend(parsed)
                elif f.startswith("libcrypto.") or f.startswith("libssl.") or f == "openssl":
                    so_ver = DependencyExtractor._extract_soname_version(f)
                    system_items.append((f, so_ver, rel_path, "system"))

        # Index lockfile packages by (parent_dir, lower_name, canonical_ecosystem)
        locked_keys: Set[Tuple[str, str, str]] = set()
        deduped_locks: List[Tuple[str, str, str, str]] = []
        seen_exact_locks: Set[Tuple[str, str, str, str]] = set()
        for name, ver, rel, eco in lockfile_items:
            parent_dir = str(Path(rel).parent)
            canon_eco = _CANONICAL_SCHEMA_ECOSYSTEM.get(eco, eco)
            locked_keys.add((parent_dir, name.lower(), canon_eco))
            exact = (name.lower(), ver, rel, canon_eco)
            if exact not in seen_exact_locks:
                seen_exact_locks.add(exact)
                deduped_locks.append((name, ver, rel, eco))

        # Keep manifest items unless superseded by a lockfile in the same directory
        final_items: List[Tuple[str, str, str, str]] = []
        for name, ver, rel, eco in manifest_items:
            parent_dir = str(Path(rel).parent)
            canon_eco = _CANONICAL_SCHEMA_ECOSYSTEM.get(eco, eco)
            if (parent_dir, name.lower(), canon_eco) in locked_keys:
                continue
            final_items.append((name, ver, rel, eco))

        final_items.extend(deduped_locks)
        final_items.extend(system_items)
        return final_items

    @staticmethod
    def _resolve_parser(filename: str) -> Optional[Callable[[Path, str], List[Tuple[str, str, str, str]]]]:
        exact = DependencyExtractor.PARSERS.get(filename)
        if exact is not None:
            return exact
        f_lc = filename.lower()
        if f_lc.startswith("requirements") and f_lc.endswith(".txt"):
            return DependencyExtractor._parse_requirements
        if f_lc.endswith(".csproj"):
            return DependencyExtractor._parse_csproj
        return None

    @staticmethod
    def extract_cargo_features(workspace_root: Path) -> Dict[str, Set[str]]:
        """
        Extracts enabled Cargo dependency features across all `Cargo.toml` files in `workspace_root`,
        returning `{crate_name_lower: {feature1, feature2, ...}}`.
        """
        features_map: Dict[str, Set[str]] = {}
        ws_resolved = Path(workspace_root).resolve()
        for root, dirs, files in os.walk(ws_resolved):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if "Cargo.toml" not in files:
                continue
            c_path = Path(root) / "Cargo.toml"
            try:
                content = c_path.read_text(encoding="utf-8", errors="ignore")
                if tomllib is not None:
                    data = tomllib.loads(content)
                    for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
                        deps = data.get(sec, {})
                        if isinstance(deps, dict):
                            for crate, spec in deps.items():
                                if isinstance(spec, dict):
                                    feats = spec.get("features", [])
                                    if isinstance(feats, list):
                                        features_map.setdefault(crate.lower(), set()).update(
                                            str(x).lower() for x in feats
                                        )
                    pkg_feats = data.get("features", {})
                    if isinstance(pkg_feats, dict):
                        for feat_list in pkg_feats.values():
                            if isinstance(feat_list, list):
                                for item in feat_list:
                                    s = str(item)
                                    if "/" in s:
                                        cr, ft = s.split("/", 1)
                                        features_map.setdefault(cr.lstrip("?").lower(), set()).add(ft.lower())
                    continue
            except Exception:
                pass
            # Regex fallback for Python 3.9/3.10
            try:
                content = c_path.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(
                    r"^([a-zA-Z0-9_\-]+)\s*=\s*\{([^}]+)\}", content, re.MULTILINE
                ):
                    crate = m.group(1).lower()
                    body = m.group(2)
                    fm = re.search(r"features\s*=\s*\[([^\]]*)\]", body)
                    if fm:
                        feats = re.findall(r'["\']([^"\']+)["\']', fm.group(1))
                        features_map.setdefault(crate, set()).update(f.lower() for f in feats)
            except OSError:
                pass
        return features_map

    @staticmethod
    def _extract_soname_version(filename: str) -> str:
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
        cleaned = spec_str.strip().split("#")[0].split(";")[0].strip()
        if not cleaned or cleaned.startswith("-"):
            return None
        m = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:\[[^\]]*\])?\s*(.*)$", cleaned)
        if not m:
            return None
        pkg = m.group(1)
        rest = m.group(2).strip()
        if not rest:
            return (pkg, "Unknown")
        return (pkg, DependencyExtractor._clean_version_spec(rest))

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
        results: List[Tuple[str, str, str, str]] = []
        try:
            if tomllib is not None:
                with open(path, "rb") as f:
                    data = tomllib.load(f)
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
                poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
                for pkg, spec in poetry_deps.items():
                    if pkg.lower() == "python":
                        continue
                    ver_str = spec.get("version", "") if isinstance(spec, dict) else str(spec)
                    results.append((pkg, DependencyExtractor._clean_version_spec(ver_str), rel_path, "python"))
                return results
        except Exception:
            pass

        # Section-aware fallback for Python 3.9/3.10 when tomllib is unavailable
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            section = ""
            in_deps_array = False
            for raw_line in content.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("[") and line.endswith("]"):
                    section = line[1:-1].strip()
                    in_deps_array = False
                    continue
                if section in ("project", "project.optional-dependencies") or section.startswith("project.optional-dependencies"):
                    if re.match(r"^[a-zA-Z0-9_\-]+\s*=\s*\[", line):
                        key_name = line.split("=", 1)[0].strip()
                        if section == "project" and key_name != "dependencies":
                            continue
                        in_deps_array = True
                        array_part = line.split("[", 1)[1]
                        for q in re.findall(r'["\']([^"\']+)["\']', array_part):
                            parsed = DependencyExtractor._parse_req_spec(q)
                            if parsed:
                                results.append((parsed[0], parsed[1], rel_path, "python"))
                        if "]" in array_part:
                            in_deps_array = False
                    elif in_deps_array:
                        for q in re.findall(r'["\']([^"\']+)["\']', line):
                            parsed = DependencyExtractor._parse_req_spec(q)
                            if parsed:
                                results.append((parsed[0], parsed[1], rel_path, "python"))
                        if "]" in line:
                            in_deps_array = False
                elif section == "tool.poetry.dependencies":
                    km = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*=\s*(.+)$', line)
                    if km and km.group(1).lower() != "python":
                        pkg = km.group(1)
                        rhs = km.group(2).strip()
                        vm = re.search(r'version\s*=\s*["\']([^"\']+)["\']', rhs)
                        raw_v = vm.group(1) if vm else rhs.strip("\"'")
                        results.append((pkg, DependencyExtractor._clean_version_spec(raw_v), rel_path, "python"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_poetry_lock(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for block in content.split("[[package]]")[1:]:
                nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                vm = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if nm:
                    results.append((nm.group(1), vm.group(1) if vm else "Unknown", rel_path, "python"))
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
                    sec_obj = data.get(section, {})
                    if not isinstance(sec_obj, dict):
                        continue
                    for pkg, ver in sec_obj.items():
                        clean_ver = DependencyExtractor._clean_version_spec(str(ver))
                        results.append((pkg, clean_ver, rel_path, "javascript"))
        except Exception:
            pass
        return results

    @staticmethod
    def _parse_package_lock_json(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            if not isinstance(data, dict):
                return results
            pkgs = data.get("packages")
            if isinstance(pkgs, dict):
                for pkg_key, meta in pkgs.items():
                    if not pkg_key or not isinstance(meta, dict):
                        continue
                    name = pkg_key.split("node_modules/")[-1]
                    ver = str(meta.get("version") or "Unknown")
                    if name:
                        results.append((name, ver, rel_path, "javascript"))
            elif isinstance(data.get("dependencies"), dict):
                for name, meta in data["dependencies"].items():
                    ver = str(meta.get("version") or "Unknown") if isinstance(meta, dict) else "Unknown"
                    results.append((name, ver, rel_path, "javascript"))
        except Exception:
            pass
        return results

    @staticmethod
    def _parse_pom_xml(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        """
        Parses Maven `pom.xml`, resolving `<properties>` placeholders (`${bc.version}`)
        and skipping `<dependencyManagement>` templates unless no active dependency overrides them.
        """
        results: List[Tuple[str, str, str, str]] = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()

            def local_tag(el: ET.Element) -> str:
                return el.tag.split("}", 1)[-1] if "}" in el.tag else el.tag

            props: Dict[str, str] = {}
            project_ver = ""
            for child in root:
                lt = local_tag(child)
                if lt == "version" and child.text:
                    project_ver = child.text.strip()
                elif lt == "properties":
                    for prop in child:
                        if prop.text:
                            props[local_tag(prop)] = prop.text.strip()
            if project_ver:
                props.setdefault("project.version", project_ver)

            def resolve_prop(val: str) -> str:
                m = re.match(r"^\$\{([^}]+)\}$", val)
                if m:
                    resolved = props.get(m.group(1), "")
                    if resolved and not resolved.startswith("${"):
                        return resolved
                    return "Unknown"
                return val

            def collect_deps(container: ET.Element) -> List[Tuple[str, str]]:
                found: List[Tuple[str, str]] = []
                for dep in container:
                    if local_tag(dep) != "dependency":
                        continue
                    art_id = ""
                    ver = "Unknown"
                    for c in dep:
                        cl = local_tag(c)
                        if cl == "artifactId" and c.text:
                            art_id = c.text.strip()
                        elif cl == "version" and c.text:
                            ver = resolve_prop(c.text.strip())
                    if art_id:
                        found.append((art_id, ver))
                return found

            mgmt_versions: Dict[str, str] = {}
            active_deps: List[Tuple[str, str]] = []

            for child in root:
                lt = local_tag(child)
                if lt == "dependencyManagement":
                    for sub in child:
                        if local_tag(sub) == "dependencies":
                            for a_id, v in collect_deps(sub):
                                if v != "Unknown":
                                    mgmt_versions[a_id] = v
                elif lt == "dependencies":
                    active_deps.extend(collect_deps(child))

            for art_id, ver in active_deps:
                resolved_ver = mgmt_versions.get(art_id, "Unknown") if ver == "Unknown" else ver
                results.append((art_id, resolved_ver, rel_path, "java"))
        except Exception:
            pass
        return results

    @staticmethod
    def _parse_gradle(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Match string notation: implementation("group:artifact:version") or implementation 'group:artifact:version'
            for m in re.finditer(
                r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|compile)\s*\(?\s*['"]([^:'"]+):([^:'"]+)(?::([^'"]+))?['"]""",
                content,
            ):
                artifact = m.group(2).strip()
                ver_raw = (m.group(3) or "").strip()
                ver = "Unknown" if (not ver_raw or ver_raw.startswith("$")) else DependencyExtractor._clean_version_spec(ver_raw)
                results.append((artifact, ver, rel_path, "gradle"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_go_mod(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        replaces: Dict[str, Tuple[str, str]] = {}
        excludes: Set[Tuple[str, str]] = set()
        raw_reqs: List[Tuple[str, str]] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            block_mode = ""  # "require", "replace", "exclude", "retract"
            for raw_line in content.splitlines():
                line = raw_line.split("//", 1)[0].strip()
                if not line:
                    continue
                if line == ")":
                    block_mode = ""
                    continue
                m_block = re.match(r"^(require|replace|exclude|retract)\s*\($", line)
                if m_block:
                    block_mode = m_block.group(1)
                    continue

                if line.startswith("replace ") or block_mode == "replace":
                    body = re.sub(r"^replace\s+", "", line).strip()
                    if "=>" in body:
                        left, right = [p.strip() for p in body.split("=>", 1)]
                        old_mod = left.split()[0]
                        r_parts = right.split()
                        if len(r_parts) >= 2 and r_parts[1].startswith("v"):
                            replaces[old_mod] = (r_parts[0], r_parts[1].lstrip("v"))
                    continue

                if line.startswith("exclude ") or block_mode == "exclude":
                    body = re.sub(r"^exclude\s+", "", line).strip()
                    m_ex = re.match(r"^([^\s]+)\s+v?([^\s]+)", body)
                    if m_ex:
                        excludes.add((m_ex.group(1), m_ex.group(2)))
                    continue

                if block_mode == "retract" or line.startswith("retract "):
                    continue

                if line.startswith("require "):
                    m = re.match(r"^require\s+([^\s]+)\s+v?([^\s]+)", line)
                    if m:
                        raw_reqs.append((m.group(1), m.group(2)))
                elif block_mode == "require":
                    m2 = re.match(r"^([^\s]+)\s+v?([^\s]+)", line)
                    if m2 and "/" in m2.group(1):
                        raw_reqs.append((m2.group(1), m2.group(2)))

            for mod, ver in raw_reqs:
                if (mod, ver) in excludes:
                    continue
                if mod in replaces:
                    rep_mod, rep_ver = replaces[mod]
                    results.append((rep_mod, rep_ver, rel_path, "go"))
                else:
                    results.append((mod, ver, rel_path, "go"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_go_sum(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        seen: Set[Tuple[str, str]] = set()
        try:
            for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = raw_line.strip().split()
                if len(parts) < 2:
                    continue
                mod = parts[0]
                ver = parts[1].split("/")[0].lstrip("v")
                if (mod, ver) not in seen:
                    seen.add((mod, ver))
                    results.append((mod, ver, rel_path, "go"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_cargo_toml(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            if tomllib is not None:
                data = tomllib.loads(content)
                for sec in ("dependencies", "dev-dependencies", "build-dependencies"):
                    deps = data.get(sec, {})
                    if not isinstance(deps, dict):
                        continue
                    for crate, spec in deps.items():
                        pkg_name = spec.get("package", crate) if isinstance(spec, dict) else crate
                        ver_str = spec.get("version", "") if isinstance(spec, dict) else str(spec)
                        results.append((str(pkg_name), DependencyExtractor._clean_version_spec(ver_str), rel_path, "rust"))
                return results
        except Exception:
            pass

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            in_deps = False
            for raw_line in content.splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if not line:
                    continue
                if line.startswith("[") and line.endswith("]"):
                    sec = line[1:-1].strip()
                    in_deps = sec in ("dependencies", "dev-dependencies", "build-dependencies") or sec.endswith(".dependencies")
                    continue
                if in_deps:
                    m = re.match(r'^([a-zA-Z0-9_\-]+)\s*=\s*(.+)$', line)
                    if m:
                        crate, rhs = m.group(1), m.group(2).strip()
                        vm = re.search(r'version\s*=\s*["\']([^"\']+)["\']', rhs)
                        raw_v = vm.group(1) if vm else rhs.strip("\"'")
                        results.append((crate, DependencyExtractor._clean_version_spec(raw_v), rel_path, "rust"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_cargo_lock(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for block in content.split("[[package]]")[1:]:
                nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                vm = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if nm:
                    results.append((nm.group(1), vm.group(1) if vm else "Unknown", rel_path, "rust"))
        except OSError:
            pass
        return results

    @staticmethod
    def _parse_csproj(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        try:
            tree = ET.parse(path)
            root = tree.getroot()
            for elem in root.iter():
                tag = elem.tag.split("}", 1)[-1] if "}" in elem.tag else elem.tag
                if tag != "PackageReference":
                    continue
                pkg = elem.attrib.get("Include") or elem.attrib.get("Update") or ""
                ver = elem.attrib.get("Version") or ""
                if not ver:
                    for c in elem:
                        ctag = c.tag.split("}", 1)[-1] if "}" in c.tag else c.tag
                        if ctag == "Version" and c.text:
                            ver = c.text.strip()
                if pkg:
                    results.append((pkg.strip(), DependencyExtractor._clean_version_spec(ver), rel_path, "nuget"))
        except Exception:
            pass
        return results

    @staticmethod
    def _parse_nuget_lock(path: Path, rel_path: str) -> List[Tuple[str, str, str, str]]:
        results: List[Tuple[str, str, str, str]] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            deps = data.get("dependencies", {}) if isinstance(data, dict) else {}
            if isinstance(deps, dict):
                for _tfm, pkgs in deps.items():
                    if isinstance(pkgs, dict):
                        for pkg_name, meta in pkgs.items():
                            ver = str(meta.get("resolved") or "Unknown") if isinstance(meta, dict) else "Unknown"
                            results.append((pkg_name, ver, rel_path, "nuget"))
        except Exception:
            pass
        return results


DependencyExtractor.PARSERS = {
    "requirements.txt": DependencyExtractor._parse_requirements,
    "pyproject.toml": DependencyExtractor._parse_pyproject,
    "poetry.lock": DependencyExtractor._parse_poetry_lock,
    "package.json": DependencyExtractor._parse_package_json,
    "package-lock.json": DependencyExtractor._parse_package_lock_json,
    "pom.xml": DependencyExtractor._parse_pom_xml,
    "build.gradle": DependencyExtractor._parse_gradle,
    "build.gradle.kts": DependencyExtractor._parse_gradle,
    "go.mod": DependencyExtractor._parse_go_mod,
    "go.sum": DependencyExtractor._parse_go_sum,
    "Cargo.toml": DependencyExtractor._parse_cargo_toml,
    "Cargo.lock": DependencyExtractor._parse_cargo_lock,
    "packages.lock.json": DependencyExtractor._parse_nuget_lock,
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
        "nuget": {"nuget", "dotnet", "csharp"},
        "dotnet": {"nuget", "dotnet", "csharp"},
        "csharp": {"nuget", "dotnet", "csharp"},
    }

    def __init__(self, catalog: Dict[str, Any]):
        self.catalog = catalog
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

        # 1. Explicitly deprecated/unmaintained libraries (AOC 09)
        if status_flag == "DEPRECATED_UNMAINTAINED":
            return dataclasses.replace(
                base,
                status="FAIL_DEPRECATED",
                severity=rule.get("severity", "CRITICAL"),
                description=rule.get("description", "Deprecated and unmaintained cryptographic package."),
            )

        # 2. Unrecommended libraries (e.g. crypto-js)
        if status_flag == "UNRECOMMENDED":
            return dataclasses.replace(
                base,
                status="WARN_UNRECOMMENDED",
                severity=rule.get("severity", "MEDIUM"),
                description=rule.get("description", "Unrecommended cryptographic package."),
            )

        # 3. EOL versions
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

        # 4. Minimum Supported Version
        min_ver = rule.get("min_supported_version")
        if min_ver and version != "Unknown" and version_lt(version, min_ver):
            return dataclasses.replace(
                base,
                status="WARN_OUTDATED",
                severity="HIGH",
                description=f"Detected version '{version}' is below baseline minimum '{min_ver}'.",
                remediation=rule.get("remediation", f"Upgrade to >= {min_ver}."),
            )

        # 5. Unknown/unpinned version
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

        # 5b. Historical FIPS 140-2 certificate only (post-2026-09-21 sunset)
        for hist in rule.get("historical_fips_versions", []):
            hist_ver = str(hist.get("version", "")).strip()
            if not hist_ver or version == "Unknown":
                continue
            matched_hist = (
                version_lt(version, hist_ver.lstrip("<").strip())
                if hist_ver.startswith("<")
                else version_matches_prefix(version, hist_ver)
            )
            if matched_hist:
                return dataclasses.replace(
                    base,
                    status="FAIL_HISTORICAL_FIPS",
                    severity=hist.get("severity", "MEDIUM"),
                    description=hist.get(
                        "note",
                        f"Version '{version}' only carries a Historical FIPS 140-2 certificate.",
                    ),
                    remediation=rule.get("remediation", "Upgrade to a FIPS 140-3 validated release."),
                    nist_controls=["SC-13"],
                    fips_status=fips_status,
                )

        # 6. Maintained version baseline met (SI-7); evaluate SC-13 FIPS 140-3 status explicitly.
        fips_rem = rule.get("fips_remediation") or rule.get("remediation")
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
                remediation=fips_rem or "Migrate SC-13 regulated cryptographic operations to a CMVP-validated module.",
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
                remediation=fips_rem or "Verify runtime FIPS provider linkage and approved-mode configuration on the deployed host.",
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
                remediation=fips_rem or "Confirm operational environment matches CMVP Security Policy.",
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


def _to_schema_findings(findings: List[CryptoFinding]) -> List[Dict[str, Any]]:
    """
    Translates internal `CryptoFinding` items into Normalized Finding Schema v1.0.0 records.
    Enforces Rule 1 ('One finding answers one question'): libraries that pass lifecycle
    checks emit a `PASS` finding for SI-7 AND a distinct SC-13 FIPS validation finding.
    Unpinned versions (`WARN_UNVERIFIED`) emit `NEEDS_REVIEW` per owner policy.
    """
    records: List[Dict[str, Any]] = []
    for f in sorted(findings, key=lambda x: (SEVERITY_RANK.get(x.severity.upper(), 99), x.name, x.version)):
        base_name = Path(f.source_file).name
        is_lock = base_name in _LOCKFILE_BASENAMES
        is_sys = f.ecosystem == "system"
        loc_kind = "file" if is_sys else "manifest"
        det_method = "binary" if is_sys else ("lockfile" if is_lock else "manifest")
        has_ver = bool(f.version and f.version != "Unknown")
        det_conf = "HIGH" if (has_ver and not is_sys) else "MEDIUM"

        canon_eco = _CANONICAL_SCHEMA_ECOSYSTEM.get(f.ecosystem.lower(), f.ecosystem.lower())
        subj: Dict[str, Any] = {
            "kind": "package",
            "name": f.name,
            "ecosystem": canon_eco,
        }
        if has_ver:
            subj["version"] = f.version

        loc: Dict[str, Any] = {"kind": loc_kind, "path": f.source_file.replace("\\", "/").lstrip("./")}
        aoc_lifecycle = split_aoc(f.aoc, default_id="AOC-09")
        subj_id_token = f"{f.name}:{f.version}"

        # Case A: Lifecycle failure / warning (FAIL_DEPRECATED, FAIL_EOL, WARN_OUTDATED, WARN_UNRECOMMENDED)
        if f.status in ("FAIL_DEPRECATED", "FAIL_EOL", "WARN_OUTDATED", "WARN_UNRECOMMENDED"):
            det = "FAIL" if f.status.startswith("FAIL") else "WARN"
            rule_id = f"crypto:{f.rule_key}"
            ver_label = f" ({f.version})" if has_ver else ""
            rec: Dict[str, Any] = {
                "finding_id": make_finding_id("cryptoscan", rule_id, loc["path"], None, subj_id_token),
                "rule_id": rule_id,
                "aoc": aoc_lifecycle,
                "controls": list(dict.fromkeys(f.nist_controls or ["SI-7"])),
                "determination": det,
                "determination_detail": f.status,
                "severity": f.severity,
                "subject": subj,
                "location": loc,
                "detection": {"method": det_method, "confidence": det_conf},
                "title": f"Unsupported or outdated cryptographic library: {f.name}{ver_label}"[:200],
                "message": f.description,
                "remediation": f.remediation,
                "extensions": {"fips": {"fips_status": f.fips_status}},
            }
            records.append(rec)
            continue

        # Case B: Unpinned version (`WARN_UNVERIFIED` -> `NEEDS_REVIEW` per owner decision)
        if f.status == "WARN_UNVERIFIED":
            rule_id = f"crypto:{f.rule_key}:unpinned"
            records.append({
                "finding_id": make_finding_id("cryptoscan", rule_id, loc["path"], None, subj_id_token),
                "rule_id": rule_id,
                "aoc": aoc_lifecycle,
                "controls": list(dict.fromkeys(f.nist_controls or ["SI-7", "SC-13"])),
                "determination": "NEEDS_REVIEW",
                "determination_detail": "WARN_UNVERIFIED",
                "severity": "INFO",
                "subject": subj,
                "location": loc,
                "detection": {"method": det_method, "confidence": "MEDIUM"},
                "title": f"Unpinned cryptographic library version: {f.name}"[:200],
                "message": f.description,
                "remediation": f.remediation,
                "extensions": {"fips": {"fips_status": f.fips_status}},
            })
            continue

        # Case C: Lifecycle baseline met -> Emit Rule 1 pair:
        #   (1) SI-7 Lifecycle PASS finding (conformant indicator)
        ver_label = f" ({f.version})" if has_ver else ""
        lifecycle_rule_id = f"crypto:{f.rule_key}"
        records.append({
            "finding_id": make_finding_id("cryptoscan", lifecycle_rule_id, loc["path"], None, subj_id_token),
            "rule_id": lifecycle_rule_id,
            "aoc": aoc_lifecycle,
            "controls": ["SI-7"],
            "determination": "PASS",
            "subject": copy.deepcopy(subj),
            "location": copy.deepcopy(loc),
            "detection": {"method": det_method, "confidence": det_conf},
            "title": f"Supported cryptographic library lifecycle: {f.name}{ver_label}"[:200],
            "message": f"Detected version '{f.version}' meets active maintenance baseline minimums.",
        })

        #   (2) SC-13 FIPS 140-3 module validation finding
        fips_rule_id = f"crypto:{f.rule_key}:fips"
        if f.status == "NOT_VALIDATED":
            records.append({
                "finding_id": make_finding_id("cryptoscan", fips_rule_id, loc["path"], None, subj_id_token),
                "rule_id": fips_rule_id,
                "aoc": aoc_lifecycle,
                "controls": ["SC-13"],
                "determination": "FAIL",
                "determination_detail": "NOT_VALIDATED",
                "severity": "MEDIUM",
                "subject": copy.deepcopy(subj),
                "location": copy.deepcopy(loc),
                "detection": {"method": det_method, "confidence": det_conf},
                "title": f"Unvalidated cryptographic module (no FIPS 140-3 cert): {f.name}{ver_label}"[:200],
                "message": f.description,
                "remediation": f.remediation,
                "extensions": {"fips": {"fips_status": "NOT_VALIDATED"}},
            })
        elif f.status == "FAIL_HISTORICAL_FIPS":
            records.append({
                "finding_id": make_finding_id("cryptoscan", fips_rule_id, loc["path"], None, subj_id_token),
                "rule_id": fips_rule_id,
                "aoc": aoc_lifecycle,
                "controls": ["SC-13"],
                "determination": "FAIL",
                "determination_detail": "FAIL_HISTORICAL_CERT",
                "severity": f.severity,
                "subject": copy.deepcopy(subj),
                "location": copy.deepcopy(loc),
                "detection": {"method": det_method, "confidence": det_conf},
                "title": f"Historical FIPS 140-2 module certificate only: {f.name}{ver_label}"[:200],
                "message": f.description,
                "remediation": f.remediation,
                "extensions": {
                    "fips": {
                        "fips_status": f.fips_status if f.fips_status in ("VALIDATED_MODULE", "CAPABLE_IF_CONFIGURED", "NOT_VALIDATED", "UNKNOWN") else "CAPABLE_IF_CONFIGURED",
                        "cert_standard": "FIPS 140-2",
                        "cert_status": "Historical",
                    }
                },
            })
        elif f.status == "CONFORMANT_INDICATOR":
            records.append({
                "finding_id": make_finding_id("cryptoscan", fips_rule_id, loc["path"], None, subj_id_token),
                "rule_id": fips_rule_id,
                "aoc": {"id": "AOC-12", "title": "Lack of FIPS Mode"},
                "controls": ["SC-13"],
                "determination": "PASS",
                "determination_detail": "CONFORMANT_INDICATOR",
                "subject": copy.deepcopy(subj),
                "location": copy.deepcopy(loc),
                "detection": {"method": det_method, "confidence": "MEDIUM"},
                "title": f"Validated cryptographic module candidate: {f.name}{ver_label}"[:200],
                "message": f.description,
                "extensions": {"fips": {"fips_status": "VALIDATED_MODULE"}},
            })
        else:
            records.append({
                "finding_id": make_finding_id("cryptoscan", fips_rule_id, loc["path"], None, subj_id_token),
                "rule_id": fips_rule_id,
                "aoc": {"id": "AOC-12", "title": "Lack of FIPS Mode"},
                "controls": ["SC-13"],
                "determination": "CANNOT_DETERMINE_STATICALLY",
                "determination_detail": f.fips_status if f.fips_status != "UNKNOWN" else "CANNOT_DETERMINE_STATICALLY",
                "severity": "INFO",
                "subject": copy.deepcopy(subj),
                "location": copy.deepcopy(loc),
                "detection": {"method": det_method, "confidence": "MEDIUM"},
                "title": f"FIPS validation status unverified from manifest: {f.name}{ver_label}"[:200],
                "message": f.description,
                "remediation": f.remediation,
                "extensions": {"fips": {"fips_status": f.fips_status}},
            })

    return records


def _resolve_workspace_target(workspace: str) -> Dict[str, str]:
    ws = Path(workspace)
    for prov_name in ("bundle_provenance.json", "ami_provenance.json"):
        p = ws / prov_name
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                ident = (
                    data.get("target_identifier")
                    or data.get("bundle_identifier")
                    or data.get("ami_identifier")
                    or ws.name
                )
                tgt: Dict[str, str] = {"identifier": str(ident), "provenance_file": prov_name}
                commit = data.get("commit_sha") or data.get("commit_metadata", {}).get("commit_hash")
                if commit and commit != "UNKNOWN":
                    tgt["commit"] = str(commit)
                ref = data.get("checked_out_ref")
                if isinstance(ref, str) and ref.strip():
                    tgt["checked_out_ref"] = ref.strip()
                return tgt
            except Exception:
                pass
    return {"identifier": ws.name or "workspace"}


# ==============================================================================
# REPORT GENERATORS
# ==============================================================================

def _escape_md_cell(val: str) -> str:
    return str(val).replace("|", "\\|").replace("\n", " ")


class CryptoReporter:
    """Formats findings into Normalized Schema v1.0.0 JSON, Markdown, and terminal deliverables."""

    @staticmethod
    def to_markdown(findings: List[CryptoFinding], workspace: str) -> str:
        now = utc_now_str()
        fails = sum(1 for f in findings if f.status.startswith("FAIL"))
        warns = sum(1 for f in findings if f.status in ("WARN_OUTDATED", "WARN_UNRECOMMENDED"))
        not_validated = sum(1 for f in findings if f.status == "NOT_VALIDATED")
        needs_review = sum(
            1 for f in findings if f.status in ("CANNOT_DETERMINE_STATICALLY", "WARN_UNVERIFIED")
        )

        md = [
            "# Cryptographic Library EOL & FIPS Validation-Status Inventory",
            f"> **Generated**: {now}  ",
            f"> **Workspace**: `{workspace}`  ",
            "> **Framework Reference**: NIST SP 800-53 (SI-7, SC-12, SC-13) / NIST FIPS 140-3 / AOC-09  ",
            "> **Scope Note**: Evaluates dependency manifest and binary lifecycle / CMVP validation status only. Run `./grc fips -w <workspace>` to evaluate approved-mode configuration, algorithms, and TLS posture.  ",
            "",
            "---",
            "",
            "## 1. Inventory & Validation-Status Summary",
            "",
            f"* **Total Cryptographic Libraries Evaluated**: `{len(findings)}`",
            f"* **Failed / EOL / Unsupported (`FAIL_*`)**: `{fails}` (Requires immediate POA&M remediation)",
            f"* **Warnings / Below Baseline (`WARN_*`)**: `{warns}`",
            f"* **Unvalidated Modules (`NOT_VALIDATED`)**: `{not_validated}` (No CMVP FIPS 140-3 certificate)",
            f"* **Needs Human or Runtime Verification (`CANNOT_DETERMINE_STATICALLY` / Unpinned)**: `{needs_review}`",
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
    def to_json(
        findings: List[CryptoFinding],
        workspace: str,
        catalog_path: Optional[Path] = None,
    ) -> str:
        cat_file = Path(catalog_path) if catalog_path else _CATALOG_FILE
        schema_findings = _to_schema_findings(findings)
        ecosystems = sorted({
            _CANONICAL_SCHEMA_ECOSYSTEM.get(f.ecosystem.lower(), f.ecosystem.lower())
            for f in findings
            if f.ecosystem
        })
        envelope: Dict[str, Any] = {
            "schema_version": "1.0.0",
            "engine": {
                "name": "CryptoScan",
                "version": ENGINE_VERSION,
                "catalogs": [get_catalog_descriptor(cat_file, rel_label="rules/crypto_catalog.json")],
            },
            "generated_at": utc_now_iso(),
            "target": _resolve_workspace_target(workspace),
            "scope": {
                "assessed_controls": ["SI-7", "SC-12", "SC-13"],
                "assessed_aocs": ["AOC-09", "AOC-12"],
                "ecosystems": ecosystems,
                "limitations": [
                    "Assesses dependency manifests and shared-object lifecycle/CMVP validation status only; run './grc fips' to evaluate source algorithms, TLS settings, and approved-mode configuration.",
                    "Dependency manifests and shared-object filenames cannot prove runtime Operational Environment (OE) or dynamic FIPS provider activation without configuration/host inspection.",
                ],
            },
            "findings": schema_findings,
        }
        return json.dumps(envelope, indent=2)

    @staticmethod
    def to_terminal(findings: List[CryptoFinding], workspace: str) -> str:
        lines = [
            "=======================================================================",
            "  Cryptographic Library EOL & FIPS Validation-Status Inventory",
            "=======================================================================",
            f"Workspace: {workspace}",
            f"Crypto Packages Detected: {len(findings)}",
            "Scope: Dependency manifest & binary lifecycle/CMVP check only (run './grc fips' for approved-mode evaluation).",
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
    if not workspace_path.is_dir():
        if workspace_path.name.lower().endswith(".bundle"):
            print(
                f"[FATAL] Workspace path is a Git bundle file, not a directory: {workspace_path}\n"
                f"        Restore the bundle first: ./grc bundle restore {workspace_path} -w ./ephemeral_workspace -r <tag> -f --read-only",
                file=sys.stderr,
            )
        else:
            print(f"[FATAL] Workspace path is not a directory: {workspace_path}", file=sys.stderr)
        sys.exit(1)

    cat_path = Path(args.catalog) if args.catalog else None
    catalog = load_crypto_catalog(cat_path)

    deps = DependencyExtractor.extract_from_workspace(workspace_path)
    scanner = CryptoScanner(catalog)
    findings = scanner.evaluate(deps)

    fmt = args.format
    if args.output and fmt == "terminal":
        if str(args.output).lower().endswith(".json"):
            fmt = "json"
        elif str(args.output).lower().endswith(".md"):
            fmt = "markdown"

    if fmt == "json":
        out = CryptoReporter.to_json(findings, str(workspace_path), catalog_path=cat_path)
    else:
        formatter = FORMATTERS.get(fmt, CryptoReporter.to_terminal)
        out = formatter(findings, str(workspace_path))

    if args.output:
        try:
            out_p = Path(args.output)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(out + ("\n" if not out.endswith("\n") else ""), encoding="utf-8")
            print(f"[SUCCESS] Crypto audit report written to: {args.output}")
        except IOError as e:
            print(f"[ERROR] Failed to write output file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print(out)


if __name__ == "__main__":
    main()
