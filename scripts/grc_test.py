#!/usr/bin/env python3
"""
GRC-xMINI (The GRC eXperience) — Unified Compliance Test & Verification Engine
Engine: scripts/grc_test.py (v1.4.4 — Yokota)

Classification: Internal Compliance & Engineering Specification
Pipeline Role: Engine #7 — Test, Mock & Invariant Verification Orchestrator
Target Frameworks: NIST SP 800-53 (SA-11, SI-7, CM-6), FedRAMP High, DISA STIG

Purpose:
  Centralizes and executes content-invariant verification suites and unit test
  discovery across all six GRC-xMINI compliance engines:
    1. scripts/transform_scans.py (Scan-to-POA&M Transformer)
    2. scripts/grc_bundle.py      (Git Bundle Review & Ingestion)
    3. scripts/crypto_lib_scan.py (EOL & Deprecated Cryptography Scanner)
    4. scripts/grc_ami.py         (AMI Cold-Mount & EBS Inspector)
    5. scripts/sbom_analyzer.py   (DISA STIG / SRG SBOM Analyzer)
    6. scripts/grc_reporter.py    (SCR/SCN Phase 4 Reporting Engine)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable, Dict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Re-export synthetic fixture generators from grc_fixtures for backward compatibility
from grc_fixtures import (  # noqa: E402
    create_mock_rootfs,
    create_synthetic_scratch_bundle,
    generate_mock_ami_metadata,
    generate_mock_ebs_volume,
)

DEFAULT_DROPOFF_DIR = os.path.join(REPO_ROOT, "artifacts", "drop-off")
DEFAULT_PICKUP_DIR = os.path.join(REPO_ROOT, "artifacts", "pick-up")
SAMPLE_SCANS_DIR = os.path.join(REPO_ROOT, "testing", "sample-scans")


# ==============================================================================
# MULTI-ENGINE CONTENT-INVARIANT TEST RUNNERS
# ==============================================================================

class TestEngine:
    """Orchestrates content-invariant verification suites across all 6 GRC-xMINI engines."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: Dict[str, bool] = {}

    def _record(self, name: str, passed: bool, detail: str = "") -> bool:
        self.results[name] = passed
        status = "PASS" if passed else "FAIL"
        suffix = f" ({detail})" if detail else ""
        print(f"    [{status}] {name}{suffix}")
        return passed

    def test_transform_scans(self) -> bool:
        """Tests scripts/transform_scans.py against sample scan datasets and verifies output invariants."""
        print("[*] [grc_test] Testing Engine #1: transform_scans.py (Scan-to-POA&M)...")
        transform_script = os.path.join(SCRIPT_DIR, "transform_scans.py")
        tenable_csv = os.path.join(SAMPLE_SCANS_DIR, "tenable_monthly_scan.csv")
        inspector_csv = os.path.join(SAMPLE_SCANS_DIR, "aws_inspector_scan.csv")
        poam_xlsx = os.path.join(SAMPLE_SCANS_DIR, "previous_open_poam.xlsx")

        for req_file in (tenable_csv, inspector_csv, poam_xlsx):
            if not os.path.isfile(req_file):
                return self._record("transform_scans", False, f"Missing required fixture: {req_file}")

        cmd = [
            sys.executable,
            transform_script,
            "--scan", tenable_csv,
            "--scan", inspector_csv,
            "--previous-open", poam_xlsx,
            "--draft-remediations", "y",
            "--dry-run",
        ]
        res = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        if self.verbose and res.stdout:
            print(res.stdout)
        out = (res.stdout or "") + (res.stderr or "")
        invariants_ok = (
            res.returncode == 0
            and "Consolidated into" in out
            and "Loaded 100 existing entries" in out
            and "51 Carried Over, 64 Newly Detected" in out
        )
        return self._record(
            "transform_scans",
            invariants_ok,
            "multi-scan reconciliation & SLA dry-run verified" if invariants_ok else f"exit={res.returncode}",
        )

    def test_grc_bundle(self) -> bool:
        """Tests scripts/grc_bundle.py verification, restoration, teardown, and self-preservation (P0 #1)."""
        print("[*] [grc_test] Testing Engine #2: grc_bundle.py (Git Bundle Review)...")
        bundle_script = os.path.join(SCRIPT_DIR, "grc_bundle.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_bundle_test_"))
        test_bundle = temp_dir / "scratch-test.bundle"
        workspace = temp_dir / "ephemeral_test_workspace"

        try:
            sha256, bundle_path = create_synthetic_scratch_bundle(test_bundle)

            # 1. Verify bundle integrity
            cmd_verify = [
                sys.executable, bundle_script, "verify", str(bundle_path),
                "--expected-sha256", sha256, "--json",
            ]
            res_verify = subprocess.run(cmd_verify, cwd=REPO_ROOT, capture_output=True, text=True)
            if res_verify.returncode != 0:
                return self._record("grc_bundle", False, f"verify failed: {res_verify.stderr.strip()}")

            # 2. Restore bundle into read-only workspace
            cmd_restore = [
                sys.executable, bundle_script, "restore", str(bundle_path),
                "--workspace", str(workspace),
                "--ref", "v1.0.0",
                "--expected-sha256", sha256,
                "--read-only",
            ]
            res_restore = subprocess.run(cmd_restore, cwd=REPO_ROOT, capture_output=True, text=True)
            if res_restore.returncode != 0:
                return self._record("grc_bundle", False, f"restore failed: {res_restore.stderr.strip()}")

            prov_file = workspace / "bundle_provenance.json"
            if not prov_file.is_file():
                return self._record("grc_bundle", False, "bundle_provenance.json missing")

            prov = json.loads(prov_file.read_text(encoding="utf-8"))
            if prov.get("bundle_sha256") != sha256 or prov.get("status") != "RESTORED":
                return self._record("grc_bundle", False, "provenance content mismatch")

            # 3. Clean workspace with a non-existent --delete-bundle path (P0 #1 regression guard)
            missing_bundle = temp_dir / "does-not-exist.bundle"
            cmd_clean = [
                sys.executable, bundle_script, "clean",
                "--workspace", str(workspace),
                "--delete-bundle", str(missing_bundle),
            ]
            res_clean = subprocess.run(cmd_clean, capture_output=True, text=True)
            if res_clean.returncode != 0 or workspace.exists() or not os.path.isfile(bundle_script):
                return self._record("grc_bundle", False, "clean or self-preservation invariant failed")

            return self._record("grc_bundle", True, "verify, restore, provenance & safe clean verified")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_crypto_scan(self) -> bool:
        """
        Tests scripts/crypto_lib_scan.py content invariants (P0 #5 numeric version compare,
        P0 #6 parent 'vendor' path handling, and .so soname version parsing).
        """
        print("[*] [grc_test] Testing Engine #3: crypto_lib_scan.py (EOL Cryptography)...")
        crypto_script = os.path.join(SCRIPT_DIR, "crypto_lib_scan.py")
        base_temp = Path(tempfile.mkdtemp(prefix="grc_crypto_test_"))
        # Place workspace under a folder containing 'vendor' to guard P0 #6
        temp_dir = base_temp / "vendor-audit-workspace"
        temp_dir.mkdir(parents=True, exist_ok=True)
        try:
            flawed_reqs = temp_dir / "requirements.txt"
            flawed_reqs.write_text(
                "pycrypto==2.6.1\ncryptography==9.0\ncryptography==100.0.0\n",
                encoding="utf-8",
            )
            (temp_dir / "libssl.so.1.1").touch()

            out_json = temp_dir / "crypto_findings.json"
            cmd = [
                sys.executable,
                crypto_script,
                "--workspace", str(temp_dir),
                "--format", "json",
                "--output", str(out_json),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0 or not out_json.is_file():
                return self._record("crypto_lib_scan", False, "execution or JSON output failed")

            payload = json.loads(out_json.read_text(encoding="utf-8"))
            findings = payload.get("findings", [])
            by_key = {(f["library_name"], f["detected_version"]): f["compliance_status"] for f in findings}

            invariants_ok = (
                by_key.get(("pycrypto", "2.6.1")) == "FAIL_DEPRECATED"
                and by_key.get(("cryptography", "9.0")) == "WARN_OUTDATED"
                and by_key.get(("cryptography", "100.0.0")) == "PASS"
                and by_key.get(("libssl.so.1.1", "1.1")) == "FAIL_EOL"
            )
            return self._record(
                "crypto_lib_scan",
                invariants_ok,
                "DEPRECATED, numeric version compare, vendor path & soname EOL verified"
                if invariants_ok
                else f"unexpected statuses: {by_key}",
            )
        finally:
            shutil.rmtree(base_temp, ignore_errors=True)

    def test_grc_ami(self) -> bool:
        """
        Tests scripts/grc_ami.py mock cold-mount, provenance, XFS mount options,
        and verifies real AWS failure does NOT silently fall back to mock mode (P0 #2).
        """
        print("[*] [grc_test] Testing Engine #4: grc_ami.py (AMI Cold-Mount & EBS)...")
        ami_script = os.path.join(SCRIPT_DIR, "grc_ami.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_ami_test_"))
        try:
            # 1. Verify that live mode (without --mock) fails on invalid AWS environment instead of faking success
            env_no_aws = dict(os.environ)
            env_no_aws["AWS_ACCESS_KEY_ID"] = "invalid"
            env_no_aws["AWS_SECRET_ACCESS_KEY"] = "invalid"
            env_no_aws["AWS_EC2_METADATA_DISABLED"] = "true"
            env_no_aws["PATH"] = "/nonexistent"
            res_live = subprocess.run(
                [sys.executable, ami_script, "verify", "ami-00000000000000000"],
                capture_output=True,
                text=True,
                env=env_no_aws,
            )
            if res_live.returncode == 0:
                return self._record("grc_ami", False, "live failure silently succeeded in mock mode (P0 #2)")

            # 2. Verify explicit --mock restore and clean
            workspace = temp_dir / "mock_ami_workspace"
            cmd_restore = [
                sys.executable, ami_script, "restore", "ami-0123456789abcdef0",
                "--mock", "--workspace", str(workspace),
            ]
            res_restore = subprocess.run(cmd_restore, capture_output=True, text=True)
            prov_path = workspace / "ami_provenance.json"
            if res_restore.returncode != 0 or not prov_path.is_file():
                return self._record("grc_ami", False, "mock restore failed")

            prov = json.loads(prov_path.read_text(encoding="utf-8"))
            mount_opts = prov.get("cold_mount_execution", {}).get("mount_options", "")
            os_id = prov.get("os_identification", {}).get("os_id", "")

            # 3. Clean workspace (without passing --mock, verifying clean reads mock_mode from provenance)
            res_clean = subprocess.run(
                [sys.executable, ami_script, "clean", "--workspace", str(workspace)],
                capture_output=True,
                text=True,
            )
            invariants_ok = (
                prov.get("status") == "COLD_MOUNTED"
                and os_id == "rhel"
                and "norecovery" in mount_opts
                and res_clean.returncode == 0
                and not workspace.exists()
            )
            return self._record("grc_ami", invariants_ok, "no silent mock fallback, XFS opts & clean verified")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_sbom_analyzer(self) -> bool:
        """
        Tests scripts/sbom_analyzer.py `--catalog-dump` CLI mode and component-to-STIG
        resolution invariants (client SDK vs server STIG, RHEL 8 vs RHEL 9).
        """
        print("[*] [grc_test] Testing Engine #5: sbom_analyzer.py (DISA STIG / SRG)...")
        sbom_script = os.path.join(SCRIPT_DIR, "sbom_analyzer.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_sbom_test_"))
        try:
            # 1. Verify --catalog-dump works standalone without --sbom
            res_dump = subprocess.run(
                [sys.executable, sbom_script, "--catalog-dump"],
                capture_output=True,
                text=True,
            )
            if res_dump.returncode != 0:
                return self._record("sbom_analyzer", False, "--catalog-dump failed without --sbom")

            # 2. Verify CycloneDX resolution invariants
            mock_sbom = temp_dir / "bom.json"
            mock_sbom.write_text(json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [
                    {"name": "openssl", "version": "1.1.1", "purl": "pkg:deb/debian/openssl@1.1.1", "type": "library"},
                    {"name": "nginx", "version": "1.22.0", "purl": "pkg:deb/debian/nginx@1.22.0", "type": "application"},
                    {"name": "redis", "version": "5.0.1", "purl": "pkg:pypi/redis@5.0.1", "type": "library"},
                    {"name": "java-jwt", "version": "4.4.0", "purl": "pkg:maven/com.auth0/java-jwt@4.4.0", "type": "library"},
                    {"name": "bash", "version": "4.4.20-4.el8", "purl": "pkg:rpm/redhat/bash@4.4.20-4.el8?distro=rhel-8", "type": "library"},
                ],
            }), encoding="utf-8")

            out_json = temp_dir / "stig_applicability.json"
            cmd = [
                sys.executable, sbom_script,
                "--sbom", str(mock_sbom),
                "--format", "json",
                "--output", str(out_json),
            ]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0 or not out_json.is_file():
                return self._record("sbom_analyzer", False, "SBOM JSON generation failed")

            payload = json.loads(out_json.read_text(encoding="utf-8"))
            by_name = {m["component_name"]: m["stig_id"] for m in payload.get("mappings", [])}
            invariants_ok = (
                by_name.get("openssl") == "U_FIPS_Cryptographic_Module_SRG"
                and by_name.get("nginx") == "U_NGINX_Web_Server_STIG"
                and by_name.get("redis") == "U_ASD_V5R1_STIG"
                and by_name.get("java-jwt") == "U_ASD_V5R1_STIG"
                and by_name.get("bash") == "U_RHEL_8_STIG"
            )
            return self._record(
                "sbom_analyzer",
                invariants_ok,
                "catalog-dump, client SDK scoping & RHEL 8 distro mapping verified"
                if invariants_ok
                else f"unexpected mappings: {by_name}",
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_grc_reporter(self) -> bool:
        """
        Tests scripts/grc_reporter.py (Engine #6):
          - Verifies PASS crypto findings are NOT ingested as POA&Ms (P0 #3)
          - Verifies missing Semgrep evidence reports NOT ASSESSED rather than PASSED (P0 #4)
          - Verifies unified 30-day HIGH SLA and sha256sum manifest generation
        """
        print("[*] [grc_test] Testing Engine #6: grc_reporter.py (Phase 4 SCR/SCN Synthesizer)...")
        reporter_script = os.path.join(SCRIPT_DIR, "grc_reporter.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_reporter_test_"))
        try:
            # Write crypto_findings.json with 1 PASS and 1 FAIL_DEPRECATED
            crypto_payload = {
                "findings": [
                    {
                        "library_name": "cryptography",
                        "detected_version": "42.0.0",
                        "manifest_file": "requirements.txt",
                        "ecosystem": "python",
                        "compliance_status": "PASS",
                        "severity": "INFO",
                        "nist_controls": ["SC-13"],
                    },
                    {
                        "library_name": "pycrypto",
                        "detected_version": "2.6.1",
                        "manifest_file": "backend/requirements.txt",
                        "ecosystem": "python",
                        "compliance_status": "FAIL_DEPRECATED",
                        "severity": "CRITICAL",
                        "nist_controls": ["SI-7", "SC-13"],
                    },
                ]
            }
            (temp_dir / "crypto_findings.json").write_text(json.dumps(crypto_payload), encoding="utf-8")

            cmd = [sys.executable, reporter_script, "--evidence", str(temp_dir), "--json"]
            res = subprocess.run(cmd, capture_output=True, text=True)
            pkg_file = temp_dir / "scr_scn_package.json"
            ruleset_file = temp_dir / "ruleset_validation.md"
            if res.returncode != 0 or not pkg_file.is_file() or not ruleset_file.is_file():
                return self._record("grc_reporter", False, "deliverable generation failed")

            pkg = json.loads(pkg_file.read_text(encoding="utf-8"))
            ruleset_md = ruleset_file.read_text(encoding="utf-8")
            findings = pkg.get("findings", [])

            # Invariants:
            # 1. Only 1 finding (pycrypto FAIL_DEPRECATED), NOT the PASS cryptography entry
            # 2. Manifest file preserved ('backend/requirements.txt')
            # 3. Semgrep did not run -> ruleset_validation.md says NOT ASSESSED (NO EVIDENCE)
            # 4. SI-4 (assessed only by Semgrep) status is NOT_ASSESSED
            si4_status = pkg.get("controls_rollup", {}).get("SI-4", {}).get("status")
            invariants_ok = (
                len(findings) == 1
                and "pycrypto" in findings[0]["title"]
                and findings[0]["file_path"] == "backend/requirements.txt"
                and "NOT ASSESSED (NO EVIDENCE)" in ruleset_md
                and si4_status == "NOT_ASSESSED"
            )
            return self._record(
                "grc_reporter",
                invariants_ok,
                "PASS exclusion, NOT_ASSESSED evidence tracking & SCR package verified"
                if invariants_ok
                else f"findings={len(findings)}, SI-4={si4_status}",
            )
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_unit_suites(self) -> bool:
        """Discovers and executes all unit tests under testing/."""
        print("[*] [grc_test] Running Python unit test suite (testing/test_*.py)...")
        testing_dir = os.path.join(REPO_ROOT, "testing")
        loader = unittest.TestLoader()
        suite = loader.discover(start_dir=testing_dir, pattern="test_*.py")
        runner = unittest.TextTestRunner(verbosity=2 if self.verbose else 1)
        res = runner.run(suite)
        success = res.wasSuccessful()
        return self._record(
            "unit_tests",
            success,
            f"Tests run: {res.testsRun}, Errors: {len(res.errors)}, Failures: {len(res.failures)}",
        )

    def run_all(self) -> bool:
        """Executes all engine checks and unit test suites with per-suite crash isolation."""
        print("==================================================================")
        print("  GRC-xMINI (v1.4.4 — Yokota) · COMPREHENSIVE TEST SUITE")
        print("==================================================================")

        suite_runners: Dict[str, Callable[[], bool]] = {
            "unit_tests": self.test_unit_suites,
            "transform_scans": self.test_transform_scans,
            "grc_bundle": self.test_grc_bundle,
            "crypto_lib_scan": self.test_crypto_scan,
            "grc_ami": self.test_grc_ami,
            "sbom_analyzer": self.test_sbom_analyzer,
            "grc_reporter": self.test_grc_reporter,
        }

        for name, fn in suite_runners.items():
            try:
                fn()
            except Exception as exc:
                self._record(name, False, f"Unhandled exception: {exc}")

        print("\n==================================================================")
        print("  TEST SUMMARY MATRIX:")
        print("------------------------------------------------------------------")
        all_passed = True
        for engine, passed in self.results.items():
            sym = "✅ PASS" if passed else "❌ FAIL"
            print(f"  • {engine:<25} : {sym}")
            if not passed:
                all_passed = False
        print("==================================================================")
        return all_passed


# ==============================================================================
# CLI DISPATCHER
# ==============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grc test",
        description="GRC-xMINI Test & Invariant Verification Engine (scripts/grc_test.py)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  all         Run complete verification suite across all 6 engines + unit tests (default)
  unit        Run unit test discovery under testing/
  transform   Test scan-to-POA&M transformation engine against sample fixtures
  bundle      Test Git bundle creation, verification, restoration, and teardown
  crypto      Test EOL cryptographic library scanner against synthetic flaws
  ami         Test AMI cold-mount mock metadata and rootfs synthesizer
  sbom        Test CycloneDX SBOM STIG analyzer
  reporter    Test Phase 4 SCR/SCN compliance reporter

Examples:
  ./grc test
  ./grc test unit
  ./grc test reporter
  python3 scripts/grc_test.py all --verbose
""",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["all", "unit", "transform", "bundle", "crypto", "ami", "sbom", "reporter"],
        default="all",
        help="Test target mode (default: all).",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show verbose command and test runner output.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    engine = TestEngine(verbose=args.verbose)

    dispatch = {
        "all": engine.run_all,
        "unit": engine.test_unit_suites,
        "transform": engine.test_transform_scans,
        "bundle": engine.test_grc_bundle,
        "crypto": engine.test_crypto_scan,
        "ami": engine.test_grc_ami,
        "sbom": engine.test_sbom_analyzer,
        "reporter": engine.test_grc_reporter,
    }

    runner = dispatch.get(args.mode)
    if not runner:
        parser.print_help()
        sys.exit(1)

    try:
        success = runner()
    except Exception as exc:
        print(f"[FATAL] Test execution crashed: {exc}", file=sys.stderr)
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
