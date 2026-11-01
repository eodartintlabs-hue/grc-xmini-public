#!/usr/bin/env python3
"""
GRC-xMINI (The GRC eXperience) — Unified Compliance Test & Verification Engine
Engine: scripts/grc_test.py (v1.4.0 — Yokota)

Classification: Internal Compliance & Engineering Specification
Pipeline Role: Engine #7 — Test, Mock & Verification Orchestrator
Target Frameworks: NIST SP 800-53 (SA-11, SI-7, CM-6), FedRAMP High, DISA STIG

Purpose:
  Centralizes and absorbs testing routines, synthetic mock generators, and verification
  harnesses across the GRC-xMINI sister compliance engines:
    1. scripts/transform_scans.py (Scan-to-POA&M Transformer)
    2. scripts/grc_bundle.py (Git Bundle Review & Ingestion)
    3. scripts/crypto_lib_scan.py (EOL & Deprecated Cryptography Scanner)
    4. scripts/grc_ami.py (AMI Cold-Mount & EBS Inspector)
    5. scripts/sbom_analyzer.py (DISA STIG / SRG SBOM Analyzer)
    6. scripts/grc_reporter.py (SCR/SCN Phase 4 Reporting Engine)

Key Capabilities:
  - Synthetic Mock Synthesis: Generates realistic mock AMI metadata, EBS volumes, and
    read-only rootfs fixtures for offline and CI testing.
  - Multi-Engine Invariant Verification: Executes self-contained verification suites
    against all sister engines without third-party dependencies (100% Python Stdlib).
  - Centralized Unit Test Execution: Wraps and orchestrates unittest discovery and reporting.
  - Artifacts Integration: Operates against artifacts/drop-off and artifacts/pick-up.
"""

import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_DROPOFF_DIR = os.path.join(REPO_ROOT, "artifacts", "drop-off")
DEFAULT_PICKUP_DIR = os.path.join(REPO_ROOT, "artifacts", "pick-up")
SAMPLE_SCANS_DIR = os.path.join(REPO_ROOT, "testing", "sample-scans")


# ==============================================================================
# 1. SYNTHETIC MOCK FIXTURE GENERATORS (Absorbed from Sister Engines)
# ==============================================================================

def generate_mock_ebs_volume(snapshot_id: Optional[str] = None) -> str:
    """Generates a synthetic AWS EBS volume identifier."""
    return f"vol-{uuid.uuid4().hex[:17]}"


def generate_mock_ami_metadata(ami_id: str, region: str = "us-east-1") -> Dict[str, Any]:
    """
    Generates realistic synthetic AWS EC2 AMI metadata.
    Absorbed from scripts/grc_ami.py to keep the core AMI engine lightweight.
    """
    snap_id = f"snap-{hashlib.sha256(ami_id.encode()).hexdigest()[:17]}"
    return {
        "image_id": ami_id,
        "name": f"rhel-9-hardened-golden-image-{ami_id[:8]}",
        "owner_id": "123456789012",
        "architecture": "x86_64",
        "creation_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "state": "available",
        "root_device_name": "/dev/sda1",
        "root_snapshot_id": snap_id,
        "root_volume_size_gb": 40,
        "encrypted": True,
        "kms_key_id": f"arn:aws:kms:{region}:123456789012:key/c01d-m0un-t001-f1p5-1402k3y00000",
        "virtualization_type": "hvm",
        "ena_support": True,
        "block_devices": [
            {
                "DeviceName": "/dev/sda1",
                "Ebs": {
                    "SnapshotId": snap_id,
                    "VolumeSize": 40,
                    "Encrypted": True,
                    "KmsKeyId": f"arn:aws:kms:{region}:123456789012:key/c01d-m0un-t001-f1p5-1402k3y00000",
                    "VolumeType": "gp3",
                },
            }
        ],
    }


def create_mock_rootfs(mount_path: Path) -> None:
    """
    Populates a synthetic Linux root filesystem fixture for offline cold-mount tests.
    Absorbed from scripts/grc_ami.py.
    """
    etc_dir = mount_path / "etc"
    etc_dir.mkdir(parents=True, exist_ok=True)
    os_release_content = (
        'NAME="Red Hat Enterprise Linux"\n'
        'VERSION="9.2 (Plow)"\n'
        'ID="rhel"\n'
        'ID_LIKE="fedora"\n'
        'VERSION_ID="9.2"\n'
        'PLATFORM_ID="platform:el9"\n'
        'PRETTY_NAME="Red Hat Enterprise Linux 9.2 (Plow)"\n'
        'ANSI_COLOR="0;31"\n'
        'CPE_NAME="cpe:/o:redhat:enterprise_linux:9::baseos"\n'
        'HOME_URL="https://www.redhat.com/"\n'
        'BUG_REPORT_URL="https://bugzilla.redhat.com/"\n'
    )
    with open(etc_dir / "os-release", "w", encoding="utf-8") as f:
        f.write(os_release_content)

    # Sample library directories with mock shared objects
    lib_dir = mount_path / "usr" / "lib64"
    lib_dir.mkdir(parents=True, exist_ok=True)
    (lib_dir / "libssl.so.3").touch()
    (lib_dir / "libcrypto.so.3").touch()


def create_synthetic_scratch_bundle(dest_bundle: Path) -> Tuple[str, Path]:
    """
    Creates a temporary Git repository in /tmp with intentional compliance flaws,
    tags it at v1.0.0, and exports it as a standalone Git packfile bundle.
    Returns (sha256_checksum, bundle_path).
    """
    temp_repo = Path(tempfile.mkdtemp(prefix="grc_test_repo_"))
    try:
        subprocess.run(["git", "init", "-b", "main"], cwd=temp_repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "GRCx Test Harness"], cwd=temp_repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@grc-x.internal"], cwd=temp_repo, check=True)

        # 1. Sample app.py with hardcoded secret and weak crypto
        app_code = (
            "import hashlib\n"
            "SECRET_KEY = 'hardcoded_test_secret_key'\n"
            "def hash_token(data):\n"
            "    return hashlib.md5(data.encode()).hexdigest()\n"
        )
        (temp_repo / "app.py").write_text(app_code, encoding="utf-8")

        # 2. Sample requirements.txt with deprecated pycrypto
        reqs = "pycrypto==2.6.1\nrequests==2.31.0\n"
        (temp_repo / "requirements.txt").write_text(reqs, encoding="utf-8")

        # 3. Commit and tag
        subprocess.run(["git", "add", "."], cwd=temp_repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "feat: test release candidate"], cwd=temp_repo, check=True, capture_output=True)
        subprocess.run(["git", "tag", "-a", "v1.0.0", "-m", "Release v1.0.0"], cwd=temp_repo, check=True, capture_output=True)

        # 4. Create Git bundle
        dest_bundle.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "bundle", "create", str(dest_bundle), "--all"], cwd=temp_repo, check=True, capture_output=True)

        # 5. Compute SHA-256
        sha256 = hashlib.sha256(dest_bundle.read_bytes()).hexdigest()
        return sha256, dest_bundle
    finally:
        shutil.rmtree(temp_repo, ignore_errors=True)


# ==============================================================================
# 2. MULTI-ENGINE COMPLIANCE TEST RUNNERS
# ==============================================================================

class TestEngine:
    """Orchestrates test suites across the six GRC-xMINI compliance engines."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.results: Dict[str, bool] = {}

    def test_transform_scans(self) -> bool:
        """Tests scripts/transform_scans.py against sample scan datasets in dry-run mode."""
        print("[*] [grc_test] Testing Engine #1: transform_scans.py (Scan-to-POA&M)...")
        transform_script = os.path.join(SCRIPT_DIR, "transform_scans.py")
        tenable_csv = os.path.join(SAMPLE_SCANS_DIR, "tenable_monthly_scan.csv")
        inspector_csv = os.path.join(SAMPLE_SCANS_DIR, "aws_inspector_scan.csv")
        poam_xlsx = os.path.join(SAMPLE_SCANS_DIR, "previous_open_poam.xlsx")

        if not os.path.isfile(tenable_csv):
            print(f"    [SKIP] Sample scan fixture not found: {tenable_csv}")
            return True

        cmd = [
            sys.executable,
            transform_script,
            "--scan", tenable_csv,
            "--scan", inspector_csv,
            "--previous-open", poam_xlsx,
            "--draft-remediations", "y",
            "--dry-run",
        ]
        res = subprocess.run(cmd, capture_output=not self.verbose, text=True)
        success = (res.returncode == 0)
        status = "PASS" if success else "FAIL"
        print(f"    [{status}] transform_scans.py executed successfully.")
        self.results["transform_scans"] = success
        return success

    def test_grc_bundle(self) -> bool:
        """Tests scripts/grc_bundle.py verification, restoration, and teardown."""
        print("[*] [grc_test] Testing Engine #2: grc_bundle.py (Git Bundle Review)...")
        bundle_script = os.path.join(SCRIPT_DIR, "grc_bundle.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_bundle_test_"))
        test_bundle = temp_dir / "scratch-test.bundle"
        workspace = temp_dir / "ephemeral_test_workspace"

        try:
            # 1. Create scratch bundle
            sha256, bundle_path = create_synthetic_scratch_bundle(test_bundle)

            # 2. Verify bundle integrity
            cmd_verify = [sys.executable, bundle_script, "verify", str(bundle_path), "--expected-sha256", sha256]
            res_verify = subprocess.run(cmd_verify, capture_output=not self.verbose, text=True)
            if res_verify.returncode != 0:
                print("    [FAIL] grc_bundle.py verify failed")
                self.results["grc_bundle"] = False
                return False

            # 3. Restore bundle into read-only workspace
            cmd_restore = [
                sys.executable,
                bundle_script,
                "restore",
                str(bundle_path),
                "--workspace", str(workspace),
                "--ref", "v1.0.0",
                "--expected-sha256", sha256,
                "--read-only",
            ]
            res_restore = subprocess.run(cmd_restore, capture_output=not self.verbose, text=True)
            if res_restore.returncode != 0:
                print("    [FAIL] grc_bundle.py restore failed")
                self.results["grc_bundle"] = False
                return False

            # Verify bundle_provenance.json was created
            prov_file = workspace / "bundle_provenance.json"
            if not prov_file.is_file():
                print("    [FAIL] bundle_provenance.json not found in restored workspace")
                self.results["grc_bundle"] = False
                return False

            # 4. Clean workspace
            cmd_clean = [sys.executable, bundle_script, "clean", "--workspace", str(workspace)]
            subprocess.run(cmd_clean, capture_output=True)

            print("    [PASS] grc_bundle.py (verify, restore, provenance, clean) passed.")
            self.results["grc_bundle"] = True
            return True
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_crypto_scan(self) -> bool:
        """Tests scripts/crypto_lib_scan.py against synthetic EOL cryptography fixtures."""
        print("[*] [grc_test] Testing Engine #3: crypto_lib_scan.py (EOL Cryptography)...")
        crypto_script = os.path.join(SCRIPT_DIR, "crypto_lib_scan.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_crypto_test_"))
        try:
            # Create synthetic flawed files
            flawed_py = temp_dir / "sample_crypto.py"
            flawed_py.write_text("import Crypto.Cipher.DES as DES\nimport hashlib\nhashlib.md5(b'test')\n", encoding="utf-8")

            flawed_reqs = temp_dir / "requirements.txt"
            flawed_reqs.write_text("pycrypto==2.6.1\n", encoding="utf-8")

            out_json = temp_dir / "crypto_findings.json"
            cmd = [
                sys.executable,
                crypto_script,
                "--workspace", str(temp_dir),
                "--output", str(out_json),
            ]
            res = subprocess.run(cmd, capture_output=not self.verbose, text=True)
            success = (res.returncode == 0 and out_json.is_file())
            status = "PASS" if success else "FAIL"
            print(f"    [{status}] crypto_lib_scan.py executed successfully.")
            self.results["crypto_lib_scan"] = success
            return success
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_grc_ami(self) -> bool:
        """Tests scripts/grc_ami.py mock ingestion and metadata validation."""
        print("[*] [grc_test] Testing Engine #4: grc_ami.py (AMI Cold-Mount & EBS)...")
        ami_script = os.path.join(SCRIPT_DIR, "grc_ami.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_ami_test_"))
        try:
            workspace = temp_dir / "mock_ami_workspace"
            cmd = [
                sys.executable,
                ami_script,
                "restore",
                "ami-0123456789abcdef0",
                "--mock",
                "--workspace", str(workspace),
            ]
            res = subprocess.run(cmd, capture_output=not self.verbose, text=True)
            success = (res.returncode == 0 and (workspace / "mnt" / "etc" / "os-release").is_file())
            status = "PASS" if success else "FAIL"
            print(f"    [{status}] grc_ami.py mock cold-mount executed successfully.")
            self.results["grc_ami"] = success
            return success
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_sbom_analyzer(self) -> bool:
        """Tests scripts/sbom_analyzer.py against mock CycloneDX SBOM."""
        print("[*] [grc_test] Testing Engine #5: sbom_analyzer.py (DISA STIG / SRG)...")
        sbom_script = os.path.join(SCRIPT_DIR, "sbom_analyzer.py")
        temp_dir = Path(tempfile.mkdtemp(prefix="grc_sbom_test_"))
        try:
            mock_sbom = temp_dir / "bom.json"
            mock_sbom.write_text(json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [
                    {"name": "openssl", "version": "1.1.1", "purl": "pkg:deb/debian/openssl@1.1.1", "type": "library"},
                    {"name": "nginx", "version": "1.22.0", "purl": "pkg:deb/debian/nginx@1.22.0", "type": "application"},
                    {"name": "python", "version": "3.9.0", "purl": "pkg:generic/python@3.9.0", "type": "application"},
                ]
            }), encoding="utf-8")

            out_md = temp_dir / "stig_matrix.md"
            cmd = [
                sys.executable,
                sbom_script,
                "--sbom", str(mock_sbom),
                "--format", "markdown",
                "--output", str(out_md),
            ]
            res = subprocess.run(cmd, capture_output=not self.verbose, text=True)
            success = (res.returncode == 0 and out_md.is_file())
            status = "PASS" if success else "FAIL"
            print(f"    [{status}] sbom_analyzer.py executed successfully.")
            self.results["sbom_analyzer"] = success
            return success
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
        status = "PASS" if success else "FAIL"
        print(f"    [{status}] Unit test suite finished (Tests run: {res.testsRun}, Errors: {len(res.errors)}, Failures: {len(res.failures)}).")
        self.results["unit_tests"] = success
        return success

    def run_all(self) -> bool:
        """Executes all engine checks and unit test suites."""
        print("==================================================================")
        print("  GRC-xMINI (v1.4.0 — Yokota) · COMPREHENSIVE TEST SUITE")
        print("==================================================================")
        self.test_unit_suites()
        self.test_transform_scans()
        self.test_grc_bundle()
        self.test_crypto_scan()
        self.test_grc_ami()
        self.test_sbom_analyzer()

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
# 3. CLI DISPATCHER
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

Examples:
  ./grc test
  ./grc test unit
  ./grc test transform
  python3 scripts/grc_test.py all --verbose
""",
    )
    parser.add_argument(
        "mode",
        nargs="?",
        choices=["all", "unit", "transform", "bundle", "crypto", "ami", "sbom"],
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

    if args.mode == "all":
        success = engine.run_all()
    elif args.mode == "unit":
        success = engine.test_unit_suites()
    elif args.mode == "transform":
        success = engine.test_transform_scans()
    elif args.mode == "bundle":
        success = engine.test_grc_bundle()
    elif args.mode == "crypto":
        success = engine.test_crypto_scan()
    elif args.mode == "ami":
        success = engine.test_grc_ami()
    elif args.mode == "sbom":
        success = engine.test_sbom_analyzer()
    else:
        parser.print_help()
        sys.exit(1)

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
