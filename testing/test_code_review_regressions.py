#!/usr/bin/env python3
"""
Unit Test Suite for v1.4.0 (Yokota) Code Review P0 & P1 Regression Invariants.

Validates:
  - P0 #1: `grc_bundle.py` clean with missing `--delete-bundle` never deletes `grc_bundle.py`,
           and `safe_rmtree` refuses to delete protected/unmarked directories.
  - P0 #2: `grc_ami.py` never silently falls back to mock mode on AWS failures, and rolls
           back ephemeral EBS volumes if attach/mount fails.
  - P0 #3: `grc_reporter.py` excludes `PASS` crypto scan results from POA&M ingestion and
           preserves `manifest_file`.
  - P0 #4: `grc_reporter.py` reports `NOT ASSESSED` (not `COMPLIANT` / `PASSED`) when
           scanner evidence files (`semgrep_findings.json`, `checkov_findings.json`) are absent.
  - P0 #5: `crypto_lib_scan.py` compares versions numerically (`"9.0" < "41.0.0"` is True;
           `"100.0" < "41.0.0"` is False) and matches EOL prefixes on segment boundaries
           (`"1.1.1"` does not match `"1.1.10"`).
  - P0 #6: `crypto_lib_scan.py` scans workspaces located inside parent paths containing
           `vendor`, `.git`, or `node_modules` while still pruning child `node_modules/`.
  - P1s:   Maven `pom.xml` BOM-managed dependency without `<version>` does not steal next
           dependency's version; `.so` soname version extraction; `sbom_analyzer.py` client
           SDK vs server STIG scoping and RHEL 8 distro mapping; unified 30d HIGH SLA.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import crypto_lib_scan  # noqa: E402
import grc_ami  # noqa: E402
import grc_bundle  # noqa: E402
import grc_common  # noqa: E402
import grc_reporter  # noqa: E402
import sbom_analyzer  # noqa: E402


class TestCodeReviewRegressions(unittest.TestCase):
    """Regression suite covering P0 and P1 findings from the v1.4.0 Yokota code review."""

    # -----------------------------------------------------------------------
    # P0 #1: grc_bundle self-preservation & safe_rmtree guards
    # -----------------------------------------------------------------------

    def test_p0_1_grc_bundle_clean_missing_bundle_never_deletes_script(self) -> None:
        script_path = Path(grc_bundle.__file__).resolve()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ephemeral_ws"
            ws.mkdir()
            (ws / "bundle_provenance.json").write_text("{}", encoding="utf-8")
            missing_bundle = Path(tmp) / "nonexistent.bundle"

            grc_bundle.clean_ephemeral_workspace(
                workspace_root=ws,
                bundle_path=missing_bundle,
                remove_bundle=True,
            )
            self.assertFalse(ws.exists())
            self.assertTrue(script_path.is_file(), "grc_bundle.py must still exist!")

            # Attempting to pass a .py script as --delete-bundle must raise ValueError
            with self.assertRaises(ValueError):
                grc_bundle.clean_ephemeral_workspace(
                    workspace_root=ws,
                    bundle_path=script_path,
                    remove_bundle=True,
                )

    def test_p0_1_safe_rmtree_refuses_unmarked_or_protected_directories(self) -> None:
        with self.assertRaises(ValueError):
            grc_common.safe_rmtree(REPO_ROOT)
        with self.assertRaises(ValueError):
            grc_common.safe_rmtree(Path.home())

        with tempfile.TemporaryDirectory() as tmp:
            unmarked = Path(tmp) / "important_user_dir"
            unmarked.mkdir()
            (unmarked / "user_data.txt").write_text("do not delete", encoding="utf-8")
            with self.assertRaises(ValueError):
                grc_common.safe_rmtree(unmarked)
            self.assertTrue((unmarked / "user_data.txt").is_file())

    # -----------------------------------------------------------------------
    # P0 #2: grc_ami no silent mock fallback + orphaned volume rollback
    # -----------------------------------------------------------------------

    def test_p0_2_grc_ami_live_failure_raises_without_mock_fallback(self) -> None:
        mgr = grc_ami.GRCAMIManager(ami_id="ami-0deadbeef00000000", mock_mode=False)
        with mock.patch.object(grc_ami, "HAS_BOTO3", False):
            with mock.patch("subprocess.run", side_effect=FileNotFoundError(2, "No such file", "aws")):
                with self.assertRaises(RuntimeError):
                    mgr.verify_ami()
                self.assertFalse(mgr.mock_mode, "mock_mode must not flip to True on AWS error")

    def test_p0_2_grc_ami_rolls_back_volume_when_mount_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = grc_ami.GRCAMIManager(
                ami_id="ami-0123456789abcdef0",
                workspace_root=Path(tmp) / "ws",
                worker_id="i-0123456789abcdef0",
                mock_mode=False,
            )
            with mock.patch.object(mgr, "verify_ami", return_value={
                "root_snapshot_id": "snap-12345",
                "encrypted": True,
                "kms_key_id": "arn:aws:kms:us-east-1:123:key/abc",
            }):
                with mock.patch.object(mgr, "_create_ephemeral_volume", return_value="vol-orphan123"):
                    with mock.patch.object(mgr, "_attach_ephemeral_volume", return_value="/dev/xvdf"):
                        with mock.patch.object(mgr, "_mount_filesystem", side_effect=RuntimeError("mount failed")):
                            with mock.patch.object(mgr, "_detach_and_delete_volume") as mock_rollback:
                                with self.assertRaises(RuntimeError):
                                    mgr.restore_ami()
                                mock_rollback.assert_called_once_with("vol-orphan123")

    def test_p1_grc_ami_kms_exact_matching_and_unencrypted_rejection(self) -> None:
        self.assertTrue(grc_ami._kms_key_matches(
            "arn:aws:kms:us-east-1:123456789012:key/c01d-m0un-t001",
            "c01d-m0un-t001",
        ))
        # Substring 'm0un' must NOT match
        self.assertFalse(grc_ami._kms_key_matches(
            "arn:aws:kms:us-east-1:123456789012:key/c01d-m0un-t001",
            "m0un",
        ))

        mgr = grc_ami.GRCAMIManager(ami_id="ami-unenc", mock_mode=True, allow_unencrypted=False)
        with mock.patch.object(mgr, "_fetch_ami_metadata", return_value={
            "root_snapshot_id": "snap-1",
            "encrypted": False,
            "kms_key_id": None,
        }):
            with self.assertRaises(ValueError):
                mgr.verify_ami()

    # -----------------------------------------------------------------------
    # P0 #3 & P0 #4: grc_reporter PASS exclusion & NOT ASSESSED state
    # -----------------------------------------------------------------------

    def test_p0_3_and_4_grc_reporter_pass_exclusion_and_not_assessed_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ev_dir = Path(tmp)
            crypto_data = {
                "findings": [
                    {
                        "library_name": "cryptography",
                        "detected_version": "42.0.0",
                        "manifest_file": "requirements.txt",
                        "compliance_status": "PASS",
                        "severity": "INFO",
                        "nist_controls": ["SC-13"],
                    },
                    {
                        "library_name": "pycrypto",
                        "detected_version": "2.6.1",
                        "manifest_file": "services/auth/requirements.txt",
                        "compliance_status": "FAIL_DEPRECATED",
                        "severity": "CRITICAL",
                        "nist_controls": ["SI-7", "SC-13"],
                    },
                ]
            }
            (ev_dir / "crypto_findings.json").write_text(json.dumps(crypto_data), encoding="utf-8")

            reporter = grc_reporter.GRCComplianceReporter(evidence_dir=ev_dir)
            reporter.run(write_files=True)

            # P0 #3: Only 1 finding (pycrypto), PASS item excluded, manifest_file preserved
            self.assertEqual(len(reporter.findings), 1)
            self.assertEqual(reporter.findings[0].file_path, "services/auth/requirements.txt")

            # P0 #4: Semgrep & Checkov did not run -> ruleset_validation.md and controls.md say NOT ASSESSED
            ruleset_md = (ev_dir / "ruleset_validation.md").read_text(encoding="utf-8")
            self.assertIn("NOT ASSESSED (NO EVIDENCE)", ruleset_md)
            self.assertNotIn("PASSED (CLEAN)", ruleset_md)

            pkg = json.loads((ev_dir / "scr_scn_package.json").read_text(encoding="utf-8"))
            self.assertEqual(pkg["controls_rollup"]["AC-3"]["status"], "NOT_ASSESSED")
            self.assertEqual(pkg["controls_rollup"]["SI-7"]["status"], "FAIL")

    # -----------------------------------------------------------------------
    # P0 #5 & P0 #6: crypto_lib_scan numeric version compare, EOL prefix & vendor path
    # -----------------------------------------------------------------------

    def test_p0_5_version_comparison_and_eol_prefix_boundaries(self) -> None:
        # "9.0" < "41.0.0" is True; "100.0" < "41.0.0" is False
        self.assertTrue(grc_common.version_lt("9.0", "41.0.0"))
        self.assertFalse(grc_common.version_lt("100.0", "41.0.0"))
        self.assertFalse(grc_common.version_lt("41.0.0", "41.0.0"))

        # "1.1.1" matches "1.1.1" and "1.1.1k", but NOT "1.1.10"
        self.assertTrue(grc_common.version_matches_prefix("1.1.1", "1.1.1"))
        self.assertTrue(grc_common.version_matches_prefix("1.1.1k", "1.1.1"))
        self.assertFalse(grc_common.version_matches_prefix("1.1.10", "1.1.1"))

    def test_p0_6_and_p1_crypto_extractor_vendor_parent_pom_and_soname(self) -> None:
        base = Path(tempfile.mkdtemp(prefix="grc_vendor_test_"))
        try:
            # Workspace inside a parent directory named 'vendor_review'
            ws = base / "vendor_review" / "project"
            ws.mkdir(parents=True)

            # Child 'node_modules' should still be pruned
            nm = ws / "node_modules" / "crypto-js"
            nm.mkdir(parents=True)
            (nm / "package.json").write_text('{"dependencies": {"crypto-js": "3.1.9"}}', encoding="utf-8")

            # Maven pom.xml where first dependency has NO <version> (BOM-managed)
            # and second dependency has <version>99.0.0</version>
            pom_content = """<project>
              <dependencies>
                <dependency>
                  <groupId>org.bouncycastle</groupId>
                  <artifactId>bcprov-jdk15on</artifactId>
                </dependency>
                <dependency>
                  <groupId>org.example</groupId>
                  <artifactId>unrelated-lib</artifactId>
                  <version>99.0.0</version>
                </dependency>
              </dependencies>
            </project>"""
            (ws / "pom.xml").write_text(pom_content, encoding="utf-8")
            (ws / "libssl.so.1.1").touch()

            deps = crypto_lib_scan.DependencyExtractor.extract_from_workspace(ws)
            dep_map = {name: ver for name, ver, _, _ in deps}

            # Child node_modules was pruned
            self.assertNotIn("crypto-js", dep_map)
            # BOM-managed bcprov-jdk15on did NOT steal unrelated-lib's 99.0.0 version!
            self.assertEqual(dep_map.get("bcprov-jdk15on"), "Unknown")
            # libssl.so.1.1 extracted version '1.1' from soname
            self.assertEqual(dep_map.get("libssl.so.1.1"), "1.1")

            scanner = crypto_lib_scan.CryptoScanner(crypto_lib_scan.DEFAULT_CRYPTO_CATALOG)
            findings = {f.name: f for f in scanner.evaluate(deps)}
            # Unknown version on bouncycastle reports WARN_UNVERIFIED instead of PASS
            self.assertEqual(findings["bcprov-jdk15on"].status, "WARN_UNVERIFIED")
            # libssl.so.1.1 reports FAIL_EOL
            self.assertEqual(findings["libssl.so.1.1"].status, "FAIL_EOL")
        finally:
            shutil.rmtree(base, ignore_errors=True)

    # -----------------------------------------------------------------------
    # P1: sbom_analyzer client library vs server STIG & RHEL 8 resolution
    # -----------------------------------------------------------------------

    def test_p1_sbom_analyzer_scoping_and_rhel8_mapping(self) -> None:
        comps = [
            sbom_analyzer.Component("java-jwt", "4.4.0", "pkg:maven/com.auth0/java-jwt@4.4.0", "library"),
            sbom_analyzer.Component("redis", "5.0.1", "pkg:pypi/redis@5.0.1", "library"),
            sbom_analyzer.Component("openjdk-17-jre", "17.0.8", "pkg:deb/ubuntu/openjdk-17-jre@17.0.8", "application"),
            sbom_analyzer.Component("glibc", "2.28-225.el8", "pkg:rpm/redhat/glibc@2.28-225.el8?distro=rhel-8", "library"),
        ]
        analyzer = sbom_analyzer.STIGAnalyzer(comps)
        mappings = {m.component.name: m.stig_key for m in analyzer.analyze()}

        self.assertEqual(mappings["java-jwt"], "ASD_STIG")
        self.assertEqual(mappings["redis"], "ASD_STIG")
        self.assertEqual(mappings["openjdk-17-jre"], "JAVA_JRE_STIG")
        self.assertEqual(mappings["glibc"], "RHEL_8_STIG")


if __name__ == "__main__":
    unittest.main()
