#!/usr/bin/env python3
"""
Unit & Integration Test Suite for FIPS 140-3 Assessment Capability (Phases 2, 3, 4, and 5)
and Normalized Finding Schema v1.0.0 (`rules/finding_schema.json`).
"""

import datetime
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

import crypto_lib_scan  # noqa: E402
import fips_discovery  # noqa: E402
import grc_bundle  # noqa: E402
import grc_common  # noqa: E402
import grc_fixtures  # noqa: E402
import grc_reporter  # noqa: E402


class TestFIPSPhases2To5(unittest.TestCase):
    """Covers Phases 2-5 discovery, algorithm policy, CMVP mapping, CBOM/SARIF, and reporter dedup."""

    def test_schema_example_and_validator_reject_invalid_payloads(self) -> None:
        example_path = Path(REPO_ROOT) / "rules" / "finding_schema.example.json"
        example = json.loads(example_path.read_text(encoding="utf-8"))
        self.assertEqual(grc_common.validate_finding_envelope(example), [])

        # Unknown top-level field must fail additionalProperties: false
        bad = dict(example)
        bad["unexpected_top_field"] = True
        self.assertTrue(len(grc_common.validate_finding_envelope(bad)) > 0)

        # FAIL without severity must fail conditional requirement
        bad_finding = json.loads(json.dumps(example))
        fail_item = next(f for f in bad_finding["findings"] if f["determination"] == "FAIL")
        del fail_item["severity"]
        errs = grc_common.validate_finding_envelope(bad_finding)
        self.assertTrue(any("severity" in e for e in errs))

    def test_phase2_manifest_parser_fixes_and_d10_ecosystems(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # 1. package.json semver range concatenation bug fix (`>=3.0.0 <4.0.0` -> `3.0.0`, NOT `3.0.04.0.0`)
            (ws / "package.json").write_text(
                json.dumps({"dependencies": {"crypto-js": ">=3.1.9 <4.0.0", "node-forge": "^1.3.1"}}),
                encoding="utf-8",
            )
            # 2. pyproject.toml section-aware parsing (ignores [tool.ruff] keys)
            (ws / "pyproject.toml").write_text(
                '[project]\nname = "demo"\ndependencies = ["cryptography>=42.0.5,<44.0.0"]\n\n'
                '[tool.mypy]\npython_version = "3.11"\nstrict = true\n',
                encoding="utf-8",
            )
            # 3. pom.xml <properties> interpolation + <dependencyManagement> exclusion
            (ws / "pom.xml").write_text(
                """<project>
                  <properties>
                    <bc.fips.version>1.0.2.5</bc.fips.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>commons-codec</groupId>
                        <artifactId>commons-codec</artifactId>
                        <version>1.10</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>org.bouncycastle</groupId>
                      <artifactId>bc-fips</artifactId>
                      <version>${bc.fips.version}</version>
                    </dependency>
                  </dependencies>
                </project>""",
                encoding="utf-8",
            )
            # 4. go.mod replace + exclude directives
            (ws / "go.mod").write_text(
                "module example.com/svc\n\n"
                "require (\n"
                "    golang.org/x/crypto v0.17.0\n"
                "    github.com/dgrijalva/jwt-go v3.2.0+incompatible\n"
                ")\n"
                "replace golang.org/x/crypto => golang.org/x/crypto v0.28.0\n"
                "exclude github.com/dgrijalva/jwt-go v3.2.0+incompatible\n",
                encoding="utf-8",
            )
            # 5. Cargo.toml + Cargo.lock deduplication + feature extraction (`aws-lc-rs` fips feature)
            (ws / "Cargo.toml").write_text(
                '[package]\nname = "svc"\nversion = "0.1.0"\n\n'
                '[dependencies]\naws-lc-rs = { version = "1.9", features = ["fips"] }\nmd-5 = "0.10.6"\n',
                encoding="utf-8",
            )
            (ws / "Cargo.lock").write_text(
                '[[package]]\nname = "aws-lc-rs"\nversion = "1.9.3"\n\n'
                '[[package]]\nname = "md-5"\nversion = "0.10.6"\n',
                encoding="utf-8",
            )
            # 6. .NET .csproj + Gradle build.gradle
            (ws / "App.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><ItemGroup>'
                '<PackageReference Include="BouncyCastle.Cryptography" Version="2.4.0" />'
                '</ItemGroup></Project>',
                encoding="utf-8",
            )
            (ws / "build.gradle").write_text(
                'dependencies {\n  implementation "org.bouncycastle:bcprov-jdk18on:1.78"\n}\n',
                encoding="utf-8",
            )

            deps = crypto_lib_scan.DependencyExtractor.extract_from_workspace(ws)
            by_name = {name: (ver, src, eco) for name, ver, src, eco in deps}

            self.assertEqual(by_name["crypto-js"][0], "3.1.9")
            self.assertEqual(by_name["node-forge"][0], "1.3.1")
            self.assertEqual(by_name["cryptography"][0], "42.0.5")
            self.assertNotIn("python_version", by_name)
            self.assertEqual(by_name["bc-fips"][0], "1.0.2.5")
            self.assertNotIn("commons-codec", by_name)
            self.assertEqual(by_name["golang.org/x/crypto"][0], "0.28.0")
            self.assertNotIn("github.com/dgrijalva/jwt-go", by_name)
            # Lockfile version wins over Cargo.toml range
            self.assertEqual(by_name["aws-lc-rs"][0], "1.9.3")
            self.assertEqual(by_name["aws-lc-rs"][1], "Cargo.lock")
            self.assertEqual(by_name["BouncyCastle.Cryptography"][0], "2.4.0")
            self.assertEqual(by_name["bcprov-jdk18on"][0], "1.78")

            features = crypto_lib_scan.DependencyExtractor.extract_cargo_features(ws)
            self.assertIn("fips", features.get("aws-lc-rs", []))

    def test_phase2_symlink_safe_read_only_bundle_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outside = Path(tmp) / "outside_target.txt"
            outside.write_text("keep writable", encoding="utf-8")
            outside.chmod(0o644)

            ws = Path(tmp) / "ws"
            ws.mkdir()
            inside = ws / "inside.txt"
            inside.write_text("freeze me", encoding="utf-8")
            (ws / "link_to_outside.txt").symlink_to(outside)

            mgr = grc_bundle.GRCBundleManager(bundle_path=ws, workspace_root=ws)
            mgr._apply_read_only(ws)
            # Inside file is read-only; outside symlink target MUST keep write permission!
            self.assertFalse(bool(inside.stat().st_mode & stat.S_IWUSR))
            self.assertTrue(bool(outside.stat().st_mode & stat.S_IWUSR))

            # Restore write so TemporaryDirectory cleanup succeeds on all platforms
            ws.chmod(0o755)
            inside.chmod(0o644)

    def test_phase3_and_4_python_ast_comment_safety_and_policy_distinctions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ev = Path(tmp) / "ev"
            ws.mkdir()

            # Commented-out and docstring MD5/DES must NEVER trigger false positives
            (ws / "clean_and_edge.py").write_text(
                '"""Docstring mentioning hashlib.md5(b"abc") and DES.new()."""\n'
                "# hashlib.md5(b'commented')\n"
                "import hashlib, hmac, random\n"
                "from cryptography.hazmat.primitives.asymmetric import rsa, ed25519, ec\n"
                "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n\n"
                "def approved_ops(key: bytes, msg: bytes) -> bytes:\n"
                "    # HMAC-SHA-1 remains FIPS-approved per SP 800-131A Rev. 2 §10\n"
                "    mac = hmac.new(key, msg, hashlib.sha1).digest()\n"
                "    sig_key = ed25519.Ed25519PrivateKey.generate()\n"
                "    digest = hashlib.sha256(msg).digest()\n"
                "    # Non-security MD5 -> NEEDS_REVIEW (not FAIL)\n"
                "    cache_id = hashlib.md5(msg, usedforsecurity=False).hexdigest()\n"
                "    return mac + digest + sig_key.sign(msg) + cache_id.encode()\n\n"
                "def bad_ops(key: bytes) -> None:\n"
                "    weak_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)\n"
                "    bad_curve = ec.generate_private_key(ec.SECP256K1())\n"
                "    ecb = Cipher(algorithms.AES(key), modes.ECB())\n"
                "    static_cbc = Cipher(algorithms.AES(key), modes.CBC(b'0123456789abcdef'))\n"
                "    token = random.randint(100000, 999999)\n"
                "    _ = (weak_rsa, bad_curve, ecb, static_cbc, token)\n",
                encoding="utf-8",
            )
            # Historical FIPS 140-2 OpenSSL 1.0.2u library + Active OpenSSL 3.1.2
            (ws / "requirements.txt").write_text("pyopenssl==24.1.0\n", encoding="utf-8")
            (ws / "libcrypto.so.1.0.2u").touch()
            (ws / "Dockerfile").write_text(
                "FROM cgr.dev/chainguard/python:latest-fips\n"
                "ENV OPENSSL_MODULES=/usr/lib64/ossl-modules\n",
                encoding="utf-8",
            )

            engine = fips_discovery.FIPSAssessmentEngine(workspace_root=ws)
            env_out = engine.run()
            engine.write_deliverables(ev)
            self.assertGreater(sum(1 for f in env_out["findings"] if f["determination"] == "FAIL"), 0)

            env = json.loads((ev / "fips_findings.json").read_text(encoding="utf-8"))
            self.assertEqual(grc_common.validate_finding_envelope(env), [])

            findings = env["findings"]
            rules_by_det = {(f["rule_id"], f["determination"]) for f in findings}

            # Verify Phase 3 nuanced policy rules:
            self.assertIn(("fips-alg:hmac-sha1", "PASS"), rules_by_det)
            self.assertIn(("fips-alg:ed25519", "PASS"), rules_by_det)
            self.assertIn(("fips-alg:sha256", "PASS"), rules_by_det)
            self.assertIn(("fips-alg:md5:context", "NEEDS_REVIEW"), rules_by_det)
            self.assertNotIn(("fips-alg:md5", "FAIL"), rules_by_det)  # docstring/comment MD5 ignored!
            self.assertIn(("fips-param:rsa-short-key", "FAIL"), rules_by_det)
            self.assertIn(("fips-param:ecc-unapproved-curve", "FAIL"), rules_by_det)
            self.assertIn(("fips-mode:aes-ecb", "FAIL"), rules_by_det)
            self.assertIn(("fips-param:static-iv-nonce", "FAIL"), rules_by_det)
            self.assertIn(("fips-alg:unapproved-prng", "FAIL"), rules_by_det)

            # Verify Phase 4 Historical FIPS 140-2 certificate detection (1747 -> FAIL_HISTORICAL_CERT)
            hist = [f for f in findings if f.get("determination_detail") == "FAIL_HISTORICAL_CERT"]
            self.assertEqual(len(hist), 1)
            self.assertEqual(hist[0]["extensions"]["fips"]["cmvp_cert"], "1747")

            # Verify Phase 4 Chainguard FIPS base image recognition (4985 Active)
            img_pass = [f for f in findings if f["rule_id"] == "fips-cfg:container-fips-base-image"]
            self.assertEqual(len(img_pass), 1)
            self.assertEqual(img_pass[0]["extensions"]["fips"]["cmvp_cert"], "4985")

            # Verify clean_and_edge.py:19 (AES-ECB) did NOT also emit a contradictory AES PASS
            self.assertNotIn(("fips-alg:aes", "PASS"), rules_by_det)

            # Framing guardrail: deliverables must NEVER claim the repo/app is "FIPS compliant" or "FIPS certified"
            assess_md = (ev / "fips_assessment.md").read_text(encoding="utf-8").lower()
            cmvp_md = (ev / "cmvp_mapping.md").read_text(encoding="utf-8").lower()
            for doc in (assess_md, cmvp_md):
                self.assertNotIn("this application is fips compliant", doc)
                self.assertNotIn("repository is fips certified", doc)
                self.assertIn("cmvp", doc)

    def test_phase4_cmvp_staleness_warning(self) -> None:
        cmvp = fips_discovery.load_cmvp_catalog()
        future_day = datetime.date(2027, 6, 1)
        warn = fips_discovery.check_cmvp_staleness(cmvp, threshold_days=90, today=future_day)
        self.assertIsNotNone(warn)
        self.assertIn("days old", warn or "")

    def test_phase5_scope_assessed_controls_and_enhancement_rollup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ev = Path(tmp) / "ev"
            ws.mkdir()
            ev.mkdir()

            # Run CryptoScan (v1.0.0 schema with scope = ["SI-7", "SC-12", "SC-13"])
            (ws / "requirements.txt").write_text("pycryptodome==3.20.0\n", encoding="utf-8")
            deps = crypto_lib_scan.DependencyExtractor.extract_from_workspace(ws)
            scanner = crypto_lib_scan.CryptoScanner(crypto_lib_scan.DEFAULT_CRYPTO_CATALOG)
            c_findings = scanner.evaluate(deps)
            (ev / "crypto_findings.json").write_text(
                crypto_lib_scan.CryptoReporter.to_json(c_findings, str(ws)),
                encoding="utf-8",
            )

            rep1 = grc_reporter.GRCComplianceReporter(evidence_dir=ev)
            rep1.run(write_files=True)
            pkg1 = json.loads((ev / "scr_scn_package.json").read_text(encoding="utf-8"))

            # CryptoScan's v1.0.0 scope only declares SI-7, SC-12, SC-13 -> IA-7 stays NOT_ASSESSED!
            self.assertEqual(pkg1["controls_rollup"]["SI-7"]["status"], "PASS")
            self.assertEqual(pkg1["controls_rollup"]["SC-13"]["status"], "FAIL")
            self.assertEqual(pkg1["controls_rollup"]["IA-7"]["status"], "NOT_ASSESSED")

            # Now run FIPSDiscovery with a deprecated TLS 1.0 hit carrying enhancement SC-8(1)
            (ws / "tls_bad.go").write_text(
                'package main\nimport "crypto/tls"\n'
                'var cfg = &tls.Config{MinVersion: tls.VersionTLS10}\n',
                encoding="utf-8",
            )
            eng2 = fips_discovery.FIPSAssessmentEngine(workspace_root=ws)
            eng2.run()
            eng2.write_deliverables(ev)

            rep2 = grc_reporter.GRCComplianceReporter(evidence_dir=ev)
            rep2.run(write_files=True)
            pkg2 = json.loads((ev / "scr_scn_package.json").read_text(encoding="utf-8"))

            # Enhancement SC-8(1) is preserved on the finding AND rolls up to SC-8 FAIL!
            tls_findings = [f for f in pkg2["findings"] if f["rule_or_cve_id"] == "fips-tls:deprecated-version"]
            self.assertEqual(len(tls_findings), 1)
            self.assertIn("SC-8(1)", tls_findings[0]["nist_controls"])
            self.assertEqual(pkg2["controls_rollup"]["SC-8"]["status"], "FAIL")
            self.assertEqual(pkg2["controls_rollup"]["IA-7"]["status"], "PASS")

    def test_phase5_multilang_fixtures_and_grc_xtest_precision_recall(self) -> None:
        # 1. Always verify standalone positive & negative fixtures from grc_fixtures.py
        with tempfile.TemporaryDirectory() as tmp:
            pos_ws = Path(tmp) / "pos"
            neg_ws = Path(tmp) / "neg"
            grc_fixtures.populate_fips_positive_fixture(pos_ws)
            grc_fixtures.populate_fips_negative_fixture(neg_ws)

            pos_env = fips_discovery.FIPSAssessmentEngine(workspace_root=pos_ws).run()
            self.assertEqual(grc_common.validate_finding_envelope(pos_env), [])
            pos_fails = [f for f in pos_env["findings"] if f["determination"] == "FAIL"]
            pos_passes = [f for f in pos_env["findings"] if f["determination"] == "PASS"]
            self.assertEqual(pos_fails, [])
            self.assertGreaterEqual(len(pos_passes), 30)

            neg_env = fips_discovery.FIPSAssessmentEngine(workspace_root=neg_ws).run()
            self.assertEqual(grc_common.validate_finding_envelope(neg_env), [])
            neg_fails = [f for f in neg_env["findings"] if f["determination"] == "FAIL"]
            self.assertGreaterEqual(len(neg_fails), 25)

        # 2. When companion GRC-xTEST corpus is checked out side-by-side, verify ground-truth precision/recall
        xtest_root = Path(REPO_ROOT).parent / "GRC-xTEST"
        expected_path = xtest_root / "fips-fixtures" / "expected_findings.json"
        if not expected_path.is_file():
            return

        spec = json.loads(expected_path.read_text(encoding="utf-8"))

        # Positive corpus assertions
        p_env = fips_discovery.FIPSAssessmentEngine(workspace_root=xtest_root / "fips-fixtures" / "positive").run()
        p_fails = [f for f in p_env["findings"] if f["determination"] == "FAIL"]
        p_pass_rules = {f["rule_id"] for f in p_env["findings"] if f["determination"] == "PASS"}
        self.assertLessEqual(len(p_fails), spec["positive"]["max_fail_findings"])
        for req_rule in spec["positive"]["expected_pass_rules"]:
            self.assertIn(req_rule, p_pass_rules)

        # Negative corpus precision (>= 90%) & recall (>= 85%)
        n_env = fips_discovery.FIPSAssessmentEngine(workspace_root=xtest_root / "fips-fixtures" / "negative").run()
        actual_pairs = {
            (f["location"]["path"], f["rule_id"])
            for f in n_env["findings"]
            if f["determination"] == "FAIL"
        }
        expected_pairs = {(p[0], p[1]) for p in spec["negative"]["expected_fail_pairs"]}
        tp = len(actual_pairs & expected_pairs)
        precision = tp / len(actual_pairs) if actual_pairs else 0.0
        recall = tp / len(expected_pairs) if expected_pairs else 0.0
        self.assertGreaterEqual(precision, spec["negative"]["min_precision"])
        self.assertGreaterEqual(recall, spec["negative"]["min_recall"])

        # Restored aoc-12-no-fips-mode.bundle verification
        aoc12_bundle = xtest_root / "bundles" / "aoc-12-no-fips-mode.bundle"
        if aoc12_bundle.is_file():
            with tempfile.TemporaryDirectory() as btmp:
                b_ws = Path(btmp) / "aoc12"
                mgr = grc_bundle.GRCBundleManager(bundle_path=aoc12_bundle, workspace_root=b_ws)
                mgr.restore_bundle(target_ref="v1.0.0", force=True, read_only=True)
                try:
                    b_env = fips_discovery.FIPSAssessmentEngine(workspace_root=b_ws).run()
                    b_pairs = {
                        (f["location"]["path"], f["rule_id"])
                        for f in b_env["findings"]
                        if f["determination"] == "FAIL"
                    }
                    for p_path, p_rule in spec["aoc_12_bundle"]["expected_fail_pairs"]:
                        self.assertIn((p_path, p_rule), b_pairs)
                finally:
                    grc_bundle.clean_ephemeral_workspace(b_ws)

        # AMI Packer non-FIPS template verification
        packer_dir = xtest_root / "ami" / "packer"
        if packer_dir.is_dir():
            pk_env = fips_discovery.FIPSAssessmentEngine(workspace_root=packer_dir).run()
            pk_pairs = {
                (f["location"]["path"], f["rule_id"])
                for f in pk_env["findings"]
                if f["determination"] == "FAIL"
            }
            for p_path, p_rule in spec["ami_packer"]["expected_fail_pairs"]:
                self.assertIn((p_path, p_rule), pk_pairs)


if __name__ == "__main__":
    unittest.main()
