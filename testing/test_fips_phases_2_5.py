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
import subprocess
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

    def test_h1_bundle_restore_rejects_head_less_empty_checkout_and_cleans_up(self) -> None:
        import contextlib
        import io

        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            src = tdir / "src_repo"
            src.mkdir()
            env = {
                **os.environ,
                "GIT_AUTHOR_NAME": "Test",
                "GIT_AUTHOR_EMAIL": "test@example.com",
                "GIT_COMMITTER_NAME": "Test",
                "GIT_COMMITTER_EMAIL": "test@example.com",
            }
            subprocess.run(["git", "-C", str(src), "init", "-q", "-b", "main"], check=True, env=env)
            (src / "app.py").write_text("import hashlib\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(src), "add", "-A"], check=True, env=env)
            subprocess.run(["git", "-C", str(src), "commit", "-q", "-m", "init"], check=True, env=env)
            subprocess.run(["git", "-C", str(src), "tag", "-a", "v1.0.0", "-m", "v1.0.0"], check=True, env=env)

            headless_bundle = tdir / "headless.bundle"
            # Omit HEAD and branches so clone leaves HEAD unborn with 0 files across all Git versions
            subprocess.run(
                ["git", "-C", str(src), "bundle", "create", str(headless_bundle), "refs/tags/v1.0.0"],
                check=True,
                capture_output=True,
            )

            ws_dest = tdir / "ws_dest"
            mgr = grc_bundle.GRCBundleManager(bundle_path=headless_bundle, workspace_root=ws_dest)
            with self.assertRaises(RuntimeError) as ctx:
                mgr.restore_bundle()
            msg = str(ctx.exception)
            self.assertIn("empty checkout", msg)
            self.assertIn("v1.0.0", msg)
            self.assertIn("--ref", msg)
            # Partial clone directory must be removed cleanly so retries do not require --force
            self.assertFalse(ws_dest.exists())

            # Restoring with explicit --ref succeeds without --force
            prov = mgr.restore_bundle(target_ref="v1.0.0", read_only=True)
            try:
                self.assertEqual(prov["status"], "RESTORED")
                self.assertTrue((ws_dest / "app.py").is_file())
                self.assertTrue((ws_dest / "bundle_provenance.json").is_file())
            finally:
                grc_bundle.clean_ephemeral_workspace(ws_dest)

            # Multi-tag bundle without --ref emits a [WARN] listing available tags on stderr
            kb_bundle = Path(__file__).resolve().parents[2] / "GRC-xTEST" / "bundles" / "kestrelbridge-fips.bundle"
            if not kb_bundle.is_file():
                (src / "v2.py").write_text("import hashlib\n", encoding="utf-8")
                subprocess.run(["git", "-C", str(src), "add", "-A"], check=True, env=env)
                subprocess.run(["git", "-C", str(src), "commit", "-q", "-m", "v1.5.0"], check=True, env=env)
                subprocess.run(["git", "-C", str(src), "tag", "-a", "v1.5.0", "-m", "v1.5.0"], check=True, env=env)
                subprocess.run(["git", "-C", str(src), "tag", "-a", "v2.0.0", "-m", "v2.0.0"], check=True, env=env)
                kb_bundle = tdir / "multi.bundle"
                subprocess.run(
                    ["git", "-C", str(src), "bundle", "create", str(kb_bundle), "HEAD", "main", "--tags"],
                    check=True,
                    capture_output=True,
                )
            kb_ws = tdir / "kb_ws"
            kb_mgr = grc_bundle.GRCBundleManager(bundle_path=kb_bundle, workspace_root=kb_ws)
            err_buf = io.StringIO()
            with contextlib.redirect_stderr(err_buf):
                kb_prov = kb_mgr.restore_bundle(read_only=True)
            try:
                self.assertEqual(kb_prov["status"], "RESTORED")
                warn_text = err_buf.getvalue()
                self.assertIn("[WARN]", warn_text)
                for tag in ("v1.0.0", "v1.5.0", "v2.0.0"):
                    self.assertIn(tag, warn_text)
            finally:
                grc_bundle.clean_ephemeral_workspace(kb_ws)

    def test_h2_fips_and_crypto_reject_bundle_file_as_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_bundle = Path(tmp) / "vendor-release.bundle"
            fake_bundle.write_bytes(b"not a dir")

            for script_name in ("fips_discovery.py", "crypto_lib_scan.py"):
                script_path = Path(SCRIPTS_DIR) / script_name
                res = subprocess.run(
                    [sys.executable, str(script_path), "-w", str(fake_bundle)],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(res.returncode, 1)
                self.assertIn("[FATAL]", res.stderr)
                self.assertIn("./grc bundle restore", res.stderr)

    def test_h3_and_m2_empty_workspace_counts_warning_and_not_assessed_posture(self) -> None:
        fips_script = Path(SCRIPTS_DIR) / "fips_discovery.py"
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            empty_ws = tdir / "empty_ws"
            empty_ws.mkdir()

            eng = fips_discovery.FIPSAssessmentEngine(workspace_root=empty_ws)
            env_out = eng.run()
            self.assertEqual(env_out["scope"]["files_inspected"]["total"], 0)
            self.assertEqual(grc_common.validate_finding_envelope(env_out), [])
            md = eng.build_assessment_markdown()
            self.assertIn("No assessable files found", md)
            self.assertNotIn("No `FAIL` or `WARN` assessment findings were detected", md)

            # JSON format exits non-zero, warns on stderr only, keeps stdout pure JSON
            res_json = subprocess.run(
                [sys.executable, str(fips_script), "-w", str(empty_ws), "-f", "json"],
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(res_json.returncode, 0)
            self.assertIn("No assessable files found", res_json.stderr)
            parsed = json.loads(res_json.stdout)
            self.assertEqual(parsed["scope"]["files_inspected"]["total"], 0)

            # --allow-empty returns 0 and writes deliverables that reporter marks NOT ASSESSED
            ev_empty = tdir / "ev_empty"
            res_allow = subprocess.run(
                [sys.executable, str(fips_script), "-w", str(empty_ws), "-e", str(ev_empty), "--allow-empty"],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res_allow.returncode, 0)
            rep_empty = grc_reporter.GRCComplianceReporter(evidence_dir=ev_empty)
            rep_empty.run(write_files=True)
            poam_empty = (ev_empty / "poam_data.md").read_text(encoding="utf-8")
            self.assertIn("NOT ASSESSED (No Assessable Files Found)", poam_empty)
            self.assertIn("`FIPSDiscovery (1 of 10)`", poam_empty)
            pkg_empty = json.loads((ev_empty / "scr_scn_package.json").read_text(encoding="utf-8"))
            self.assertEqual(pkg_empty["summary"]["overall_status"], "NOT_ASSESSED")

        # Verify rebuilt KestrelBridge v2.0.0 bundle restores without -r and stays COMPLIANT
        xtest_root = Path(REPO_ROOT).parent / "GRC-xTEST"
        kb_v2 = xtest_root / "bundles" / "kestrelbridge-v2.0.0.bundle"
        if kb_v2.is_file():
            with tempfile.TemporaryDirectory() as tmp2:
                ws_v2 = Path(tmp2) / "kb_v2"
                ev_v2 = Path(tmp2) / "ev_v2"
                mgr = grc_bundle.GRCBundleManager(bundle_path=kb_v2, workspace_root=ws_v2)
                mgr.restore_bundle(force=True, read_only=True)
                try:
                    eng_v2 = fips_discovery.FIPSAssessmentEngine(workspace_root=ws_v2)
                    env_v2 = eng_v2.run()
                    eng_v2.write_deliverables(ev_v2)
                    self.assertGreater(env_v2["scope"]["files_inspected"]["total"], 0)
                    self.assertEqual(sum(1 for f in env_v2["findings"] if f["determination"] == "FAIL"), 0)
                    self.assertEqual(sum(1 for f in env_v2["findings"] if f["determination"] == "NEEDS_REVIEW"), 0)
                    self.assertEqual(sum(1 for f in env_v2["findings"] if f["determination"] == "CANNOT_DETERMINE_STATICALLY"), 0)
                    self.assertEqual(sum(1 for f in env_v2["findings"] if f["determination"] == "PASS"), 31)

                    rep_v2 = grc_reporter.GRCComplianceReporter(evidence_dir=ev_v2, workspace_dir=ws_v2)
                    rep_v2.run(write_files=True)
                    poam_v2 = (ev_v2 / "poam_data.md").read_text(encoding="utf-8")
                    self.assertIn("COMPLIANT (Clean Out-of-Band Audit)", poam_v2)
                    self.assertIn("`FIPSDiscovery (1 of 10)`", poam_v2)
                finally:
                    grc_bundle.clean_ephemeral_workspace(ws_v2)

    def test_h5_crypto_bc_fips_historical_remediation_and_reporter_reconciliation(self) -> None:
        cat = crypto_lib_scan.load_crypto_catalog(Path(REPO_ROOT) / "rules" / "crypto_catalog.json")
        scanner = crypto_lib_scan.CryptoScanner(cat)
        findings = scanner.evaluate([
            ("bc-fips", "1.0.2.5", "signer/pom.xml", "java"),
            ("bc-fips", "2.0.0", "signer/pom.xml", "java"),
            ("golang.org/x/crypto", "0.17.0", "partner-client/go.mod", "go"),
        ])
        self.assertEqual(findings[0].status, "FAIL_HISTORICAL_FIPS")
        self.assertEqual(findings[0].severity, "MEDIUM")
        self.assertIn("3673", findings[0].description)

        self.assertEqual(findings[1].status, "CANNOT_DETERMINE_STATICALLY")
        self.assertNotIn("Upgrade bc-fips to >= 2.0.0", findings[1].remediation)

        self.assertEqual(findings[2].status, "NOT_VALIDATED")
        self.assertNotIn(">= v0.17.0", findings[2].remediation)

        schema_recs = crypto_lib_scan._to_schema_findings([findings[0]])
        hist_recs = [r for r in schema_recs if r["determination"] == "FAIL"]
        self.assertEqual(len(hist_recs), 1)
        self.assertEqual(hist_recs[0]["determination_detail"], "FAIL_HISTORICAL_CERT")
        self.assertEqual(hist_recs[0]["severity"], "MEDIUM")

        # When both CryptoScan and FIPSDiscovery run on KestrelBridge v2.0.0, FIPSDiscovery PASS
        # supersedes CryptoScan CANNOT_DETERMINE_STATICALLY so reporter stays COMPLIANT
        xtest_root = Path(REPO_ROOT).parent / "GRC-xTEST"
        kb_v2 = xtest_root / "bundles" / "kestrelbridge-v2.0.0.bundle"
        if kb_v2.is_file():
            with tempfile.TemporaryDirectory() as tmp:
                ws_v2 = Path(tmp) / "kb_v2"
                ev_v2 = Path(tmp) / "ev_v2"
                ev_v2.mkdir(parents=True)
                mgr = grc_bundle.GRCBundleManager(bundle_path=kb_v2, workspace_root=ws_v2)
                mgr.restore_bundle(force=True, read_only=True)
                try:
                    c_deps = crypto_lib_scan.DependencyExtractor.extract_from_workspace(ws_v2)
                    c_findings = crypto_lib_scan.CryptoScanner(cat).evaluate(c_deps)
                    (ev_v2 / "crypto_findings.json").write_text(
                        crypto_lib_scan.CryptoReporter.to_json(c_findings, str(ws_v2)),
                        encoding="utf-8",
                    )
                    fips_eng = fips_discovery.FIPSAssessmentEngine(workspace_root=ws_v2)
                    fips_eng.run()
                    fips_eng.write_deliverables(ev_v2)

                    rep = grc_reporter.GRCComplianceReporter(evidence_dir=ev_v2, workspace_dir=ws_v2)
                    rep.run(write_files=True)
                    pkg = json.loads((ev_v2 / "scr_scn_package.json").read_text(encoding="utf-8"))
                    self.assertEqual(pkg["summary"]["overall_status"], "COMPLIANT")
                    self.assertEqual(pkg["summary"]["total_findings"], 0)
                    self.assertEqual(pkg["summary"]["verification_required_count"], 0)
                finally:
                    grc_bundle.clean_ephemeral_workspace(ws_v2)

    def test_h7_component_scoped_dockerfile_and_pypi_wheel_linkage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "svc_repo"
            (ws / "docs-site").mkdir(parents=True)
            (ws / "gateway").mkdir(parents=True)
            (ws / "gateway" / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")

            # Unrelated sibling UBI 9 Dockerfile + non-FIPS gateway Dockerfile must NOT promote gateway cryptography
            (ws / "docs-site" / "Dockerfile").write_text(
                "FROM registry.access.redhat.com/ubi9/python-312\n",
                encoding="utf-8",
            )
            (ws / "gateway" / "Dockerfile").write_text(
                "FROM python:3.12-slim-bookworm\nRUN pip install --no-cache-dir -r requirements.txt\n",
                encoding="utf-8",
            )
            env_1 = fips_discovery.FIPSAssessmentEngine(workspace_root=ws).run()
            crypt_1 = [f for f in env_1["findings"] if f["subject"]["name"] == "cryptography"]
            self.assertEqual(len(crypt_1), 1)
            self.assertEqual(crypt_1[0]["determination"], "CANNOT_DETERMINE_STATICALLY")

            # Even with UBI 9 in gateway/Dockerfile + OpenSSL fips_sect, plain pip wheel stays CANNOT_DETERMINE_STATICALLY
            (ws / "appliance" / "rootfs" / "etc" / "pki" / "tls").mkdir(parents=True)
            (ws / "appliance" / "rootfs" / "etc" / "pki" / "tls" / "openssl.cnf").write_text(
                "[provider_sect]\nfips = fips_sect\n[fips_sect]\nactivate = 1\n",
                encoding="utf-8",
            )
            (ws / "gateway" / "Dockerfile").write_text(
                "FROM registry.access.redhat.com/ubi9/python-312\n"
                "RUN pip install --no-cache-dir -r requirements.txt\n",
                encoding="utf-8",
            )
            env_2 = fips_discovery.FIPSAssessmentEngine(workspace_root=ws).run()
            crypt_2 = [f for f in env_2["findings"] if f["subject"]["name"] == "cryptography"]
            self.assertEqual(crypt_2[0]["determination"], "CANNOT_DETERMINE_STATICALLY")

            # Switching gateway/Dockerfile to --no-binary cryptography promotes it legitimately to PASS
            (ws / "gateway" / "Dockerfile").write_text(
                "FROM registry.access.redhat.com/ubi9/python-312\n"
                "RUN pip install --no-cache-dir --no-binary cryptography -r requirements.txt\n",
                encoding="utf-8",
            )
            env_3 = fips_discovery.FIPSAssessmentEngine(workspace_root=ws).run()
            crypt_3 = [f for f in env_3["findings"] if f["subject"]["name"] == "cryptography"]
            self.assertEqual(crypt_3[0]["determination"], "PASS")

    def test_m1_m3_m4_m5_m7_m8_provenance_and_cli_hardening(self) -> None:
        fips_script = Path(SCRIPTS_DIR) / "fips_discovery.py"
        with tempfile.TemporaryDirectory() as tmp:
            tdir = Path(tmp)
            # M1: --fail-on threshold behavior
            ws_nr = tdir / "ws_needs_review"
            ws_nr.mkdir()
            (ws_nr / "requirements.txt").write_text("cryptography==42.0.5\n", encoding="utf-8")

            r_never = subprocess.run(
                [sys.executable, str(fips_script), "-w", str(ws_nr), "-f", "json", "--fail-on", "never"],
                capture_output=True, text=True,
            )
            self.assertEqual(r_never.returncode, 0)
            r_fail = subprocess.run(
                [sys.executable, str(fips_script), "-w", str(ws_nr), "-f", "json", "--fail-on", "FAIL"],
                capture_output=True, text=True,
            )
            self.assertEqual(r_fail.returncode, 0)
            r_nr = subprocess.run(
                [sys.executable, str(fips_script), "-w", str(ws_nr), "-f", "json", "--fail-on", "NEEDS_REVIEW"],
                capture_output=True, text=True,
            )
            self.assertEqual(r_nr.returncode, 1)

            # M4: Planted spoofed fips_provenance.json inside audited workspace must be ignored everywhere
            (ws_nr / "fips_provenance.json").write_text(
                json.dumps({"target_identifier": "SPOOFED_TARGET", "commit_sha": "deadbeef1234"}),
                encoding="utf-8",
            )
            env_m4 = fips_discovery.FIPSAssessmentEngine(workspace_root=ws_nr).run()
            self.assertEqual(env_m4["target"]["identifier"], "ws_needs_review")
            self.assertNotIn("commit", env_m4["target"])
            c_m4 = json.loads(crypto_lib_scan.CryptoReporter.to_json([], str(ws_nr)))
            self.assertEqual(c_m4["target"]["identifier"], "ws_needs_review")

            ev_m4 = tdir / "ev_m4"
            ev_m4.mkdir()
            rep_m4 = grc_reporter.GRCComplianceReporter(evidence_dir=ev_m4, workspace_dir=ws_nr)
            rep_m4.load_provenance()
            self.assertEqual(rep_m4.provenance, {})

            # M8: Collision suffixing for auto-generated pick-up paths only
            base_dir = tdir / "2026-11-15_190000_kb@v1.0.0_fips"
            self.assertEqual(fips_discovery._next_available_evidence_dir(base_dir), base_dir)
            base_dir.mkdir()
            d2 = fips_discovery._next_available_evidence_dir(base_dir)
            self.assertEqual(d2.name, "2026-11-15_190000_kb@v1.0.0_fips_2")
            d2.mkdir()
            d3 = fips_discovery._next_available_evidence_dir(base_dir)
            self.assertEqual(d3.name, "2026-11-15_190000_kb@v1.0.0_fips_3")

        # M3, M5, M7 on KestrelBridge bundles
        xtest_root = Path(REPO_ROOT).parent / "GRC-xTEST"
        kb_v15 = xtest_root / "bundles" / "kestrelbridge-v1.5.0.bundle"
        kb_v2 = xtest_root / "bundles" / "kestrelbridge-v2.0.0.bundle"
        if kb_v15.is_file() and kb_v2.is_file():
            with tempfile.TemporaryDirectory() as tmp2:
                t2 = Path(tmp2)
                ws15 = t2 / "ws15"
                mgr15 = grc_bundle.GRCBundleManager(bundle_path=kb_v15, workspace_root=ws15)
                prov15 = mgr15.restore_bundle(force=True, read_only=True)
                try:
                    self.assertEqual(prov15["checked_out_ref"], "v1.5.0")
                    self.assertIsNone(prov15["verification"]["checksum_verified"])
                    self.assertEqual(prov15["verification"]["checksum_status"], "NOT_CHECKED")
                    self.assertTrue(prov15["verification"]["git_bundle_valid"])

                    v_match = mgr15.verify_bundle(expected_sha256=prov15["bundle_sha256"])
                    self.assertTrue(v_match["checksum_verified"])
                    self.assertEqual(v_match["checksum_status"], "MATCH")

                    eng15 = fips_discovery.FIPSAssessmentEngine(workspace_root=ws15)
                    self.assertEqual(eng15._default_evidence_slug(), "kestrelbridge-v1.5.0@v1.5.0")
                    env15 = eng15.run()
                    self.assertEqual(env15["target"].get("checked_out_ref"), "v1.5.0")
                finally:
                    grc_bundle.clean_ephemeral_workspace(ws15)

                ws20 = t2 / "ws20"
                ev20 = t2 / "ev20"
                grc_bundle.GRCBundleManager(bundle_path=kb_v2, workspace_root=ws20).restore_bundle(force=True, read_only=True)
                try:
                    res_host = subprocess.run(
                        [str(Path(REPO_ROOT) / "grc"), "scan", "--host-only", "-w", str(ws20), "-e", str(ev20)],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(res_host.returncode, 0, res_host.stderr)
                    self.assertTrue((ev20 / "crypto_findings.json").is_file())
                    self.assertTrue((ev20 / "fips_findings.json").is_file())
                    self.assertTrue((ev20 / "sha256sum").is_file())
                    self.assertIn("COMPLIANT (Clean Out-of-Band Audit)", (ev20 / "poam_data.md").read_text(encoding="utf-8"))
                finally:
                    grc_bundle.clean_ephemeral_workspace(ws20)


if __name__ == "__main__":
    unittest.main()
