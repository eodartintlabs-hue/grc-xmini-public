# Design Review Analysis: `hygiene/FIPS_140-3_HANDOFF.md`

> **Scope inspected**: [hygiene/FIPS_140-3_HANDOFF.md](../hygiene/FIPS_140-3_HANDOFF.md) across the full **GRCx Initiative Triad**:
> * **`GRC-xMINI`**: [GRC-xMINI](../README.md) @ `e2b17ed` (`v1.4.4 — Yokota`)
> * **`GRC-xBOT`**: [GRC-xBOT](../../GRC-xBOT/README.md) @ `9fe4680` (`v1.2.1 — Motegi`)
> * **`GRC-xTEST`**: [GRC-xTEST](../../GRC-xTEST/README.md) @ `d6f6f2d` (`v1.4.0 — Yokota`)
>
> **Workspace status**: Read-only analysis complete. No project code, rules, or existing documentation files were modified or deleted.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Evaluation of Each Finding & Recommendation](#2-evaluation-of-each-finding--recommendation)
   * [2.1 Current-State Defects (`D1`–`D12` in §2.2 & Phase 0 in §3)](#21-current-state-defects-d1d12-in-22--phase-0-in-3)
   * [2.2 Evaluation of Implementation Phases (§3 & §4.1–4.6)](#22-evaluation-of-implementation-phases-3--4146)
3. [What the Review Missed: Architectural Problems Across the Triad](#3-what-the-review-missed-architectural-problems-across-the-triad)
4. [Ambiguities, Outdated References & Contradictions](#4-ambiguities-outdated-references--contradictions)
   * [4.1 Outdated or Contradictory Items Flagged](#41-outdated-or-contradictory-items-flagged)
   * [4.2 Questions for You to Answer Before Implementation](#42-questions-for-you-to-answer-before-implementation)
5. [Proposed Order of Work](#5-proposed-order-of-work)

---

## 1. Executive Summary

The handoff document in [FIPS_140-3_HANDOFF.md](../hygiene/FIPS_140-3_HANDOFF.md) is **compliance-sound and accurate in its diagnosis of all three repositories**:
* `GRC-xMINI` currently conflates library maintenance/EOL status (`SI-7`) with FIPS 140-3 module validation (`SC-13`), mislabels `AOC-03` weak-crypto rules under `SI-16` (Memory Protection), and advertises `AOC-12` (Lack of FIPS Mode) without implementing any rules for it.
* `GRC-xTEST` already ships a dedicated synthetic test bundle ([bundles/aoc-12-no-fips-mode/](../../GRC-xTEST/bundles/aoc-12-no-fips-mode/README.md)) and Packer fixture ([non-fips-kernel.pkr.hcl](../../GRC-xTEST/ami/packer/non-fips-kernel.pkr.hcl)), but when `verify_pipeline.sh` runs against `aoc-12-no-fips-mode.bundle`, none of its 4 non-FIPS config files (`etc/default/grub`, `etc/crypto-policies/config`, `etc/pki/tls/openssl.cnf`, `conf/java.security`) are inspected by any scanner.
* `GRC-xBOT` (`v1.2.1 — Motegi`) routes `"fips"`, `"140-2"`, and `"140-3"` queries to the manifest-only `./grc crypto` workflow and only accepts pre-staged local `.bundle` files from `artifacts/drop-off/`.

However, **several recommendations in the review will break existing pipeline invariants or tests if implemented literally**—most notably because [grc_reporter.py](../scripts/grc_reporter.py) and [crypto_lib_scan.py](../scripts/crypto_lib_scan.py) use a binary `PASS` vs. `NON-COMPLIANT/POA&M` state machine that cannot yet represent tri-state determinations (`CANNOT_DETERMINE_STATICALLY`, `NEEDS_REVIEW`, `CONFORMANT_INDICATOR`), and [test_grc_bot.py](../../GRC-xBOT/testing/test_grc_bot.py) enforces strict workflow counts and CLI flag contracts across `GRC-xBOT` and `GRC-xMINI`.

---

## 2. Evaluation of Each Finding & Recommendation

### 2.1 Current-State Defects (`D1`–`D12` in §2.2 & Phase 0 in §3)

#### **D1 — AOC-12 "Lack of FIPS Mode" is documented (and has a `GRC-xTEST` bundle) but is not implemented**
* **Position**: **Agree.**
* **Code Confirmation**: **Confirmed across `GRC-xMINI` and `GRC-xTEST`.**
  * [GRC-xMINI/README.md](../README.md#L191), [docs/grc-xtest-guide.md](../docs/grc-xtest-guide.md#L325-L332), and [GRC-xTEST/README.md](../../GRC-xTEST/README.md#L116) document `AOC-12`.
  * `GRC-xTEST` actually contains the synthetic fixture directory [bundles/aoc-12-no-fips-mode/](../../GRC-xTEST/bundles/aoc-12-no-fips-mode/README.md) with 5 intentional violations:
    1. [etc/default/grub](../../GRC-xTEST/bundles/aoc-12-no-fips-mode/etc/default/grub#L8): `GRUB_CMDLINE_LINUX="... fips=0"`
    2. [etc/crypto-policies/config](../../GRC-xTEST/bundles/aoc-12-no-fips-mode/etc/crypto-policies/config#L3): `DEFAULT`
    3. [etc/pki/tls/openssl.cnf](../../GRC-xTEST/bundles/aoc-12-no-fips-mode/etc/pki/tls/openssl.cnf#L9-L17): `default = default_sect` active; `# [fips_sect] / # activate = 1` commented out
    4. [conf/java.security](../../GRC-xTEST/bundles/aoc-12-no-fips-mode/conf/java.security#L3-L7): `security.provider.1=sun.security.provider.Sun` (FIPS providers omitted)
    5. [src/fips_bypass.py](../../GRC-xTEST/bundles/aoc-12-no-fips-mode/src/fips_bypass.py#L13-L19): `hashlib.md5(data)` without `usedforsecurity=False` and `getattr(ssl, "FIPS_mode", lambda: 0)()`
  * Yet [custom-baseline-ruleset.yaml](../rules/custom-baseline-ruleset.yaml#L532-L598) jumps directly from `AOC-11` (line 532) to `AOC-140` (line 596), and neither `crypto_lib_scan.py` nor `grc_ami.py` inspects `grub`, `crypto-policies`, `openssl.cnf`, or `java.security`.
* **Effort / Risk**:
  * Phase 0 doc correction: **Low effort / Low risk**.
  * Phase 4 implementation (detecting all 5 patterns already in `GRC-xTEST/bundles/aoc-12-no-fips-mode/`): **Medium effort / Low–Medium risk**.
* **What it would break or complicate**:
  * [docs/grc-xtest-guide.md](../docs/grc-xtest-guide.md#L332) states that `aoc-12-no-fips-mode.bundle` writes findings to `semgrep_findings.json`. Implementing AOC-12 in the stdlib FIPS engine means `grc-xtest-guide.md` and `GRC-xTEST/README.md` (`Primary Scanner`) should reference `fips_discovery.py` / `crypto_lib_scan.py`.
  * If any Semgrep rules are added later, `GRCComplianceReporter.generate_ruleset_validation_markdown()` in [grc_reporter.py](../scripts/grc_reporter.py#L1089) (and its docstring at line 17, plus `GRC-xTEST/README.md:83` and `GRC-xBOT/playbooks/workflows.json:167`) hardcode `"37"` rules.

---

#### **D2 — Wrong NIST control mapping (`SI-16` instead of `SC-13`)**
* **Position**: **Partly Agree.** Agree with remapping `AOC-03` to `SC-13` and fixing `SI-16` in `grc_reporter.py`, but the review misses several affected files across `GRC-xMINI` and `GRC-xTEST`, plus a parser limitation in `grc_reporter.py`.
* **Code Confirmation**: **Confirmed.**
  * [custom-baseline-ruleset.yaml](../rules/custom-baseline-ruleset.yaml#L101-L233): All 8 `grc-aoc03-*` rules map `nist_control: "SI-16: Cryptographic Protection"`.
  * [grc_reporter.py](../scripts/grc_reporter.py#L107-L113): `NIST_CONTROLS_CATALOG["SI-16"]` is titled `"Memory Protection / Cryptographic Hash Integrity"` with `"assessed_by": ["Semgrep", "CryptoScan"]`.
  * Also present in [GRC-xMINI/README.md](../README.md#L183), [testing/TESTING.md](../testing/TESTING.md#L249), and [docs/grc-xtest-guide.md](../docs/grc-xtest-guide.md#L43) (plus lines 234, 415).
  * **Uncited locations found across the Triad**:
    1. **`GRC-xTEST` docs**: [GRC-xTEST/README.md](../../GRC-xTEST/README.md#L108) (`NIST SP 800-53 SI-16, SC-13`) and [GRC-xTEST/bundles/aoc-03-legacy-crypto/README.md](../../GRC-xTEST/bundles/aoc-03-legacy-crypto/README.md#L3) (`Target Control: NIST SP 800-53 SI-16`).
    2. **Committed demo artifacts**: `GRC-xMINI/testing/demo-evidence/{aoc-04-command-injection,aoc-07-iac-misconfig,aoc-09-eol-libraries,aoc-10-critical-cves,aoc-combo-4x}/` (`controls.md`, `ruleset_validation.md`, `scr_scn_package.json`, and their `sha256sum` files) all contain `SI-16` mapped to `AOC-03`.
    3. **ASD STIG catalog**: [stig_catalog.json](../rules/stig_catalog.json#L23) and [sbom_analyzer.py](../scripts/sbom_analyzer.py#L55) list `"SI-16"` under `ASD_STIG.nist_controls` (which is valid for ASD STIG memory protection and should *not* be removed, only kept distinct from crypto).
* **Effort / Risk**: **Low effort / Medium risk**.
* **What it would break or complicate**:
  * **False `COMPLIANT` on `SI-16`**: In `GRCComplianceReporter._control_was_assessed()` ([grc_reporter.py](../scripts/grc_reporter.py#L843-L853)), a control with 0 findings is marked `✅ COMPLIANT` if any scanner in its `assessed_by` list ran. Once `AOC-03` is remapped to `SC-13`, **zero** Semgrep rules in `custom-baseline-ruleset.yaml` map to `SI-16` (`grc-aoc10-go-unsafe-pointer` at line 521 maps to `RA-5`). If `"Semgrep"` is left in `NIST_CONTROLS_CATALOG["SI-16"]["assessed_by"]`, `SI-16` will falsely report `✅ COMPLIANT` on every Semgrep run despite having zero rules testing it. Either `SI-16` should have `"assessed_by": []` (so it reports `⚪ NOT ASSESSED`), or `grc-aoc10-go-unsafe-pointer` should map to `SI-16`.
  * **Multi-control mapping limitation**: D2 recommends remapping `AOC-03` to *"SC-13 (and SC-12 where key material is involved)"*. However, `load_baseline_rules()` ([grc_reporter.py](../scripts/grc_reporter.py#L384)) and `parse_semgrep()` ([grc_reporter.py](../scripts/grc_reporter.py#L433)) use `re.search(r"([A-Z]{2}-\d+)", nist_raw)`, which extracts **only the first control ID** and ignores any second control.

---

#### **D3 — `fips_capable: true` gets reported as a `PASS`-level reassurance**
* **Position**: **Partly Agree.** The compliance critique is spot-on, but changing `CryptoFinding.status` from `"PASS"` to `"CANNOT_DETERMINE_STATICALLY"` in Phase 0 without refactoring `grc_reporter.py` and `grc_test.py` will break the reporting pipeline.
* **Code Confirmation**: **Confirmed.** `CryptoScanner._audit_dependency()` in [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L520-L528) returns `status="PASS"`, `severity="INFO"`, `description=f"Supported cryptographic library. FIPS Capable: {rule.get('fips_capable', False)}."`.
* **Effort / Risk**: **Low–Medium effort / High risk** (due to downstream reporter coupling).
* **What it would break or complicate**:
  1. **POA&M Flooding in `grc_reporter.py`**: Look at `GRCComplianceReporter.parse_crypto_scan()` in [grc_reporter.py](../scripts/grc_reporter.py#L579-L582):
     ```python
     status = str(item.get("compliance_status") or "FAIL").strip().upper()
     # Never ingest compliant PASS items as POA&M findings
     if status == "PASS":
         continue
     ```
     `parse_crypto_scan()` skips **only** `status == "PASS"`. If `crypto_lib_scan.py` emits `compliance_status: "CANNOT_DETERMINE_STATICALLY"` for `openssl >= 3.0.0` or `cryptography >= 41.0.0`, `grc_reporter.py` will ingest every healthy, up-to-date library as an open FedRAMP POA&M item titled `"Unsupported/Deprecated Cryptographic Library: cryptography (42.0.0)"` ([grc_reporter.py](../scripts/grc_reporter.py#L603)) and fail `SI-7`, `SC-12`, and `SC-13`!
  2. **Breaks existing test suite**: `TestEngine.test_crypto_scan()` in [grc_test.py](../scripts/grc_test.py#L198) asserts `by_key.get(("cryptography", "100.0.0")) == "PASS"`.
  3. **Architectural fix needed**: `CryptoFinding` ([crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L171-L200)) should separate **library lifecycle status** (`compliance_status`: `PASS` / `WARN_OUTDATED` / `FAIL_EOL` / `FAIL_DEPRECATED` for `SI-7` / `AOC-09`) from **FIPS validation status** (`fips_status`: `VALIDATED_MODULE` / `CAPABLE_IF_CONFIGURED` / `NOT_VALIDATED` / `UNKNOWN` and `sc13_determination`: `CANNOT_DETERMINE_STATICALLY`), or `grc_reporter.py:parse_crypto_scan()` must be updated concurrently.

---

#### **D4 — `cryptography` (PyCA) marked `APPROVED` / `fips_capable: true`**
* **Position**: **Agree.**
* **Code Confirmation**: **Confirmed** in [crypto_catalog.json](../rules/crypto_catalog.json#L43-L53) and [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L99-L109).
* **Effort / Risk**: **Low effort / Low–Medium risk**.
* **What it would break or complicate**: Same `grc_reporter.py` and `grc_test.py` coupling noted in **D3** if `compliance_status` is altered without updating `parse_crypto_scan()`.

---

#### **D5 — `pycrypto` remediation recommends `pycryptodome`; `pycryptodome`/`pycryptodomex` missing from catalog**
* **Position**: **Agree.**
* **Code Confirmation**: **Confirmed** in [crypto_catalog.json](../rules/crypto_catalog.json#L39), [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L95), and [testing/TESTING.md](../testing/TESTING.md#L288). Neither `pycryptodome` nor `pycryptodomex` exists in `crypto_catalog.json`.
* **Effort / Risk**: **Low effort / Low risk**.
* **What it would break or complicate**:
  * Look at `CryptoScanner._audit_dependency()` in [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L452-L528): it only checks `if status_flag == "DEPRECATED_UNMAINTAINED"` (line 453) and `if status_flag == "UNRECOMMENDED"` (line 461), plus `eol_versions` and `min_supported_version`. It has **no branch** for `NOT_VALIDATED`! If you add `pycryptodome` to `crypto_catalog.json` with `"status": "NOT_VALIDATED"` (or `"fips_status": "NOT_VALIDATED"`) and do not add a handler in `_audit_dependency()`, `_audit_dependency()` will fall through to step 6 (line 521) and return `status="PASS"`!

---

#### **D6 — `golang-x-crypto` marked `APPROVED`**
* **Position**: **Partly Agree.** Agree that `golang.org/x/crypto` is outside the Go Cryptographic Module boundary (`NOT_VALIDATED`), but flagging its mere presence in `go.mod` as a hard failure will create noisy false positives.
* **Code Confirmation**: **Confirmed** in [crypto_catalog.json](../rules/crypto_catalog.json#L89-L98) and [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L145-L153). Because `golang-x-crypto` defines no `min_supported_version` or `eol_versions`, `_audit_dependency()` unconditionally returns `PASS` (even when `version == "Unknown"`, because line 508 only triggers `WARN_UNVERIFIED` when `min_ver or rule.get("eol_versions")` is truthy!).
* **Effort / Risk**: **Low effort / Low–Medium risk**.
* **What it would break or complicate**:
  * Almost every Go project has `golang.org/x/crypto` in `go.mod` (often as an indirect dependency via `golang.org/x/net` or `golang.org/x/sys`). Moreover, `_parse_go_mod()` in [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L369-L384) does not distinguish direct dependencies from `// indirect` dependencies. At the `go.mod` level, `golang.org/x/crypto` should emit `NOT_VALIDATED` / `NEEDS_REVIEW` (warning), reserving hard `FAIL` findings for actual AST/import usage of non-approved subpackages (`chacha20poly1305`, `blowfish`, `salsa20`, `ripemd160`, etc.) in `.go` source files.

---

#### **D7 — AOC-09 Semgrep message recommends `hashlib` or `pyca/cryptography` without FIPS qualification**
* **Position**: **Agree.**
* **Code Confirmation**: **Confirmed** in [custom-baseline-ruleset.yaml](../rules/custom-baseline-ruleset.yaml#L411). Note that the sibling AOC-09 rules for Go (line 427), Java (line 441), and JS/TS (line 454) have the same omission (`"Migrate to standard crypto/sha256 or crypto/aes"`, `"Use standard JCA/JCE providers"`, `"Migrate to Web Crypto API or Node.js native crypto"`) and should be updated alongside line 411 for consistency.
* **Effort / Risk**: **Low effort / Low risk**.
* **What it would break or complicate**: Nothing.

---

#### **D8 — `README.md:138` advertises `crypto_lib_scan.py (EOL & FIPS 140-3)`**
* **Position**: **Partly Agree.** Agree with the fix, but the review missed four other files across `GRC-xMINI` and `GRC-xBOT` making the same overclaim.
* **Code Confirmation**: **Confirmed** at [GRC-xMINI/README.md](../README.md#L138).
  * **Additional locations missed by review**:
    * [GRC-xMINI/amplifying-info/GOVERNANCE.md](../amplifying-info/GOVERNANCE.md#L74) (`"Detect deprecated, unmaintained, or non-FIPS 140-3 validated cryptographic modules"`)
    * [GRC-xMINI/amplifying-info/GOVERNANCE.md](../amplifying-info/GOVERNANCE.md#L157-L162) (`"3.5 NIST FIPS 140-3: Cryptographic Module Validation — Enforcement Script: scripts/crypto_lib_scan.py"`)
    * [GRC-xMINI/amplifying-info/ARCHITECTURE.md](../amplifying-info/ARCHITECTURE.md#L127) (`"identify deprecated, unmaintained, or non-FIPS 140-3 compliant cryptographic libraries"`)
    * [GRC-xBOT/playbooks/workflows.json](../../GRC-xBOT/playbooks/workflows.json#L112) (`"Scans dependency manifests (requirements.txt, package.json, go.mod, pom.xml, Cargo.toml) ... for End-of-Life (EOL), deprecated, or non-FIPS cryptographic libraries against NIST SP 800-53 SC-13"` — note it also claims `Cargo.toml`, which `crypto_lib_scan.py` does not currently parse!).
* **Effort / Risk**: **Low effort / Low risk**.
* **What it would break or complicate**: Nothing.

---

#### **D9 — No CMVP data in catalog**
* **Position**: **Agree.**
* **Code Confirmation**: **Confirmed** in [crypto_catalog.json](../rules/crypto_catalog.json#L14-L99).
* **Effort / Risk**: **High effort / Medium risk**.
* **What it would break or complicate**: Static source manifests (`requirements.txt`, `package.json`, `pom.xml`) rarely identify the exact host OS/kernel/CPU Operational Environment (OE) or sub-patch level to which a CMVP certificate is bound. Without container/AMI OS context (`etc/os-release` or `Dockerfile` `FROM`), most application-level matches can only honestly resolve to `CANNOT_DETERMINE_STATICALLY` (capable module, unverified OE/mode) or `FAIL_HISTORICAL_CERT` (when the library family only holds 140-2 certs).

---

#### **D10 — Narrow manifest and language coverage in `DependencyExtractor`**
* **Position**: **Agree.**
* **Code Confirmation**: **Confirmed.** `DependencyExtractor.PARSERS` in [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L387-L393) only handles `requirements.txt`, `pyproject.toml`, `package.json`, `pom.xml`, and `go.mod`, plus filename checks in `extract_from_workspace()` ([crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L231)) for `libcrypto.*`, `libssl.*`, and `openssl`. (Notably, [GRC-xBOT/playbooks/workflows.json](../../GRC-xBOT/playbooks/workflows.json#L112) already claims `Cargo.toml` is supported.)
* **Effort / Risk**: **Medium–High effort / Low–Medium risk**.
* **What it would break or complicate**:
  1. `DependencyExtractor.extract_from_workspace()` ([crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L228)) uses an exact filename dictionary lookup (`DependencyExtractor.PARSERS.get(f)`). That cannot match glob/suffix patterns like `*.csproj`, `requirements-*.txt`, or `Dockerfile.*` without refactoring `extract_from_workspace` to support pattern/extension dispatchers.
  2. Parsing both a manifest (`package.json`, `pyproject.toml`, `Cargo.toml`) and its lockfile (`package-lock.json`, `poetry.lock`, `Cargo.lock`) in the same repo will emit duplicate findings for the same package unless `DependencyExtractor` deduplicates `(package, version, directory)` or prefers lockfile versions over unpinned manifest ranges.

---

#### **D11 — No GitHub URL intake in `grc_bot.py` or `grc_bundle.py`**
* **Position**: **Partly Agree.**
* **Code Confirmation**: **Confirmed in both `GRC-xBOT` and `GRC-xMINI`.**
  * [GRC-xMINI/scripts/grc_bundle.py](../scripts/grc_bundle.py#L141-L145): `GRCBundleManager.__init__` requires `self.bundle_path.is_file()` on local disk.
  * [GRC-xBOT/scripts/grc_bot.py](../../GRC-xBOT/scripts/grc_bot.py#L395-L508): `CommandPlanner` only inspects local `.bundle` files in `artifacts/drop-off/`.
  * [GRC-xBOT/scripts/grc_bot.py](../../GRC-xBOT/scripts/grc_bot.py#L1280-L1286) & [GRC-xBOT/grc-bot](../../GRC-xBOT/grc-bot#L77-L105): `build_cli()` only accepts `choices=["chat", "status", "guide", "ask", "mode"]`. Running `./grc-bot fips https://github.com/org/repo` currently falls through the `*)` case in `grc-bot:101` into `python3 scripts/grc_bot.py ask "fips https://github.com/org/repo"`, which routes to the local `./grc crypto` workflow!
* **Effort / Risk**: **Medium effort / Medium risk**.
* **What it would break or complicate**:
  1. **`GRC-xBOT` Test Contract ([testing/test_grc_bot.py](../../GRC-xBOT/testing/test_grc_bot.py#L66-L72) & [L496-L570](../../GRC-xBOT/testing/test_grc_bot.py#L496-L570))**:
     * `test_playbooks_loaded_all_seven_workflows` asserts `self.assertEqual(len(workflows), 7)`. Adding `"fips"` as an 8th workflow in `playbooks/workflows.json` will fail this test unless updated.
     * `test_planner_flags_against_contract_and_live_xmini_when_present` checks every workflow in `playbooks/workflows.json` against `contract_allowed_flags` and `GRC-xMINI/scripts/*.py`.
  2. **`IntentRouter` Keyword Collision ([scripts/grc_bot.py](../../GRC-xBOT/scripts/grc_bot.py#L307-L308))**:
     * Currently `"fips"` boosts `"crypto"` (`scores["crypto"] += 3.0`), and `"fips"`, `"140-2"`, `"140-3"`, `"sc-13"` are in `workflows["crypto"]["keywords"]` ([playbooks/workflows.json](../../GRC-xBOT/playbooks/workflows.json#L114-L115)). Adding a `"fips"` workflow requires re-partitioning those keywords so `"crypto"` and `"fips"` don't tie or misroute existing tests in `test_grc_bot.py:73-95`.
  3. See Phase 1 analysis below (§2.2) regarding `--filter=blob:none` vs. `git bundle create`, detached ref checkout bugs in `grc_bundle.py`, and `SECURITY.md` offline guarantees.

---

#### **D12 — Weak-crypto detection depends on Docker + Semgrep**
* **Position**: **Agree.**
* **Code Confirmation**: **Confirmed** in [GRC-xMINI/grc](../grc#L219-L239), [docker/scan_orchestrator.sh](../docker/scan_orchestrator.sh#L33-L47), and [GRC-xTEST/scripts/verify_pipeline.sh](../../GRC-xTEST/scripts/verify_pipeline.sh#L54-L79) (where host-native verification in step `[2/5]` can only run `crypto_lib_scan.py` on the 12 bundles and skips all AST/config checks when Docker is not running).
* **Effort / Risk**: **High effort / Medium risk**.
* **What it would break or complicate**: When Docker *is* used (`./grc scan --all`), running both Semgrep (`AOC-03`/`AOC-05`/`AOC-09`) and the new stdlib `fips_discovery.py` will produce **duplicate POA&M findings** for the same `file:line` in `grc_reporter.py` unless cross-engine finding deduplication is added to `GRCComplianceReporter` (which currently only deduplicates CVEs across Grype and Trivy via `_seen_vuln_keys` at [grc_reporter.py](../scripts/grc_reporter.py#L295)).

---

### 2.2 Evaluation of Implementation Phases (§3 & §4.1–4.6)

| Phase | Verdict | Code & Architectural Assessment | Effort / Risk | What It Breaks or Complicates |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 0: Corrections (§3)** | **Partly Agree** | Review says: *"Embedded `DEFAULT_CRYPTO_CATALOG` kept in sync, or replaced by loading the JSON with a failing test if the two diverge."* In [crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L156-L164), `DEFAULT_CRYPTO_CATALOG` is **overwritten at module import time** if `rules/crypto_catalog.json` exists! In fact, they have *already* diverged (`openssl` `0.9.8` is in `crypto_catalog.json:26` but missing from `crypto_lib_scan.py:79-83`). | **Low Effort / Medium Risk** | A test comparing `crypto_lib_scan.DEFAULT_CRYPTO_CATALOG` to `crypto_catalog.json` is a tautology unless the import-time overwrite at lines 156–164 is removed or renamed. Also see D3/D5/D6 impacts on `grc_reporter.py` and `grc_test.py`. |
| **Phase 1: GitHub Intake (§4.1)** | **Partly Agree** | Review proposes: `git clone --mirror (or --filter=blob:none)` $\rightarrow$ `git bundle create` $\rightarrow$ `grc_bundle.py verify` $\rightarrow$ `restore --read-only`, and writing `fips_provenance.json`. | **Medium Effort / Medium Risk** | 1. **`--filter=blob:none` + `git bundle create` conflict**: `git bundle create` requires objects to be present in the packfile; on a blobless clone it either triggers a full network fetch of all missing blobs or fails offline.<br>2. **`restore_bundle` ref checkout bug**: `git clone` of a `--mirror` bundle followed by `git checkout --detach <target_ref>` ([grc_bundle.py](../scripts/grc_bundle.py#L247-L255)) fails if `<target_ref>` is a non-default branch not mapped as a local branch or if the mirror bundle lacks `HEAD`.<br>3. **`fips_provenance.json` breaks `safe_rmtree` and `grc_reporter.py`**: `safe_rmtree` ([grc_common.py](../scripts/grc_common.py#L205)) and `load_provenance()` ([grc_reporter.py](../scripts/grc_reporter.py#L343-L353)) only recognize `bundle_provenance.json` and `ami_provenance.json`. |
| **Phase 2: Crypto Discovery / CBOM (§4.2)** | **Partly Agree** | Stdlib `ast` works well for Python source files (provided target code syntax $\le$ the host Python version), but Python's stdlib has **no AST parser** for Go, Java/Kotlin, JS/TS, C/C++, Rust, or .NET. | **High Effort / Medium–High Risk** | Non-Python ecosystems in a stdlib-only scanner must rely on comment-stripping lexical/regex scanners, which cannot resolve cross-file constants or type aliases. Confidence levels (`HIGH` vs. `MEDIUM`/`LOW`) must reflect AST vs. regex detection. |
| **Phase 3: Algorithm & Parameter Rules (§4.3)** | **Agree** | Data-driven `rules/fips_algorithm_policy.json` with NIST citations (`SP 800-131A Rev. 2`, `SP 800-140C/D`, `FIPS 186-5`, `SP 800-52 Rev. 2`) fits the externalized catalog pattern established in `v1.4.2` ([grc_common.py](../scripts/grc_common.py)). | **Medium Effort / Low Risk** | Must distinguish raw `SHA-1` (disallowed for digital signatures/general hashing) from `HMAC-SHA-1` (still approved with constraints in SP 800-140C), and `NEEDS_REVIEW` items must not be ingested by `grc_reporter.py` as `CRITICAL`/`HIGH` 30-day SLA breaches. |
| **Phase 4: CMVP Mapping & Approved-Mode (§4.4)** | **Partly Agree** | Curating `rules/cmvp_catalog.json` for major modules and checking approved-mode config intent (`openssl.cnf`, `GODEBUG=fips140`, `java.security`, kernel `fips=1`) directly solves D1 and D9 and will immediately light up all 5 files in `GRC-xTEST/bundles/aoc-12-no-fips-mode/`. | **High Effort / Medium Risk** | 1. **Signature verification vs. stdlib-only**: Python 3's stdlib (`hashlib`/`hmac`) cannot verify asymmetric signatures (Ed25519/ECDSA/RSA/Sigstore) on `cmvp_catalog.json` without shelling out to `openssl`/`cosign`/`ssh-keygen` or adding a small pure-Python verifier.<br>2. **NIST CMVP data structure**: NIST's public feeds index *modules* and *cert numbers*, not PyPI/npm/Maven/Cargo package names; `update-data` can auto-refresh cert status (`Active`/`Historical`/`Revoked`) by cert number, but `(package, version) -> cert_number` mappings require curated maintenance. |
| **Phase 5: Reporting & Test Corpus (§4.5)** | **Partly Agree** | Emitting `fips_assessment.md`, `fips_findings.json`, `fips_findings.sarif`, `cbom.cdx.json`, and `cmvp_mapping.md` in `artifacts/pick-up/<timestamp>/` matches existing conventions across `GRC-xMINI` and `GRC-xBOT`. | **Medium Effort / Medium Risk** | Integrating with `grc_reporter.py` (`controls.md`, `poam_data.md`, `scr_scn_package.json`) conflicts with §1.1 (*"Report wording must never say 'compliant' or 'certified'"*) because `grc_reporter.py` hardcodes `"COMPLIANT"` / `"NON-COMPLIANT"` in 8+ places and tests assert those exact strings. |
| **Phase 6: Personal-Device Packaging (§4.6)** | **Partly Agree** | Python CLI entry point + `pipx install` solves Windows/macOS bash friction. | **Medium–High Effort / Medium Risk** | **`python -m zipapp` breaks file-path assumptions**: `grc_common.py:30-34`, `crypto_lib_scan.py:157`, `grc_reporter.py:368`, and `grc_bot.py:40-42` load catalogs/playbooks via `Path(__file__).resolve().parent.parent / ...` and `.is_file()` / `open()`. Inside a `.pyz` zipapp, `__file__` is inside a zip archive, causing `.is_file()` to return `False` and `open()` to raise `NotADirectoryError` unless migrated to `importlib.resources` or extracted to a user cache directory. |

---

## 3. What the Review Missed: Architectural Problems Across the Triad

1. **`CryptoScanner._match_rule()` Ignores Ecosystem Scoping ([GRC-xMINI/scripts/crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L411-L426))**
   * Every rule in [crypto_catalog.json](../rules/crypto_catalog.json) declares an `"ecosystems"` array (e.g., `["maven", "gradle", "java"]`), and `DependencyExtractor` extracts `ecosystem` for every dependency.
   * However, `CryptoScanner._match_rule(self, name)` **never checks `ecosystem`**—it matches solely on regex against `name`. As the catalog grows in Phase 4 (where `openssl` exists as a system library, a Rust crate `openssl`, a Python wrapper `pyOpenSSL`, and an npm wrapper), matching by name alone will apply the wrong ecosystem's version thresholds and CMVP certs.

2. **Defective Version Parsing in `DependencyExtractor` for Existing Manifests ([GRC-xMINI/scripts/crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L259-L385))**
   * **`package.json` version concatenation bug ([crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L331))**: `clean_ver = re.sub(r"[^0-9\.]", "", str(ver)).strip(".")` strips all non-numeric characters across the entire string. A range like `">=1.3.1 <2.0.0"` or `"1.2.x || 1.3.x"` is concatenated into `"1.3.12.0.0"` or `"1.2.1.3"`, which then passes `version_lt("1.3.12.0.0", "1.3.1")` as `1.3.12 > 1.3.1` even if `<1.3.1` was allowed!
   * **`go.mod` `replace` and `exclude` misparsing ([crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L379-L381))**: Any line matching `^([^\s]+)\s+v([^\s]+)` inside a `replace (...)` or `exclude (...)` block is extracted as a required dependency, while the target of a `replace` directive (often how Go teams swap in a FIPS-validated fork!) is ignored.
   * **Maven `pom.xml` unresolved properties and `<dependencyManagement>` ([crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L348-L363))**: `_parse_pom_xml` walks `root.iter()` for all `<dependency>` tags (conflating `<dependencyManagement>` templates with active dependencies) and turns any `<version>${bc.version}</version>` into `"Unknown"` instead of looking up `<bc.version>` in the same file's `<properties>` element.
   * **`pyproject.toml` fallback regex on Python 3.9/3.10 ([crypto_lib_scan.py](../scripts/crypto_lib_scan.py#L283-L321))**: When `tomllib` is `None` (Python 3.9/3.10, which the project explicitly supports per §1.2!), the fallback regex at line 316 `re.findall(r'["\']([a-zA-Z0-9_\-\.]+)(?:[=><~^!]+([0-9a-zA-Z_\.\-]+))["\']', content)` matches **any quoted string with `=`, `>`, `<`, `!`, `~`, or `^`** anywhere in `pyproject.toml` (including ruff/pytest/black/poetry config strings) and misses unpinned dependencies like `"cryptography"`!

3. **Fragile Regex YAML Parser in `grc_reporter.py` ([GRC-xMINI/scripts/grc_reporter.py](../scripts/grc_reporter.py#L377-L386))**
   * `load_baseline_rules()` uses a single multi-line regex with `re.DOTALL`:
     `r"  - id:\s*([^\n]+).*?severity:\s*([^\n]+).*?message:\s*\"([^\"]+)\".*?aoc:\s*\"([^\"]+)\".*?nist_control:\s*\"([^\"]+)\""`
   * If any rule in `custom-baseline-ruleset.yaml` uses multiline YAML strings, single quotes, or places `nist_control` before `aoc`, `.*?` greedily matches across rule boundaries and silently drops or corrupts rules in `ruleset_validation.md`.
   * Additionally, `re.search(r"([A-Z]{2}-\d+)", r_nist)` (lines 384 and 433) strips control enhancements: `SC-8(1)` and `SC-28(1)` (explicitly required by §1.1 and §4.5 of the review) are truncated to `SC-8` and `SC-28`.

4. **Symlink `chmod` Traversal on Host in `grc_bundle.py` ([GRC-xMINI/scripts/grc_bundle.py](../scripts/grc_bundle.py#L334-L347))**
   * `_apply_read_only()` runs on the **host** during `grc bundle restore --read-only` and calls `f_path.chmod(0o444)` on every file in `os.walk(path)`.
   * Because `Path.chmod()` follows symlinks by default, an untrusted repo containing a symlink pointing to a host file outside the workspace will cause `restore_bundle` to `chmod 0444` the host file. `_apply_read_only()` should skip symlinks (`if f_path.is_symlink(): continue`).
   * Conversely, `safe_rmtree()` in [grc_common.py](../scripts/grc_common.py#L247) calls `shutil.rmtree(resolved)` without an `onerror`/`onexc` handler to restore write permissions—which fails on Windows (and on POSIX if a restored subdirectory is `0555`) when cleaning up a `--read-only` workspace.

5. **`./grc scan` Evidence Path Extraction Uses Fragile `grep`/`cut` ([GRC-xMINI/grc](../grc#L186-L199))**
   * `./grc` extracts `bundle_source_path` from `bundle_provenance.json` via `grep -o` and `cut -d'"' -f4`, then runs `basename "${BUNDLE_SOURCE}" .bundle`. If the source is a GitHub URL or local directory path (Phase 1), or if provenance is stored in `fips_provenance.json`, evidence directory naming breaks.

6. **`GRC-xBOT` `IntentRouter` Score Normalization Saturates at 2 Keywords ([GRC-xBOT/scripts/grc_bot.py](../../GRC-xBOT/scripts/grc_bot.py#L289-L320))**
   * `IntentRouter.classify()` adds `2.0` per single-word keyword match, `3.0` per phrase match, and `3.0` for contextual token sets, then divides by `6.0` (`confidence = min(1.0, best_score / 6.0)`).
   * Because `"crypto"` and a new `"fips"` workflow share core vocabulary (`fips`, `140-3`, `openssl`, `crypto`, `sc-13`), a query like *"run a fips 140-3 crypto scan on openssl"* will give both `"crypto"` and `"fips"` a score $\ge 6.0$ (`100%` confidence), and `max(scores, key=lambda k: scores[k])` will pick whichever key appears first in `playbooks/workflows.json`! We must explicitly disambiguate `"fips"` vs. `"crypto"` in `IntentRouter.classify()`.

---

## 4. Ambiguities, Outdated References & Contradictions

### 4.1 Outdated or Contradictory Items Flagged

1. **Triad Codename Convention in §4.6 & §5 (`GRC-xBOT` Circuits vs. `GRC-xMINI` / `GRC-xTEST` Bases)**:
   * The handoff (§4.6 line 156, §5 line 170) lists `v1.3.0 — Tsukuba`, `v1.4.0 — Autopolis`, and `v2.2.0 — Daytona` (which are `GRC-xBOT`'s racing-circuit codenames per [GRC-xBOT/hygiene/ROADMAP.md](../../GRC-xBOT/hygiene/ROADMAP.md#L33-L40)), whereas `GRC-xMINI` and `GRC-xTEST` use military base stationings (`v1.4.x — Yokota`, `v2.0.0 — Pearl Harbor`, `v2.1.0 — Kaneohe`, `v2.2.0 — Wahiawa` per [GRC-xMINI/hygiene/ROADMAP.md](../hygiene/ROADMAP.md#L37-L42)).
   * Since this feature spans all three repositories (`GRC-xMINI` engines/catalogs, `GRC-xBOT` co-pilot workflow/CLI, and `GRC-xTEST` fixtures), each repo's roadmap should track its own codename series (`Yokota`/`Pearl Harbor` for `GRC-xMINI` & `GRC-xTEST` $\leftrightarrow$ `Tsukuba`/`Autopolis`/`Laguna Seca` for `GRC-xBOT`).
2. **Internal Contradiction on `AOC-12` Across `GRC-xMINI` and `GRC-xTEST` Docs**:
   * [GRC-xMINI/README.md](../README.md#L191), [docs/grc-xtest-guide.md](../docs/grc-xtest-guide.md#L325), and [GRC-xTEST/README.md](../../GRC-xTEST/README.md#L116) define `AOC-12` (`aoc-12-no-fips-mode.bundle`) as **Lack of FIPS Mode (`SC-13`)**.
   * However, [GRC-xMINI/amplifying-info/GOVERNANCE.md](../amplifying-info/GOVERNANCE.md#L254) defines `AOC-12` (`aoc-12-hardcoded-keys.bundle`) as **Exposed Private RSA / SSH Keys (`IA-5`, `SC-12`)** (and lines 244–254 of `GOVERNANCE.md` list an older AOC-04 through AOC-12 numbering scheme that contradicts both `custom-baseline-ruleset.yaml` and `GRC-xTEST`).
3. **Minor Metadata Drift in `GRC-xBOT`**:
   * [GRC-xBOT/playbooks/workflows.json](../../GRC-xBOT/playbooks/workflows.json#L2-L3) still has `"schema_version": "1.0.0", "series": "Suzuka"`, whereas `load_playbooks()` in [GRC-xBOT/scripts/grc_bot.py](../../GRC-xBOT/scripts/grc_bot.py#L67) uses `"schema_version": "1.2.1", "series": "Motegi"`.
   * [GRC-xBOT/QUICK_REFERENCE.md](../../GRC-xBOT/QUICK_REFERENCE.md#L112) still lists `OPEN FedRAMP-POAM.xlsx, CLOSED FedRAMP-POAM.xlsx` instead of the unified 2-tab `FedRAMP-POAM.xlsx` introduced in `GRC-xMINI v1.4.3`.
4. **Deliverable Filename Drift in `GRC-xMINI` Docs vs. Code**:
   * [DATAFLOW.md](../amplifying-info/DATAFLOW.md#L198-L205) and [GOVERNANCE.md](../amplifying-info/GOVERNANCE.md#L285-L290) refer to `crypto_lib_findings.json`, `gitleaks_report.json`, `grype_cve_report.json`, and `trivy_cve_report.json`, whereas [grc](../grc#L248), [scan_orchestrator.sh](../docker/scan_orchestrator.sh), and [grc_reporter.py](../scripts/grc_reporter.py#L804-L812) actually produce and consume `crypto_findings.json`, `gitleaks_findings.json`, `grype_findings.json`, and `trivy_findings.json`.

### 4.2 Questions for You to Answer Before Implementation

1. **Separation of `AOC-09` (EOL/Maintenance) vs. `SC-13` (FIPS Validation) in `crypto_lib_scan.py` & `grc_reporter.py`**:
   * When `cryptography >= 41.0.0` or `openssl >= 3.0.0` is detected with no approved-mode config evidence, its FIPS determination is `CANNOT_DETERMINE_STATICALLY`. Should `grc_reporter.py` exclude `CANNOT_DETERMINE_STATICALLY` and `NEEDS_REVIEW` from the mandatory 30/90-day FedRAMP POA&M table in `poam_data.md` (placing them instead in a separate "Items Requiring Human / Runtime Verification" section and marking `SC-13` as `INDETERMINATE / NEEDS_REVIEW`), so healthy dependencies aren't mislabeled as *"Unsupported/Deprecated Cryptographic Library"* POA&Ms?
2. **Scope of the "Never Say Compliant" Rule (§1.1)**:
   * Should the ban on the word `"compliant"` apply **only** to the new FIPS deliverables (`fips_assessment.md`, `fips_findings.json`, `cmvp_mapping.md`), or do you also want `grc_reporter.py`'s existing `poam_data.md`, `controls.md`, and `scr_scn_package.json` changed from `COMPLIANT` / `NON-COMPLIANT` (which will require updating existing unit tests)?
3. **Committed Demo Evidence (`GRC-xMINI/testing/demo-evidence/*`) & `GRC-xTEST` Bundles**:
   * In Phase 0 (fixing D2 `SI-16` $\rightarrow$ `SC-13`), should we regenerate/update the 5 committed sample output directories under `GRC-xMINI/testing/demo-evidence/` (and their `sha256sum` manifests) and update `GRC-xTEST/README.md` + `GRC-xTEST/bundles/aoc-03-legacy-crypto/README.md` so they no longer show `SI-16` for `AOC-03`?
4. **Your 5 Open Owner Decisions from §6 of the Handoff**:
   * **Q4a (Roadmap Placement)**: In `GRC-xBOT/hygiene/ROADMAP.md`, `v1.3.0 — Tsukuba` is currently scoped to `./grc-bot remediate` and `v1.4.0 — Autopolis` to `./grc-bot iac`. Should the FIPS 140-3 readiness analyzer be added as a co-feature in `v1.3.0 — Tsukuba` / `GRC-xMINI v1.4.5 — Yokota`, or given its own minor release (`GRC-xMINI v1.5.0` / `GRC-xBOT v1.5.0`)?
   * **Q4b (Engine Location)**: Confirm keeping the deterministic scanning engines (`crypto_lib_scan.py`, `fips_discovery.py`, `grc_bundle.py`) and catalogs (`rules/*.json`) in `GRC-xMINI`, with `GRC-xBOT` orchestrating them via `./grc fips` / `CommandPlanner` (matching how `GRC-xBOT` currently orchestrates all 7 `GRC-xMINI` engines)?
   * **Q4c (Submodules & LFS)**: Confirm default = no submodule recursion (`--recurse-submodules` opt-in) and `GIT_LFS_SKIP_SMUDGE=1`?
   * **Q4d (CMVP Staleness & Signing)**: Confirm 90-day staleness warning threshold? And for catalog integrity under the Python stdlib-only constraint, should we verify via SHA-256 manifest + optional `cosign`/`openssl`/`ssh-keygen -Y verify` when present on host?
   * **Q4e (GHES Support)**: Support configurable GitHub Enterprise Server host allowlists in Phase 1 (via `--allowed-hosts` / `GRC_GITHUB_HOSTS`, defaulting to `github.com`), or defer GHES to a later release?

---

## 5. Proposed Order of Work

Below is the recommended execution order across **`GRC-xMINI`**, **`GRC-xBOT`**, and **`GRC-xTEST`**, structured to prevent breaking existing tests while laying clean foundations for each dependent phase:

### Step 1: Phase 0 — Baseline Corrections & Tri-State Model Foundation (`GRC-xMINI`, `GRC-xBOT`, `GRC-xTEST`)
* **What to do**:
  1. **Fix D2 (`SI-16` $\rightarrow$ `SC-13`)**:
     * In `GRC-xMINI`: Update `AOC-03` rules in `rules/custom-baseline-ruleset.yaml`, update `NIST_CONTROLS_CATALOG["SI-16"]` in `scripts/grc_reporter.py` (set `assessed_by: []` or map `grc-aoc10-go-unsafe-pointer` to `SI-16`), update `load_baseline_rules()` / `parse_semgrep()` to preserve control enhancements (`SC-8(1)`, `SC-28(1)`) and multi-control lists, and update `README.md`, `testing/TESTING.md`, `docs/grc-xtest-guide.md`, and `amplifying-info/GOVERNANCE.md`.
     * In `GRC-xTEST`: Update `README.md:108` and `bundles/aoc-03-legacy-crypto/README.md:3`.
  2. **Fix D3–D6 (`crypto_catalog.json` & `crypto_lib_scan.py`)**:
     * Bump `crypto_catalog.json` to `1.1.0`; replace boolean `fips_capable` with `fips_status` (`VALIDATED_MODULE`, `CAPABLE_IF_CONFIGURED`, `NOT_VALIDATED`, `UNKNOWN`).
     * Update `cryptography` (`CAPABLE_IF_CONFIGURED`), `pycrypto` remediation, add `pycryptodome` / `pycryptodomex` (`NOT_VALIDATED`), and set `golang-x-crypto` (`NOT_VALIDATED`).
     * Remove the import-time overwrite of `DEFAULT_CRYPTO_CATALOG` in `scripts/crypto_lib_scan.py:156-164` and add a unit test that fails if `DEFAULT_CRYPTO_CATALOG` and `rules/crypto_catalog.json` drift.
     * Enforce `ecosystems` matching in `CryptoScanner._match_rule()` and update `grc_reporter.py:parse_crypto_scan()` so `CAPABLE_IF_CONFIGURED` / `CANNOT_DETERMINE_STATICALLY` does not get misreported as an EOL/deprecated library POA&M.
  3. **Fix D1, D7, D8**: Update AOC-09 messages in `custom-baseline-ruleset.yaml`, mark AOC-12 as "Planned (Phase 4)" in `README.md` / `docs/grc-xtest-guide.md` (and reconcile `GOVERNANCE.md:254`), and reword FIPS 140-3 capability claims in `GRC-xMINI/README.md`, `GOVERNANCE.md`, `ARCHITECTURE.md`, and `GRC-xBOT/playbooks/workflows.json:112`.
* **Dependencies**: None (prerequisite for all subsequent phases).
* **Reason to do first**: High compliance value, low effort, and fixes the tri-state handling in `crypto_lib_scan.py` and `grc_reporter.py` before new FIPS detectors feed into them.

### Step 2: Fix Existing `DependencyExtractor` Bugs + D10 Manifest Expansion (`GRC-xMINI` & `GRC-xTEST`)
* **What to do**:
  1. Fix existing parser defects in `scripts/crypto_lib_scan.py` (`package.json` range concatenation bug, `pyproject.toml` Python 3.9/3.10 fallback, `pom.xml` `<properties>` resolution, `go.mod` `replace` handling).
  2. Extend `DependencyExtractor` to dispatch by filename pattern/extension and add parsers for `Cargo.toml`/`Cargo.lock`, `*.csproj`/`packages.lock.json`, `build.gradle[.kts]`, and lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`) with manifest/lockfile deduplication.
* **Dependencies**: Depends on Step 1 (`crypto_catalog.json` v1.1.0 schema and ecosystem-aware `_match_rule`).
* **Reason**: Every downstream phase (CBOM generation in Phase 2 and CMVP module mapping in Phase 4) depends on accurate dependency and version extraction across all target ecosystems.

### Step 3: Phase 3 + Phase 2 — Algorithm Policy Catalog & Stdlib Source/Config Discovery (`GRC-xMINI/scripts/fips_discovery.py`)
* **What to do**:
  1. Author `rules/fips_algorithm_policy.json` (Phase 3) with verified NIST citations (`SP 800-131A Rev. 2`, `SP 800-140C/D`, `SP 800-90A Rev. 1`, `FIPS 186-5`, `SP 800-52 Rev. 2`) first so the discovery engine has a declarative rule schema to evaluate against.
  2. Build `scripts/fips_discovery.py` (Phase 2) using `ast` for Python and comment-stripping lexical/pattern analyzers for Go, Java/Kotlin, JS/TS, C/C++, Rust, .NET, and config/IaC files (`openssl.cnf`, `java.security`, `etc/default/grub`, `etc/crypto-policies/config`, `Dockerfile`, K8s/nginx TLS), emitting CycloneDX 1.6 `cbom.cdx.json` and structured algorithm/mode findings (`AOC-03`, `AOC-05`, `AOC-12`).
* **Dependencies**: Depends on Step 2 (dependency inventory feeds into `cbom.cdx.json` alongside source-level `cryptographic-asset` detections).
* **Reason for reversing Phase 3 before Phase 2**: Defining the data-driven algorithm and parameter schema (`fips_algorithm_policy.json`) first ensures `fips_discovery.py` extracts the exact fields (algorithm, mode, key size, curve, purpose hint) required by the policy engine.

### Step 4: Phase 4 — CMVP Catalog Mapping & Approved-Mode Evidence (Fixes D1 & D9 Across `GRC-xMINI` & `GRC-xTEST`)
* **What to do**:
  1. Create `rules/cmvp_catalog.json` with versioned metadata, staleness check (default 90 days), and curated mappings for OpenSSL 3 FIPS provider, BC-FIPS, Go 1.24+ native FIPS module, AWS-LC-FIPS, BoringCrypto, wolfCrypt FIPS, and major FIPS OS base images.
  2. Combine dependency inventory (Step 2) + approved-mode config evidence (Step 3) + `cmvp_catalog.json` to compute final module determinations (`CONFORMANT_INDICATOR`, `FAIL_HISTORICAL_CERT` for 140-2-only modules, `NOT_VALIDATED`, `CANNOT_DETERMINE_STATICALLY`).
  3. Verify against `GRC-xTEST/bundles/aoc-12-no-fips-mode.bundle` and `GRC-xTEST/ami/packer/non-fips-kernel.pkr.hcl` so all 5 AOC-12 violation patterns are caught host-natively in `GRC-xTEST/scripts/verify_pipeline.sh`.
* **Dependencies**: Depends on Steps 2 and 3.

### Step 5: Phase 1 — Hardened GitHub URL & Local Path Intake (`GRC-xMINI` & `GRC-xBOT`)
* **What to do**:
  1. In `GRC-xMINI`:
     * Fix `_apply_read_only()` in `grc_bundle.py` to skip symlinks and update `safe_rmtree()` in `grc_common.py` to handle read-only file removal cross-platform and recognize `fips_provenance.json`.
     * Add strict URL validation (`https://` scheme, configurable host allowlist defaulting to `github.com`, rejecting `ext::`/`file://`/leading-dash refs) and hardened `git` invocation (`-c core.hooksPath=/dev/null`, `-c protocol.file.allow=never`, `GIT_LFS_SKIP_SMUDGE=1`, no submodules by default) to `grc_bundle.py`, plus `./grc fips <target>` CLI routing.
     * **Adjustment to review**: Instead of `git clone --filter=blob:none` + `git bundle create` (which conflicts on missing blobs), use `git clone --bare --depth 1` (or full clone when `--full-history` is requested) with direct commit SHA pinning and bundle creation of the target ref.
  2. In `GRC-xBOT`:
     * Add the `"fips"` workflow to `playbooks/workflows.json`, update `IntentRouter.classify()`, `CommandPlanner.build_recommended_commands()`, `build_cli()`, and `grc-bot` (`./grc-bot fips <url|bundle|path>`), and update `testing/test_grc_bot.py` (`contract_allowed_flags`, workflow count, and URL validation tests).
* **Dependencies**: Can be developed in parallel with Steps 2–4, and wired into `./grc fips` / `./grc-bot fips` once Steps 3–4 are ready.

### Step 6: Phase 5 — FIPS Deliverables, SARIF Output, Reporter Integration & `GRC-xTEST` Corpus Expansion
* **What to do**:
  1. Generate `fips_assessment.md` (with §1.1 framing), `fips_findings.json`, `fips_findings.sarif`, `cbom.cdx.json`, `cmvp_mapping.md`, and `fips_provenance.json` sealed with `sha256sum` under `artifacts/pick-up/<timestamp>/`.
  2. Integrate `fips_findings.json` into `grc_reporter.py` with cross-engine deduplication (so Semgrep + `fips_discovery.py` don't double-report the same `file:line`) and tri-state control rollup support.
  3. Add positive ("clean FIPS") and negative fixtures across Python, Go, Java, JS/TS, Rust, C/C++, and .NET in `GRC-xMINI/scripts/grc_fixtures.py` and `GRC-xTEST`.
* **Dependencies**: Depends on Steps 3, 4, and 5.

### Step 7: Defer / Re-scope — Phase 6 (`zipapp` / PyInstaller Single-Binary Packaging) & Automated NIST CMVP Scraping
* **What to defer or adjust**:
  * **Keep**: Adding `pyproject.toml` console script entry points (`pipx install .`) for `GRC-xMINI` and `GRC-xBOT` and migrating resource lookups to `importlib.resources`—low effort and high portability value on macOS/Linux/Windows.
  * **Defer**: Building `python -m zipapp` / PyInstaller standalone binaries and automated live scraping of NIST CMVP web pages until after v1 of the assessment engine is validated (`v2.0.0` / `v2.2.0`), because `.xlsx` templates and offline ruleset files require filesystem extraction shims for `zipapp`, and CMVP module-to-package mapping requires human curation regardless of raw cert status polling.
