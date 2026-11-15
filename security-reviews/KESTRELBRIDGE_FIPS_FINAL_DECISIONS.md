# KestrelBridge FIPS Dry-Run Review — Final Consensus Decisions

**Status:** Finalized Consensus Decisions (Ready for Implementation)  
**Date:** 2026-11-15  
**Source Review:** `GRC-xMINI/security-reviews/KESTRELBRIDGE_FIPS_REVIEW_v2.md`  
**Roundtable Analysis:** `GRC-xMINI/security-reviews/KESTRELBRIDGE_FIPS_REVIEW_v2_RESPONSE.md`  
**Repositories Covered:** `GRC-xMINI`, `GRC-xBOT`, and `GRC-xTEST`  
**Reviewers:** Software Developer / Designer, Cybersecurity Architect, and GRC Engineer

---

## 1. Executive Summary Table

Every finding from `KESTRELBRIDGE_FIPS_REVIEW_v2.md` was independently evaluated against live source code, JSON Schema constraints, multi-engine reporter logic, automated unit tests, and the three-release KestrelBridge compliance narrative (`v1.0.0` Non-Compliant -> `v1.5.0` Needs Review -> `v2.0.0` Compliant).

| ID / Scope | Topic | Final Disposition | Target Repo(s) & Key File(s) | Critical Guardrails / Revisions |
| :--- | :--- | :--- | :--- | :--- |
| **H1** | `bundle restore` succeeds on empty checkout | **Accepted with Safeguards** | `GRC-xTEST/scenarios/kestrelbridge/build_bundle.sh`<br>`GRC-xMINI/scripts/grc_bundle.py` | Add `HEAD` to both `git bundle create` commands and rebuild all 4 KestrelBridge bundles; clean up partial `.git` directory on `UNKNOWN`/0-file failure before exiting non-zero; warn prominently when restoring a multi-tag bundle without `-r`. |
| **H2** | `./grc fips` accepts a file as `-w` | **Accepted & Expanded** | `GRC-xMINI/scripts/fips_discovery.py`<br>`GRC-xMINI/scripts/crypto_lib_scan.py` | Enforce `ws.is_dir()` and print the `./grc bundle restore` hint for `.bundle` files in **both** `fips_discovery.py` and `crypto_lib_scan.py`. |
| **H3** | `0` files inspected reported clean | **Modified** | `GRC-xMINI/rules/finding_schema.json`<br>`GRC-xMINI/rules/finding_schema.example.json`<br>`GRC-xMINI/scripts/grc_common.py`<br>`GRC-xMINI/scripts/fips_discovery.py` | Update `finding_schema.json` and `validate_finding_envelope()` **first** so `scope.files_inspected` does not violate `additionalProperties: false`; separate total workspace files from FIPS-assessable files; emit warnings strictly to `sys.stderr` (protecting `--format json\|sarif\|cbom` pipes); support `--allow-empty`. |
| **M2 (v2)** | POA&M posture on empty workspace vs. `v2.0.0` | **Modified** | `GRC-xMINI/scripts/grc_reporter.py` | Keep `"COMPLIANT (Clean Out-of-Band Audit)"` for KestrelBridge `v2.0.0` (`0/0/0/31`) and add the optional `"Engines Run"` header line; set `"NOT ASSESSED (No Assessable Files Found)"` **only** when `FIPSDiscovery` reports `0` inspected files and no other scanner contributed evidence (protecting the other 8 engines and `testing/test_code_review_regressions.py`). |
| **H6** | `verify_pipeline.sh` fails on KestrelBridge bundles | **Accepted with Safeguards** | `GRC-xTEST/scripts/verify_pipeline.sh` | Resolve refs dynamically via `git bundle list-heads` (iterating all 3 tags on `kestrelbridge-fips.bundle`), print true bundle counts (`16`), assert exact KestrelBridge counts (`31/0/0/1`, `6/2/1/17`, `0/0/0/31`), deduplicate Docker `[5/5]` runs across identical KestrelBridge snapshots, and isolate `-e` output to a temporary directory. |
| **H4** | FIPS request routes to `crypto` instead of `fips` | **Accepted with Fixes** | `GRC-xBOT/playbooks/workflows.json`<br>`GRC-xBOT/scripts/grc_bot.py`<br>`GRC-xBOT/testing/test_grc_bot.py` | Add `fips` as the 8th workflow; move `fips`/`140-2`/`140-3` out of `crypto` and prioritize `fips` in `IntentRouter.classify()` tie-breaking; pass deterministic `-e artifacts/pick-up/<timestamp>_fips` when chaining `./grc report -e`; update `test_grc_bot.py` to expect 8 workflows and validate multi-command flags per subcommand. |
| **M6** | xBOT silently picks release tag / bundle | **Accepted with Safeguards** | `GRC-xBOT/scripts/grc_bot.py` | Use semantic version sorting (`v2.0.0 > v1.5.0 > v1.0.0`) via a new sibling helper while keeping `parse_bundle_heads_output()` backward compatible; prompt interactively in `chat`; in non-interactive `ask`/`guide`, default to highest semver tag while prominently listing skipped tags (`v1.0.0`, `v1.5.0`). |
| **H5** | `crypto` vs. `fips` disagreement on same dependency | **Accepted + Reporter Fix** | `GRC-xMINI/scripts/crypto_lib_scan.py`<br>`GRC-xMINI/rules/crypto_catalog.json`<br>`GRC-xMINI/scripts/grc_reporter.py` | Score `bc-fips 1.0.2.x` at `MEDIUM` (Historical CMVP #3673), suppress already-met upgrade clauses (`golang.org/x/crypto 0.17.0`, `bc-fips 2.0.0`), state manifest-only scope in `./grc crypto`, **and** update `grc_reporter.py` so `FIPSDiscovery` `PASS`/`FAIL` verdicts supersede `CryptoScan` manifest-only `CANNOT_DETERMINE_STATICALLY` verification items in `./grc scan all`. |
| **H7** | Approved-mode OE matched workspace-wide | **Challenged ("Choose One" Rejected)** | `GRC-xMINI/scripts/fips_discovery.py`<br>`GRC-xTEST/scenarios/kestrelbridge/releases/v2.0.0/gateway/Dockerfile`<br>KestrelBridge bundles | Scope `Dockerfile` base-image and PyPI wheel vs. system OpenSSL linkage checks strictly to the owning component directory while preserving `appliance/rootfs/etc/` as appliance-level OE evidence. **Reject** the `0/0/1/30` baseline option (it breaks `M2 v2` by flipping `v2.0.0` to `NEEDS REVIEW`); **require** updating `v2.0.0/gateway/Dockerfile` and rebuilding bundles so `v2.0.0` stays `0/0/0/31` (`COMPLIANT`). |
| **M1** | Missing `--fail-on` CI exit gate | **Accepted with Clarification** | `GRC-xMINI/scripts/fips_discovery.py` | Add `--fail-on {FAIL,NEEDS_REVIEW,never}` (default `never`); `NEEDS_REVIEW` triggers on `FAIL`, `WARN`, `NEEDS_REVIEW`, and `CANNOT_DETERMINE_STATICALLY`; document that `./grc scan` preserves `\|\| true` before report synthesis. |
| **M3** | `<bundle-stem>@<ref>` naming & `checked_out_ref` | **Modified** | `GRC-xMINI/rules/finding_schema.json`<br>`GRC-xMINI/scripts/grc_common.py`<br>`GRC-xMINI/scripts/grc_bundle.py`<br>`GRC-xMINI/scripts/fips_discovery.py`<br>`GRC-xMINI/grc` | Allow `target.checked_out_ref` in schema validator **first**; normalize Git's raw `HEAD -> main, tag: ...` string to a clean ref token in `grc_bundle.py`; permit `@` in target slugs in both `fips_discovery.py` and `GRC-xMINI/grc`. |
| **M4** | Untrusted workspace `fips_provenance.json` | **Accepted & Expanded** | `GRC-xMINI/scripts/fips_discovery.py`<br>`GRC-xMINI/grc` | Stop reading `fips_provenance.json` from the audited workspace in `_target_metadata()`, exclude provenance JSON files from scanning, **and** remove lines 218–220 of `GRC-xMINI/grc` that copied `${RESOLVED_WORKSPACE}/fips_provenance.json` into `${RESOLVED_EVIDENCE}/`. |
| **M5** | `checksum_verified` defaults `True` when unchecked | **Accepted with Clarification** | `GRC-xMINI/scripts/grc_bundle.py` | Emit `"checksum_verified": null` and `"checksum_status": "NOT_CHECKED"` when `--expected-sha256` is omitted, while keeping `"git_bundle_valid": true` visible alongside it. |
| **M7** | `./grc scan` without Docker & `--host-only` | **Challenged & Modified** | `GRC-xMINI/grc` | Check Docker **before** `mkdir -p "${RESOLVED_EVIDENCE}"` with platform-neutral error `"Please start the Docker daemon"`. **Reject** silent automatic fallback on `./grc scan all` (fail-closed violation); add explicit `--host-only` running `crypto` + `fips`, and run `sbom` only if `sbom.cdx.json` already exists. |
| **M8** | Same-second evidence folder collision | **Modified** | `GRC-xMINI/scripts/fips_discovery.py` | Append collision suffixes (`_2`, `_3`, etc.) **only** when `-e` / `--evidence` was omitted and the auto-generated folder exists, so explicit `-e` multi-engine runs continue working. |
| **Priority 6** | `docs/fips_discovery-guide.md` & scenario/bot docs | **Accepted** | `GRC-xMINI/docs/fips_discovery-guide.md`<br>`GRC-xTEST/scenarios/kestrelbridge/README.md`<br>`GRC-xBOT` docs | Apply all table updates after code changes settle (`[y/N]` prompts, `WARN` reserved, `--fail-on`, `--allow-empty`, `files_inspected`, `<bundle-stem>@<ref>` UTC naming, KestrelBridge-only workflow, `GRC-xBOT` `fips` workflow). |
| **Priority 7** | CLI help, path redaction, sealing, severity | **Modified** | `GRC-xMINI/grc`<br>`GRC-xMINI/scripts/fips_discovery.py`<br>`GRC-xMINI/scripts/grc_bundle.py`<br>`GRC-xMINI/scripts/crypto_lib_scan.py`<br>`GRC-xMINI/scripts/grc_reporter.py`<br>`GRC-xBOT/playbooks/workflows.json` | Route `--help`/`-h` to usage (`exit 0`); store repo-relative/basename paths without breaking `grc` or `grc_reporter.py`; document/suffix `Z` for UTC; seal `./grc crypto --output` folders with `sha256sum` **only** inside dedicated `artifacts/pick-up/<run>/` dirs; align engine counts; recommend `HIGH / CAT II` (30-day SLA) for confirmed FIPS boundary `FAIL` findings pending explicit owner sign-off. |

---

## 2. Priority 1 — False-Clean Evidence (`H1`, `H2`, `H3`, `M2`)

### `H1`: Bundle Restore Succeeds on an Empty Checkout
* **Decision:** **Accepted with Safeguards**
* **Final Implementation Requirements:**
  1. In `GRC-xTEST/scenarios/kestrelbridge/build_bundle.sh` (lines 58 and 87), include `HEAD` in both `git bundle create` invocations (`git bundle create "$FILE" HEAD main --tags`) and regenerate all four KestrelBridge bundles (`kestrelbridge-v1.0.0.bundle`, `kestrelbridge-v1.5.0.bundle`, `kestrelbridge-v2.0.0.bundle`, `kestrelbridge-fips.bundle`).
  2. In `GRC-xMINI/scripts/grc_bundle.py` (`restore_bundle`, lines 201–292), inspect commit hash and tracked working-tree files (`git ls-files`) immediately after cloning/checking out. If `commit_hash == "UNKNOWN"` or `0` tracked files exist:
     * Clean up the failed partial workspace / `.git` directory before raising an error so subsequent retries do not fail waiting for `--force`.
     * Do **not** write `bundle_provenance.json` with `"status": "RESTORED"`.
     * Print the available bundle refs (`git bundle list-heads`) and a `--ref <tag>` remediation hint, then exit non-zero.
  3. Whenever a multi-tag bundle (such as `kestrelbridge-fips.bundle`) is restored via `HEAD` without `-r` / `--ref`, emit a prominent warning naming the skipped tags (for example `v1.0.0` and `v1.5.0`) so an analyst does not mistake `HEAD` (`v2.0.0`, `COMPLIANT`) for an audit of every release in the packfile.
  4. Add an automated regression test in `GRC-xMINI/testing/` attempting to restore a synthetic `HEAD`-less bundle without `--ref` and asserting a non-zero exit code and clean failure behavior.

### `H2`: Running `./grc fips` Accepts a File as the Workspace
* **Decision:** **Accepted & Expanded**
* **Final Implementation Requirements:**
  1. Replace `if not ws.exists():` in `GRC-xMINI/scripts/fips_discovery.py` (`main()`, line 3272) with a directory check (`ws.is_dir()`). When given a `.bundle` file, emit `[FATAL]` with the `./grc bundle restore` instruction and exit `1` without writing to `artifacts/pick-up/`.
  2. Mirror the exact same `is_dir()` check and `.bundle` restore hint in `GRC-xMINI/scripts/crypto_lib_scan.py` (`main()`, line 1614), which shares the same vulnerability when invoked via `./grc crypto -w <file.bundle>`.

### `H3`: Zero Files Inspected Reported as a Clean Result
* **Decision:** **Modified (Schema + Stream Separation Required)**
* **Final Implementation Requirements:**
  1. **Schema first:** Update `GRC-xMINI/rules/finding_schema.json`, `GRC-xMINI/rules/finding_schema.example.json`, and `GRC-xMINI/scripts/grc_common.py` (`validate_finding_envelope()`, line 491) to allow an optional `files_inspected` object inside `scope` before emitting it in `fips_discovery.py`. Without this update, `additionalProperties: false` raises `ValueError: Internal schema invariant violation in FIPSDiscovery`.
  2. Count and record files inspected across the five cryptographic surfaces (Python source, polyglot source, dependency manifests, deploy/IaC, OS config) plus total workspace files in `fips_findings.json` (`scope.files_inspected`), `fips_provenance.json`, terminal preview output, and `fips_assessment.md`.
  3. Distinguish a **completely empty directory** (`0` total workspace files—broken mount or failed restore) from a **non-empty workspace with `0` FIPS-assessable files** (e.g., pure documentation or non-crypto shell repo). Replace the clean-result sentence with `"No assessable files found"` whenever `0` assessable files are inspected, and add `--allow-empty` to control non-zero exit behavior in standalone `./grc fips` runs (noting that `./grc scan` wraps `run_fips_engine` with `|| true`).
  4. Route all empty-workspace warnings strictly to `sys.stderr` (never `stdout`) so `--format json`, `sarif`, and `cbom` streams piped into `jq` remain valid JSON.

### `M2 (v2)`: POA&M Posture on Empty Workspace vs. KestrelBridge `v2.0.0`
* **Decision:** **Modified (Protect Other 8 Engines & Existing Tests)**
* **Final Implementation Requirements:**
  1. Preserve `"COMPLIANT (Clean Out-of-Band Audit)"` for KestrelBridge `v2.0.0` (`0 FAIL`, `0 NEEDS_REVIEW`, `0 CANNOT_DETERMINE_STATICALLY`, `31 PASS`) and all populated clean runs.
  2. Add the additive `"Engines Run"` header line to `poam_data.md` without altering the posture badge.
  3. In `GRC-xMINI/scripts/grc_reporter.py` (lines 1298–1305), emit `"NOT ASSESSED (No Assessable Files Found)"` **only** when `FIPSDiscovery` reported `0` inspected files **and** no other loaded scanner contributed valid findings or evidence. Never default missing file-count metadata from the other eight engines (Semgrep, Gitleaks, Checkov, Grype, Trivy, OpenSCAP, CryptoScan, SBOM) to `0`, so multi-engine scans and standalone unit tests in `GRC-xMINI/testing/test_code_review_regressions.py` do not break.

---

## 3. Priority 2 — Broken Regression Harness (`H6`)

### `H6`: `verify_pipeline.sh` Fails with Versioned KestrelBridge Bundles Present
* **Decision:** **Accepted with Safeguards (Dynamic Refs, Dedup, Temp Isolation)**
* **Final Implementation Requirements:**
  1. Update `GRC-xTEST/scripts/verify_pipeline.sh` (lines 58–94) to dynamically resolve refs from `git bundle list-heads` per bundle (preferring tags, and iterating `v1.0.0`, `v1.5.0`, and `v2.0.0` on `kestrelbridge-fips.bundle`) instead of hard-coding `--ref v1.0.0`.
  2. Replace fixed text such as `"12 bundles"` with the dynamic count of processed bundles (`16` total: 12 AOC bundles + 4 KestrelBridge bundles).
  3. Run `fips_discovery.py --format json` for each KestrelBridge tag and assert exact determination counts (`FAIL / NEEDS_REVIEW / CANNOT_DETERMINE_STATICALLY / PASS`):
     * `v1.0.0`: `31 / 0 / 0 / 1`
     * `v1.5.0`: `6 / 2 / 1 / 17`
     * `v2.0.0`: `0 / 0 / 0 / 31`
  4. In the Docker container loop (`[5/5]`, lines 129–143):
     * Resolve refs dynamically.
     * Avoid executing all 10 heavyweight Docker scanners twice over identical KestrelBridge snapshots (`kestrelbridge-fips.bundle` tags vs. the 3 single-version bundles)—either audit the 3 tags once or run `--fips` on the redundant single-version bundles.
     * Pass a temporary `-e "${TMP_WS}/evidence_..."` directory so running `verify_pipeline.sh` does not dump test artifacts into `GRC-xMINI/artifacts/pick-up/`.

---

## 4. Priority 3 — `GRC-xBOT` FIPS Workflow (`H4`, `M6`)

### `H4`: Dedicated `fips` Workflow in `GRC-xBOT`
* **Decision:** **Accepted with 3 Code/Test Fixes**
* **Final Implementation Requirements:**
  1. Add `fips` as the 8th workflow in `GRC-xBOT/playbooks/workflows.json` and integrate it into `GRC-xBOT/scripts/grc_bot.py` (`CommandPlanner`, interactive chat menu, `guide <workflow>`, and startup banner workflow count).
  2. Move `"fips"`, `"140-2"`, and `"140-3"` from `crypto` to `fips` (and add `"cmvp"`, `"cbom"`, `"approved mode"`), leaving `eol`, `aoc-09`, and library names on `crypto`. In `IntentRouter.classify()` (lines 290–320), adjust contextual boosts and break tie scores in favor of `"fips"` when FIPS-specific terms appear so queries containing both `"bundle"`, `"crypto"`, and `"fips"` do not route to `"bundle"` or `"crypto"`.
  3. Preview command: `restore ... --ref <ref> --force --read-only && ./grc fips -w ./ephemeral_workspace --dry-run ; clean`. Production command: generate an explicit deterministic `-e artifacts/pick-up/<timestamp>_fips` path inside `CommandPlanner` and pass that exact `-e` argument to both `./grc fips` and `./grc report -e` (when report generation is included).
  4. Update `GRC-xBOT/testing/test_grc_bot.py`: update the expected workflow count from `7` to `8`, and extend `test_planner_flags_against_contract_and_live_xmini_when_present()` (lines 502–569) so multi-command plans validate `bundle` flags against `grc_bundle.py`, `fips` flags against `fips_discovery.py`, and `report` flags against `grc_reporter.py`.

### `M6`: Multi-Tag & Multi-Bundle Disclosure
* **Decision:** **Accepted with Safeguards (Semver Sort + Explicit Disclosure)**
* **Final Implementation Requirements:**
  1. Sort bundle version tags using semantic version parsing (so `v2.0.0 > v1.10.0 > v1.5.0 > v1.0.0`, avoiding ASCII lexicographic mistakes).
  2. Add a sibling helper (e.g., `list_bundle_refs()`) while keeping `parse_bundle_heads_output()` backward compatible for existing unit tests in `test_grc_bot.py`.
  3. Surface all available tags and staged bundles in Live Context; prompt the operator to choose in interactive `chat` mode; in non-interactive `ask`/`guide` mode, select the highest semantic version tag / newest bundle while prominently listing skipped alternatives (`v1.0.0`, `v1.5.0`) and clarifying that earlier tags were not assessed.

---

## 5. Priority 4 — Engine Consistency & `PASS` Quality (`H5`, `H7`)

### `H5`: Crypto and FIPS Engines Disagree on the Same Dependency
* **Decision:** **Accepted + Reporter Deduplication Fix**
* **Final Implementation Requirements:**
  1. In `GRC-xMINI/scripts/crypto_lib_scan.py` and `GRC-xMINI/rules/crypto_catalog.json`:
     * Make `bc-fips 1.0.2.x` version-aware (`MEDIUM`, Historical CMVP `#3673`) rather than emitting `INFO`.
     * Suppress or reword version-upgrade clauses in remediation strings when the installed dependency already meets `min_supported_version` (e.g., `golang.org/x/crypto 0.17.0`, `bc-fips 2.0.0`).
     * Explicitly state in `./grc crypto` output that it assesses manifest/binary validation status only and recommends `./grc fips` for approved-mode evaluation.
  2. **Crucial `grc_reporter.py` fix:** Update `GRC-xMINI/scripts/grc_reporter.py` (`_ingest_schema_envelope` lines 767–794, `parse_crypto_scan` lines 889–911, `_deduplicate_findings` lines 1204–1260) to reconcile `self.verification_items` as well as `self.findings`. When `fips_findings.json` is loaded in the same evidence directory, concrete `PASS` or `FAIL` verdicts from `FIPSDiscovery` must supersede manifest-only `CANNOT_DETERMINE_STATICALLY` / `NEEDS_REVIEW` entries emitted by `CryptoScan` for the same dependency and manifest location—otherwise `./grc scan all` on `v2.0.0` would falsely flip from `COMPLIANT` to `NEEDS REVIEW`.

### `H7`: Approved-Mode Evidence Matched Workspace-Wide
* **Decision:** **Challenged ("Choose One" Rejected; `v2.0.0/gateway/Dockerfile` Fix Required)**
* **Final Implementation Requirements:**
  1. In `GRC-xMINI/scripts/fips_discovery.py` (`_scan_dockerfile` ~line 1481, `fips-cfg:container-fips-base-image` ~line 2009, CMVP mapping ~lines 2597–2607), scope container `Dockerfile` base-image matching and Python PyPI wheel vs. system OpenSSL checks strictly to the component directory tree owning the manifest—so an unrelated `docs-site/Dockerfile` cannot promote `gateway/requirements.txt` `cryptography` to `PASS`.
  2. Keep `appliance/rootfs/etc/` host configs (`/etc/pki/tls/openssl.cnf`, `/etc/crypto-policies/config`, `/etc/default/grub`) eligible as deployment/appliance-level Operational Environment evidence because `appliance/rootfs/` is a sibling directory of `gateway/`, `partner-client/`, and `signer/`, not a strict directory ancestor.
  3. **Reject the `0/0/1/30` option:** Leaving `v2.0.0/gateway/Dockerfile` on plain PyPI `pip install` would force `v2.0.0` to `0/0/1/30`, setting `verify_count = 1` in `grc_reporter.py` and breaking `M2 (v2)` by turning `v2.0.0` into `NEEDS REVIEW`. Therefore, **update `GRC-xTEST/scenarios/kestrelbridge/releases/v2.0.0/gateway/Dockerfile`** (installing `python3-cryptography` via `dnf` or building with `--no-binary cryptography` against UBI 9 system OpenSSL `CMVP #4857`) and rebuild all affected bundles so `v2.0.0` legitimately remains at `0 FAIL / 0 NEEDS_REVIEW / 0 CANNOT_DETERMINE_STATICALLY / 31 PASS` (`COMPLIANT`). *(See Section 8 — Owner Confirmations for final confirmation of this synthetic fixture edit.)*

---

## 6. Priority 5 — Provenance & Process Hardening (`M1`, `M3`, `M4`, `M5`, `M7`, `M8`)

| ID | Final Implementation Decision |
| :--- | :--- |
| **M1 (`--fail-on`)** | Add `--fail-on {FAIL,NEEDS_REVIEW,never}` (default `never`) to `fips_discovery.py`. Selecting `NEEDS_REVIEW` exits non-zero on `FAIL`, `WARN`, `NEEDS_REVIEW`, or `CANNOT_DETERMINE_STATICALLY`. Document that `./grc scan` preserves `\|\| true` before report generation. |
| **M3 (`<bundle-stem>@<ref>` & `checked_out_ref`)** | Update `GRC-xMINI/rules/finding_schema.json` and `GRC-xMINI/scripts/grc_common.py` (`validate_finding_envelope()`, line 477) to permit `target.checked_out_ref`. Normalize Git's raw `HEAD -> main, tag: ...` output in `grc_bundle.py` to a clean ref token. Permit `@` in slug sanitizers across both `fips_discovery.py` (line 3316) and `GRC-xMINI/grc` (lines 191–198) so `./grc fips` and `./grc scan fips` produce matching `<bundle-stem>@<ref>` names. |
| **M4 (Untrusted workspace provenance)** | Stop reading `fips_provenance.json` from the audited workspace inside `fips_discovery.py` (`_target_metadata`), exclude `bundle_provenance.json`, `ami_provenance.json`, and `fips_provenance.json` from FIPS scanning, **and** remove lines 218–220 from `GRC-xMINI/grc` that copied `${RESOLVED_WORKSPACE}/fips_provenance.json` into `${RESOLVED_EVIDENCE}/`. |
| **M5 (`checksum_verified`)** | In `GRC-xMINI/scripts/grc_bundle.py` (`verify_bundle`, line 166), emit `"checksum_verified": null` and `"checksum_status": "NOT_CHECKED"` when `--expected-sha256` is omitted, while retaining `"git_bundle_valid": true`. Verify compatibility with `testing/demo-evidence/` fixtures and `grc_reporter.py`. |
| **M7 (Docker-less `./grc scan`)** | **Reject silent automatic fallback** on `./grc scan all` (silently skipping 7–8 container scanners breaks fail-closed integrity). Check Docker **before** running `mkdir -p "${RESOLVED_EVIDENCE}"` in `GRC-xMINI/grc` (lines 209/229) using platform-neutral text (`"Please start the Docker daemon"`). Add an explicit opt-in `--host-only` flag that runs host-native `crypto` + `fips`, and runs `sbom` only if `sbom.cdx.json` already exists (since Syft requires Docker). |
| **M8 (Folder collision)** | In `fips_discovery.py`, append collision suffixes (`_2`, `_3`, etc.) **only** when `-e` / `--evidence` was omitted and the auto-generated folder already exists—never block explicit `-e` evidence directories used by multi-stage `./grc scan` pipelines. |

---

## 7. Priority 6 (Documentation) & Priority 7 (Polish)

### Priority 6 — Documentation Synchronization (Apply Last, After Code Lands)
* Update `GRC-xMINI/docs/fips_discovery-guide.md` once all code changes above are complete:
  * Fix interactive chat approval hints from `[p]` / `[y]` to `[y/N]`.
  * Mark `WARN` explicitly as "reserved" in Section 1.2 (since no rule currently emits `WARN`), and reconcile Section 1.2's PASS criteria with `H7`.
  * Document `<bundle-stem>@<ref>` default evidence naming and UTC timestamps, `--fail-on`, `--allow-empty`, `scope.files_inspected`, updated `H2` `[FATAL]` error text, and the new `GRC-xBOT` `fips` workflow.
  * Update Section 4 command walkthroughs (adding KestrelBridge-only paths where AOC fixtures were assumed, and updating `-r` instructions once `H1` bundles carry `HEAD`).
* Update `GRC-xTEST/scenarios/kestrelbridge/README.md` (`gateway/Dockerfile` linkage details under `H7` while keeping `v2.0.0` at `0/0/0/31`) and `GRC-xBOT` documentation (`README.md`, `QUICK_REFERENCE.md`) for the 8th `fips` workflow.

### Priority 7 — Polish Decisions
1. **CLI Help (`GRC-xMINI/grc`, line 323):** Route `./grc --help` and `./grc -h` to usage help (`exit 0`) instead of `"Unknown GRC pipeline command"`.
2. **Host Path Redaction (`fips_discovery.py` line 3150, `grc_bundle.py` lines 268, 271):** Replace absolute local paths (`workspace_path`, `bundle_source_path`) with repo-relative paths or basenames while verifying `GRC-xMINI/grc` (line 191) and `grc_reporter.py` (line 1280) handle relative/basename values cleanly.
3. **UTC Folder Timestamps:** Document UTC clearly (and/or suffix `Z` consistently) without breaking `IntentRouter`/folder parsers.
4. **Sealing `./grc crypto --output` (`crypto_lib_scan.py`):** Write a directory-wide `sha256sum` seal **only** when `--output` targets a dedicated directory under `artifacts/pick-up/` (or write a single-file `.sha256` sidecar when `--output` targets shared paths such as `/tmp/` or repo root) so `crypto_lib_scan.py` never attempts to hash unrelated files in `/tmp` or the repo root.
5. **Engine Count Alignment (`GRC-xBOT/playbooks/workflows.json`, line 204):** Synchronize engine descriptions across `GRC-xBOT` and `GRC-xMINI` (`"all 10 compliance engines"` vs. `"8 engines"`).
6. **Confirmed FIPS Boundary Severity (`grc_reporter.py`):** Recommend promoting confirmed FIPS 140-3 boundary failures (`AOC-03`/`AOC-09`/`AOC-12` `FAIL`, unvalidated algorithms such as ChaCha20 or unvalidated libraries) from `MEDIUM / CAT III` (90-day SLA) to `HIGH / CAT II` (30-day SLA) per NIST SP 800-53 `SC-13` / `IA-7` and DISA ASD STIG, while keeping `NEEDS_REVIEW` and `CANNOT_DETERMINE_STATICALLY` outside POA&Ms in Section 4 (`Needs Human or Runtime Verification`). *(Deferred pending owner confirmation—see Section 8.)*

---

## 8. Owner Confirmations, Out-of-Scope Gaps & Final Verification Gate

### Two Explicit Owner Policy Confirmations Before Editing
1. **`H7` / `M2 (v2)` Resolution:** Confirm updating `GRC-xTEST/scenarios/kestrelbridge/releases/v2.0.0/gateway/Dockerfile` (e.g., `dnf install -y python3-cryptography` or `PIP_NO_BINARY=cryptography`) and rebuilding the bundles so `v2.0.0` stays legitimately at `0/0/0/31` (`COMPLIANT`).
2. **Priority 7 Severity Policy (`grc_reporter.py`):** Confirm whether confirmed FIPS boundary `FAIL` findings (`SC-13` / `IA-7`) should move from `MEDIUM / CAT III` (90-day SLA) to `HIGH / CAT II` (30-day SLA), or stay `MEDIUM` to preserve existing POA&M test fixtures.

### Known KestrelBridge `v1.0.0` Detection Gaps (Deferred — Feature Work Only)
Per `KESTRELBRIDGE_FIPS_REVIEW_v2.md` and `scenarios/kestrelbridge/README.md`, the following three planted flaws in `v1.0.0` are **not** part of this remediation pass (adding rules for them will raise `v1.0.0` above `31 FAIL` and require updating baseline tables across all three repos simultaneously):
* `random.getrandbits()` DEK generation (`gateway/kestrelbridge/envelope.py:15`)
* `Signature.getInstance("SHA1withRSA")` (`signer/.../ManifestSigner.java:16`)
* RSA-OAEP with SHA-1 / MGF1-SHA-1 (`gateway/kestrelbridge/envelope.py:33`)

### Required Verification Gate After Implementation
1. `./grc test all` (`GRC-xMINI`) and `./grc-bot test` (`GRC-xBOT`) pass with updated schema, reporter, and multi-command flag tests.
2. `GRC-xTEST/scripts/verify_pipeline.sh` exits `0` across all `16` bundles, asserts KestrelBridge counts (`31/0/0/1`, `6/2/1/17`, `0/0/0/31`), deduplicates Docker `[5/5]` scans, and leaves `GRC-xMINI/artifacts/pick-up/` clean.
3. Restoring each of the 4 KestrelBridge bundles without `-r` either checks out its expected commit cleanly or exits non-zero with partial workspace cleanup; `./grc fips -w <file.bundle>` and `./grc crypto -w <file.bundle>` fail cleanly with restore instructions; `./grc fips -w <empty dir>` fails on empty directories and prints warnings strictly to `stderr`.
4. `./grc scan all` on `v2.0.0` preserves `COMPLIANT (Clean Out-of-Band Audit)` (verifying `H5`'s `grc_reporter.py` fix), while Docker-down `./grc scan` fails fast before creating unsealed folders unless `--host-only` is passed.
5. `./grc-bot ask "FIPS 140-3 check on the staged bundle"` routes cleanly to the `fips` workflow, names the selected semver tag and skipped alternatives, and produces a valid preview/live command sequence.
