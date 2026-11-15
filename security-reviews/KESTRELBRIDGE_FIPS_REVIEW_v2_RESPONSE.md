# Critical Triad Review of the KestrelBridge FIPS Dry-Run Report (Version 2)

**Document Purpose:** Three-Role Architectural, Engineering, and Compliance Challenge  
**Source Reviewed:** `GRC-xMINI/security-reviews/KESTRELBRIDGE_FIPS_REVIEW_v2.md` (dated November 15, 2026)  
**Repositories Audited:** `GRC-xMINI` (commit `fed7813`), `GRC-xBOT` (commit `79cc8df`), and `GRC-xTEST` (commit `aa3593d`) plus the KestrelBridge scenario and guides  
**Format Note:** Written as a spoken roundtable transcript formatted for audio listening via Speechify.

---

## Cast of Reviewers

Three domain specialists are reviewing every recommendation in the Version 2 dry-run report before a single line of code changes.

* **Software Developer / Designer:** Focuses on the Python standard-library codebase, schema validators, CLI flag contracts, shell wrappers, Git bundle internals, and automated unit test invariants.
* **Cybersecurity Architect:** Focuses on FIPS 140-3 cryptographic module boundaries, Operational Environment alignment, fail-closed versus fail-open design, and untrusted repository attack surfaces.
* **GRC Engineer:** Focuses on NIST SP 800-53 Revision 5 control rollups, FedRAMP High POA&M lifecycles, CMVP validation versus control compliance, 3PAO audit defensibility, and the three-stage narrative of the KestrelBridge demo.

---

## Opening Remarks: Setting the Ground Rules

**GRC Engineer:** Welcome, everyone. We just received Version 2 of the KestrelBridge FIPS dry-run review. Before we treat it as an unquestioned engineering backlog, we need to interrogate every single recommendation the same way we just challenged Version 1's M2 finding. Remember, in Version 1, the review wanted us to stop printing "COMPLIANT" on KestrelBridge version 2.0.0 even though version 2.0.0 was explicitly built to represent the remediated, clean end state of the demo. Version 2 fixed that headline contradiction, which proves why challenging these recommendations is worth the effort. Let's walk through Version 2 from top to bottom and catch any remaining breaks in logic.

**Cybersecurity Architect:** Agreed. The dry runs caught real bugs, especially around empty checkouts and untrusted files in the workspace. My concern is where the suggested fixes either violate our security boundaries, introduce subtle schema or test regressions, or contradict other parts of the very same document.

**Software Developer / Designer:** I went through the actual scripts across GRC-xMINI, GRC-xBOT, and GRC-xTEST while reading Version 2. The bottom line is that almost every priority area contains either a hidden breaking assumption, a cross-repo interaction the review overlooked, or an internal contradiction between two tasks. Let's examine them in priority order.

---

## Section 1: Priority 1 — False-Clean Evidence (`H1`, `H2`, `H3`, and `M2`)

### Finding `H1`: Bundle Restore Succeeds on an Empty Checkout

**Software Developer / Designer:** On `H1`, the core bug report is spot-on. When we created the KestrelBridge bundles in `GRC-xTEST/scenarios/kestrelbridge/build_bundle.sh`, both `git bundle create` commands passed `main` and `--tags`, omitting `HEAD`. By contrast, the main `scripts/build_bundles.sh` passes `HEAD v1.0.0`. Because `grc_bundle.py`'s `restore_bundle` method only runs `git checkout` when the caller supplies the `--ref` flag, cloning a bundle that has no `HEAD` checks out zero working files, logs an `UNKNOWN` commit hash, writes `bundle_provenance.json` with status `"RESTORED"`, and exits zero.

**GRC Engineer:** That is a severe audit integrity failure. An auditor runs restore without a reference flag, sees success, runs the FIPS engine, and gets zero findings on a release that actually has 31 failures. Fixing `build_bundle.sh` to include `HEAD` and making `restore_bundle` fail when the commit hash is `UNKNOWN` or zero tracked files exist are both essential.

**Cybersecurity Architect:** Wait—look closely at the side effect of adding `HEAD` to the multi-tag bundle, `kestrelbridge-fips.bundle`. On the three single-version bundles, `HEAD` unambiguously points to that bundle's single release. On the multi-tag bundle, `HEAD` points to `main`, which matches tag `v2.0.0`—zero failures, 31 passes. If an analyst restores `kestrelbridge-fips.bundle` without `--ref` thinking they are scanning the product's history, `restore_bundle` will quietly check out `v2.0.0` (`COMPLIANT`) without mentioning that `v1.0.0` with 31 failures and `v1.5.0` with 6 failures also exist in that packfile. So in addition to failing on empty checkouts, `restore_bundle` should print a prominent warning whenever a bundle holds multiple tags and the user omitted `--ref`.

**Software Developer / Designer:** There is a second engineering bug in `H1` as written. Look at the execution order in `restore_bundle`: it runs `self.workspace_root.mkdir()` and `git clone` first, and only gathers `commit_info` afterward. If we raise an error when `commit_hash` equals `UNKNOWN` and fail without cleaning up, we leave a broken `.git` folder inside the workspace directory. The next time the user tries restoring with a valid `--ref`, it will fail unless they pass `--force`. When `restore_bundle` rejects an empty or `UNKNOWN` checkout, it needs to remove the failed partial directory before exiting non-zero.

**Consensus Verdict on `H1`:** Accept the core fix, but clean up the partial clone directory on failure and warn loudly whenever a multi-tag bundle is restored via `HEAD` without an explicit `--ref`.

---

### Finding `H2`: Running `grc fips` Accepts a File as the Workspace

**Cybersecurity Architect:** On `H2`, `fips_discovery.py`'s `main` function checks `ws.exists()`, not `ws.is_dir()`. Passing a `.bundle` file directly to `--workspace` passes existence, scans nothing, and writes seven sealed deliverables reporting zero findings. Requiring `ws.is_dir()` and printing a fatal hint to run `./grc bundle restore` when given a `.bundle` file is completely sound.

**Software Developer / Designer:** Notice what Version 2 missed, though: `crypto_lib_scan.py` (`./grc crypto`) has the exact same `if not workspace_path.exists():` check in its `main` function at line 1614. If an analyst passes `kestrelbridge-fips.bundle` to `./grc crypto -w`, it will silently scan zero files and output a clean result just like `fips_discovery.py` did. We should apply the identical `is_dir()` guard and bundle hint to both `fips_discovery.py` and `crypto_lib_scan.py`.

**Consensus Verdict on `H2`:** Accept, and mirror the exact `is_dir()` check into `crypto_lib_scan.py`.

---

### Finding `H3`: Zero Files Inspected Reported as a Clean Result

**Software Developer / Designer:** Now let's challenge `H3` hard, because there are **three separate breaks in logic** hidden inside it. First, `H3` instructs us to put the broken-down counts of inspected files inside the `scope` object of `fips_findings.json`. However, `fips_discovery.py` validates every JSON envelope with `validate_finding_envelope()` in `grc_common.py`, which enforces `additionalProperties: false` from `rules/finding_schema.json`. Currently, `scope` strictly permits only four keys: `assessed_controls`, `assessed_aocs`, `ecosystems`, and `limitations`. If we drop a `files_inspected` object into `scope` without updating both `rules/finding_schema.json` and `grc_common.py`, `build_envelope()` will throw a `ValueError` and crash on every single run.

**Cybersecurity Architect:** Here is the second break in logic. `H3` asks `fips_discovery.py` to exit non-zero whenever zero assessable files are found unless `--allow-empty` is passed. Think about what happens in two real scenarios: first, during `./grc scan all` against a documentation-only repo or an Ansible-only IaC bundle where Semgrep, Gitleaks, or Checkov find plenty of issues, but zero files match the five FIPS crypto surfaces. Notice also that in `GRC-xMINI/grc` line 263, `run_fips_engine` ends with `|| true`, so a non-zero exit code from `fips_discovery.py` is swallowed inside `./grc scan` anyway.

**GRC Engineer:** There is an important audit distinction between **zero total files in the workspace** (a completely empty folder from a broken mount or failed bundle restore) and **non-zero total files with zero FIPS-assessable files** (for example, a pure shell or documentation bundle). An empty directory should fail hard as a broken target. A non-empty workspace with zero crypto-relevant files is an "out of FIPS scope" condition—the report should still warn clearly and say zero FIPS-assessable files were inspected rather than claiming "no issues detected," without falsely making the whole bundle scan crash unless the caller explicitly wants that gate.

**Software Developer / Designer:** Third break in logic: `H3` prints a prominent warning on zero files, and `H6` runs `fips_discovery.py --format json` and pipes it straight into `jq`. If any warning prints to standard output instead of `stderr` while `--format json`, `sarif`, or `cbom` is active, it corrupts the JSON stream and breaks downstream automation. All warnings must go strictly to standard error.

**Consensus Verdict on `H3`:** Update `rules/finding_schema.json`, `finding_schema.example.json`, and `grc_common.py` alongside `fips_discovery.py` so `files_inspected` passes schema validation; separate total workspace files from FIPS-assessable files; send all warnings to `stderr`; and align exit behavior with `./grc scan`'s `|| true` wrapper.

---

### Finding `M2` (Version 2): POA&M Posture Says "COMPLIANT" When Nothing Was Assessed

**GRC Engineer:** Let's examine how Version 2 rewrote `M2`. I appreciate that Version 2 retracted Version 1's mistake and explicitly locked in that KestrelBridge `v2.0.0` must keep the posture `"COMPLIANT (Clean Out-of-Band Audit)"`. That preserves the entire three-act demo arc from Non-Compliant (`v1.0.0`) to Needs Review (`v1.5.0`) to Compliant (`v2.0.0`).

**Software Developer / Designer:** Even in Version 2, though, the implementation rule written for `M2` has a major multi-engine bug. Look at what `M2` says: *"Use the files-inspected count from H3. When the count is 0 (or the evidence folder has findings files but no assessed files), set the posture to `NOT ASSESSED (No Assessable Files Found)` instead of `COMPLIANT`."* Think about how `grc_reporter.py` actually works! `grc_reporter.py` ingests up to nine different evidence files—Semgrep, Gitleaks, Checkov, Grype, Trivy, OpenSCAP, CryptoScan, FIPSDiscovery, and SBOM. **None of the other eight engines emit `H3`'s `files_inspected` count.** Worse, existing unit tests in `testing/test_code_review_regressions.py` create synthetic evidence folders with only `crypto_findings.json` or `semgrep_findings.json` and assert compliant behavior when findings are absent. If `grc_reporter.py` defaults the `files_inspected` count to zero whenever `fips_findings.json` is absent or lacks that metadata, it will falsely label clean Semgrep, Checkov, or CryptoScan runs as `NOT ASSESSED`.

**Cybersecurity Architect:** Exactly right. The check in `grc_reporter.py` must be scoped properly: report `"NOT ASSESSED (No Assessable Files Found)"` only when `FIPSDiscovery` ran and reported zero inspected files AND no other loaded scanner provided valid findings or evidence—or when every loaded scanner that reports file counts recorded zero inspected files. Never assume zero files inspected for engines that do not report file-count metadata.

**GRC Engineer:** Also note the optional `"Engines Run"` header line (`FIPSDiscovery (1 of 10)`) Version 2 suggests adding to `poam_data.md`. As an additive header line that does not alter the `"COMPLIANT (Clean Out-of-Band Audit)"` posture badge on `v2.0.0`, that is genuinely helpful for a 3PAO reviewer who wants to know which scanners contributed to the clean posture.

**Consensus Verdict on `M2` (v2):** Keep `"COMPLIANT (Clean Out-of-Band Audit)"` for `v2.0.0` and populated runs; trigger `"NOT ASSESSED (No Assessable Files Found)"` strictly when `FIPSDiscovery` reports zero inspected files with no other engine evidence present, so existing multi-engine scans and unit tests do not break.

---

## Section 2: Priority 2 — Broken Regression Harness (`H6`)

### Finding `H6`: `verify_pipeline.sh` Fails with Versioned KestrelBridge Bundles Present

**Software Developer / Designer:** `H6` is definitely a real regression in `GRC-xTEST/scripts/verify_pipeline.sh`. Right now line 66 hardcodes `--ref v1.0.0` for every `.bundle` in `bundles/`, which immediately breaks on `kestrelbridge-v1.5.0.bundle` and `kestrelbridge-v2.0.0.bundle`. And the status messages hardcode "12 bundles" even though there are now 16 bundles in that directory (12 AOC bundles plus 4 KestrelBridge bundles).

**Cybersecurity Architect:** Look at the subtle logic trap in `H6`'s third sentence, though. It says: *"iterate all three tags for `kestrelbridge-fips.bundle`. Apply the same fix to the Docker loop at lines 129 through 143."* Hold on! Think about what happens in section 5 of `verify_pipeline.sh` when Docker is running if we run all 10 containerized scanners on **every tag** of `kestrelbridge-fips.bundle` AND on all three standalone bundles (`kestrelbridge-v1.0.0.bundle`, `kestrelbridge-v1.5.0.bundle`, `kestrelbridge-v2.0.0.bundle`):
1. You execute the exact same heavyweight Docker suite (`Semgrep`, `Gitleaks`, `Checkov`, `Syft`, `Grype`, `Trivy`, `OpenSCAP`) **twice** over the identical `v1.0.0`, `v1.5.0`, and `v2.0.0` codebases—six redundant multi-container audits for one scenario!
2. Even more critically, as we established when reviewing KestrelBridge `v2.0.0`, its Terraform (`main.tf`) and Kubernetes (`gateway.yaml`) files are **FIPS-only** synthetic fixtures—they intentionally omit non-FIPS Checkov checks like Kubernetes `runAsNonRoot` or memory limits. Running `./grc scan` (which defaults to `all`, including Checkov) inside `verify_pipeline.sh` is fine as long as it doesn't falsely expect 0 non-FIPS findings, or better yet, `verify_pipeline.sh`'s Docker loop can skip repeating the exact same snapshots across both the multi-tag and standalone KestrelBridge bundles (for instance, auditing the three tags on `kestrelbridge-fips.bundle` once, or running `--fips` on the duplicate single-version bundles).

**GRC Engineer:** Agreed—and let's also watch out for the cleanup behavior of `./grc scan` inside `verify_pipeline.sh` line 138. Because `./grc scan` writes timestamped folders into `GRC-xMINI/artifacts/pick-up/`, running `verify_pipeline.sh` with Docker enabled dumps 16 or more synthetic evidence folders into the operator's `GRC-xMINI/artifacts/pick-up/` directory unless `--evidence` points to a temporary directory! Passing `-e "${TMP_WS}/evidence_${bundle_name}"` inside test scripts avoids polluting real analyst outboxes.

**Consensus Verdict on `H6`:** Resolve tags dynamically from `git bundle list-heads`, print dynamic bundle counts, add exact KestrelBridge JSON count assertions, avoid duplicating six full Docker container scans over identical snapshots, and isolate test evidence outputs to temporary directories instead of polluting `GRC-xMINI/artifacts/pick-up/`.

---

## Section 3: Priority 3 — `GRC-xBOT` FIPS Workflow (`H4` and `M6`)

### Finding `H4`: A FIPS Request Never Runs the FIPS Engine

**GRC Engineer:** The dry-run team caught a genuine operational gap here. Right now, when an analyst asks `GRC-xBOT` for a FIPS 140-3 check, `GRC-xBOT` routes them to `./grc crypto` (`crypto_lib_scan.py`), which only checks dependency manifests and leaves out all the source-code algorithms, TLS configs, and OS FIPS toggles that `./grc fips` inspects. Adding a dedicated `fips` workflow as the 8th workflow in `playbooks/workflows.json` fixes that completely.

**Software Developer / Designer:** Now let's look at the **three code-level breaks** waiting in `GRC-xBOT` if we implement `H4` naively:
1. **`IntentRouter` Score Saturation and Tie-Breaking:** Look at `GRC-xBOT/scripts/grc_bot.py` lines 290 to 320. `IntentRouter.classify()` caps confidence at `6.0` points, uses Python dictionary iteration order on ties (`max(scores, key=lambda k: scores[k])`), and gives `+3.0` contextual boosts! If `"bundle"` and `"crypto"` stay ahead of `"fips"` in `playbooks/workflows.json`, then `H4`'s own test query—*"Audit vendor-release.bundle for FIPS 140-3 mode, CMVP modules, and weak crypto"*—contains `"bundle"`, `".bundle"`, `"crypto"`, `"fips"`, `"140-3"`, and `"cmvp"`. Both `"crypto"` and `"bundle"` can score high or tie with `"fips"`! We must remove `"fips"`, `"140-2"`, and `"140-3"` from `"crypto"`'s keywords and token boost, and add a strong FIPS-first contextual boost (plus explicit tie-break priority toward `"fips"` when FIPS-specific tokens appear).
2. **Evidence Folder Mismatch Between `./grc fips` and `./grc report`:** Look at `H4`'s suggested production command: run `./grc fips -w ./ephemeral_workspace` (without `-e`), *"optionally followed by `./grc report -e <folder>`."* That is impossible unless `CommandPlanner` generates an explicit `-e artifacts/pick-up/<timestamp>_fips` path up front and passes the **same** `-e` argument to both `./grc fips` and `./grc report`. Otherwise `./grc fips` auto-generates its own timestamped slug internally at runtime, and `CommandPlanner` cannot predict the exact second in the future to pass to `./grc report`.
3. **Contract Test Failure in `test_grc_bot.py`:** Look at `GRC-xBOT/testing/test_grc_bot.py` lines 69 and 549 to 569. First, line 69 asserts `len(workflows) == 7`—obviously we update that to 8. Second, and much subtler, `test_planner_flags_against_contract_and_live_xmini_when_present()` takes **all** `--long-flags` across `preview_argv`, `live_steps`, and `cleanup_argv` and checks that **every single flag string** exists literally in one Python file (`script_map[wid]`). When `./ephemeral_workspace` does not exist, the `fips` workflow chains `./grc bundle restore ... --ref ... --force --read-only` before `./grc fips ... --dry-run`. Because `--ref` and `--read-only` live in `grc_bundle.py`—NOT `fips_discovery.py`—checking all emitted flags solely against `fips_discovery.py` will fail the unit test! Just like the `crypto` test currently works only when `ephemeral_workspace_exists: True` in line 516 of `test_grc_bot.py`, we need to make sure the test validates `bundle` flags against `grc_bundle.py`, `fips` flags against `fips_discovery.py`, and `report` flags against `grc_reporter.py`!

**Consensus Verdict on `H4`:** Implement the 8th `fips` workflow, explicitly separate `IntentRouter` scoring for `fips` vs `crypto` vs `bundle`, pass deterministic `-e artifacts/pick-up/<timestamp>_fips` paths whenever chaining `./grc report`, and update `test_grc_bot.py` to validate multi-command flags against their respective target scripts.

---

### Finding `M6`: xBOT Picks a Release Without Saying So

**Cybersecurity Architect:** `M6` asks `GRC-xBOT` to surface all tags and staged bundles instead of silently grabbing `bundles[0]` or the first tag from `parse_bundle_heads_output`. And for non-interactive `ask` or `guide` runs, `M6` instructs `GRC-xBOT` to **default to the highest version tag** and announce the alternatives. Look carefully at the audit trap here on `kestrelbridge-fips.bundle`! Its highest tag is `v2.0.0`, which has zero failures and 31 passes. If an analyst stages a multi-tag release bundle containing unaddressed legacy branches or older active releases and runs non-interactive `./grc-bot ask`, `xBOT` will preview `v2.0.0` cleanly. That is defensible for "latest release", **only** if the status banner and preview text prominently warn that multiple tags exist (listing `v1.0.0` and `v1.5.0`) and that selecting only the highest tag does not assess earlier releases! Also note that semantic version sorting (`v1.10.0` higher than `v1.2.0`) must be used rather than string sort.

**Software Developer / Designer:** Also remember `test_grc_bot.py` line 172 checks `parse_bundle_heads_output()` directly with a string return value, and line 458 tests alphabetical picking on multiple staged files. Keeping `parse_bundle_heads_output` cleanly returning the selected highest semver tag while adding a sibling helper `list_bundle_refs()` preserves backward compatibility for existing callers while giving `WorkspaceInspector` and `CommandPlanner` full visibility into all tags and staged bundles.

**Consensus Verdict on `M6`:** Implement multi-tag and multi-bundle disclosure using semver sorting, interactively prompt in `chat` mode, and explicitly warn in non-interactive mode when choosing the highest tag or newest bundle over alternatives.

---

## Section 4: Priority 4 — Engine Consistency and PASS Quality (`H5` and `H7`)

### Finding `H5`: The Crypto and FIPS Engines Disagree on the Same Dependency

**Software Developer / Designer:** Look closely at `H5` and what we found in `grc_reporter.py` that the review missed completely. First, `crypto_lib_scan.py` and `fips_discovery.py` actually **do** have legitimate differences in scope: `crypto_lib_scan.py` inspects **only** package manifests (`pom.xml`, `go.mod`, `requirements.txt`) and compiled shared objects (`libssl.so.1.1`) without looking at `java.security`, `openssl.cnf`, or Dockerfiles. On `v2.0.0`, from a pure manifest perspective, `cryptography 42.0.5` and `bc-fips 2.0.0` genuinely lack approved-mode context in `crypto_lib_scan.py`, so `CANNOT_DETERMINE_STATICALLY` makes sense *from that engine alone*—and telling the user *"validation status only; run `./grc fips` for approved-mode assessment"* is a great clarification. At the same time, marking `bc-fips 1.0.2.5` at `MEDIUM` (Historical cert #3673) instead of `INFO` fixes a genuine contradiction on `v1.0.0`.

**Cybersecurity Architect:** Wait—Look at `H5`'s complaint about `golang.org/x/crypto` in `crypto_catalog.json` line 138! `H5` criticizes `crypto_lib_scan.py` for printing *"Update golang.org/x/crypto >= v0.17.0"* when `0.17.0` is already installed. Let's check `rules/crypto_catalog.json` line 138: that whole remediation string is actually `"Update golang.org/x/crypto >= v0.17.0 (mitigating Terrapin SSH CVE-2023-48795), and ensure FIPS-regulated primitives use Go standard library 'crypto/*' with GODEBUG=fips140=only..."` Because `crypto_catalog.json` uses one static string per library family, it mentions both the CVE floor (`>= 0.17.0`) and the FIPS migration rule together—just as `bouncycastle-fips` at line 202 says *"Upgrade bc-fips to >= 2.0.0 and confirm JVM/application approved-mode enforcement."* Making `crypto_lib_scan.py` suppress or reword version-upgrade clauses when the installed version already satisfies `min_supported_version` makes the remediation text accurate across versions instead of misleading analysts.

**GRC Engineer:** Now here is the **huge downstream bug in `grc_reporter.py` that `H5` completely missed**. Look at `grc_reporter.py` `_ingest_schema_envelope` (lines 767 to 794), `parse_crypto_scan` (lines 889 to 911), and `_deduplicate_findings` (lines 1204 to 1260). `_deduplicate_findings()` deduplicates confirmed findings (`self.findings`), **but it never deduplicates or reconciles `self.verification_items`!** Think about what happens in `./grc scan all` on KestrelBridge `v2.0.0` when **both** `crypto_findings.json` and `fips_findings.json` sit in the same pick-up directory:
* `fips_discovery.py` looks at `java.security` and the UBI 9 image, confirms approved mode, and marks `bc-fips 2.0.0` and `cryptography 42.0.5` as `PASS` (`0 FAIL`, `0 NEEDS_REVIEW`, `31 PASS`).
* `crypto_lib_scan.py` looks at `pom.xml` and `requirements.txt` alone and emits `CANNOT_DETERMINE_STATICALLY` for `bc-fips 2.0.0` and `cryptography 42.0.5`.
* `grc_reporter.py` drops `PASS` from `FIPSDiscovery`, ingests both `CANNOT_DETERMINE_STATICALLY` entries from `CryptoScan` into `self.verification_items`, sets `verify_count = 2`, and flips `v2.0.0`'s Overall Audit Posture in `poam_data.md` from `"COMPLIANT (Clean Out-of-Band Audit)"` to `"NEEDS REVIEW (Human / Runtime Verification Required)"`!

**Software Developer / Designer:** What a catch! In `./grc scan all`, `v2.0.0` would literally flip from `COMPLIANT` to `NEEDS REVIEW` because `grc_reporter.py` ignores `FIPSDiscovery`'s authoritative `PASS` determinations when processing `CryptoScan`'s manifest-only `CANNOT_DETERMINE_STATICALLY` verification items! When `fips_findings.json` is loaded in the same evidence directory, `grc_reporter.py` must suppress or supersede any `CryptoScan` `CANNOT_DETERMINE_STATICALLY` / `NEEDS_REVIEW` verification item whose dependency and manifest location have already received a concrete `PASS` or `FAIL` determination from `FIPSDiscovery`.

**Consensus Verdict on `H5`:** Fix Historical `bc-fips 1.0.2.x` scoring and version-satisfied remediation phrasing in `crypto_lib_scan.py`, clarify manifest-only scope in `CryptoScan` output, AND extend `grc_reporter.py` so `FIPSDiscovery` `PASS`/`FAIL` verdicts supersede manifest-only `CryptoScan` verification items in combined `./grc scan all` runs.

---

### Finding `H7`: Approved-Mode Evidence Matched Across the Whole Workspace

**Cybersecurity Architect:** Look at `H7` carefully—this is the single biggest internal contradiction in the entire Version 2 document. `H7` correctly identifies two real security flaws in `fips_discovery.py`:
1. Any UBI 9 `Dockerfile` anywhere in the repo (even in an unrelated `docs-site/` directory) globally promotes Python `cryptography` in `gateway/` to `PASS`.
2. In `v2.0.0/gateway/Dockerfile`, Python `cryptography` is installed via plain `pip install --no-cache-dir -r requirements.txt`. Standard PyPI `cryptography` wheels bundle their own static, unvalidated OpenSSL binary rather than linking RHEL UBI 9's system FIPS OpenSSL (`CMVP #4857`), unless installed via OS packages (`dnf install python3-cryptography`) or compiled from source against system headers (`--no-binary cryptography`). So globally promoting a plain `pip install` on UBI 9 to `PASS` violates FIPS 140-3 module boundary validation!

**GRC Engineer:** Now look at the direct break in logic between `H7` and `M2 (v2)`. In `H7`, under **Baseline impact**, the review writes: *"v2.0.0 will move from 0/0/0/31 to 0/0/1/30 unless the v2.0.0 gateway Dockerfile is updated to show that evidence. Choose one."* Wait a second! In `M2 (v2)`, the review explicitly commands: *"Do not change: v2.0.0 must keep the posture COMPLIANT (Clean Out-of-Band Audit). This is the intended end state of the KestrelBridge demo."* You **cannot** choose `0/0/1/30`! Because if `v2.0.0` emits `1 CANNOT_DETERMINE_STATICALLY`, then `verify_count` in `grc_reporter.py` becomes 1, which forces `poam_data.md` to say **`NEEDS REVIEW (Human / Runtime Verification Required)`** instead of **`COMPLIANT`**, breaking both the ground rules table and `M2 (v2)`! Therefore, updating `KestrelBridge v2.0.0/gateway/Dockerfile` (for example using `dnf install -y python3-cryptography` or `PIP_NO_BINARY=cryptography`) is **mandatory**, not an option—and makes the demo genuinely stronger because the difference between `v1.5.0` and `v2.0.0` now teaches engineers *why* PyPI static wheels break UBI 9 FIPS linkage!

**Software Developer / Designer:** There is also a **second bug** in `H7`'s proposed implementation. Read the exact wording: *"Scope base-image evidence to the component that owns the manifest (same directory or the nearest ancestor containing both)."* Let's check the KestrelBridge directory tree:
* `gateway/requirements.txt` and `gateway/Dockerfile` sit together inside `gateway/`. So Dockerfile base-image scoping works cleanly for `gateway/`, and for `portal/Dockerfile` plus `portal/package.json`.
* However, `appliance/rootfs/etc/pki/tls/openssl.cnf`, `appliance/rootfs/etc/crypto-policies/config`, and `appliance/rootfs/etc/default/grub` sit under `appliance/rootfs/`—they are **siblings** of `gateway/`, `partner-client/`, and `portal/`, **not directory ancestors**! If you restrict *all* approved-mode evidence to directory ancestors, `appliance/rootfs/etc/` stops matching anything in `gateway/` or `signer/`! Make sure component scoping applies strictly to container `Dockerfile` base-image and container-local `ENV` evidence, while host/appliance `/etc/` configuration signals remain valid deployment-level Operational Environment evidence across the appliance workspace (while excluding unrelated component Dockerfiles).

**Consensus Verdict on `H7`:** Scope `Dockerfile` base-image evidence (and PyPI wheel vs. system OpenSSL checks) strictly to the owning component directory tree, keep `appliance/rootfs/etc/` as appliance-level OE evidence, and **require** updating `KestrelBridge v2.0.0/gateway/Dockerfile` (using system `python3-cryptography` or `--no-binary cryptography`) so `v2.0.0` legitimately stays at `0 FAIL / 0 NEEDS_REVIEW / 0 CANNOT_DETERMINE_STATICALLY / 31 PASS` and keeps its `COMPLIANT` posture under `M2 (v2)`.

---

## Section 5: Priority 5 — Provenance and Process Hardening (`M1`, `M3`, `M4`, `M5`, `M7`, `M8`)

**Software Developer / Designer:** Let's examine all six Medium items in Priority 5 quickly—five of them have subtle edge cases we must catch before coding.

**Cybersecurity Architect:** First, **`M1`** (`--fail-on {FAIL,NEEDS_REVIEW,never}`, default `never`). Notice two breaks:
1. Under `--fail-on NEEDS_REVIEW`, the gate should fail on **both** `NEEDS_REVIEW` and `CANNOT_DETERMINE_STATICALLY` (plus `FAIL`), because both represent unverified indeterminate conformance that requires human sign-off.
2. Remember `GRC-xMINI/grc` line 263 runs `fips_discovery.py ... || true` during `./grc scan --fips`. That means `--fail-on` works for direct `./grc fips` CI gates as specified, and we should document that `./grc scan` runs the report synthesis step regardless of finding exit status.

**Software Developer / Designer:** Second, **`M3`** (`<bundle-stem>@<ref>` naming and `checked_out_ref` metadata). Three traps here:
1. Like `H3`, `validate_finding_envelope()` in `grc_common.py` (line 477) strictly limits `target` keys to `identifier`, `provenance_file`, and `commit`. Adding `checked_out_ref` directly inside `target` of `fips_findings.json` without updating `rules/finding_schema.json` and `grc_common.py` will raise a schema crash!
2. On single-version bundles such as `kestrelbridge-v1.5.0.bundle`, `<bundle-stem>@<ref>` produces redundant names like `kestrelbridge-v1.5.0@v1.5.0`—which is acceptable for uniformity, **provided** we actually use the clean tag or ref name rather than Git's formatted `HEAD` string. In `grc_bundle.py`, when `-r` is omitted and `HEAD` is checked out cleanly, `_get_commit_metadata()` sets `ref` via `git log --format=%D`, producing a raw string like `"HEAD -> main, tag: v1.5.0"`. If `grc_bundle.py` doesn't resolve `checked_out_ref` to a clean branch/tag token first, you end up with arrows, commas, and spaces inside `checked_out_ref`.
3. In `fips_discovery.py` line 3316, the target slug sanitizer strips `@` because its regex only allows `[A-Za-z0-9._-]`. So we must explicitly permit `@` in the evidence folder slug sanitizer (and update `./grc scan`'s folder namer in `GRC-xMINI/grc` lines 191 to 198) so `./grc fips` and `./grc scan fips` use the exact same naming function!

**Cybersecurity Architect:** Third, **`M4`** (Do not trust vendor-supplied `fips_provenance.json` inside the audited workspace). Look at `GRC-xMINI/grc` lines 218 to 220! Not only does `fips_discovery.py`'s `_target_metadata()` read `fips_provenance.json` inside the workspace, **`GRC-xMINI/grc` itself copies `${RESOLVED_WORKSPACE}/fips_provenance.json` straight into `${RESOLVED_EVIDENCE}/fips_provenance.json`** before running scanners! If a malicious repo plants a spoofed `fips_provenance.json`, `./grc scan` literally copies it into the evidence package. We must remove lines 218 to 220 from `GRC-xMINI/grc` as well as removing `fips_provenance.json` from `_target_metadata()` and excluding `bundle_provenance.json` / `ami_provenance.json` from FIPS scanning.

**GRC Engineer:** Fourth, **`M5`** (`verify_bundle` recording `checksum_verified: null` and `checksum_status: "NOT_CHECKED"` when `--expected-sha256` is omitted). Let's check existing test fixtures before breaking anything! Our committed `testing/demo-evidence/*/bundle_provenance.json` files already contain `"checksum_verified": true`, and check whether `grc_reporter.py` or `testing/` asserts boolean `checksum_verified` anywhere. Changing `"checksum_verified"` to `null` is cleaner and more honest for external baseline matching, as long as we keep `"git_bundle_valid": true` clearly visible right beside it so nobody confuses "no baseline hash provided to compare against" with "corrupt Git packfile"—`git bundle verify` still cryptographically verifies the packfile's internal SHA-1/SHA-256 object stream even when `--expected-sha256` isn't passed. Calling the status `"BASELINE_NOT_PROVIDED"` or `"NOT_CHECKED"` alongside `"git_bundle_valid": true` avoids misinterpretation.

**Software Developer / Designer:** Fifth, **`M7`** (`./grc scan` without Docker and `--host-only`). Two **critical breaks** in `M7` as written:
1. Read `M7`'s suggested `--host-only` scope: *"Offer `--host-only` (or fall back automatically with a warning) to run crypto, FIPS and SBOM engines."* Look at `run_sbom_engine` in `GRC-xMINI/grc` lines 266 to 285! `run_sbom_engine` checks whether `sbom.cdx.json` exists in `${RESOLVED_EVIDENCE}`, and if it does not, **it calls `run_container_engine "syft"` via Docker!** On a raw code workspace without a pre-existing `sbom.cdx.json`, the SBOM analyzer **cannot** generate an SBOM without Docker. It can only run in `--host-only` mode if the user supplies an existing SBOM, otherwise `--host-only` runs `crypto` and `fips` and skips `sbom` with a clear notice.
2. **Never allow automatic silent fallback when Docker is down during `./grc scan all`!** Look at the review's suggestion: *"or fall back automatically with a warning."* That is the exact opposite of Priority 1's fail-closed philosophy! If an operator runs `./grc scan` expecting all 10 security scanners (including Semgrep SAST, Gitleaks secrets, Checkov IaC, Grype/Trivy CVEs, and Syft SBOM) and Docker Desktop happens to be stopped, silently falling back to just Python crypto/FIPS checks would still exit zero and leave only two engines assessed! Docker-missing must fail fast **before** creating an unsealed `artifacts/pick-up/` folder (fixing the stray folder bug) and advise the user either to start Docker or explicitly re-run with `--host-only` (which visibly scopes the run to host-native engines). And yes, definitely change `"Please start Docker for Mac"` to `"Please start the Docker daemon"` so Linux and WSL2 users aren't confused.

**Software Developer / Designer:** Finally, **`M8`** (Same-second folder collision in `fips_discovery.py`). If `fips_discovery.py` globally refuses to write into an existing folder with a `sha256sum`, think about `./grc scan all -w ./ephemeral_workspace -e ./my_ev` or re-running `./grc scan fips -e ./my_ev` when `grc` already created the folder and copied `bundle_provenance.json` into it (or when combining engines into one evidence dir). Collision avoidance (appending `_01`, `_02`, or a microsecond suffix) should apply **only when `-e` (`--evidence`) was omitted** and the default timestamp path already exists on disk! When `-e` is explicitly passed, `write_deliverables()` must continue writing cleanly to the requested evidence directory.

**Consensus Verdict on Priority 5:** Fix `validate_finding_envelope()` and `GRC-xMINI/grc`'s untrusted provenance copy alongside `M3` and `M4`; make `--host-only` in `M7` an explicit opt-in flag (never silent fallback on `./grc scan all`) that handles `sbom` gracefully when `sbom.cdx.json` is absent; and scope `M8`'s collision-suffix logic strictly to auto-generated default evidence folders.

---

## Section 6: Priority 6 (`fips_discovery-guide.md`) and Priority 7 (Polish)

**GRC Engineer:** Everything in Priority 6's table for `docs/fips_discovery-guide.md` is spot-on once our code updates settle. In particular:
* Fixing the interactive chat prompt hint from `[p]` / `[y]` to `[y/N]` (since `grc_bot.py` uses `y/N` confirmation prompts for both preview and live execution) prevents immediate user confusion during live demos.
* Marking `WARN` as "reserved" in Section 1.2 (since no rule currently emits `WARN`) keeps the documentation strictly honest to code.
* Updating the KestrelBridge `H1` / `M3` / `H7` / `H4` walkthroughs *after* implementing the code changes ensures every terminal command works literally as printed.

**Cybersecurity Architect:** Let's challenge three items in **Priority 7 — Polish** so we don't accidentally introduce bugs while polishing:
1. **Redacting host paths (`workspace_path`, `bundle_source_path`) in `fips_provenance.json` and `bundle_provenance.json`:** Stripping `/Users/<username>/...` from sealed deliverables is good hygiene. Just be careful not to break `GRC-xMINI/grc` line 191 or `grc_reporter.py` line 1280, which read `bundle_source_path` from `bundle_provenance.json` to display `Source Subject` and name the evidence folder. Using basename or repo-relative paths (when inside the repo root) works cleanly as long as those consumers are tested against relative/basename values.
2. **Sealing `./grc crypto --output` folders with `sha256sum`:** Wait! Think about what happens if a user runs `./grc crypto -w ./ephemeral_workspace --format json --output ./crypto_results.json` in the repo root, or `--output /tmp/crypto.json`! If `crypto_lib_scan.py` blindly hashes *every* file in `out_p.parent` into `out_p.parent / "sha256sum"`, it will try to hash your entire `GRC-xMINI` directory or `/tmp`! We should only write a directory-wide `sha256sum` when `-o` targets a dedicated directory inside `artifacts/pick-up/` (or write a companion `.sha256` / single-file `sha256sum` entry for the output file itself when `--output` is passed elsewhere).
3. **Severity of FIPS boundary failures in `grc_reporter.py` (`MEDIUM / CAT III` vs. `HIGH / CAT II`):** Review Priority 7's final bullet asks whether ChaCha20 use and unvalidated crypto libraries (`NOT_VALIDATED`) should stay `MEDIUM / CAT III` (90-day SLA) or be raised to `HIGH / CAT II` (30-day SLA). From an RMF and DISA STIG perspective, `SC-13` (Cryptographic Protection) and `IA-7` (Cryptographic Module Authentication) explicitly require FIPS 140-validated cryptography for confidentiality and integrity protection in federal systems. Using a completely unvalidated algorithm like ChaCha20-Poly1305 or `pycryptodome` across a FIPS security boundary is a **DISA STIG CAT II (`HIGH`, 30-day SLA)** finding under the Application Security and Development STIG (`APSC-DV-002010` / `V-222542` / `V-222543`), whereas `CANNOT_DETERMINE_STATICALLY` and `NEEDS_REVIEW` remain outside POA&Ms in Section 4 (`Needs Human or Runtime Verification`).

**Software Developer / Designer:** Good catch—let's leave the final policy toggle on `HIGH` versus `MEDIUM` cleanly configurable or explicitly confirmed by the project owner, since existing `grc_reporter.py` tests and `custom-baseline-ruleset.yaml` expectations may assume specific severity counts. Note also that Priority 7's other three polish items—routing `./grc --help` and `./grc -h` to usage text instead of "Unknown GRC pipeline command", appending `Z` or explicitly documenting UTC folder timestamps, and aligning `GRC-xBOT`'s engine count ("8 engines" vs "10 compliance engines")—are trivial, zero-risk wins.

---

## Summary Action List Before Implementation Begins

**GRC Engineer:** To summarize our consensus for the repo owner before any edits are made:

1. **Resolve two owner decisions first:** First, confirm whether `KestrelBridge v2.0.0/gateway/Dockerfile` should be updated to install system `python3-cryptography` or use `--no-binary cryptography` (which keeps `v2.0.0` at `31 PASS` and `COMPLIANT`, resolving the conflict between `H7` and `M2 v2`). Second, confirm whether confirmed `FIPS` / `SC-13` boundary failures (`NOT_VALIDATED`, `FAIL_ALGORITHM`, `FAIL_FIPS_MODE`) should move from `MEDIUM` (90-day SLA) to `HIGH` (30-day SLA).
2. **Protect schema and reporter invariants during `H3`, `M2`, `M3`, and `H5`:** Update `rules/finding_schema.json` and `grc_common.py` before adding `files_inspected` or `checked_out_ref` fields; keep non-FIPS engines and unit tests unaffected by `M2`'s empty-workspace rule; and make `grc_reporter.py` deduplicate `CryptoScan` manifest-only verification items against `FIPSDiscovery` `PASS`/`FAIL` verdicts.
3. **Preserve fail-closed security during `H1`, `H2`, `M4`, and `M7`:** Clean up failed empty bundle clones, mirror `is_dir()` into `crypto_lib_scan.py`, stop `GRC-xMINI/grc` from copying untrusted workspace `fips_provenance.json` files, and never silently fall back to host-only scanning during `./grc scan all` when Docker is stopped.
4. **Update `GRC-xBOT`, `GRC-xTEST/scripts/verify_pipeline.sh`, and `docs/fips_discovery-guide.md` together** so IntentRouter tie-breaking, multi-command flag contract tests, KestrelBridge assertions, and documentation remain 100 percent synchronized.
