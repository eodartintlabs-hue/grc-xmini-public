# KestrelBridge FIPS Dry-Run Review — Corrections for Antigravity

**Date:** 2026-11-15
**Repos reviewed:** GRC-xMINI `fed7813`, GRC-xBOT `79cc8df`, GRC-xTEST `aa3593d` (plus the uncommitted KestrelBridge scenario, bundles and `docs/fips_discovery-guide.md`)
**Source:** two dry runs of the four use cases in `GRC-xMINI/docs/fips_discovery-guide.md` using the KestrelBridge bundles. Run in a Linux shell (Python 3.10.12, git 2.34.1), no Docker, GRC-xBOT Mode 1 only.

## How to use this document

Each task below has an ID, the file to change, how to reproduce the problem, the change required, and an acceptance check. Work through them in the order given. Line numbers refer to the commits above and may drift; confirm by searching for the quoted text.

Ground rules:

- Keep every engine 100% Python standard library. Add no dependencies.
- Do not change the KestrelBridge baseline counts. With the correct tag checked out, `./grc fips` must still report:

  | Tag | FAIL | NEEDS_REVIEW | CANNOT_DETERMINE_STATICALLY | PASS |
  | --- | --- | --- | --- | --- |
  | `v1.0.0` | 31 | 0 | 0 | 1 |
  | `v1.5.0` | 6 | 2 | 1 | 17 |
  | `v2.0.0` | 0 | 0 | 0 | 31 |

  Task H7 is the one exception; it is expected to move `v2.0.0` and says how.
- `gateway/tests/test_fixtures.py` must continue to produce zero findings at every tag.
- Add or extend a test in `./grc test fips` (or the relevant suite) for every behaviour change.
- Run `./grc test all`, `./grc-bot test` and `GRC-xTEST/scripts/verify_pipeline.sh` after each group of tasks.

## What already works (do not regress)

- `./grc bundle verify`, `restore -r <tag>`, and `clean`.
- `./grc fips` dry-run, full 7-file package, and single-format exports (`-f cbom|sarif|cmvp -o`).
- `./grc scan --fips` and `./grc report -e`; all `sha256sum` seals verified.
- GRC-xBOT detects staged bundles, resolves a single-tag bundle's ref correctly, runs preview then production in chat, cleans up, and reports a failed step correctly ("Step 2 exited with code 1").

---

## Priority 1 — False-clean evidence

These let a sealed package say "0 findings" or "COMPLIANT" for a release that should have 31 FAILs. Fix these first.

### H1. `bundle restore` succeeds on an empty checkout

- **Files:** `GRC-xMINI/scripts/grc_bundle.py` (`restore_bundle`, about lines 201–292); `GRC-xTEST/scenarios/kestrelbridge/build_bundle.sh` (lines 58 and 87).
- **Problem:** None of the four KestrelBridge bundles contains a `HEAD` ref (they are created with `git bundle create ... main --tags`). `git clone` of such a bundle checks out nothing. `restore_bundle` only runs `git checkout` when `--ref` is given, so without `-r` it prints `Checked out Commit: UNKNOWN (HEAD)`, then `[SUCCESS]`, and exits 0 with a workspace that holds only `.git` and `bundle_provenance.json`.
- **Reproduce:**
  ```bash
  cd GRC-xMINI
  ./grc bundle restore ../GRC-xTEST/bundles/kestrelbridge-v1.0.0.bundle -w ./ephemeral_kb -f --read-only
  ./grc fips -w ./ephemeral_kb --dry-run        # 0 FAIL, 0 PASS (expected 31 FAIL)
  ./grc fips -w ./ephemeral_kb -e /tmp/empty && ./grc report -e /tmp/empty
  grep "Overall Audit Posture" /tmp/empty/poam_data.md   # COMPLIANT (Clean Out-of-Band Audit)
  ```
- **Required change:**
  1. In `restore_bundle`, after the clone and optional checkout, fail with a non-zero exit if the commit hash is `UNKNOWN` or the working tree has no tracked files. The error must list the refs found in the bundle and tell the user to pass `--ref <one of them>`.
  2. Do not write `bundle_provenance.json` with `"status": "RESTORED"` in that case.
  3. In `build_bundle.sh`, include `HEAD` in both `git bundle create` calls (for example `git bundle create "$FILE" HEAD main --tags`) so a plain clone checks out `main`. Rebuild the four bundles. Note the bundle SHA-256 values will change.
- **Acceptance:** The reproduce commands above either restore the right commit (after the rebuild) or exit non-zero with a clear message (for any bundle that still lacks `HEAD`). Add a test that restores a HEAD-less bundle without `--ref` and asserts a non-zero exit.

### H2. `./grc fips` accepts a file as the workspace

- **File:** `GRC-xMINI/scripts/fips_discovery.py`, `main()` (about line 3272: `if not ws.exists():`).
- **Problem:** A `.bundle` file passed to `-w` passes the check, and the engine writes 7 sealed files with 0 findings, exit 0.
- **Reproduce:** `./grc fips -w ../GRC-xTEST/bundles/kestrelbridge-fips.bundle`
- **Required change:** Require `ws.is_dir()`. If the path is a file ending in `.bundle`, print the `./grc bundle restore` hint that the guide's troubleshooting table already promises. Exit 1.
- **Acceptance:** The command above prints `[FATAL]` and exits 1; nothing is written to `artifacts/pick-up/`.

### H3. Zero files inspected is reported as a clean result

- **File:** `GRC-xMINI/scripts/fips_discovery.py` (scan loop, envelope builder, `build_assessment_markdown`, `build_terminal_preview`).
- **Problem:** An empty workspace produces a report saying no `FAIL` or `WARN` findings were detected. Nothing records how many files were inspected, so a reader cannot tell "clean" from "nothing scanned".
- **Reproduce:** `mkdir /tmp/empty_ws && ./grc fips -w /tmp/empty_ws -f markdown`
- **Required change:**
  1. Count files inspected, broken down by surface (Python, polyglot source, manifests, deploy/IaC, OS config). Put the counts in `fips_findings.json` (`scope`), `fips_provenance.json`, the terminal preview and `fips_assessment.md`.
  2. When the total is 0, print a prominent warning, state "No assessable files found" in the report instead of the clean-result sentence, and exit non-zero unless a new `--allow-empty` flag is passed.
- **Acceptance:** The empty-workspace run exits non-zero with the warning. A normal KestrelBridge run shows non-zero counts and unchanged findings.

### M2. POA&M posture says "COMPLIANT" on a FIPS-only static scan

- **File:** `GRC-xMINI/scripts/grc_reporter.py` (about lines 1299–1305).
- **Problem:** With only `FIPSDiscovery` run and 0 findings, `poam_data.md` reads "COMPLIANT (Clean Out-of-Band Audit)". The FIPS report itself says static evidence shows configuration intent only, and nine other engines did not run.
- **Required change:** Derive the posture text from what ran. When fewer than all engines contributed, or when the only evidence is static FIPS, use wording such as "NO FINDINGS FROM ENGINES RUN (FIPSDiscovery only; runtime verification required)". Keep "COMPLIANT" for a full-suite clean run only. If H3's file count is 0, the posture must be "NOT ASSESSED".
- **Acceptance:** `./grc scan --fips` on `v2.0.0` no longer prints the unqualified "COMPLIANT" string; the empty-workspace case prints "NOT ASSESSED".

---

## Priority 2 — Broken regression harness

### H6. `verify_pipeline.sh` fails with the versioned KestrelBridge bundles present

- **File:** `GRC-xTEST/scripts/verify_pipeline.sh` (lines 58–94 and 129–143).
- **Problem:** The loop over `bundles/*.bundle` hard-codes `--ref v1.0.0`. `kestrelbridge-v1.5.0.bundle` and `-v2.0.0.bundle` have no such tag, so step 2 stops with `Failed to checkout ref 'v1.0.0'`, exit 1. The script also checks exit codes only, and prints fixed text ("12 bundles", "All 12 synthetic release bundles", "115 active open…") whatever actually ran.
- **Reproduce:** `cd GRC-xTEST && ./scripts/verify_pipeline.sh`
- **Required change:**
  1. Resolve each bundle's ref from `git bundle list-heads` (prefer a tag; for `kestrelbridge-fips.bundle` iterate all three tags). Apply the same fix to the Docker loop at lines 129–143.
  2. Print the real number of bundles processed.
  3. Add count assertions for KestrelBridge: run `fips_discovery.py --format json` at each tag and compare the determination counts to the baseline table at the top of this document. Fail the script on any mismatch.
- **Acceptance:** The script exits 0 with all 16 bundles present, reports the true count, and fails if a baseline count is changed deliberately.

---

## Priority 3 — GRC-xBOT FIPS workflow

### H4. A FIPS request never runs the FIPS engine

- **Files:** `GRC-xBOT/playbooks/workflows.json` (the `crypto` workflow at line 108; its keywords at line 113–115 include `"fips"`, `"140-2"`, `"140-3"`); `GRC-xBOT/scripts/grc_bot.py` (command synthesis near lines 395–480; menu).
- **Problem:** "Audit … for FIPS 140-3 mode, CMVP modules, and weak crypto" matches the crypto-library playbook at 100% confidence and runs `./grc crypto`. On `v1.0.0` that reports 3 packages where `./grc fips` reports 31 FAILs. The menu has 7 workflows and none is FIPS. The crypto playbook only mentions `./grc fips -w <workspace>` in passing, after its own command has already cleaned the workspace.
- **Required change:**
  1. Add a `fips` workflow. Preview command: `restore … --ref <ref> --force --read-only && ./grc fips -w ./ephemeral_workspace --dry-run ; clean`. Production command: the same with `./grc fips -w ./ephemeral_workspace` (no `--dry-run`), optionally followed by `./grc report -e <folder>`.
  2. Move the keywords `fips`, `140-2`, `140-3`, and add `cmvp`, `cbom`, `approved mode`, to the new workflow. Leave `eol`, `aoc-09`, library names on `crypto`.
  3. Add it to the chat menu, `guide <workflow>` help text, the banner's workflow count, and `./grc-bot test`.
- **Acceptance:** `./grc-bot ask "Walk me through a FIPS 140-3 check on the staged bundle"` maps to the FIPS workflow and its preview shows 31 FAIL for a staged `kestrelbridge-v1.0.0.bundle`.

### M6. xBOT picks a release without saying so

- **File:** `GRC-xBOT/scripts/grc_bot.py` (`parse_bundle_heads_output` line 113, `detect_bundle_ref` line 144, `bundles[0]` at lines 401, 409, 478).
- **Problem:** For `kestrelbridge-fips.bundle` it returns the first tag listed (`v1.0.0`) and never mentions `v1.5.0` or `v2.0.0`. With several bundles staged it uses `bundles[0]` silently.
- **Required change:** When a bundle has more than one tag, or more than one bundle is staged, list the choices in "Live Context" and, in chat, ask which to use. In non-interactive `ask`/`guide`, default to the highest version tag and say so, naming the alternatives.
- **Acceptance:** With the multi-tag bundle staged, the output names all three tags and states which one was chosen and why.

---

## Priority 4 — Engine consistency and PASS quality

### H5. The crypto and FIPS engines disagree on the same dependency

- **Files:** `GRC-xMINI/scripts/crypto_lib_scan.py` (bc-fips entry near lines 190–202, `fips_status: CAPABLE_IF_CONFIGURED`); `GRC-xMINI/rules/crypto_catalog.json` (lines 92–99); `GRC-xMINI/rules/cmvp_catalog.json` (line 195).
- **Problem:**

  | Tag | Dependency | `./grc crypto` | `./grc fips` |
  | --- | --- | --- | --- |
  | `v1.0.0` | `bc-fips` 1.0.2.5 | INFO, `CAPABLE_IF_CONFIGURED` | FAIL, Historical certificate |
  | `v1.5.0` | `bc-fips` 2.0.0 (Sun providers first) | INFO | FAIL, approved mode disabled |
  | `v2.0.0` | `bc-fips` 2.0.0, `cryptography` 42.0.5 | `CANNOT_DETERMINE_STATICALLY` | PASS |

- **Required change:** Make the crypto engine version-aware for modules with Historical certificates (`bc-fips` 1.0.2.x must not be INFO). Where the two engines can disagree because only FIPS looks at configuration, have the crypto output say so explicitly ("validation status only; run `./grc fips` for approved-mode assessment") rather than emit a verdict that contradicts FIPS. Also fix the remediation text that asks for upgrades already met ("Update golang.org/x/crypto >= v0.17.0" on 0.17.0; "Upgrade bc-fips to >= 2.0.0" on 2.0.0).
- **Acceptance:** `./grc crypto` on `v1.0.0` flags `bc-fips` 1.0.2.5 at MEDIUM or higher with the Historical note; remediation text is omitted or reworded when the installed version already meets the minimum.

### H7. Approved-mode evidence is matched across the whole workspace

- **File:** `GRC-xMINI/scripts/fips_discovery.py` (`_scan_dockerfile` near line 1481; `fips-cfg:container-fips-base-image` near line 2009; CMVP mapping near lines 2597–2607).
- **Problem:** Any Dockerfile in the workspace with a UBI 9 `FROM` line promotes `cryptography` from `CANNOT_DETERMINE_STATICALLY` to PASS, even one in an unrelated directory. In `v2.0.0` the gateway installs `cryptography` with `pip`, which is the static-wheel case the engine's own verification note warns about.
- **Reproduce:**
  ```bash
  cp -r ../GRC-xTEST/scenarios/kestrelbridge/releases/v1.5.0 /tmp/t1
  mkdir /tmp/t1/docs-site
  printf 'FROM registry.access.redhat.com/ubi9/nginx-124\nCOPY . /srv\n' > /tmp/t1/docs-site/Dockerfile
  ./grc fips -w /tmp/t1 -f json | jq -r '.findings[] | select(.rule_id|test("cryptography")) | .determination'
  # prints PASS; expected CANNOT_DETERMINE_STATICALLY
  ```
- **Required change:** Scope base-image evidence to the component that owns the manifest (same directory or the nearest ancestor containing both). For Python wheels installed by `pip` in that Dockerfile, keep `CANNOT_DETERMINE_STATICALLY` unless there is evidence the wheel is built against the system OpenSSL (for example an OS package install of `python3-cryptography`, or `--no-binary cryptography`).
- **Baseline impact:** `v2.0.0` will move from 0/0/0/31 to 0/0/1/30 unless the `v2.0.0` gateway Dockerfile is updated to show that evidence. Choose one, then update the baseline table in the guide, the scenario README and the H6 assertions together.
- **Acceptance:** The reproduce command prints `CANNOT_DETERMINE_STATICALLY`.

---

## Priority 5 — Provenance and process hardening

| ID | File | Problem | Required change | Acceptance |
| --- | --- | --- | --- | --- |
| M1 | `GRC-xMINI/scripts/fips_discovery.py` `main()` | Always exits 0, so CI cannot gate on findings. | Add `--fail-on {FAIL,NEEDS_REVIEW,never}` (default `never` to stay backward compatible). Document it. | `./grc fips -w <v1.0.0> --dry-run --fail-on FAIL` exits non-zero; on `v2.0.0` it exits 0. |
| M3 | `fips_discovery.py` `_target_metadata` (about line 2753) and `main()` evidence path; `grc_bundle.py` line 267 | `./grc fips` names the folder with the 64-char bundle SHA-256; `./grc scan fips` uses the bundle name. The checked-out ref is in no FIPS deliverable, so the three tags of one bundle share one identifier. | Use `<bundle-stem>@<ref>` for the folder slug and display name; keep the SHA-256 as a separate field. Record `checked_out_ref` in `fips_provenance.json`, `fips_findings.json` and the Markdown headers. Make both commands name folders the same way. | Three tags of `kestrelbridge-fips.bundle` give three distinguishable folder names and identifiers. |
| M4 | `fips_discovery.py` `_target_metadata` | Reads `fips_provenance.json` from inside the audited tree first, so a vendor file can set the target identifier and commit. | Stop reading `fips_provenance.json` from the workspace. Trust only provenance written by `./grc bundle restore` / `./grc ami restore`, and exclude those files from scanning. | A planted `fips_provenance.json` has no effect on output. |
| M5 | `grc_bundle.py` `verify_bundle` (line 166) | `checksum_verified` defaults to `True` when no `--expected-sha256` is given. | Record `"checksum_verified": null` and `"checksum_status": "NOT_CHECKED"` unless an expected hash was supplied. | Provenance from a plain restore shows `NOT_CHECKED`. |
| M7 | `GRC-xMINI/grc` (about line 230) | `./grc scan` (all) with no Docker exits before the host-native engines and leaves an unsealed pick-up folder holding only `bundle_provenance.json`. | Check Docker before creating the evidence folder. Offer `--host-only` (or fall back automatically with a warning) to run crypto, FIPS and SBOM engines. Fix the message "Docker for Mac" to be platform-neutral. | No stray folder after a Docker-less run; host-native engines can be run in one command. |
| M8 | `fips_discovery.py` `main()` / `write_deliverables` (line 3196) | Two runs in the same second write to the same folder; the second replaces the first. | Refuse to write into an existing sealed folder, or append a short suffix. | Two back-to-back runs produce two folders. |

---

## Priority 6 — Documentation: `GRC-xMINI/docs/fips_discovery-guide.md`

Apply after the code changes so the text matches the final behaviour.

| Guide location | Current text | Correction |
| --- | --- | --- |
| §4.2 Step 4 (line 281–282) | `./grc bundle restore artifacts/drop-off/vendor-release.bundle -w ./ephemeral_workspace -f --read-only` | Add `-r <tag>`, or state that the bundle must carry `HEAD`. |
| §4.3 Pattern B step 4 (line 351) | Restore without `-r` | Same correction. |
| §4.4.3 Option B (line 434 onward) | "no `-r` needed" | True only once the bundles are rebuilt with `HEAD` (task H1). Until then add `-r v1.0.0` / `v1.5.0` / `v2.0.0`. |
| §4.3 Pattern B step 3 (line 345) | "Approve Preview ([p]) first, then Live ([y])" | Both prompts are `[y/N]`. There is no `[p]` option. |
| Troubleshooting row 1 (line 490) | Passing a `.bundle` directly gives `[FATAL] Workspace path does not exist` | Only true after task H2. Update the quoted message to the new one. |
| §2.1 and §3, default evidence path | `<YYYY-MM-DD_HHMMSS>_<target>_fips` | State what `<target>` is (after M3: `<bundle-stem>@<ref>`) and that the timestamp is UTC. |
| §1.2 determinations | `WARN` listed as a live determination | No rule emits `WARN`. Either add a rule or mark it "reserved". |
| §1.2 lead sentence | PASS is withheld where static analysis cannot verify | Reconcile with task H7. |
| §4.3 Pattern A, §4.4.1, §4.4.2 | Written around AOC bundles and fixtures | Add a KestrelBridge-only route, or say plainly that these steps need the AOC corpus. |
| New | — | Document `--fail-on`, `--allow-empty`, the files-inspected counts and the new GRC-xBOT FIPS workflow. |

Also update `GRC-xTEST/scenarios/kestrelbridge/README.md` if H7 changes the `v2.0.0` baseline, and `GRC-xBOT` docs (`README.md`, `QUICK_REFERENCE.md`) for the new workflow.

---

## Priority 7 — Polish

- `GRC-xMINI/grc` (line 323): `./grc --help` and `./grc -h` return "Unknown GRC pipeline command". Route them to the usage text.
- `fips_discovery.py` line 3150 and `grc_bundle.py` lines 268, 271: sealed evidence stores absolute host paths (`workspace_path`, `bundle_source_path`), which exposes the local username. Store paths relative to the repo root, or the basename only.
- Evidence folder timestamps are UTC with no marker. Append `Z` or document it.
- `./grc crypto --output` folders have no `sha256sum` seal, unlike FIPS folders. Seal them the same way.
- `GRC-xBOT/playbooks/workflows.json` line 204 says "all 8 compliance engines"; `./grc scan` says 10. Make them agree.
- `grc_reporter.py`: ChaCha20 use and an unvalidated crypto library are rated MEDIUM / CAT III with a 90-day SLA. Confirm with the owner whether a FIPS boundary failure should be HIGH; do not change without that decision.

## Known detection gaps (already listed in the scenario README; not regressions)

Planted in `v1.0.0` and still undetected. Treat as feature work after the fixes above:

- `random.getrandbits()` used to generate a DEK (`gateway/kestrelbridge/envelope.py:15`).
- `Signature.getInstance("SHA1withRSA")` (`signer/.../ManifestSigner.java:16`).
- RSA-OAEP with SHA-1 / MGF1-SHA-1 (`gateway/kestrelbridge/envelope.py:33`).

Adding these will raise the `v1.0.0` FAIL count above 31; update the baseline everywhere in the same change.

## Not verified in the dry runs

- Anything requiring Docker: `./grc scan all`, the xBOT `bundle` playbook's scan step, step 5 of `verify_pipeline.sh`.
- macOS-specific behaviour (the runs were on Linux).
- GRC-xBOT Mode 2 (Gemma).
- Tasks H2, H7, M4, M5 and M8 were reproduced in the first run only; the code was unchanged for the second run.

## Final verification checklist

1. `./grc test all` and `./grc-bot test` pass.
2. `GRC-xTEST/scripts/verify_pipeline.sh` exits 0 with all 16 bundles present and asserts the KestrelBridge baseline.
3. For each of the four KestrelBridge bundles, restore without `-r` either checks out the correct commit or exits non-zero. No path produces a sealed 0-finding package for `v1.0.0`.
4. `./grc fips -w <file.bundle>` and `./grc fips -w <empty dir>` exit non-zero.
5. `./grc-bot ask "FIPS 140-3 check on the staged bundle"` runs the FIPS engine and names the release it chose.
6. Every command block in `docs/fips_discovery-guide.md` §4 runs as written against the KestrelBridge bundles and gives the documented counts.
