# KestrelBridge FIPS Dry-Run Review — Third Run (v3)

**Version:** v3. Read alongside `KESTRELBRIDGE_FIPS_FINAL_DECISIONS.md`; items are judged against those agreed decisions, not against v2's original wording.
**Date:** 2026-11-15 (evening)
**Code tested:** the working trees on disk, not only the commits.

| Repo | Last commit | Uncommitted changes tested |
| --- | --- | --- |
| GRC-xMINI | `39b2b64` (v1.5.1) | `grc`, `fips_discovery.py`, `crypto_lib_scan.py`, `grc_bundle.py`, `grc_reporter.py`, `grc_common.py`, `crypto_catalog.json`, `finding_schema.json`, tests |
| GRC-xTEST | `828b86b` (v1.5.1) | Rebuilt `kestrelbridge-fips.bundle`, `-v1.0.0.bundle`, `-v2.0.0.bundle`; v2.0.0 `gateway/Dockerfile` |
| GRC-xBOT | `79cc8df` (v1.5.0) | All of the `fips` workflow: `grc-bot`, `workflows.json`, `grc_bot.py`, tests |

**Environment:** Linux shell (Python 3.10.12, git 2.34.1), no Docker, GRC-xBOT Mode 1. Scratch copy; the owner's folders were not modified.

**Scope:** KestrelBridge bundles only. Use Cases 1 and 2 used `kestrelbridge-v1.0.0.bundle`, `-v1.5.0.bundle` and `-v2.0.0.bundle`. Use Cases 3 and 4 used `kestrelbridge-fips.bundle` at each tag. No AOC bundles.

---

## 1. Result

Every use case now works as the guide writes it, including restores without `-r`. All counts match the baseline, every seal verifies, and the v2.0.0 POA&M still reads "COMPLIANT (Clean Out-of-Band Audit)".

| Use case | Bundle | FAIL / NR / CDS / PASS | Notes |
| --- | --- | --- | --- |
| 1. GRC-xMINI only | `kestrelbridge-v1.0.0.bundle` | 31 / 0 / 0 / 1 | Restored without `-r` via `HEAD`. POA&M non-compliant. |
| | `kestrelbridge-v1.5.0.bundle` | 6 / 2 / 1 / 17 | |
| | `kestrelbridge-v2.0.0.bundle` | 0 / 0 / 0 / 31 | POA&M "COMPLIANT", plus new "Engines Run: FIPSDiscovery (1 of 10)" line. |
| 2. xBOT + xMINI | each versioned bundle | as above | `ask` and `chat` route to the new `fips` workflow at 100%. Guide Step 4 as written also correct. |
| 3. Full triad | `kestrelbridge-fips.bundle` | as above per tag | xBOT lists tags newest-first, defaults to `v2.0.0`, names skipped tags. Restore without `-r` checks out `HEAD` (`v2.0.0`) with a `[WARN]`. |
| 4. xMINI + xTEST | `kestrelbridge-fips.bundle`, Option A | as above per tag | `./grc test all` 55 tests OK; `./grc-bot test` 17 OK; `--fail-on` exits correctly; section 5 `jq` commands work. |
| 4. `verify_pipeline.sh` | 4 KestrelBridge bundles | — | Exit 0; "4 bundles (6 tag/ref snapshots)". Fails with a clear message when a baseline count is changed. |

Other confirmations: the false-positive guard file (`gateway/tests/test_fixtures.py`) produced no findings at any tag, and no rule emits `WARN`.

## 2. Commit status — read first

Most of the fixes below exist only as uncommitted changes. The last commits contain H1, H2, H3, M2 and H6. Everything else verified here (H4, M6 in GRC-xBOT; H5, H7, M1, M3, M4, M5, M7, M8 in GRC-xMINI; the rebuilt bundles and v2.0.0 Dockerfile in GRC-xTEST) would be lost or half-applied if the working trees were reset.

Commit the three GRC-xTEST bundle rebuilds and the v2.0.0 `gateway/Dockerfile` change together. The bundle SHA-256 values differ from the committed v1.5.1 ones.

## 3. Status of v2 items against the agreed decisions

| ID | Topic | Status | Evidence |
| --- | --- | --- | --- |
| H1 | Empty checkout on restore | **Fixed** | All 4 bundles carry `HEAD`. A HEAD-less bundle without `-r` now exits 1 with "Bundle restore produced an empty checkout … Pass --ref v1.0.0", and leaves no workspace. |
| H2 | `.bundle` as workspace | **Fixed** | `./grc fips` and `./grc crypto` both exit 1 with the restore hint. |
| H3 | Zero files reported clean | **Partial** — see R2 | Counts recorded everywhere; `[WARN]` on stderr; exit 2; JSON on stdout stays valid. But full runs still write and seal a package and print `[SUCCESS]`. |
| M2 (v2) | Posture wording | **Fixed** | v2.0.0 stays "COMPLIANT"; empty workspace with `--allow-empty` gives "NOT ASSESSED (No Assessable Files Found)". |
| H6 | `verify_pipeline.sh` | **Fixed** | Dynamic refs, true counts, baseline assertion proven to fail on mismatch. |
| H4 | xBOT FIPS workflow | **Fixed** (uncommitted) | 8th workflow; correct counts for all bundles; preview then production with `./grc report`. |
| M6 | Silent tag/bundle choice | **Fixed** (uncommitted), one gap — see R3 | Tags listed newest-first; chat prompts; `ask` warns and names skipped tags and bundles. |
| H5 | Crypto vs FIPS disagreement | **Fixed** (uncommitted), one nit — see R5 | `bc-fips` 1.0.2.5 now MEDIUM `FAIL_HISTORICAL_FIPS`; capable modules defer to `./grc fips`; met-version remediation text removed. |
| H7 | Workspace-wide approved-mode evidence | **Fixed** (uncommitted) | Unrelated UBI 9 Dockerfile no longer promotes `cryptography`. v2.0.0 stays 31 PASS via `--no-binary cryptography`; removing that flag drops it to `CANNOT_DETERMINE_STATICALLY`, as intended. |
| M1 | `--fail-on` | **Fixed** (uncommitted) | `FAIL`/`NEEDS_REVIEW` exit 1 on v1.0.0 and v1.5.0, 0 on v2.0.0; `never` exits 0. |
| M3 | `<bundle-stem>@<ref>` naming | **Fixed** for `./grc fips` and `./grc scan` (uncommitted); xBOT not aligned — see R4 | Folders such as `…_kestrelbridge-fips@v2.0.0_fips`; `target.checked_out_ref` in `fips_findings.json`. |
| M4 | Untrusted workspace provenance | **Fixed** per decision (uncommitted); small residual — see R8 | Planted `fips_provenance.json` ignored. A vendor-planted `bundle_provenance.json` is overwritten by `bundle restore`. |
| M5 | `checksum_verified` | **Fixed** (uncommitted) | `null` / `NOT_CHECKED` without a hash; `MATCH` with a correct one; exit 1 on a wrong one. |
| M7 | Docker-less scan | **Fixed** (uncommitted) | Fails before creating a folder; `--host-only` runs crypto + FIPS + report. |
| M8 | Same-second collision | **Fixed** per decision (uncommitted) | Auto-named folders get `_2`. Explicit `-e` overwrites by design — but see R1. |
| Priority 6 | Docs | **Partial** — see R6 | |
| Priority 7 | Polish | **Not yet done** — see R7 | |

---

## 4. Remaining tasks

### R1 (High). GRC-xBOT can overwrite a sealed evidence package from a different release

- **Where:** `GRC-xBOT/scripts/grc_bot.py`, `CommandPlanner`, about line 647: `ev_dir = f"artifacts/pick-up/{ts}_fips"`, with `ts` from `datetime.now()` to the second (line 462).
- **What happened:** In Use Case 2, the v1.5.0 run and the v2.0.0 run both planned `artifacts/pick-up/2026-11-16_004756_fips`. Because xBOT passes an explicit `--evidence`, the M8 suffix protection does not apply (by design, per the decisions doc). The v2.0.0 package silently replaced the v1.5.0 one. The folder now holds 31 PASS and a "COMPLIANT" POA&M, its seal verifies, and the name gives no hint that a different release was ever assessed there.
- **Reproduce:** stage two different KestrelBridge bundles one after the other and run `chat` → `fips` → `y` → `y` for each within the same second (scripted). Or run the planner twice with the same timestamp.
- **Required change:** Keep the M8 decision in `fips_discovery.py` unchanged. Fix it in xBOT instead:
  1. Name the folder `<ts>_<bundle-stem>@<ref>_fips`, matching `./grc fips` and `./grc scan`.
  2. Before handing the path to the commands, if it already exists, append `_2`, `_3`, … exactly as `fips_discovery.py` does for auto-named folders.
- **Acceptance:** Two xBOT FIPS runs in the same second, for different or identical bundles, produce two distinct folders, and neither package is altered.

### R2 (Medium). Empty workspace still produces a sealed package

- **Where:** `GRC-xMINI/scripts/fips_discovery.py`, `main()` and `write_deliverables`.
- **What happened:**
  - `./grc fips -w <empty dir> -e <dir>` exits 2 and warns, but writes all 7 files, seals them, and prints `[SUCCESS] Wrote 7 FIPS assessment deliverables`.
  - Without `-e`, it creates `artifacts/pick-up/<ts>_empty_fips/` with a sealed package.
  - An empty directory and a directory with only non-assessable files (a single `README.md`) give the identical message.
- **Why it matters:** The guide (`--allow-empty` row) says deliverables are written *with* `--allow-empty`, implying not without. A sealed folder in `pick-up/` reads as finished evidence; `[SUCCESS]` contradicts the exit code. Decision H3 item 3 asks for the two empty cases to be told apart.
- **Required change:**
  1. Without `--allow-empty`, write nothing when 0 assessable files were inspected; print the warning and exit 2. No `[SUCCESS]` line.
  2. With `--allow-empty`, keep today's behaviour (write, seal, "NOT ASSESSED" posture).
  3. Distinguish the messages: `workspace_total == 0` → "Workspace is empty (restore may have failed)"; `workspace_total > 0` → "No FIPS-assessable files among N workspace files".
- **Acceptance:** Without `--allow-empty`, no folder appears in `pick-up/` and `/tmp/x` stays absent for `-e /tmp/x`. The two empty cases print different messages.

### R3 (Medium). Invalid tag at the xBOT prompt silently audits the default

- **Where:** `GRC-xBOT/scripts/grc_bot.py`, about lines 1231–1241 (`else: selected_ref = default_ref`).
- **What happened:** At "Select release tag to audit [v2.0.0]:", entering `v9.9.9` silently selected `v2.0.0`. A typo such as `v1.0.` would audit the clean release instead of the legacy one, with nothing on screen to show it.
- **Required change:** Accept an empty answer (default), a listed number, or an exact listed tag. For anything else, print "Unknown tag 'v9.9.9'; choose 1–3 or a listed tag" and prompt again (with a sensible retry limit, then abort without running).
- **Acceptance:** Entering an unknown tag re-prompts; no command runs until a valid choice is made.

### R4 (Low). xBOT evidence folders use local time and no target name

- **Where:** `GRC-xBOT/scripts/grc_bot.py` line 462 (`datetime.now()`), lines 573, 589, 647, 738.
- **What happened:** xBOT names folders `<local-time>_fips`; GRC-xMINI names them `<UTC>_<bundle-stem>@<ref>_fips`. On the owner's Mac (UTC−5) an xBOT folder made at 19:46 sorts before a `./grc fips` folder made a minute earlier at 00:45 UTC the next day. This was read from the code; the test machine runs in UTC, so it did not show there.
- **Required change:** Use `datetime.now(datetime.timezone.utc)` and the same naming as GRC-xMINI (covered by R1 item 1).
- **Acceptance:** xBOT and `./grc fips` folders made a minute apart sort in the order they were made.

### R5 (Low). Contradictory status label in `./grc crypto`

- **Where:** `GRC-xMINI/scripts/crypto_lib_scan.py` / `rules/crypto_catalog.json`.
- **What happened:** v1.0.0 prints `bc-fips 1.0.2.5 Status: FAIL_HISTORICAL_FIPS (FIPS: CAPABLE_IF_CONFIGURED)`. A Historical-only certificate is not "capable if configured".
- **Required change:** For versions resolved to a Historical certificate, print `FIPS: HISTORICAL` (or `NOT_VALIDATED`) in the parenthesis.
- **Acceptance:** The v1.0.0 line no longer says `CAPABLE_IF_CONFIGURED`.

### R6 (Medium). Documentation still describes the old xBOT routing

- **`GRC-xMINI/docs/fips_discovery-guide.md`:**
  - Line 241 still says GRC-xBOT routes "fips" intents through the `crypto` playbook. It now has a `fips` workflow.
  - Lines 266 and 320 say `./grc-bot guide crypto` for the FIPS walkthrough; should be `./grc-bot guide fips`.
  - The `usage:` block (line 91) and flag table omit `--fail-on`, which the decisions doc says to document.
  - `./grc scan --host-only` and the POA&M "Engines Run" line are not mentioned.
- **`GRC-xBOT/README.md` and `QUICK_REFERENCE.md`:** no mention of the `fips` workflow (decision Priority 6).
- **Acceptance:** Every command in guide §4 runs as written and routes to the workflow the text names; `--fail-on` and `--host-only` appear in the flag tables.

### R7 (Low). Priority 7 polish not yet applied

All five were accepted in the decisions doc and are still as before:

| Item | Current behaviour |
| --- | --- |
| `./grc --help` | Still "Unknown GRC pipeline command", exit 1. |
| Host path redaction | `fips_provenance.json` and `scr_scn_package.json` still contain absolute paths (`workspace_path`). |
| `./grc crypto --output` sealing | Output folder holds `crypto_audit.md` with no `sha256sum`. |
| Engine-count text | `GRC-xBOT/playbooks/workflows.json` line 234 still says "all 8 compliance engines"; `./grc scan` says 10. |
| UTC folder timestamps | Documented in the guide (done); no `Z` marker in names. Acceptable as documented. |

### R8 (Low, optional). Planted `bundle_provenance.json` in a directly scanned repo

- **What happened:** When `./grc fips -w` points at a local checkout (no `bundle restore`), a `bundle_provenance.json` committed by the vendor sets the target identifier and commit in the output. Via `bundle restore` this is safe, because restore overwrites the file.
- **Suggested change:** Only trust `bundle_provenance.json` whose `workspace_path` matches the scanned workspace and whose `session_id` is present, or record its source as "untrusted (found in workspace)" in the provenance output.

---

## 5. Owner decision still open

**FIPS boundary severity (decisions doc §8 item 2):** ChaCha20 and unvalidated crypto libraries are still MEDIUM / CAT III with a 90-day SLA in the POA&M. No change was made, which is correct until the owner decides.

## 6. Not verified

- Anything needing Docker: `./grc scan all`, the xBOT `bundle` playbook's scan step, `verify_pipeline.sh` step 5 deduplication.
- macOS-specific behaviour, including R4.
- GRC-xBOT Mode 2 (Gemma).
- `verify_pipeline.sh` with the AOC bundles present (excluded from this run by scope).

## 7. Verification checklist for this round

1. `./grc test all` and `./grc-bot test` pass.
2. `verify_pipeline.sh` exits 0 and still asserts `31/0/0/1`, `6/2/1/17`, `0/0/0/31`.
3. Two xBOT FIPS runs in the same second produce two folders (R1).
4. `./grc fips -w <empty dir>` without `--allow-empty` writes nothing and does not print `[SUCCESS]` (R2).
5. An unknown tag at the xBOT prompt re-prompts (R3).
6. Guide §4 commands route to the workflows the text names (R6).
7. All fixes in sections 3 and 4 are committed, with the three rebuilt bundles and the v2.0.0 Dockerfile in one GRC-xTEST commit.
