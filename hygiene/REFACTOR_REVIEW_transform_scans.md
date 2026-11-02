# transform_scans.py Modularization Review (`hygiene/REFACTOR_REVIEW_transform_scans.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG.md"><b>🩹 Patch Log Index</b></a> &nbsp;·&nbsp;
  <a href="ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="RELEASING.md"><b>🏷️ Releasing</b></a> &nbsp;·&nbsp;
  <a href="../docs/transform_scans-guide.md"><b>📊 Scan-to-POA&M Guide</b></a>
</p>

> **Date**: `2026-11-01` · **Baseline**: `Yokota` (`v1.4.x`), commit `1c6e476`  
> **Scope**: `scripts/transform_scans.py` and its sibling engines in `scripts/`  
> **Type**: Read-only maintainability review. No code was changed.  
> **Follows**: Engine code review v1.4.0, §6 item 7 ("Split the module"). Phase 2 (`v1.4.2`) already extracted `PoamIdAllocator`, `_close_item()`, `TransformConfig`, and the scanner adapters. This review covers the remaining split.

---

## 1. Current State

| File | Lines |
| :--- | ---: |
| `transform_scans.py` | **3,338** |
| `grc_reporter.py` | 1,334 |
| `grc_ami.py` | 1,031 |
| `sbom_analyzer.py` | 935 |
| `crypto_lib_scan.py` | 742 |
| `grc_test.py` | 522 |
| `grc_bundle.py` | 498 |
| `grc_common.py` | 293 |
| `grc_fixtures.py` | 156 |

`transform_scans.py` is about 38% of all engine code. Its longest functions are:

| Function | Lines |
| :--- | ---: |
| `main()` | 526 |
| `write_combined_poam_workbook()` | 303 |
| `analyze_and_report_sla()` | 176 |
| `_populate_worksheet_element()` | 143 |
| `reconcile_poam_entries()` | 138 |
| `write_poam_workbook()` | 137 |
| `load_existing_poam_workbook()` | 110 |

---

## 2. Recommendations

### 2.1 Split into a `poam/` package along existing seams

The file already falls into clear sections, so most functions can move unchanged:

| New module | Contents | Source lines (approx.) | Size |
| :--- | :--- | :--- | ---: |
| `poam/schema.py` | `POAM_FIELDS`, column helpers (`col_to_idx`, `idx_to_col`, `resolve_col_letters`), header detection, `DATE_FIELDS`, `SLA_DAYS_BY_RISK`, `RISK_ORDER` | L93–265 | ~250 |
| `poam/xlsx_io.py` | OOXML namespace handling, sheet resolution, `read_xlsx_rows`, Excel serial ⇄ date, `sanitize_excel_string` | L268–590 | ~300 |
| `poam/scanners.py` | `load_scan_records`, `detect_scanner_type`, `TenableAdapter`, `InspectorAdapter`, `SCANNER_ADAPTERS`, `normalize_scan_rows`, `merge_scan_entries` | L590–656, L877–1240 | ~450 |
| `poam/enrichment.py` | `infer_nist_controls`, CISA KEV catalog + BOD 22-01, CVE/URL/asset extraction | L671–876 | ~200 |
| `poam/reconcile.py` | `load_existing_poam_workbook`, `PoamIdAllocator`, `_merge_carry_over`, `_close_item`, both reconcilers | L1241–1714 | ~470 |
| `poam/writer.py` | `build_remediation_plan_with_urls`, template style discovery, worksheet population, workbook writers | L1715–2464 | ~750 |
| `poam/sla.py` | `normalize_risk`, `compute_sla_date`, `analyze_and_report_sla` | L493–526, L2465–2640 | ~230 |
| `transform_scans.py` | CLI entry point: argument parsing, file discovery and prompts, orchestration | L2641–3337 | ~200 after §2.2 |

Moving the scanner adapters into their own module pays off soonest. A new scanner (Qualys, Wiz, etc.) then becomes a new adapter class instead of an edit to the engine. If the adapter count grows, promote `scanners.py` to a `scanners/` package with one file per scanner.

### 2.2 Break up `main()` (526 lines)

`main()` already contains seven numbered comment steps. Turn each into a function and have `main()` call them in order:

1. `resolve_scan_inputs()`: CLI argument or interactive prompt in `artifacts/drop-off/`
2. `resolve_previous_poams()`: previous OPEN and CLOSED workbooks
3. `ingest_scans()`: load and normalize scan findings
4. `reconcile()`: load previous POA&Ms, reconcile Open → Closed
5. `check_remediation_plans()`: Column K check and `[y/n]` prompt
6. `write_output()`: combined OPEN + CLOSED workbook
7. `report_sla()`: SLA breach and finding-age analysis

This is the biggest readability gain for the least risk. The three near-identical file-prompt flows can also share one `prompt_for_file(label, exts, allow_empty)` helper (engine review §6, refactor item 6).

### 2.3 Remove duplicate code paths

- **`write_poam_workbook()` is only called by tests.** The production path calls `write_combined_poam_workbook()` (L3311), which repeats the same style-discovery and populate steps. Options:
  - Have the combined writer call a shared single-sheet writer once per tab, or
  - Delete `write_poam_workbook()` and point its two tests (`testing/test_transform_scans.py` L477, L769) at the combined writer.
- **Two reconcilers.** `reconcile_poam_entries_legacy` (the default) and `reconcile_poam_entries` (strict) are selected by `--match-mode` (L3252). Per the 2026-11-01 reviewer decision, legacy closure behavior is **intended company policy**. Decide whether strict mode still has a user. If it doesn't, retire it to remove ~140 lines and a code path that has to be tested. If it does, move both into `reconcile.py` and share their common steps.

### 2.4 Use the shared code in `grc_common.py`

`grc_common.py` exists, but `transform_scans.py` does not import it:

| Issue | Location | Proposal |
| :--- | :--- | :--- |
| Own `SCRIPT_DIR` / `REPO_ROOT` | `transform_scans.py` L62–63 (also `grc_test.py` L32–33) | Import from `grc_common` |
| Local-time `datetime.date.today()` | `transform_scans.py` L2968 | Use `grc_common.utc_today()`, as the other engines do, to avoid off-by-one dates near midnight |
| Three severity normalizers | `grc_common.normalize_severity`, `grc_reporter.normalize_severity_and_cat`, `transform_scans.normalize_risk` | One mapping table in `rules/severity_policy.json` that all three read |

The severity scales are different (FedRAMP Critical/High/Moderate/Low versus HIGH/MEDIUM/LOW), so don't merge the functions directly. The goal is that a policy change happens in one place.

Only `transform_scans.py` and `crypto_lib_scan.py` use `xml.etree.ElementTree`, and crypto uses it only for `pom.xml`. `xlsx_io.py` should stay POA&M-specific for now. There's no need to promote it to `grc_common`.

---

## 3. Migration Plan

1. **Keep a compatibility wrapper.** `transform_scans.py` re-imports the public names from the new modules, so `import transform_scans as ts` in `testing/test_transform_scans.py` and `testing/test_code_review_regressions.py` keeps working during the move.
2. **Move leaf modules first:** `schema.py` → `xlsx_io.py` → `enrichment.py` → `sla.py`. These have the fewest internal dependencies.
3. **Then move the dependent modules:** `scanners.py` → `reconcile.py` → `writer.py`.
4. **Last:** split `main()` (§2.2) and remove duplicates (§2.3). These are the steps most likely to change behavior.
5. After **each** move, run `testing/test_transform_scans.py`, the regression suite, and `grc_test.py transform`, then commit. Use one commit per module so any regression can be bisected.
6. Once the tests point directly at the `poam.*` modules, remove the re-exports from the wrapper.

**Suggested release category**: `Bug Fix` / maintenance patch (`v1.4.x`) per [`RELEASING.md`](RELEASING.md). There's no user-facing behavior change unless §2.3 retires strict mode, which would be a CLI change and belongs in a minor release.

---

## 4. Expected Outcome

| Metric | Before | After (est.) |
| :--- | ---: | ---: |
| Largest file | 3,338 | ~750 (`writer.py`) |
| Largest function | 526 (`main`) | ~300 (`write_combined_poam_workbook`, next refactor target) |
| Files touched to add a scanner | 1 large shared file | 1 new adapter |
| Severity policy definitions | 3 | 1 |
