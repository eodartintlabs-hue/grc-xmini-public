# Release Notes (`hygiene/RELEASE_NOTES.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="../testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG.md"><b>🩹 v1 Patch Log</b></a> &nbsp;·&nbsp;
  <a href="ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="RELEASING.md"><b>🏷️ Releasing</b></a> &nbsp;·&nbsp;
  <a href="../docs/transform_scans-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc_bundle-guide.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc-xtest-guide.md"><b>🎯 GRC-xTEST Guide</b></a>
</p>

> **Project**: GRCx — The GRC eXperience  
> **Current release**: `v1.4.4 — Yokota` (Restricted Beta / Integration Testing)  
> **Maintainer**: Byron Turner  
> This file records **shipped** changes only. Commit and author accountability is tracked in [`PATCH_LOG.md`](PATCH_LOG.md). Planned work lives in [`ROADMAP.md`](ROADMAP.md). Versioning, codenames, and the release procedure live in [`RELEASING.md`](RELEASING.md).

---

## Release Summary

| Version | Codename | Date | Type | Commit | Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [`v1.4.4`](#v144--yokota) | Yokota | 2026-11-02 | Bug fix | _TBD after tagging_ | Native Qualys VMDR & Wiz Cloud Security adapters, 4-way scanner auto-detection, vendor remediation URL drafting, and pure standard-library synthetic demo data generator (`scripts/generate_demo_data.py`) |
| [`v1.4.3`](#v143--yokota) | Yokota | 2026-11-01 | Bug fix | `43839b9` | Multi-worksheet FedRAMP v3.1 POA&M template ingestion (strict Worksheet #1 reading + dynamic header/guidance row skipping) and unified 2-tab `FedRAMP-POAM.xlsx` (`Open POA&M Items` + `Closed POA&M Items`) output in `artifacts/pick-up/` |
| [`v1.4.2`](#v142--yokota) | Yokota | 2026-11-01 | Bug fix | `7b05926` | Code Review Phase 2 (Externalized policy catalogs `rules/severity_policy.json` & `rules/stig_catalog.json`, `Ec2Backend` strategy pattern, `PoamIdAllocator`, `TenableAdapter`/`InspectorAdapter`, `@dataclass` models, 34 unit tests, and Bold White `GRCx` logo update) |
| [`v1.4.1`](#v141--yokota) | Yokota | 2026-11-01 | Bug fix | `c8c629f` | Code Review Phase 1 (P0/P1 security & compliance integrity fixes across all 7 engines, `grc_common.py`, `grc_fixtures.py`, and 29 regression tests) |
| [`v1.4.0`](#v140--yokota) | Yokota | 2026-11-01 | Minor | `4e88635` | GRC-xMINI rebrand under GRC-x Initiative, grc_test engine #7, artifacts drop-off/pick-up, and purple MINI logo |
| [`v1.3.4`](#v134--sasebo) | Sasebo | 2026-11-01 | Hygiene / Docs | `802bdc9` | Documentation hygiene, GRC-xTEST rebranding, dual desktop navigation fork, and patch log restructuring |
| [`v1.3.3`](#v133--sasebo) | Sasebo | 2026-10-31 | Bug fix | `f4b9075` | Dynamic POA&M ID nomenclature (`YYYY-MMM-#####`), backward-compatible ID parsing, and unit test suite expansion |
| [`v1.3.2`](#v132--sasebo) | Sasebo | 2026-10-31 | Bug fix | `3a041cd` | Multi-scan POA&M transformation (up to 5 scans), finding consolidation, and tri-ledger patch logs (`BUG`, `MINOR`, `MAJOR`) |
| [`v1.3.0`](#v130--sasebo) | Sasebo | 2026-10-29 | Minor | `3398d69` | `scans/` drop-in folder and file picker; POA&M engine data-integrity hardening; unit tests |
| [`v1.2.0`](#v120--misawa) | Misawa | 2026-10-20 | Minor | `c510bc3` | Standalone Tenable / AWS Inspector scan-to-FedRAMP POA&M transformer |
| [`v1.1.0`](#v110--kadena) | Kadena | 2026-10-20 | Minor | `b2eea63` | Rebrand to GRCx; `INSTALL.md` and `COMMANDS.md`; logo lockups |
| [`v1.0.6`](#v106--yokosuka) | Yokosuka | 2026-10-19 | Docs | `bf1c799` | System requirements; 4-in-1 multi-AOC verification evidence |
| [`v1.0.5`](#v105--yokosuka) | Yokosuka | 2026-10-19 | Docs | `48d1d34` | Initial product roadmap |
| [`v1.0.4`](#v104--yokosuka) | Yokosuka | 2026-10-18 | Bug fix | `19c41dc` | `./grc scan` now runs all 9 engines; per-engine `--engine` dispatch |
| [`v1.0.3`](#v103--yokosuka) | Yokosuka | 2026-10-18 | Docs | `48a43ff` | Demo evidence moved to `testing/demo-evidence/` |
| [`v1.0.2`](#v102--yokosuka) | Yokosuka | 2026-10-18 | Docs | `3445ac6` | Docs reorganized into `amplifying-info/`, `testing/`, `hygiene/` |
| [`v1.0.1`](#v101--yokosuka) | Yokosuka | 2026-10-18 | Docs | `d038e81` | Codename adoption, release tracking files, live demo runbook |
| [`v1.0.0`](#v100--yokosuka) | Yokosuka | 2026-10-18 | Beta baseline | `9bc27c3` | Initial 5-phase bundle and AMI review pipeline |

---

## v1.4.4 — Yokota

**Native Qualys VMDR & Wiz Scanner Adapters, Multi-Scanner Detection & Synthetic Demo Generator** · November 02, 2026 · Tag `v1.4.4`

### Multi-Scanner Compliance Architecture & Synthetic Demo Tooling

1. **Native Qualys VMDR Scanner Adapter (`scripts/transform_scans.py`)**:
   - Implemented `QualysAdapter` normalizing Qualys VMDR vulnerability exports (`.csv` and `.xlsx`) into standard FedRAMP POA&M fields.
   - Maps Qualys numeric severity levels (`5 -> Critical`, `4 -> High`, `3 -> Moderate`, `2/1 -> Low`) and textual severity headers.
   - Normalizes QID source identifiers, vulnerability titles, threats, impacts, and scanner technical evidence (`[Scanner Evidence]: ...`).
   - Automatically correlates IP, DNS, NetBIOS, Port, and Protocol into consolidated asset identifiers (`Host (Port/Proto)`).
2. **Native Wiz Cloud Security Scanner Adapter (`scripts/transform_scans.py`)**:
   - Implemented `WizAdapter` normalizing cloud infrastructure and container workload findings from Wiz vulnerability reports (`.csv` and `.xlsx`).
   - Normalizes Wiz IDs (`WIZ-...`), vulnerability names, descriptions, affected package names, and file paths.
   - Captures cloud asset context across virtual machine workloads and Kubernetes container pods (`Asset Name (Asset Type)`).
   - Ingests fixed versions, remediation guidance, and sets vendor dependency tracking when fixes are unavailable.
3. **4-Way Dynamic Scanner Auto-Detection & Asset Alias Expansion (`scripts/transform_scans.py`)**:
   - Upgraded `detect_scanner_type()` with multi-marker heuristic scoring to accurately auto-detect Tenable, AWS Inspector, Qualys VMDR, and Wiz exports without manual flags.
   - Extended `extract_row_asset_aliases()` to parse `IP`, `DNS`, `Asset Name`, and `Resource Name` for seamless host reconciliation across mixed-scanner environments.
   - Added `qualys` and `wiz` to the `--scanner` CLI argument options.
4. **Vendor Remediation Plan URL Drafter Expansion (`scripts/transform_scans.py`)**:
   - Extended `build_remediation_plan_with_urls()` with official vendor reference builders:
     - Qualys: extracts advisory URLs, links to National Vulnerability Database (`https://nvd.nist.gov/vuln/detail/CVE-...`), and official Qualys Threat Research.
     - Wiz: extracts reference advisories, NVD links, and the official Wiz Vulnerability Database (`https://www.wiz.io/vulnerability-database`).
5. **Pure Standard-Library Synthetic Demo Dataset Generator (`scripts/generate_demo_data.py`)**:
   - Created `scripts/generate_demo_data.py` (zero third-party dependencies, standard library `zipfile` and `xml.etree.ElementTree`) generating full-fidelity compliance test datasets:
     - `previous_open_poam.xlsx`: 160 entries spanning MAR, MAY, JUL, AUG, OCT 2026 (`YYYY-MMM-#####` format) using the official FedRAMP v3.1 5-worksheet template.
     - `tenable_vulnerability_report.xlsx`: 80 findings (40 matched, 40 new).
     - `qualys_vulnerability_report.xlsx`: 30 findings (20 matched, 10 new).
     - `aws_inspector_report.xlsx`: 150 findings (10 matched, 140 new).
     - `wiz_vulnerability_report.xlsx`: 70 findings (10 matched, 60 new).
     - Automatic dual-environment distribution to both `artifacts/drop-off/` and `GRC-xTEST/scans/`.
6. **Regression Test Suite Expansion (`testing/test_transform_scans.py`, `scripts/grc_test.py`)**:
   - Added unit tests for Qualys and Wiz adapters and scanner auto-detection (`test_qualys_adapter_and_auto_detection`, `test_wiz_adapter_and_auto_detection`).
   - All 38 unit tests pass with zero errors, and all 7 compliance engines pass under `scripts/grc_test.py`.

---

## v1.4.3 — Yokota

**Multi-Worksheet FedRAMP POA&M Ingestion & Unified 2-Tab Output Workbook (`FedRAMP-POAM.xlsx`)** · November 01, 2026 · Tag `v1.4.3`

### FedRAMP v3.1 5-Sheet Template Support & Single-Workbook Deliverable

1. **Multi-Worksheet FedRAMP POA&M Template Ingestion (`scripts/transform_scans.py`)**:
   - Added `get_workbook_sheets()`, `get_workbook_sheet_names()`, and updated `resolve_sheet_path(z, sheet_index=0)` to resolve worksheets in exact `<sheets>` tab order from `xl/workbook.xml` and `xl/_rels/workbook.xml.rels` across both standard and Strict OpenXML namespaces.
   - Updated `load_existing_poam_workbook()` so uploaded multi-worksheet FedRAMP workbooks (such as the 5-tab `Open POA&M Items`, `Closed POA&M Items`, `Configuration Findings`, `PL-2 Findings`, `Record of Changes` template) strictly read **only Worksheet #1 (`sheet_index=0`)** and ignore all remaining tabs.
   - Added `detect_poam_header_and_start_row()` and row-level instruction filters so FedRAMP v3.1 templates with `POAM ID` on Row 5 and `Guidance` / `Examples` / `Mandatory or Situational` on Rows 6–8 automatically start reading/writing data at Row 9 and never mistake template instruction rows for open vulnerabilities.
2. **Unified 2-Tab `FedRAMP-POAM.xlsx` Output Workbook in `artifacts/pick-up/` (`scripts/transform_scans.py`)**:
   - Added `_populate_worksheet_element()` and `write_combined_poam_workbook()` to generate a single combined 2-worksheet `.xlsx` deliverable named **`FedRAMP-POAM.xlsx`** inside `artifacts/pick-up/<YYYY-MM-DD_HHMMSS>/`:
     - **Tab 1 (`Open POA&M Items`, `xl/worksheets/sheet1.xml`)**: Active carry-over and newly detected Open POA&M entries with auto-calculating SLA formulas (`fullCalcOnLoad="1"`), FedRAMP header banner/logo, and risk rating dropdown validations.
     - **Tab 2 (`Closed POA&M Items`, `xl/worksheets/sheet2.xml`)**: Newly closed and historical Closed POA&M entries with unified `xl/sharedStrings.xml` indices, mapped `xl/styles.xml` cell formatting, and isolated drawing relationships (`xl/drawings/drawing2.xml`).
   - Automatic closed-tab carry-forward: When a previously generated 2-tab `FedRAMP-POAM.xlsx` is supplied via `--previous-open` (without `--previous-closed`), `transform_scans.py` automatically loads existing closed items from Tab 2 (`Closed POA&M Items`).
3. **Regression Tests & Documentation (`testing/test_transform_scans.py`, `scripts/grc_test.py`, `README.md`, `COMMANDS.md`, `docs/transform_scans-guide.md`)**:
   - Added `test_five_worksheet_fedramp_template_reads_only_first_worksheet_and_skips_guidance_rows` and `test_combined_fedramp_poam_workbook_contains_open_and_closed_tabs_in_single_file` in `testing/test_transform_scans.py` (36 unit tests + all 7 compliance engines passing via `./grc test`).
   - Added `cwd=REPO_ROOT` to `grc_bundle` subprocess calls in `scripts/grc_test.py`.

---

## v1.4.2 — Yokota

**Architecture & Maintainability Refactoring (Code Review Phase 2)** · November 01, 2026 · Tag `v1.4.2`

### Phase 2 Structural Refactoring & Externalized Policy Catalogs

1. **Externalized Policy & Benchmark Catalogs (`rules/` & `scripts/grc_common.py`)**:
   - Added [`rules/severity_policy.json`](../rules/severity_policy.json) and [`rules/stig_catalog.json`](../rules/stig_catalog.json) as single sources of truth for FedRAMP ConMon SLAs (`30 / 30 / 90 / 180` days), DISA STIG impact categories, OS-to-STIG mappings, and the 18 DISA STIG/SRG profiles.
   - Extended [`scripts/grc_common.py`](../scripts/grc_common.py) with `load_severity_policy()`, `normalize_severity()`, `get_severity_policy()`, `load_stig_catalog()`, `load_os_stig_mapping()`, and `write_output()`.
2. **`scripts/grc_bundle.py` (`CommitMetadata` Dataclass & Null-Delimited Git Parsing)**:
   - Added `@dataclass class CommitMetadata` (with `.unknown()` and `.to_dict()`) and `_git()` subprocess helper.
   - Upgraded `extract_commit_metadata()` to use `git log -1 -z` null-byte (`\x00`) field delimiters so commit subjects containing `|||` are parsed cleanly, and updated `git checkout` to `--detach <ref> --`.
3. **`scripts/grc_ami.py` (`Ec2Backend` Strategy Pattern)**:
   - Replaced interleaved `if self.mock_mode:` / `elif HAS_BOTO3:` / `else:` branches across 4 methods with a clean `Ec2Backend` Strategy hierarchy (`MockBackend`, `AwsCliBackend`, `Boto3Backend` with cached `self.ec2` client) and loaded `OS_STIG_MAPPING` from `rules/stig_catalog.json`.
4. **`scripts/crypto_lib_scan.py` (Synced Catalog & Dispatch Registries)**:
   - Synchronized `DEFAULT_CRYPTO_CATALOG` with `rules/crypto_catalog.json`, added `DependencyExtractor.PARSERS` dispatch table, and refactored `CryptoReporter` with `to_terminal()` and `FORMATTERS` dispatch dictionary.
5. **`scripts/sbom_analyzer.py` (`@dataclass` Models, Nested CycloneDX & Resolver Chain)**:
   - Converted `Component` and `STIGMapping` to `@dataclass` (with safe non-string field coercion in `Component.__post_init__`), added recursive `components[].components` CycloneDX traversal, loaded `DISA_STIG_CATALOG` from `rules/stig_catalog.json`, and refactored `STIGAnalyzer` to a Chain-of-Responsibility resolver list (`self._resolvers`).
6. **`scripts/grc_reporter.py` (`PARSERS` Registry & SBOM STIG Ingestion)**:
   - Added `_load_json()`, `PARSERS` registry dictionary, `_md_header()`, and `parse_sbom_stig()` (ingesting `stig_applicability.json` / `sbom_stig_map.json` into `scr_scn_package.json`).
7. **`scripts/transform_scans.py` (`PoamIdAllocator`, Scanner Adapters & Strict Date Validation)**:
   - Extracted `PoamIdAllocator` and `_close_item()` shared across `reconcile_poam_entries` and `reconcile_poam_entries_legacy` (retaining `MATCH_MODE = "legacy"` default).
   - Added `TransformConfig` dataclass, `TenableAdapter` / `InspectorAdapter` classes (with distinct fallback asset keys when `Host` or `Resource ID` is absent), `_resolve_poam_arg_or_prompt()` helper, and strict `--reference-date` validation.
8. **Expanded Regression Suite & CLI Banner (`testing/test_code_review_regressions.py`, `./grc`, `README.md`)**:
   - Added Phase 2 unit tests (34 total unit tests + all 7 compliance engines passing via `./grc test`).
   - Updated the `./grc fetch` terminal logo to render `GRCx` in Bold White (`\033[1;97m`) above `MINI` in Purple (`\033[38;5;135m`).

---

## v1.4.1 — Yokota

**Bug Fix & Compliance Integrity Patch (Code Review Phase 1)** · November 01, 2026 · Tag `v1.4.1`

### P0 & P1 Code Review Remediation Across All 7 Engines

1. **Shared Standard-Library Foundation (`scripts/grc_common.py` & `scripts/grc_fixtures.py`)**:
   - Extracted [`scripts/grc_common.py`](../scripts/grc_common.py) (`sha256_file`, `utc_now_iso`, `safe_rmtree` with provenance marker enforcement, `version_lt`, `version_matches_prefix`, `SLA_DAYS_POLICY`, and `SEVERITY_RANK`).
   - Extracted [`scripts/grc_fixtures.py`](../scripts/grc_fixtures.py) so `grc_ami.py` no longer imports `grc_test.py` at runtime.
2. **`scripts/grc_bundle.py` (P0 #1 Self-Deletion & Guarded Teardown)**:
   - Extracted standalone `clean_ephemeral_workspace()` so `clean --delete-bundle <missing_path>` never instantiates `GRCBundleManager` with `Path(__file__)` and refuses to delete `.py` scripts.
   - Protected `restore --force` and `clean` with `safe_rmtree`, added 40/64-hex SHA-1/SHA-256 ref parsing, combined `stdout + stderr`, guarded `git checkout` option injection (`--`), and fixed `.git` path-part pruning so `.github/` files are locked read-only.
3. **`scripts/grc_ami.py` (P0 #2 Silent Mock Fallback & XFS Cold-Mount)**:
   - Removed implicit fallback to `self.mock_mode = True` when AWS CLI/boto3 fails; live AWS errors now fail hard unless `--mock` is explicitly passed.
   - Added automatic EBS volume rollback (`_detach_and_delete_volume`) on attach/mount failure, required `--worker-id` in live `restore`, resolved worker AZ dynamically, added Nitro NVMe `/dev/disk/by-id/` resolution and `blkid` XFS/ext4 mount flag detection (`ro,norecovery,nouuid,noexec,nosuid`), enforced exact KMS key/ARN matching, and rejected unencrypted root snapshots by default (`--allow-unencrypted` override).
4. **`scripts/crypto_lib_scan.py` (P0 #5 Numeric Version Compare & P0 #6 Path Filter)**:
   - Replaced lexicographic string comparison with integer-tuple `version_lt` and segment-boundary `version_matches_prefix`.
   - Replaced substring path filtering (`"vendor" in root`) with in-place `os.walk` directory pruning (`dirs[:] = [d for d in dirs if d not in SKIP_DIRS]`).
   - Added `.so` soname version extraction (`libssl.so.1.1` $\rightarrow$ `"1.1"` $\rightarrow$ `FAIL_EOL`), `WARN_UNVERIFIED` for unknown versions, stdlib `xml.etree.ElementTree` `pom.xml` parsing, `tomllib` `pyproject.toml` parsing, and severity-rank sorting.
5. **`scripts/sbom_analyzer.py` (CLI `--catalog-dump` & Component-to-STIG Scoping)**:
   - Placed `--sbom` and `--catalog-dump` in a mutually exclusive CLI group.
   - Separated component matching into `ALWAYS_MATCH_NAME_MAP` and `PLATFORM_SERVICE_NAME_MAP` so client libraries (`pkg:pypi/redis`, `java-jwt`) map to `ASD_STIG` rather than server STIGs, and added RHEL 8 PURL (`distro=rhel-8` / `.el8`) detection.
6. **`scripts/grc_reporter.py` (P0 #3 Crypto `PASS` Exclusion & P0 #4 `NOT ASSESSED` State)**:
   - Excluded `compliance_status == "PASS"` crypto items from POA&M ingestion and preserved `manifest_file`.
   - Tracked `loaded_scanners` so missing scanner outputs (`semgrep_findings.json`, `checkov_findings.json`) report `NOT ASSESSED (NO EVIDENCE)` rather than `PASSED (CLEAN)` / `COMPLIANT`.
   - Unified HIGH SLA to 30 days, added deterministic `POAM-xxx-HASH` IDs anchored to provenance dates, word-boundary Checkov classification, and per-record error isolation.
7. **`scripts/transform_scans.py` & `scripts/grc_test.py`**:
   - Preserved `MATCH_MODE = "legacy"` as default per company policy and updated `--match-mode` CLI help text to match; removed `testing/sample-scans/` and `REPO_ROOT` from `fallback_dirs`; unified in-file and cross-file CVE/KEV merge logic; cleaned `calcChain.xml` relationships from `workbook.xml.rels` and `[Content_Types].xml`; defaulted non-interactive `--draft-remediations ask` to `"n"`.
   - Upgraded `scripts/grc_test.py` (including `grc_reporter.py`) and added `testing/test_code_review_regressions.py` (29 unit & regression tests passing).

---

## v1.4.0 — Yokota

**Minor Capability Release** · November 01, 2026 · Tag `v1.4.0`

### 5 Core Objectives of the Yokota Series

1. **Engine #7 — `scripts/grc_test.py` Compliance Invariant & Mock Engine**:
   - Absorbed synthetic mock generators and test harnesses across all sister engines (`transform_scans.py`, `grc_bundle.py`, `crypto_lib_scan.py`, `grc_ami.py`, `sbom_analyzer.py`, `grc_reporter.py`).
   - Slimmed sister engines (e.g. extracted 54 lines of synthetic mock fixtures from `scripts/grc_ami.py` into `grc_test.py`), keeping source code smaller and nimble.
   - Built self-contained invariant verification runners and integrated them into the root CLI via `./grc test [suite]`.
2. **Rebrand to GRC-xMINI under the GRC-x Initiative**:
   - Rebranded the core compliance runtime to **GRC-xMINI**, formalizing that both **GRC-xMINI** and **GRC-xTEST** are core components of the overarching **GRC-x Initiative**.
3. **Artifacts Directory Restructure (`artifacts/drop-off` and `artifacts/pick-up`)**:
   - Relocated intake and deliverable directories into `artifacts/`: `artifacts/drop-off/` (formerly `scans/`) and `artifacts/pick-up/` (formerly `evidence/`).
   - Maintained backward-compatibility in `scripts/transform_scans.py` with automatic fallback to legacy directories.
4. **Timestamped Deliverable Directories with Automatic Fallback**:
   - Deliverables inside `artifacts/pick-up/` now automatically generate a timestamped subfolder (`YYYY-MM-DD_HHMMSS`) instead of using input filenames.
   - Includes automatic graceful fallback to the legacy naming convention (`poam-<scan_basename>`) if system date/time is unavailable.
5. **New Terminal Logo & Fetch Banner**:
   - Replaced terminal fetch banner (`./grc fetch`) with high-contrast Bold Black `GRCx` (`\033[1;30m`) and custom cyber double-line `MINI` wordmark in Purple (`\033[38;5;135m`), synchronizing styling with `GRC-xTEST`.

---

## v1.3.4 — Sasebo

**Hygiene & Documentation Update** · November 01, 2026 · Tag `v1.3.4`

### Repository Hygiene, GRC-xTEST Rebranding, and Navigation Fork

- **Section 2 reverse-chronological order in `PATCH_LOG.md`**: Inverted Section 2 of `hygiene/PATCH_LOG.md` so that the newest releases (`v1.3.4`, `v1.3.3`, etc.) display at the top and older releases (`v1.0.0`) at the bottom.
- **Separation of planned releases from patch logs**: Removed all future/planned release entries from running patch logs (`hygiene/PATCH_LOG.md`, `PATCH_LOG_BUG.md`, `PATCH_LOG_MINOR.md`, `PATCH_LOG_MAJOR.md`). All future and planned work is now consolidated exclusively in [`hygiene/ROADMAP.md`](ROADMAP.md).
- **Zero personal email policy**: Conducted repository-wide audit and verified zero instances of personal email addresses (`eodartintlabs@gmail.com`) across tracked code, documentation, and metadata.
- **Rebranded test repository to `GRC-xTEST`**: Rebranded the synthetic testing repository from `grc-test-dummies` to `GRC-xTEST` ([`https://github.com/eodartintlabs-hue/grc-xtest.git`](https://github.com/eodartintlabs-hue/grc-xtest.git)). In addition to synthetic test bundles (`bundles/*.bundle`), `GRC-xTEST` now provides synthetic Tenable and AWS Inspector scan fixtures (`scans/*.csv`, `scans/*.xlsx`) for testing `scripts/transform_scans.py`.
- **Documentation renamed & restructured**:
  - `docs/test-dummies-guide.md` $\rightarrow$ [`docs/grc-xtest-guide.md`](../docs/grc-xtest-guide.md): Added Table of Contents, dual-platform desktop navigation instructions (`%USERPROFILE%\Desktop\GRC-x` and `~/Desktop/GRC-x`), testing pathways for bundles, and scan transform testing with `GRC-xTEST` fixtures.
  - `docs/scan-transform-guide.md` $\rightarrow$ [`docs/transform_scans-guide.md`](../docs/transform_scans-guide.md): Added Table of Contents and dual desktop pathways. Structured into 7 standard sections: Section 3 (Windows Command Prompt / PowerShell usage), Section 4 (macOS Terminal usage), Section 5 (Under the hood engine mechanics), Section 6 (Sample terminal outputs), and Section 7 (Expected output files & locations).
  - `docs/grc-bundle-use-case.md` $\rightarrow$ [`docs/grc_bundle-guide.md`](../docs/grc_bundle-guide.md): Updated title and links.
- **`README.md` Section 10 Product Roadmap focused**: Streamlined Section 10 of `README.md` to highlight the latest pushed release (`v1.3.4 — Sasebo`) with comprehensive links to the `hygiene/` directory (`ROADMAP.md`, `RELEASE_NOTES.md`, `PATCH_LOG.md`, `RELEASING.md`).

---

## v1.3.3 — Sasebo

**Bug fix** · October 31, 2026 · Tag `v1.3.3`

### Dynamic POA&M ID nomenclature (`YYYY-MMM-#####`)

- **Standardized dynamic POA&M naming convention**: Replaced the static year-based `POAM-2026-####` nomenclature for newly detected POA&M items with the dynamic FedRAMP standard:
  ```text
  YYYY-MMM-#####
  ```
  *(Example: `2026-SEP-00347` or `2026-OCT-00001`)*
- **Deterministic month abbreviations (`MONTH_ABBRS`)**: Utilized an explicit English lookup table (`JAN` .. `DEC`) ensuring deterministic 3-letter uppercase month abbreviations regardless of host OS language or locale settings.
- **5-digit zero-padded sequence**: Padded sequence numbers to 5 digits (`00001` .. `99999`) while maintaining strictly monotonic ID sequence progression across both OPEN and CLOSED workbooks.
- **Backward-compatible ID parsing**: Updated sequence parsing in `reconcile_poam_entries` and `reconcile_poam_entries_legacy` to seamlessly recognize both the new `YYYY-MMM-#####` convention and legacy `POAM-YYYY-####` formats when reconciling against previous workbooks.
- **Unit test suite expansion**: Added `test_poam_id_dynamic_nomenclature_year_month_sequence` in `testing/test_transform_scans.py` verifying direct formatting and end-to-end reconciliation numbering (16 unit tests passing).

---

## v1.3.2 — Sasebo

**Bug fix** · October 31, 2026 · Tag `v1.3.2`

### Multi-scan transformation & finding consolidation (up to 5 scans)

- **Interactive multi-scan selection prompt**: Fixed the scan ingestion workflow in `scripts/transform_scans.py` (`./grc transform`) which previously allowed selecting only one scan file at a time. Each time a scan file is selected interactively, the app prompts:
  ```text
  [?] Would you like to add an additional scan file to also be transformed? [y/N]:
  ```
  Entering `y` allows analysts to select additional scan files (up to **5 scan files** total) from `scans/` without running separate sessions or manually merging Excel workbooks afterward.
- **Finding consolidation (`merge_scan_entries`)**: Enforces 1 POA&M row per unique `(Vulnerability + Asset)` pair across all input scans:
  - Preserves the earliest `Original Detection Date` across scans.
  - Retains the highest risk rating (recomputing the FedRAMP SLA date accordingly).
  - Merges asset identifiers, host aliases, network ports, and protocols.
  - Aggregates all source scan filenames into the `Supporting Documents` column.
- **Combined asset discovery**: Combines scanned hosts and alias maps across all scans prior to reconciliation, ensuring auto-closure verification recognizes assets scanned in any of the provided files.
- **CLI multi-scan support**: Added multi-scan support for CLI flags (`--scan scan1.csv --scan scan2.csv` or comma-separated `--scan scan1.csv,scan2.csv`) and positional arguments, with strict validation capping input at 5 scans.
- **Reporting & output updates**: Updated terminal SLA aging banners, `poam_transform_summary.md`, and default output directory names (`evidence/poam-<scan>-and-<N>-more`) to reflect all ingested scan sources.
- **Unit test suite expansion**: Added tests in `testing/test_transform_scans.py` verifying multi-scan finding consolidation, deduplication invariants, SLA recalculation, CLI limit enforcement, and interactive simulated prompts (15 unit tests passing).

### Tri-ledger patch architecture (`hygiene/PATCH_LOG_*.md`)

- Partitioned the running release ledger into three dedicated category logs aligned with Semantic Versioning:
  - [`hygiene/PATCH_LOG_BUG.md`](PATCH_LOG_BUG.md): Tracks patch-level bug fixes, operational adjustments, scanner flag updates, and hygiene patches (`vX.Y.Z` where `Z > 0`).
  - [`hygiene/PATCH_LOG_MINOR.md`](PATCH_LOG_MINOR.md): Tracks backward-compatible minor feature releases introducing new engines, subcommands, or compliance frameworks (`vX.Y.0` where `Y > 0`).
  - [`hygiene/PATCH_LOG_MAJOR.md`](PATCH_LOG_MAJOR.md): Tracks major foundational baselines and lifecycle milestones (`vX.0.0`).
- [`hygiene/PATCH_LOG.md`](PATCH_LOG.md) serves as the master navigation hub and cross-series reference table.

---

## v1.3.0 — Sasebo

**Minor release** · October 29, 2026 · Tag `v1.3.0`

### Drop-in `scans/` folder and file selection

- Added a root **`scans/`** folder where analysts drop Tenable / AWS Inspector exports (`.csv`, `.xlsx`) and previous OPEN / CLOSED FedRAMP POA&M workbooks (`.xlsx`), so long file paths no longer need to be typed.
- Running `./grc transform` interactively lists detected files with numbers (`[1]`, `[2]`, …) and accepts either a number or a filename.
- All file inputs (`--scan` / `-s`, `--previous-open` / `-p`, `--previous-closed`, or the positional argument) search `scans/` first and match filenames case-insensitively, with or without an extension. They fall back to `testing/sample-scans/` and then to direct paths.
- `scans/` is re-checked when the analyst answers the prompt, so a file dropped in while the prompt is open is still found.

### POA&M data-integrity fixes (`scripts/transform_scans.py`)

- **Host-verified auto-close.** Before informational rows are filtered out, the engine records every scanned host (including Tenable plugin `19506`, *Nessus Scan Information*) and links `Host` / `IP Address` / `DNS Name` / `FQDN` aliases that appear together. A previous OPEN item is only closed as "Verified remediated" if its host, or an alias, was confirmed scanned. Items on unscanned hosts stay OPEN and are flagged for review, unless `--close-unscanned-hosts` is passed.
- **CISA KEV and BOD 22-01.** Tenable's `Exploit Available = Yes` is no longer treated as KEV membership. KEV status and BOD 22-01 due dates (Columns Z and AA) now come from an offline CISA KEV catalog ([`rules/cisa_kev_catalog.json`](../rules/cisa_kev_catalog.json), override with `--kev-catalog`), using CISA's own `dateAdded` and `dueDate`.
- **POA&M IDs.** The next `POAM-YYYY-NNNN` number is computed across both the previous OPEN and CLOSED workbooks, so closed IDs are never reused. Fallback matching by weakness name can no longer give two scan items the same ID. A `[WARNING]` is printed when the script runs without `-p`.
- **SLA and detection dates.** SLA dates are recalculated when duplicate rows on the same host are merged. `Plugin Publication Date` is no longer used as a fallback for the original detection date.

### Excel template handling

- All OpenXML namespace prefixes (`mc`, `x14`, `x14ac`, `x15`, `mx`, `mv`, `xm`, `xr`) are preserved instead of being renamed to `ns0`, `ns1`, ….
- Illegal XML 1.0 control characters are stripped, and cell text is capped at Excel's 32,767-character limit.
- `fullCalcOnLoad="1"` is set in `xl/workbook.xml`, `<dimension>` is updated, and cell styles are discovered from the template instead of hard-coded.
- `.xlsx` files are read with `ET.iterparse` streaming.

### New options and tests

- New flags: `--dry-run`, `--strict-fedramp-risk`, `--close-unscanned-hosts`, `--kev-catalog`.
- Added a 10-test standard-library `unittest` suite ([`testing/test_transform_scans.py`](../testing/test_transform_scans.py)) covering OpenXML round-tripping, host-verified closure, KEV lookup, and SLA recalculation.

### Docs

- Version strings updated to `v1.3.0 (Sasebo)` in `./grc`, `docs/scan-transform-guide.md`, `COMMANDS.md`, `INSTALL.md`, `README.md`, and `hygiene/*`.

> **Not in this release:** the workstation portability work (UID/GID fixes, pinned scanner image, Podman / SELinux support, `./grc doctor`) is planned for `v1.3.1`. See [`ROADMAP.md`](ROADMAP.md).

---

## v1.2.0 — Misawa

**Minor release** · October 20, 2026 · Tag `v1.2.0` (`c510bc3`)

### Scan-to-FedRAMP POA&M transformer

- Added [`scripts/transform_scans.py`](../scripts/transform_scans.py) (`./grc transform`), a standalone engine written only with the Python 3 standard library. It needs no Docker container, no `.bundle` file, and no `pip` installs.
- Auto-detects **Tenable** (Nessus, Tenable.sc, Tenable.io) and **AWS Inspector** exports in `.csv` or `.xlsx`, and maps each unique vulnerability and asset pair to one row across the 27 FedRAMP POA&M columns.

### Bundled FedRAMP templates

- [`templates/OPEN FedRAMP-POAM-Template.xlsx`](../templates/OPEN%20FedRAMP-POAM-Template.xlsx): Columns B–AB, data from row 5.
- [`templates/CLOSED LEGACY FedRAMP-POAM-Template.xlsx`](../templates/CLOSED%20LEGACY%20FedRAMP-POAM-Template.xlsx): Columns A–AA, data from row 3.
- The OPEN template's risk-rating dropdown and Column M (Scheduled Completion Date) formula were extended to support Critical (+30 days), High (+30), Moderate (+90), and Low (+180).

### Open-to-closed reconciliation

- Accepts a previous OPEN POA&M (`--previous-open`, or prompted).
- Findings still present keep their POA&M ID, Original Detection Date (Column L), and analyst-entered fields; Status Date (Column N) is updated.
- Findings no longer in the scan, or marked False Positive = Yes, move to the CLOSED workbook with a dated note.

### Remediation plans and SLA reporting

- If any OPEN entries lack a Remediation Plan (Column K), the analyst is asked (`y/n`) whether to draft them. Drafts include links to the Tenable plugin page, AWS ALAS advisory, AWS Inspector docs, and NVD.
- Reports how many OPEN entries are past their Scheduled Completion Date and how old each finding is, both in the terminal and in `poam_transform_summary.md`.

### Docs and samples

- Added the analyst guide [`docs/scan-transform-guide.md`](../docs/scan-transform-guide.md), sample Tenable and Inspector exports, a sample previous OPEN POA&M, and generated evidence in `testing/demo-evidence/`.
- Roadmap updated: Misawa and Sasebo swapped places, and the cloud lift and local LLM work moved to `v2.1.0+ — Kaneohe`.

---

## v1.1.0 — Kadena

**Minor release** · October 20, 2026 · Tag `v1.1.0` (`b2eea63`)

- **Rebrand to GRCx — "The GRC eXperience"**, replacing *GRC Bundle Review Pipeline* across documentation, CLI wrappers, and analyzer metadata (`scripts/sbom_analyzer.py`, `scripts/grc_bundle.py`).
- **Logo:** light and dark lockups in [`assets/logo/`](../assets/logo/), shown in `README.md` with a theme-adaptive `<picture>` header.
- **CLI banner:** `./grc fetch` now shows the GRCx banner and `GRCx v1.1.0 (Kadena)`.
- **New guides:** [`INSTALL.md`](../INSTALL.md) (setup through first scan, including viewing outputs in Cursor) and [`COMMANDS.md`](../COMMANDS.md) (every `./grc` command and flag).
- **Cleanup:** removed `docs/workspace-layout.md`, `docs/review-workflow.md`, and `docs/design-rules-and-aocs.md`, and shortened `README.md` Section 8 to link to the new guides.

---

## v1.0.6 — Yokosuka

**Patch (docs)** · October 19, 2026 · Tag `v1.0.6` (`bf1c799`)

- Added minimum and recommended hardware and software requirements to `README.md` Section 7 and to `docs/workspace-layout.md` (that file was later removed in `v1.1.0`).
- Added a 4-in-1 synthetic verification bundle ([`testing/demo-evidence/aoc-combo-4x/`](../testing/demo-evidence/aoc-combo-4x/)) combining AOC-02, AOC-04, AOC-07, and AOC-09. It produced 19 normalized POA&M findings across 7 NIST SP 800-53 controls.

---

## v1.0.5 — Yokosuka

**Patch (docs)** · October 19, 2026 · Tag `v1.0.5` (`48d1d34`)

- Added the first product roadmap ([`ROADMAP.md`](ROADMAP.md)) and a roadmap section in `README.md`. In this first version, Sasebo was `v1.2.0` and Misawa was `v1.3.0`; the two were swapped in `v1.2.0`.
- Added the Roadmap link to the navigation bar on every documentation page.

---

## v1.0.4 — Yokosuka

**Patch (bug fix)** · October 18, 2026 · Tag `v1.0.4` (`19c41dc`)

- **Fix:** `./grc scan` ran the seven containerized scanners and then went straight to `grc_reporter.py`, skipping `scripts/crypto_lib_scan.py` and `scripts/sbom_analyzer.py`. Full scans now run all nine engines before Phase 4 reports are generated.
- **Per-engine runs:** `./grc` and `docker/scan_orchestrator.sh` accept `--all` or `--engine <name>`. Engine names: `semgrep`, `gitleaks`, `checkov`, `syft`, `grype`, `trivy`, `oscap`, `crypto`, `sbom`. `grype` and `sbom` run `syft` first if `sbom.cdx.json` is missing.
- Added `--no-report` (skip Phase 4) and `./grc scan --help`.
- `bundle_provenance.json` and `ami_provenance.json` are now copied into `evidence/` in every scan mode.

---

## v1.0.3 — Yokosuka

**Patch (docs)** · October 18, 2026 · Tag `v1.0.3` (`48a43ff`)

- Moved synthetic test outputs into [`testing/demo-evidence/`](../testing/demo-evidence/) and added `evidence/.gitkeep`, so root `evidence/` holds only real reviews. Updated `live-demo.md`, `DATAFLOW.md`, and `GOVERNANCE.md` to match.
- Reworked the patch ledger table: removed duplicate version and codename columns, and added Commit and Author columns.

---

## v1.0.2 — Yokosuka

**Patch (docs)** · October 18, 2026 · Tag `v1.0.2` (`3445ac6`)

- Reorganized documentation into `amplifying-info/` (architecture, data flow, governance), `testing/` (test plan, live demo), and `hygiene/` (release tracking). `README.md` and `SECURITY.md` stay at the root so GitHub shows them natively.
- Updated all navigation bars, relative links, and SVG asset paths.

---

## v1.0.1 — Yokosuka

**Patch (docs)** · October 18, 2026 · Tag `v1.0.1` (`d038e81`)

- Adopted the Yokosuka codename in Git tags, docs, and the CLI banner.
- Renamed `grc-bundle Use Case.md` to [`docs/grc-bundle-use-case.md`](../docs/grc-bundle-use-case.md).
- Standardized the Git author identity on the GitHub `noreply` address.
- Added the patch ledger, release notes, and [`live-demo.md`](../testing/live-demo.md) (a presentation script covering AOC-09, AOC-10, and AOC-04).
- Added Phase 4 evidence packages for AOC-04, AOC-09, and AOC-10. These later moved to `testing/demo-evidence/` in `v1.0.3`.

---

## v1.0.0 — Yokosuka

**Beta baseline** · October 18, 2026 · Tag `v1.0.0` (`9bc27c3`)

First end-to-end beta of the **GRC Bundle & AMI Review Pipeline** (renamed GRCx in `v1.1.0`), released to designated integration testers. It targets FedRAMP High, DISA STIG, NIST SP 800-53 Rev. 5, and DoD RMF environments.

### Five-phase review lifecycle

1. **Pull & verify:** SHA-256 checksum and `git bundle verify` checks ([`scripts/grc_bundle.py`](../scripts/grc_bundle.py)), plus AMI KMS encryption checks ([`scripts/grc_ami.py`](../scripts/grc_ami.py)).
2. **Ephemeral restore:** read-only extraction (`chmod 0444` for bundles; `mount -o ro,noload,noexec,nosuid` for AMI snapshots) with `bundle_provenance.json` / `ami_provenance.json`.
3. **Air-gapped scan:** containerized analysis in `grc-scanner:local` with `--network none` and `/workspace:ro`.
4. **Compliance synthesis:** `poam_data.md`, `controls.md`, `ruleset_validation.md`, `scr_scn_package.json`, and `sha256sum` seals ([`scripts/grc_reporter.py`](../scripts/grc_reporter.py)).
5. **Teardown:** workspace cleanup and volume detachment (`./grc bundle clean`, `./grc ami clean`).

### Engines

- **Containerized (7):** Semgrep (37 custom rules in [`rules/custom-baseline-ruleset.yaml`](../rules/custom-baseline-ruleset.yaml)), Gitleaks, Checkov, Syft, Grype, Trivy, and OpenSCAP.
- **Host Python auditors (2):** [`scripts/crypto_lib_scan.py`](../scripts/crypto_lib_scan.py) (EOL / non-FIPS crypto libraries) and [`scripts/sbom_analyzer.py`](../scripts/sbom_analyzer.py) (SBOM-to-STIG applicability). These weren't run automatically by `./grc scan` until `v1.0.4`.

### Documentation

[`README.md`](../README.md), [`ARCHITECTURE.md`](../amplifying-info/ARCHITECTURE.md), [`DATAFLOW.md`](../amplifying-info/DATAFLOW.md), [`SECURITY.md`](../SECURITY.md), [`GOVERNANCE.md`](../amplifying-info/GOVERNANCE.md), [`TESTING.md`](../testing/TESTING.md), and [`test-dummies-guide.md`](../docs/test-dummies-guide.md) (paired with [`grc-test-dummies`](https://github.com/eodartintlabs-hue/grc-test-dummies)).
