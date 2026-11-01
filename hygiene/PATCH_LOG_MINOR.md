# Minor Capability Releases Ledger (`hygiene/PATCH_LOG_MINOR.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="../testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG.md"><b>🩹 Patch Log Index</b></a> &nbsp;·&nbsp;
  <a href="ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="RELEASING.md"><b>🏷️ Releasing</b></a> &nbsp;·&nbsp;
  <a href="../docs/transform_scans-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc_bundle-guide.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc-xtest-guide.md"><b>🎯 GRC-xTEST Guide</b></a>
</p>

<p align="center">
  <b>Sub-Ledgers</b>: 
  <a href="PATCH_LOG_BUG.md"><b>🐛 Bug Fixes & Patches</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG_MINOR.md"><b>✨ Minor Releases</b></a> &nbsp;·&nbsp;
  <a href="PATCH_LOG_MAJOR.md"><b>🏛️ Major Releases & Baselines</b></a>
</p>

> **Ledger Scope**: **Minor Capability & Feature Releases (`vX.Y.0` where `Y > 0`)**  
> **Active Series Codename**: `Yokota` (`v1.4.x`) · Previous: `Sasebo` (`v1.3.x`), `Misawa` (`v1.2.0`), `Kadena` (`v1.1.0`)  
> **Companion Documents**: See [`PATCH_LOG_BUG.md`](PATCH_LOG_BUG.md) for bug fixes and patches, [`PATCH_LOG_MAJOR.md`](PATCH_LOG_MAJOR.md) for major baselines, [`RELEASE_NOTES.md`](RELEASE_NOTES.md) for narrative notes, and [`RELEASING.md`](RELEASING.md) for release procedures. (Planned releases are tracked in **[`ROADMAP.md`](ROADMAP.md)**).

---

## 1. Running Minor Capability Release Table

This ledger tracks all backward-compatible minor feature releases—introducing new scanner engines, CLI subcommands, compliance frameworks, or major workflow enhancements—maintaining full commit, file-scope, and **Author / POC** accountability (most recent release listed first):

| Version | Commit | Date | Category | Subsystem / Files Affected | Summary of Changes | Author / POC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`v1.4.0`<br/>(`Yokota`)** | `3d4aeae` | `2026-11-01` | `Minor Release` | `scripts/grc_test.py`, `scripts/grc_ami.py`, `scripts/transform_scans.py`, `artifacts/*`, `./grc`, `README.md`, `INSTALL.md`, `COMMANDS.md`, `docs/*`, `hygiene/*` | Added Engine #7 (`scripts/grc_test.py`) absorbing test & synthetic mock routines from sister engines; rebranded core runtime to `GRC-xMINI` under the `GRC-x Initiative`; restructured `scans/` and `evidence/` into `artifacts/drop-off/` and `artifacts/pick-up/`; added timestamped deliverable directory generation (`YYYY-MM-DD_HHMMSS`) with fallback; updated CLI terminal banner with Bold Black GRCx and Purple MINI wordmark; 18 unit tests + all 7 engines verified. | Byron Turner |
| **`v1.3.0`<br/>(`Sasebo`)** | `3398d69` | `2026-10-29` | `Minor Release` | `scans/.gitkeep`, `scripts/transform_scans.py`, `rules/cisa_kev_catalog.json`, `testing/test_transform_scans.py`, `testing/sample-scans/*`, `testing/demo-evidence/*`, `./grc`, `docs/*`, `COMMANDS.md`, `INSTALL.md`, `README.md`, `hygiene/*` | Added designated root **`scans/`** drop-in folder with interactive numbered file selection (`[1]`, `[2]`, ...) and extensionless filename resolution; hardened [`scripts/transform_scans.py`](../scripts/transform_scans.py) for FedRAMP deliverable integrity: host-verified auto-closure (via Tenable Plugin `19506` & IP/DNS alias reconciliation) retaining unscanned hosts in OPEN for review, offline CISA KEV catalog lookup ([`rules/cisa_kev_catalog.json`](../rules/cisa_kev_catalog.json)) for BOD 22-01 due dates, monotonic POA&M ID numbering across OPEN + CLOSED workbooks, duplicate-merge SLA recalculation, full OpenXML namespace preservation (`mc`, `x14`, `x14ac`), XML control-char sanitization (`32,767` char cap), `ET.iterparse` streaming, `--dry-run`, `--strict-fedramp-risk`, and a 10-test unit suite ([`testing/test_transform_scans.py`](../testing/test_transform_scans.py)); added [`hygiene/RELEASING.md`](RELEASING.md); bumped CLI and docs to `GRCx v1.3.0 (Sasebo)`. | Byron Turner |
| **`v1.2.0`<br/>(`Misawa`)** | `c510bc3` | `2026-10-20` | `Minor Release` | `scripts/transform_scans.py`, `templates/*`, `docs/*`, `testing/sample-scans/*`, `testing/demo-evidence/*`, `./grc`, `COMMANDS.md`, `INSTALL.md`, `README.md`, `hygiene/*` | Added standalone Scan-to-FedRAMP POA&M Transformation Engine ([`scripts/transform_scans.py`](../scripts/transform_scans.py) / `./grc transform`) for **Tenable** and **AWS Inspector** `.csv`/`.xlsx` scan exports; bundled official [`OPEN FedRAMP-POAM-Template.xlsx`](../templates/OPEN%20FedRAMP-POAM-Template.xlsx) and [`CLOSED LEGACY FedRAMP-POAM-Template.xlsx`](../templates/CLOSED%20LEGACY%20FedRAMP-POAM-Template.xlsx); implemented Open $\rightarrow$ Closed POA&M reconciliation, interactive `[y/n]` remediation plan URL drafting (Tenable Plugin, AWS ALAS, Inspector & NVD links), and SLA breach / finding age reporting; added standalone analyst guide; updated roadmap (swapped `Misawa` `v1.2.0` & `Sasebo` `v1.3.0`; moved Cloud Lift & Local LLM baseline to `v2.1.0+ — Kaneohe`). | Byron Turner |
| **`v1.1.0`<br/>(`Kadena`)** | `b2eea63` | `2026-10-20` | `Minor Release` | `INSTALL.md`, `COMMANDS.md`, `assets/logo/*`, `./grc`, `README.md`, `SECURITY.md`, `docs/*`, `hygiene/*`, `amplifying-info/*`, `testing/*`, `scripts/*` | Rebranded platform to **GRCx — "The GRC eXperience"** across all active documentation, CLI wrappers, and analyzer metadata; added dedicated onboarding guide ([`INSTALL.md`](../INSTALL.md), including viewing outputs in Cursor) and CLI reference ([`COMMANDS.md`](../COMMANDS.md)); removed 3 redundant legacy `docs/` files and slimmed down `README.md`; added Light/Dark seagull-escaping-square brand lockups (`assets/logo/`) and updated `grcfetch` CLI banner to `GRCx v1.1.0 (Kadena)`. | Byron Turner |
