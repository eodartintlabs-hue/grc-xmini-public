# Standalone Scan-to-FedRAMP POA&M Transformation Guide (`docs/scan-transform-guide.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../INSTALL.md"><b>⚙️ Install Guide</b></a> &nbsp;·&nbsp;
  <a href="../COMMANDS.md"><b>⌨️ CLI Commands</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="../testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="../testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/PATCH_LOG.md"><b>🩹 v1 Patch Log</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="scan-transform-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="grc-bundle-use-case.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Engine**: [`scripts/transform_scans.py`](../scripts/transform_scans.py) · **CLI Command**: `./grc transform`  
> **Release Series**: `v1.3.3 — Sasebo` *(Introduced in `v1.2.0 — Misawa`, enhanced with `scans/` drop-in folder in `v1.3.0 — Sasebo`, multi-scan ingestion in `v1.3.2 — Sasebo`, dynamic `YYYY-MMM-#####` POA&M IDs in `v1.3.3 — Sasebo`)*  
> **Execution Mode**: **100% Standalone** *(Requires only Python 3.9+ Standard Library — no Docker container, no `.bundle` file, and no `pip install` needed)*

---

## 1. Why `transform_scans.py` Is Designed as a Standalone Engine

Unlike internal pipeline engines such as `crypto_lib_scan.py` or `sbom_analyzer.py`—which typically run as automated stages inside the 5-phase `.bundle` or `AMI` review lifecycle—**`transform_scans.py` (`./grc transform`) is built to be used directly and independently by GRC analysts** during monthly or weekly Continuous Monitoring (ConMon) cycles.

In day-to-day federal and defense compliance operations, GRC analysts frequently receive raw **Tenable (Nessus / Tenable.sc / Tenable.io)** or **AWS Inspector** vulnerability scan exports in `.csv` or `.xlsx` format and must manually:
1. Map thousands of scanner rows into the 27 columns of the official **OPEN FedRAMP POA&M template (`.xlsx`)**.
2. Compare the new scan against last month's filled-out **OPEN FedRAMP POA&M** to determine which items are still open (and must preserve their immutable `Original Detection Date`) versus which items have been remediated and must move to the **CLOSED FedRAMP POA&M template (`.xlsx`)**.
3. Track down official Tenable or AWS remediation links for any POA&M entries missing a **Remediation Plan (`Column K`)**.
4. Calculate how many days old each finding is from its `Original Detection Date` and identify how many entries have breached their **FedRAMP SLA (`Scheduled Completion Date`)**.

**`./grc transform`** automates this entire workflow in seconds from a single command.

---

## 2. Do I Need Docker? & How to Run on Windows, macOS, and Linux

### 🐳 Does the User Need to Start the Docker Container?
**No.** You do **not** need Docker running—or even installed—to run `transform_scans.py`:
* **[`scripts/transform_scans.py`](../scripts/transform_scans.py)** is written using **100% Python 3 Standard Library modules** (`csv`, `zipfile`, `xml.etree.ElementTree`, `datetime`, `re`).
* When you run `./grc transform` or invoke `scripts/transform_scans.py` directly, it executes natively on your host workstation and never calls `docker`.
* Docker (`grc-scanner:local`) is only used when running Phase 3 code/image scanners (`./grc scan`).

---

### 📁 The Designated `scans/` Drop-In Folder (Zero Path Copy-Pasting)
Instead of hunting for file paths and copy-pasting long directory strings into the terminal, **GRCx** includes a designated **`scans/`** folder at the root of the repository:
1. **Drop your files into `scans/`**: Drag and drop your Tenable or AWS Inspector scan export (`.csv` or `.xlsx`) and your previous month's `OPEN FedRAMP-POAM.xlsx` (if reconciling) directly into the **`scans/`** directory.
2. **Run `./grc transform` (or `python .\scripts\transform_scans.py`)**:
   * **GRCx** automatically scans `scans/` and displays a **numbered list** of detected files (`[1]`, `[2]`, etc.).
   * Select a file simply by typing its **number** (e.g., `1`) OR typing its **filename** (with or without the `.csv`/`.xlsx` extension, e.g., `tenable_monthly_scan`).
   * Even on the command line (`--scan` / `--previous-open`), you only need to pass the filename (e.g., `--scan my_scan.csv` or `--scan my_scan`)—**GRCx** automatically looks inside `scans/` first!

---

### 🪟 How Windows Users Utilize the Transform Engine
Because `scripts/transform_scans.py` uses cross-platform `os.path` handling and zero third-party packages, a Windows GRC analyst can run it in **three ways**—including **natively in Windows PowerShell or Command Prompt without WSL2 or Docker**:

#### Option 1: Native Windows PowerShell or Command Prompt (`cmd.exe`) — *Simplest for GRC Analysts*
A Windows user only needs **Python 3.9+** installed (from `python.org` or the Microsoft Store). Drop your scan and previous POA&M files into the **`scans\`** folder, then run:

* **Interactive Guided Mode** *(Automatically lists files in `scans\` with numbers `[1]`, `[2]` and prompts for your selection and `[y/n]` remediation URL drafting)*:
  ```powershell
  python .\scripts\transform_scans.py
  ```
  *(or `py -3 .\scripts\transform_scans.py` using the Windows Python Launcher)*
* **One-Line CLI Mode (Using Filenames in `scans\`)**:
  ```powershell
  python .\scripts\transform_scans.py --scan tenable_scan.csv --previous-open "OPEN FedRAMP-POAM.xlsx" --draft-remediations y
  ```

#### Option 2: Git Bash on Windows *(Included with Git for Windows)*
Inside a Git Bash terminal window on Windows, run:
```bash
python scripts/transform_scans.py --scan tenable_scan.csv
```

#### Option 3: Windows Subsystem for Linux (WSL2)
Inside WSL2 (Ubuntu/Debian), `./grc` works identically to macOS and Linux:
```bash
./grc transform --scan tenable_scan.csv
```

---

### 🍎 How macOS & 🐧 Linux Users Run `./grc transform`

#### Option A: Interactive Drop-In Mode (Recommended for Daily Analyst Use)
Drop your scan export (`.csv` or `.xlsx`) and previous OPEN POA&M (`.xlsx`) into the **`scans/`** folder and run `./grc transform` with **no arguments**:

```bash
./grc transform
```

1. **Scan File Selection Prompt (Numbered List, Filename in `scans/`, Multi-Scan Support up to 5 Scans)**:
   ```text
   === GRCx Standalone FedRAMP POA&M Scan Transformer ===
     [*] Scan / Workbook files (.csv, .xlsx) detected in 'scans/':
         [1] aws_inspector_scan.csv
         [2] previous_open_poam.xlsx
         [3] tenable_monthly_scan.csv
   [?] Select scan file by number [1-3] or enter filename in scans/ (.csv/.xlsx): 3
   [+] Added scan [1/5]: tenable_monthly_scan.csv

   [?] Would you like to add an additional scan file to also be transformed? [y/N]: y
     [*] Additional scan files (.csv, .xlsx) [Scan 2/5] detected in 'scans/':
         [1] aws_inspector_scan.csv
         [2] previous_open_poam.xlsx
   [?] Select additional scan file #2 by number [1-2] or enter filename in scans/ (.csv/.xlsx): 1
   [+] Added scan [2/5]: aws_inspector_scan.csv

   [?] Would you like to add an additional scan file to also be transformed? [y/N]: n
   ```
   * Select your first scan by number (e.g., `3` for `tenable_monthly_scan.csv`).
   * Each time a scan is selected, GRCx prompts: `Would you like to add an additional scan file to also be transformed? [y/N]:`.
   * Type **`y`** to ingest up to **5 scan files** simultaneously into the same POA&M tracker without running separate sessions, or press **Enter** / type **`n`** when finished.
2. **Previous POA&M Selection Prompt**:
   ```text
     [*] Previous POA&M workbooks (.xlsx) detected in 'scans/':
         [1] previous_open_poam.xlsx
   [?] Select previous OPEN FedRAMP POA&M by number [1-1], enter filename in scans/,
       or press Enter if none (initial baseline): 1
   ```
   * Type **`1`** (or `previous_open_poam`), or press **Enter** if you are generating a brand-new POA&M baseline.
3. **Missing Remediation Plan Prompt (`[y/n]`)**:
   ```text
   [!] 5 of 6 OPEN POA&M entries are missing a Remediation Plan (Column K).
       Would you like GRCx to draft missing remediation plans with official Tenable/AWS remediation links? (y/n): y
   ```
   * Enter **`y`** to automatically populate `Column K` with a structured remediation action and direct URL links to Tenable's plugin database (`https://www.tenable.com/plugins/nessus/<Plugin_ID>`), AWS ALAS advisories (`https://explore.alas.aws.amazon.com/<ALAS_ID>.html`), AWS Inspector documentation, and NVD CVE records.

#### Option B: Non-Interactive / One-Line CLI Mode
Pass filenames in `scans/` (with or without extensions, or full paths) directly on the command line for repeatable or scripted execution. Pass multiple `--scan` flags (or positional arguments) to combine up to **5 scans** at one time:

```bash
./grc transform \
  --scan tenable_monthly_scan.csv \
  --scan aws_inspector_scan.csv \
  --previous-open previous_open_poam.xlsx \
  --draft-remediations y \
  --output-dir ./evidence/poam-consolidated-oct
```

For an initial baseline with no previous POA&M file, pass `--no-previous`:

```bash
./grc transform \
  --scan aws_inspector_scan.csv \
  --no-previous \
  --draft-remediations y \
  --output-dir ./evidence/poam-inspector-oct
```

---

## 3. What Happens Under the Hood

### 3.1 1-Row-Per-`(Vulnerability + Asset)` Mapping into Official Templates
`transform_scans.py` reads the base templates stored in [`templates/`](../templates/):
* **[`templates/OPEN FedRAMP-POAM-Template.xlsx`](../templates/OPEN%20FedRAMP-POAM-Template.xlsx)** (*Sheet: `Open POA&M Items`, columns `B` through `AB`, data starting at `Row 5`*)
* **[`templates/CLOSED LEGACY FedRAMP-POAM-Template.xlsx`](../templates/CLOSED%20LEGACY%20FedRAMP-POAM-Template.xlsx)** (*Sheet: `Closed POA&M Items`, columns `A` through `AA`, data starting at `Row 3`*)

Each unique `(Vulnerability Source ID + Asset Identifier)` combination is normalized into a dedicated POA&M row. Informational/None rows are automatically excluded, and `Scheduled Completion Date` (`Column M`) is computed using both an embedded Excel formula and cached date serial numbers:
* **`Critical` / `High`**: `Original Detection Date + 30 days`
* **`Moderate`** (*including scanner `Medium`*): `Original Detection Date + 90 days`
* **`Low`**: `Original Detection Date + 180 days`

### 3.2 Open $\rightarrow$ Closed POA&M Reconciliation
When a previously filled-out `OPEN FedRAMP-POAM.xlsx` is supplied:
* **Carried-Over Open Items**: Findings present in both the previous OPEN POA&M and the new scan retain their original `POAM ID`, **never-changing `Original Detection Date` (`Column L`)**, and analyst-curated fields (`Controls`, `Point of Contact`, existing `Remediation Plan`, `Risk Adjustment`, `Deviation Rationale`), while updating `Status Date` (`Column N`).
* **Newly Detected Open Items**: Findings present in the new scan that were not in the previous OPEN POA&M receive the next sequential dynamic `POAM ID` following the FedRAMP `YYYY-MMM-#####` convention (e.g. `2026-SEP-00347` or `2026-OCT-00001`) and a new `Original Detection Date`.
* **Remediated $\rightarrow$ Moved to Closed**: Findings from the previous OPEN POA&M that are **no longer present in the new scan** (or have `False Positive` set to `Yes`) are automatically removed from the `OPEN` workbook and written into `CLOSED FedRAMP-POAM.xlsx` (`Columns A..AA`), with `Status Date` updated to the closure date and a verification timestamp appended to `Comments`.

---

## 4. Sample Terminal Output: SLA Breach & Finding Age Report

Try running the bundled sample Tenable reconciliation right now:

```bash
./grc transform \
  --scan testing/sample-scans/tenable_monthly_scan.csv \
  --previous-open testing/sample-scans/previous_open_poam.xlsx \
  --draft-remediations y
```

**Terminal Output**:
```text
[*] Loaded 7 scan rows from 'tenable_monthly_scan.csv' (Detected source: TENABLE)
[*] Loaded 5 existing entries from previous OPEN POA&M: previous_open_poam.xlsx
[+] Drafted 5 Remediation Plans with official TENABLE remediation URLs.

================================================================================================
  GRCx (v1.3.3 — Sasebo) · FEDRAMP POA&M TRANSFORMATION & SLA AGING REPORT
================================================================================================
  Analysis Reference Date : 2026-10-20
  Finished OPEN POA&M     : evidence/poam-tenable_monthly_scan/OPEN FedRAMP-POAM.xlsx
  Finished CLOSED POA&M   : evidence/poam-tenable_monthly_scan/CLOSED FedRAMP-POAM.xlsx
------------------------------------------------------------------------------------------------
  • Total Active OPEN POA&M Entries   : 6  (3 Carried Over, 3 Newly Detected)
  • Entries Moved OPEN -> CLOSED      : 2  (Total in Closed Workbook: 2)
  • OPEN Entries w/ PASSED SLA Date   : 3 of 6 (ACTION REQUIRED — SLA BREACH)
================================================================================================

  ITEMIZED OPEN POA&M AGING & SLA STATUS:
  POAM ID         | Risk     | Orig. Detected | Age (Days Old)   | SLA Due Date | SLA Status
  --------------------------------------------------------------------------------------------
  POAM-2026-0003  | Moderate | 2026-06-15     | 127 days old     | 2026-09-13   | 🚨 PASSED SLA (37 days overdue)
  POAM-2026-0001  | Critical | 2026-08-05     | 76 days old      | 2026-09-04   | 🚨 PASSED SLA (46 days overdue)
  POAM-2026-0002  | Critical | 2026-08-25     | 56 days old      | 2026-09-24   | 🚨 PASSED SLA (26 days overdue)
  POAM-2026-0007  | Moderate | 2026-09-10     | 40 days old      | 2026-12-09   | ✅ Within SLA (50 days remaining)
  POAM-2026-0008  | Low      | 2026-09-25     | 25 days old      | 2027-03-24   | ✅ Within SLA (155 days remaining)
  POAM-2026-0006  | High     | 2026-10-05     | 15 days old      | 2026-11-04   | ✅ Within SLA (15 days remaining)

  ENTRIES MOVED FROM OPEN -> CLOSED FEDRAMP POA&M IN THIS CYCLE:
    • POAM-2026-0004 | SSH Weak Key Exchange Algorithms Enabled (dif | Asset: 10.42.10.25 (22/TCP) | Closed: 2026-10-20
    • POAM-2026-0005 | NGINX HTTP/2 Rapid Reset DoS Vulnerability (C | Asset: 10.42.10.30 (443/TCP) | Closed: 2026-10-20
================================================================================================
```

---

## 5. Output Files Generated

Every `./grc transform` run writes three deliverables into `--output-dir` (default: `evidence/poam-<scan-name>/`):

| Output File | Format | Purpose |
| :--- | :--- | :--- |
| **`OPEN FedRAMP-POAM.xlsx`** | Excel (`.xlsx`) | Official FedRAMP Open POA&M workbook populated with all active findings (`Columns B..AB`, `Row 5+`), preserved detection dates, auto-calculating SLA formulas, and drafted Tenable/AWS remediation URLs. |
| **`CLOSED FedRAMP-POAM.xlsx`** | Excel (`.xlsx`) | Official FedRAMP Closed POA&M workbook (`Columns A..AA`, `Row 3+`) containing all previously open entries verified as remediated in the new scan. |
| **`poam_transform_summary.md`** | Markdown (`.md`) | Human-readable SLA Breach & Finding Age summary table that can be previewed directly inside **Cursor** (`Cmd+Shift+V` / `Ctrl+Shift+V`). |
