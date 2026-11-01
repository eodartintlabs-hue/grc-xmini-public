# Standalone Scan-to-FedRAMP POA&M Transformation Guide (`docs/transform_scans-guide.md`)

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
  <a href="../hygiene/PATCH_LOG.md"><b>🩹 Patch Log Index</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/RELEASING.md"><b>🏷️ Releasing</b></a> &nbsp;·&nbsp;
  <a href="transform_scans-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="grc_bundle-guide.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="grc-xtest-guide.md"><b>🎯 GRC-xTEST Guide</b></a>
</p>

> **Engine**: [`scripts/transform_scans.py`](../scripts/transform_scans.py) · **CLI Command**: `./grc transform`  
> **Release Series**: `v1.3.4 — Sasebo` *(Introduced in `v1.2.0 — Misawa`, enhanced with `scans/` drop-in folder in `v1.3.0 — Sasebo`, multi-scan ingestion in `v1.3.2 — Sasebo`, dynamic `YYYY-MMM-#####` POA&M IDs in `v1.3.3 — Sasebo`)*  
> **Execution Mode**: **100% Standalone** *(Requires only Python 3.9+ Standard Library — no Docker container, no `.bundle` file, and no `pip install` needed)*

---

## Table of Contents

1. [Why `transform_scans.py` Is Designed as a Standalone Engine](#1-why-transform_scanspy-is-designed-as-a-standalone-engine)
2. [Prerequisites, Workstation Desktop Navigation & Docker Isolation](#2-prerequisites-workstation-desktop-navigation--docker-isolation)
   * [2.1 Workstation Terminal / Command Prompt Navigation](#21-workstation-terminal--command-prompt-navigation)
   * [2.2 Do I Need Docker?](#22-do-i-need-docker)
   * [2.3 The Designated `scans/` Drop-In Folder](#23-the-designated-scans-drop-in-folder-zero-path-copy-pasting)
3. [How Windows Users Use the `transform_scans` Engine](#3-how-windows-users-use-the-transform_scans-engine)
   * [3.1 Native PowerShell or Command Prompt (Interactive Mode)](#31-native-powershell-or-command-prompt-interactive-mode)
   * [3.2 One-Line Command Prompt / PowerShell CLI Mode](#32-one-line-command-prompt--powershell-cli-mode)
   * [3.3 Git Bash on Windows](#33-git-bash-on-windows)
   * [3.4 Windows Subsystem for Linux (WSL2)](#34-windows-subsystem-for-linux-wsl2)
4. [How macOS Users Use the `transform_scans` Engine](#4-how-macos-users-use-the-transform_scans-engine)
   * [4.1 Interactive Drop-In Mode (`./grc transform`)](#41-interactive-drop-in-mode-recommended-for-analyst-workflow)
   * [4.2 Non-Interactive One-Line CLI Mode](#42-non-interactive-one-line-cli-mode)
   * [4.3 Combining Multiple Scans (Up to 5 Scans)](#43-combining-multiple-scans-up-to-5-scans)
5. [What Happens Under the Hood: The 5 Automated GRC Functions](#5-what-happens-under-the-hood-the-5-automated-grc-functions)
   * [5.1 27-Column FedRAMP Mapping (1 Row per Vulnerability + Asset)](#51-27-column-fedramp-mapping-1-row-per-vulnerability--asset)
   * [5.2 Open -> Closed Reconciliation with Verified Host Auto-Closure](#52-open---closed-reconciliation-with-verified-host-auto-closure)
   * [5.3 SLA Breach & Finding Age Calculation](#53-sla-breach--finding-age-calculation)
   * [5.4 Interactive Remediation Plan URL Drafting](#54-interactive-remediation-plan-url-drafting)
   * [5.5 Dynamic FedRAMP `YYYY-MMM-#####` POA&M ID Numbering](#55-dynamic-fedramp-yyyy-mmm--poam-id-numbering)
6. [Sample Terminal & Command Prompt Output: SLA Breach & Finding Age Report](#6-sample-terminal--command-prompt-output-sla-breach--finding-age-report)
7. [Expected Output Files & Where to Find Them](#7-expected-output-files--where-to-find-them)

---

## 1. Why `transform_scans.py` Is Designed as a Standalone Engine

Unlike internal pipeline engines such as `crypto_lib_scan.py` or `sbom_analyzer.py`—which run as automated containerized stages inside the 5-phase `.bundle` or `AMI` review lifecycle—**`transform_scans.py` (`./grc transform`) is built to be used directly and independently by GRC analysts** during monthly or weekly Continuous Monitoring (ConMon) cycles.

In day-to-day federal, defense, and enterprise compliance operations, GRC analysts frequently receive raw **Tenable (Nessus / Tenable.sc / Tenable.io)** or **AWS Inspector** vulnerability scan exports in `.csv` or `.xlsx` format and must manually:
1. Map thousands of scanner rows into the 27 columns of the official **OPEN FedRAMP POA&M template (`.xlsx`)**.
2. Compare the new scan against last month's filled-out **OPEN FedRAMP POA&M** to determine which items are still open (and must preserve their immutable `Original Detection Date`) versus which items have been remediated and must move to the **CLOSED FedRAMP POA&M template (`.xlsx`)**.
3. Track down official Tenable or AWS remediation links for any POA&M entries missing a **Remediation Plan (`Column K`)**.
4. Calculate how many days old each finding is from its `Original Detection Date` and identify how many entries have breached their **FedRAMP SLA (`Scheduled Completion Date`)**.

**`./grc transform`** automates this entire workflow in seconds from a single command.

---

## 2. Prerequisites, Workstation Desktop Navigation & Docker Isolation

### 2.1 Workstation Terminal / Command Prompt Navigation
When using GRCx, the project folder typically resides directly on the user's **Desktop** (`Desktop/GRC-x`). Before executing commands, open your system shell and navigate to the project directory:

#### 🪟 Windows (Command Prompt `cmd.exe`)
Open **Command Prompt** (search `cmd` in the Start Menu) and navigate to the Desktop folder:
```cmd
cd %USERPROFILE%\Desktop\GRC-x
```

#### 🪟 Windows (PowerShell)
Open **PowerShell** and navigate to the Desktop folder:
```powershell
cd $HOME\Desktop\GRC-x
```

#### 🍎 macOS (Terminal)
Open **Terminal** (`Cmd + Space`, type `Terminal`) and navigate to the Desktop folder:
```bash
cd ~/Desktop/GRC-x
```

---

### 2.2 Do I Need Docker?
**No.** You do **not** need Docker running—or even installed—to run `transform_scans.py`:
* **[`scripts/transform_scans.py`](../scripts/transform_scans.py)** is written using **100% Python 3 Standard Library modules** (`csv`, `zipfile`, `xml.etree.ElementTree`, `datetime`, `re`, `argparse`, `pathlib`).
* When you run `./grc transform` or invoke `scripts/transform_scans.py` directly, it executes natively on your host workstation and never calls `docker`.
* Docker (`grc-scanner:local`) is only required when running Phase 3 source code or virtual machine containerized scanners (`./grc scan`).

---

### 2.3 The Designated `scans/` Drop-In Folder (Zero Path Copy-Pasting)
Instead of hunting for absolute file paths and copy-pasting long directory strings into the terminal, **GRCx** includes a designated **`scans/`** folder at the root of the repository:
1. **Drop your files into `scans/`**: Drag and drop your Tenable or AWS Inspector scan export (`.csv` or `.xlsx`) and your previous month's `OPEN FedRAMP-POAM.xlsx` (if reconciling) directly into the **`scans/`** directory.
2. **Run `./grc transform` (or `python .\scripts\transform_scans.py`)**:
   * **GRCx** automatically scans `scans/` and displays a **numbered list** of detected files (`[1]`, `[2]`, etc.).
   * Select a file simply by typing its **number** (e.g., `1`) OR typing its **filename** (with or without the `.csv`/`.xlsx` extension, e.g., `tenable_monthly_scan`).
   * Even on the command line (`--scan` / `--previous-open`), you only need to pass the filename (e.g., `--scan my_scan.csv` or `--scan my_scan`)—**GRCx** automatically looks inside `scans/` first!

---

## 3. How Windows Users Use the `transform_scans` Engine

Because `scripts/transform_scans.py` uses cross-platform `os.path` and `pathlib` handling and requires zero third-party packages, Windows GRC analysts can run it natively without WSL2 or Docker.

### 3.1 Native PowerShell or Command Prompt (Interactive Mode)
A Windows user only needs **Python 3.9+** installed (available from `python.org` or the Microsoft Store). 

1. Open **Command Prompt** or **PowerShell** and navigate to your desktop folder:
   ```cmd
   cd %USERPROFILE%\Desktop\GRC-x
   ```
2. Drop your scan and previous POA&M files into the **`scans\`** folder.
3. Run the engine interactively:
   ```powershell
   python .\scripts\transform_scans.py
   ```
   *(or `py -3 .\scripts\transform_scans.py` using the Windows Python Launcher)*
4. Follow the numbered prompts to select your primary scan file, optionally add additional scans (up to 5 scans total), select your previous OPEN POA&M, and approve remediation URL drafting.

### 3.2 One-Line Command Prompt / PowerShell CLI Mode
For repeatable monthly auditing or scripting, pass arguments directly:

**Command Prompt (`cmd.exe`)**:
```cmd
python scripts\transform_scans.py --scan tenable_monthly_scan.csv --scan aws_inspector_scan.csv --previous-open previous_open_poam.xlsx --draft-remediations y
```

**PowerShell**:
```powershell
python .\scripts\transform_scans.py `
  --scan tenable_monthly_scan.csv `
  --scan aws_inspector_scan.csv `
  --previous-open previous_open_poam.xlsx `
  --draft-remediations y
```

### 3.3 Git Bash on Windows
If Git for Windows is installed, open **Git Bash** on your Desktop:
```bash
cd ~/Desktop/GRC-x
python scripts/transform_scans.py --scan tenable_monthly_scan.csv --previous-open previous_open_poam.xlsx --draft-remediations y
```

### 3.4 Windows Subsystem for Linux (WSL2)
Inside WSL2 (Ubuntu/Debian), the `./grc` shell wrapper runs natively:
```bash
cd ~/Desktop/GRC-x
./grc transform --scan tenable_monthly_scan.csv --previous-open previous_open_poam.xlsx --draft-remediations y
```

---

## 4. How macOS Users Use the `transform_scans` Engine

macOS analysts execute the engine using the root `./grc` CLI dispatcher or direct Python invocation.

### 4.1 Interactive Drop-In Mode (Recommended for Analyst Workflow)
1. Open **Terminal** and navigate to your desktop folder:
   ```bash
   cd ~/Desktop/GRC-x
   ```
2. Drop your scan export (`.csv` or `.xlsx`) and previous OPEN POA&M (`.xlsx`) into the **`scans/`** folder.
3. Run `./grc transform` with no arguments:
   ```bash
   ./grc transform
   ```
4. **Interactive Prompts**:
   * **Primary Scan Selection**:
     ```text
     === GRCx Standalone FedRAMP POA&M Scan Transformer ===
       [*] Scan / Workbook files (.csv, .xlsx) detected in 'scans/':
           [1] aws_inspector_scan.csv
           [2] previous_open_poam.xlsx
           [3] tenable_monthly_scan.csv
     [?] Select scan file by number [1-3] or enter filename in scans/ (.csv/.xlsx): 3
     [+] Added scan [1/5]: tenable_monthly_scan.csv
     ```
   * **Additional Scan Files Prompt (Up to 5 Scans)**:
     ```text
     [?] Would you like to add an additional scan file to also be transformed? [y/N]: y
       [*] Additional scan files (.csv, .xlsx) [Scan 2/5] detected in 'scans/':
           [1] aws_inspector_scan.csv
           [2] previous_open_poam.xlsx
     [?] Select additional scan file #2 by number [1-2] or enter filename in scans/ (.csv/.xlsx): 1
     [+] Added scan [2/5]: aws_inspector_scan.csv

     [?] Would you like to add an additional scan file to also be transformed? [y/N]: n
     ```
   * **Previous OPEN POA&M Prompt**:
     ```text
       [*] Previous POA&M workbooks (.xlsx) detected in 'scans/':
           [1] previous_open_poam.xlsx
     [?] Select previous OPEN FedRAMP POA&M by number [1-1], enter filename in scans/,
         or press Enter if none (initial baseline): 1
     ```
   * **Remediation Plan URL Drafting Prompt**:
     ```text
     [!] 5 of 6 OPEN POA&M entries are missing a Remediation Plan (Column K).
         Would you like GRCx to draft missing remediation plans with official Tenable/AWS remediation links? (y/n): y
     ```

### 4.2 Non-Interactive One-Line CLI Mode
Pass filenames directly for non-interactive execution:
```bash
./grc transform \
  --scan tenable_monthly_scan.csv \
  --previous-open previous_open_poam.xlsx \
  --draft-remediations y
```

### 4.3 Combining Multiple Scans (Up to 5 Scans)
Ingest up to 5 scans simultaneously into the exact same POA&M tracker:
```bash
./grc transform \
  --scan tenable_monthly_scan.csv \
  --scan aws_inspector_scan.csv \
  --previous-open previous_open_poam.xlsx \
  --draft-remediations y \
  --output-dir ./evidence/poam-consolidated-cycle
```

---

## 5. What Happens Under the Hood: The 5 Automated GRC Functions

### 5.1 27-Column FedRAMP Mapping (1 Row per Vulnerability + Asset)
`transform_scans.py` loads the official FedRAMP Excel templates bundled in [`templates/`](../templates/):
* **[`templates/OPEN FedRAMP-POAM-Template.xlsx`](../templates/OPEN%20FedRAMP-POAM-Template.xlsx)** (*Sheet: `Open POA&M Items`, Columns `B` through `AB`, data starting at `Row 5`*)
* **[`templates/CLOSED LEGACY FedRAMP-POAM-Template.xlsx`](../templates/CLOSED%20LEGACY%20FedRAMP-POAM-Template.xlsx)** (*Sheet: `Closed POA&M Items`, Columns `A` through `AA`, data starting at `Row 3`*)

Each unique `(Vulnerability Source ID + Asset Identifier)` pair is normalized into a distinct POA&M row. Informational/None scanner rows are excluded from POA&M creation. `Scheduled Completion Date` (`Column M`) is computed using both embedded Excel formulas and cached serial numbers:
* **`Critical` / `High`**: `Original Detection Date + 30 days`
* **`Moderate`** (*including scanner `Medium`*): `Original Detection Date + 90 days`
* **`Low`**: `Original Detection Date + 180 days`

### 5.2 Open -> Closed Reconciliation with Verified Host Auto-Closure
When a previous `OPEN FedRAMP-POAM.xlsx` is provided:
* **Carried-Over Open Items**: Findings appearing in both the previous OPEN POA&M and the new scan preserve their existing `POAM ID`, **immutable `Original Detection Date` (`Column L`)**, and analyst notes (`Controls`, `Point of Contact`, `Remediation Plan`), while updating `Status Date` (`Column N`).
* **Newly Detected Open Items**: Findings appearing in the scan that were not in the previous POA&M receive a new sequential dynamic `POAM ID` (`YYYY-MMM-#####`) and a fresh detection date.
* **Verified Auto-Closure**: Findings from the previous POA&M whose host was actively scanned in the new assessment (verified via Tenable Plugin `19506` or AWS Inspector host presence) and are no longer found move to `CLOSED FedRAMP-POAM.xlsx` with closure notes.
* **Host Not Scanned Retention**: Findings whose host was **not** observed in the scan are retained in `OPEN` with a `[Review Required: Asset was not observed in the latest scan]` flag to prevent premature or fraudulent auto-closure of offline assets.
* **Approved False Positives**: Entries marked `False Positive = Yes` in the previous OPEN POA&M automatically move to CLOSED.

### 5.3 SLA Breach & Finding Age Calculation
The engine evaluates finding ages (`Today - Original Detection Date`) and SLA statuses:
* Identifies all findings where `Scheduled Completion Date < Today`.
* Reports the exact overdue duration in days for every overdue item.

### 5.4 Interactive Remediation Plan URL Drafting
When enabled, Column K is populated with direct URLs to vendor remediation documentation:
* **Tenable Nessus / SecurityCenter**: `https://www.tenable.com/plugins/nessus/<Plugin_ID>`
* **AWS Inspector / Amazon Linux**: `https://explore.alas.aws.amazon.com/<ALAS_ID>.html`
* **NVD CVE Repository**: `https://nvd.nist.gov/vuln/detail/<CVE_ID>`

### 5.5 Dynamic FedRAMP `YYYY-MMM-#####` POA&M ID Numbering
Newly detected POA&M items are assigned dynamic IDs following the standard:
```text
YYYY-MMM-#####
```
*(Example: `2026-SEP-00347` or `2026-OCT-00001`)*
* **`YYYY`**: 4-digit assessment year.
* **`MMM`**: Deterministic 3-letter English month abbreviation (`MONTH_ABBRS`: `JAN` .. `DEC`).
* **`#####`**: Strictly monotonic 5-digit zero-padded sequence number continuing past the highest ID in existing OPEN and CLOSED workbooks.

---

## 6. Sample Terminal & Command Prompt Output: SLA Breach & Finding Age Report

Running a transformation outputs the itemized SLA Breach & Aging table directly in your shell:

```text
[*] Ingesting findings from 1 scan file(s)...
  [1/1] 'tenable_monthly_scan.csv': 75 rows (Source: TENABLE, Scanned host identifiers: 30)
[*] Loaded 5 existing entries from previous OPEN POA&M: previous_open_poam.xlsx
[+] Drafted 5 Remediation Plans with official TENABLE remediation URLs.

================================================================================================
  GRCx (v1.3.4 — Sasebo) · FEDRAMP POA&M TRANSFORMATION & SLA AGING REPORT
================================================================================================
  Analysis Reference Date : 2026-10-31
  Source Scan File(s)     : tenable_monthly_scan.csv (1 file)
  Finished OPEN POA&M     : evidence/poam-tenable_monthly_scan/OPEN FedRAMP-POAM.xlsx
  Finished CLOSED POA&M   : evidence/poam-tenable_monthly_scan/CLOSED FedRAMP-POAM.xlsx
------------------------------------------------------------------------------------------------
  • Total Active OPEN POA&M Entries   : 65  (5 Carried Over, 60 Newly Detected)
  • Entries Moved OPEN -> CLOSED      : 2   (Total in Closed Workbook: 2)
  • OPEN Entries w/ PASSED SLA Date   : 28 of 65 (ACTION REQUIRED — SLA BREACH)
================================================================================================

  ITEMIZED OPEN POA&M AGING & SLA STATUS:
  POAM ID         | Risk     | Orig. Detected | Age (Days Old)   | SLA Due Date | SLA Status
  --------------------------------------------------------------------------------------------
  2026-SEP-00347  | Critical | 2026-06-05     | 148 days old     | 2026-07-05   | 🚨 PASSED SLA (118 days overdue)
  2026-SEP-00348  | High     | 2026-06-05     | 148 days old     | 2026-07-05   | 🚨 PASSED SLA (118 days overdue)
  2026-OCT-00001  | Moderate | 2026-06-05     | 148 days old     | 2026-09-03   | 🚨 PASSED SLA (58 days overdue)
  2026-OCT-00002  | Moderate | 2026-09-10     | 51 days old      | 2026-12-09   | ✅ Within SLA (39 days remaining)
  2026-OCT-00003  | Low      | 2026-09-25     | 36 days old      | 2027-03-24   | ✅ Within SLA (144 days remaining)

  ENTRIES MOVED FROM OPEN -> CLOSED FEDRAMP POA&M IN THIS CYCLE:
    • 2026-AUG-00102 | SSH Weak Key Exchange Algorithms Enabled | Asset: 10.42.10.25 (22/TCP) | Closed: 2026-10-31
    • 2026-AUG-00105 | NGINX HTTP/2 Rapid Reset DoS Vuln       | Asset: 10.42.10.30 (443/TCP) | Closed: 2026-10-31
================================================================================================
```

---

## 7. Expected Output Files & Where to Find Them

Every transformation run writes three deliverables into `--output-dir` (default: `evidence/poam-<scan-name>/`):

| Output File | Format | Purpose |
| :--- | :--- | :--- |
| **`OPEN FedRAMP-POAM.xlsx`** | Excel (`.xlsx`) | Official FedRAMP Open POA&M workbook populated with all active findings (`Columns B..AB`, `Row 5+`), preserved detection dates, auto-calculating SLA formulas, dynamic `YYYY-MMM-#####` IDs, and drafted Tenable/AWS remediation URLs. |
| **`CLOSED FedRAMP-POAM.xlsx`** | Excel (`.xlsx`) | Official FedRAMP Closed POA&M workbook (`Columns A..AA`, `Row 3+`) containing all previously open entries verified as remediated in the new scan. |
| **`poam_transform_summary.md`** | Markdown (`.md`) | Human-readable SLA Breach & Finding Age summary table that can be previewed directly inside **Cursor** (`Cmd+Shift+V` / `Ctrl+Shift+V`). |

All files can be accessed immediately on your workstation under:
* **macOS / Linux**: `~/Desktop/GRC-x/evidence/poam-<scan-name>/`
* **Windows**: `%USERPROFILE%\Desktop\GRC-x\evidence\poam-<scan-name>\`
