# GRC-xMINI — Installation & Quickstart Guide (`INSTALL.md`)

<p align="center">
  <a href="README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="INSTALL.md"><b>⚙️ Install Guide</b></a> &nbsp;·&nbsp;
  <a href="COMMANDS.md"><b>⌨️ CLI Commands</b></a> &nbsp;·&nbsp;
  <a href="amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="testing/TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="testing/live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="hygiene/RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="hygiene/PATCH_LOG.md"><b>🩹 v1 Patch Log</b></a> &nbsp;·&nbsp;
  <a href="hygiene/ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="docs/transform_scans-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="docs/grc_bundle-guide.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="docs/grc-xtest-guide.md"><b>🎯 GRC-xTEST Guide</b></a>
</p>

> **Purpose**: A step-by-step onboarding guide for new users—from downloading **GRCx** (*The GRC eXperience*) off GitHub and building the local scanner container, all the way to running your first audit and inspecting the compliance reports in **Cursor**.

---

## Step 1: Verify Prerequisites

Before downloading **GRCx**, confirm your workstation has the four required tools installed and that **Docker Desktop** (or **OrbStack** / Linux Docker Engine) is running:

| Tool | Minimum Version | Purpose | Verify Command |
| :--- | :--- | :--- | :--- |
| **Git** | `2.30+` | Downloads the repo and verifies/extracts `.bundle` files | `git --version` |
| **Python 3** | `3.9+` | Runs host orchestration & **`transform_scans.py`** (uses `100%` standard library—no `pip install` needed) | `python3 --version` *(macOS/Linux)*<br/>`python --version` *(Windows)* |
| **Docker** *(Bundle/AMI Scans Only)* | `24.0+` | Runs the air-gapped 9-engine scanner container (`grc-scanner:local`). **Not required for `transform_scans.py` (`./grc transform`).** | `docker info` |
| **Cursor** | Latest | Used to open the workspace and view rendered Markdown & JSON audit deliverables | `cursor --version` *(optional CLI)* |

> [!TIP]
> **Only Using the Scan-to-POA&M Transformer (`transform_scans.py`)?**
> You do **NOT** need to start or install **Docker** to run the Tenable / AWS Inspector Scan-to-FedRAMP POA&M transformation engine (`scripts/transform_scans.py`). It executes natively on **macOS, Linux, and Windows (PowerShell / Command Prompt / Git Bash / WSL2)** using only **Python 3.9+**. You only need Docker running if you are executing Step 3 (`./grc docker-build`) or Step 4B (`./grc scan`) against a `.bundle` or `AMI`.

---

## Step 2: Download `GRCx` from GitHub

Open your terminal (`zsh` or `bash`) and navigate to the directory where you want to store the project (for example, `~/Desktop`):

```bash
cd ~/Desktop
```

### Option A: Clone Directly from GitHub (Standard Network)
Clone the **GRCx** repository (and optionally the companion **GRC-xTEST** repository if you want synthetic test bundles and scan fixtures to practice with):

```bash
git clone https://github.com/eodartintlabs-hue/grc-x.git GRC-x
git clone https://github.com/eodartintlabs-hue/grc-xtest.git GRC-xTEST
```

### Option B: Clone from a Portable `.bundle` File (Self-Hosted / Air-Gapped Transfer)
If you received **GRCx** as a portable Git bundle file (e.g., `grcx-v1.4.1.bundle`), verify and clone directly from the file with zero network access:

```bash
git bundle verify grcx-v1.4.1.bundle
git clone grcx-v1.4.1.bundle GRC-x
```

---

## Step 3: Set Up the CLI & Build the Scanner Image

1. **Enter the repository directory and ensure `./grc` is executable**:
   ```bash
   cd ~/Desktop/GRC-x
   chmod +x ./grc
   ```

2. **Verify the CLI is working by displaying the `GRCx` system banner**:
   ```bash
   ./grc fetch
   ```

3. **Build the local `grc-scanner:local` Docker container image**:
   This one-time setup step packages Semgrep, Gitleaks, Checkov, Syft, Grype, Trivy, OpenSCAP, and offline vulnerability databases into a local container image so all future scans run **100% offline (`--network none`)**:
   ```bash
   ./grc docker-build
   ```
   *(Note: If you skip this step, `./grc scan` will automatically build `grc-scanner:local` on your first scan.)*

---

## Step 4: Run Your First Workflow

**GRCx** supports two primary workflows depending on your role:

### Workflow A: Standalone Scan-to-FedRAMP POA&M Transformation (`transform_scans.py`)
> **Does NOT require Docker or a `.bundle` file**: Because `scripts/transform_scans.py` uses **100% Python 3 Standard Library** modules, you do **not** need to start the Docker container to run it. Simply drop your scan files (`.csv`/`.xlsx`) and previous OPEN POA&M (`.xlsx`) into the **`artifacts/drop-off/`** folder at the repository root!

#### 🍎 macOS / 🐧 Linux / 🪟 Windows WSL2
Drop your files into **`artifacts/drop-off/`** and run `./grc transform` interactively (or pass just the filenames):

```bash
# Interactive Drop-In Mode (lists files in scans/ by number, prompts to add up to 5 scans):
./grc transform

# Or One-Line CLI Mode (resolves filenames automatically from scans/):
./grc transform \
  --scan tenable_monthly_scan.csv \
  --previous-open previous_open_poam.xlsx \
  --draft-remediations y
```

#### 🪟 Windows Users (Native PowerShell, Command Prompt & Git Bash — No WSL2 or Docker Required)
Because `./grc` is a Bash script, native Windows users in **PowerShell** or **Command Prompt (`cmd.exe`)** drop their files into **`scans\`** and invoke `scripts\transform_scans.py` directly with Python 3 (`python` or `py -3`):

* **Interactive Drop-In Mode (PowerShell or Command Prompt)** — *Automatically lists files in `scans\` by number (`[1]`, `[2]`) and prompts you step-by-step*:
  ```powershell
  python .\scripts\transform_scans.py
  ```
* **One-Line CLI Mode (PowerShell / Command Prompt)**:
  ```powershell
  python .\scripts\transform_scans.py --scan tenable_monthly_scan.csv --previous-open previous_open_poam.xlsx --draft-remediations y
  ```
* **Git Bash on Windows**:
  ```bash
  python scripts/transform_scans.py --scan tenable_monthly_scan.csv --previous-open previous_open_poam.xlsx --draft-remediations y
  ```

This generates `OPEN FedRAMP-POAM.xlsx`, `CLOSED FedRAMP-POAM.xlsx`, and `poam_transform_summary.md` inside `./evidence/poam-tenable_monthly_scan/` while printing an itemized SLA Breach & Finding Age report to your terminal. *(See **[`docs/transform_scans-guide.md`](docs/transform_scans-guide.md)** for full details).*

### Workflow B: 5-Phase Git `.bundle` Compliance Audit (`./grc bundle` + `./grc scan`)
Follow the 5-phase **GRCx** workflow to audit a `.bundle` file (the example below uses the 4-in-1 synthetic test bundle from `../GRC-xTEST`, or you can substitute `/path/to/your-release.bundle`):

```bash
# 1. Verify bundle integrity and record its SHA-256 hash
./grc bundle verify ../GRC-xTEST/bundles/aoc-combo-4x.bundle

# 2. Restore the bundle into an isolated, read-only ephemeral workspace
./grc bundle restore ../GRC-xTEST/bundles/aoc-combo-4x.bundle \
  --workspace ./ephemeral_workspace \
  --read-only \
  --force

# 3. Run all 9 compliance engines + Phase 4 report synthesis
./grc scan --all -w ./ephemeral_workspace

# 4. Clean up the ephemeral workspace when finished
./grc bundle clean --workspace ./ephemeral_workspace
```

When `./grc scan` finishes, all generated audit deliverables are saved inside `./evidence/<bundle-name>/` (for example, `./evidence/aoc-combo-4x/`).

---

## Step 5: View the Output Files in Cursor

Once your scan is complete, open the repository in **Cursor** to inspect the human-readable Markdown work papers and machine-readable JSON evidence:

### 1. Open the Project in Cursor
* **From your terminal**:
  ```bash
  cursor ~/Desktop/GRC-x
  ```
* **Or from the Cursor app menu**:
  Click **File $\rightarrow$ Open Folder...**, select `GRC-x`, and click **Open**.

### 2. Locate Your Audit Deliverables in the Cursor Sidebar
In Cursor's left-hand **Explorer** sidebar (`Cmd+Shift+E` on macOS / `Ctrl+Shift+E` on Windows & Linux), expand the **`evidence/`** folder (or **`testing/demo-evidence/`** for pre-generated sample outputs) and click into your bundle's folder (e.g., `evidence/aoc-combo-4x/`):

```text
evidence/<bundle-name>/
├── poam_data.md              # 📋 Executive Risk Summary & FedRAMP POA&M Table (30/60/90-day SLAs)
├── controls.md               # 🛡️ NIST SP 800-53 Rev. 5 Control Pass/Fail Traceability Matrix
├── ruleset_validation.md     # 📏 Itemized Audit Log of all 37 Custom Semgrep AST Rules
├── stig_matrix.md            # 🏛️ DISA STIG & DoD Cloud SRG Applicability Matrix
├── scr_scn_package.json      # 📦 Unified Machine-Readable eMASS / ServiceNow / Archer Payload
├── bundle_provenance.json    # 🔐 Cryptographic Chain-of-Custody & Git Commit Provenance
└── sha256sum                 # 🔏 Tamper-Evident SHA-256 Seal of All Deliverables
```

### 3. Render the Markdown Reports in Cursor (Formatted View)
By default, clicking a `.md` file (`poam_data.md`, `controls.md`, `ruleset_validation.md`, or `stig_matrix.md`) opens the raw Markdown source. To view the formatted tables, badges, and status icons:

1. Click on **`poam_data.md`** in the Cursor Explorer.
2. Open **Markdown Preview**:
   * **macOS Shortcut**: Press **`Cmd + Shift + V`** (or **`Cmd + K` then `V`** to open the formatted preview side-by-side).
   * **Windows / Linux Shortcut**: Press **`Ctrl + Shift + V`** (or **`Ctrl + K` then `V`** for side-by-side preview).
   * **Mouse Option**: Right-click the `poam_data.md` tab at the top of the editor and select **"Open Preview"** (or click the **Open Preview to the Side** icon in the top-right corner of the editor tab bar).

### 4. Inspect Raw Scanner Telemetry & JSON Packages
To drill down into raw scanner outputs (`scr_scn_package.json`, `semgrep_findings.json`, `checkov_findings.json`, `crypto_findings.json`, or `sbom.cdx.json`):
* Click any `.json` file in Cursor.
* Use **`Cmd + F`** (`Ctrl + F`) to search by POA&M ID (`POAM-001`), NIST control (`IA-2`, `SI-4`, `SC-13`), or file path.
* Use Cursor's code-folding arrows in the left gutter to collapse or expand individual findings arrays.

---

> ⌨️ **Next Step**: Need to look up a specific command or run a single scanner engine? See **[`COMMANDS.md`](COMMANDS.md)** for a complete, plain-English reference of every command **GRCx** accepts.
