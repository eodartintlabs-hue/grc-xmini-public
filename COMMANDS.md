# GRCx — CLI Command Reference (`COMMANDS.md`)

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
  <a href="docs/scan-transform-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="docs/grc-bundle-use-case.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="docs/test-dummies-guide.md"><b>🎯 Test Dummies Guide</b></a>
</p>

> **Purpose**: A quick-lookup reference of every command accepted by the **`./grc`** CLI dispatcher and a concise explanation of what each command does.

---

## 1. Standalone GRC Analyst Workflow: Scan-to-FedRAMP POA&M Transformation

> [!TIP]
> * **Drop-In `scans/` Folder (No Path Copy-Pasting)**: Drop your Tenable / AWS Inspector scan exports (`.csv` or `.xlsx`) and your previous OPEN FedRAMP POA&M (`.xlsx`) into the **`scans/`** folder at the repository root. When you run `./grc transform`, **GRCx** automatically lists detected files with numbers (`[1]`, `[2]`, ...) and lets you pick by number or type just the filename (with or without extension)!
> * **Does NOT Require Docker**: Unlike Phase 3 bundle/AMI scanners (`./grc scan`), **`transform_scans.py`** is written in **100% Python 3 Standard Library** (`csv`, `zipfile`, `xml.etree.ElementTree`) and runs directly on the host machine. You do **not** need to start or install the `grc-scanner:local` Docker container to use it.
> * **Native Windows Support (No WSL2 Required)**: Windows users can run the transform engine directly in **Windows PowerShell**, **Command Prompt (`cmd.exe`)**, **Git Bash**, or **WSL2**. See the Windows command examples below and **[`docs/scan-transform-guide.md`](docs/scan-transform-guide.md)**.

### `./grc transform [scan_filename...] [--scan <filename>...] [--previous-open <open_poam_filename>] [--draft-remediations <ask|y|n>] [-o <output_dir>]` *(macOS / Linux / WSL2)*
### `python .\scripts\transform_scans.py [scan_filename...] [--scan <filename>...] [--previous-open <open_poam_filename>]` *(Windows PowerShell & Command Prompt)*
Ingests up to **5 Tenable or AWS Inspector** vulnerability scan exports in `.csv` or `.xlsx` format from the designated **`scans/`** drop-in folder (or direct paths) into the same POA&M tracker. In interactive mode, GRCx prompts after each scan selection if you'd like to add another scan file (up to 5 scans). Findings are normalized and deduplicated into the official **`OPEN FedRAMP-POAM-Template.xlsx`** and **`CLOSED LEGACY FedRAMP-POAM-Template.xlsx`** workbooks (1 row per unique `Vulnerability + Asset` pair). During execution, it performs four automated GRC functions:
1. **Open $\rightarrow$ Closed POA&M Reconciliation**: Prompts for (or accepts via `--previous-open`) your previously filled-out OPEN FedRAMP POA&M form from `scans/`. Entries still present in the new scan carry over into the new OPEN POA&M with their original `POAM ID` and immutable `Original Detection Date`; entries no longer present in the new scan (or marked `False Positive = Yes`) are automatically moved to the **CLOSED FedRAMP POA&M** workbook.
2. **Interactive Missing Remediation Plan Drafter (`[y/n]`)**: Detects any OPEN POA&M entries missing a `Remediation Plan` (`Column K`) and asks if you want **GRCx** to draft them. Entering `y` populates `Column K` with the recommended fix and official remediation URLs (`https://www.tenable.com/plugins/nessus/<Plugin_ID>`, `https://explore.alas.aws.amazon.com/<ALAS_ID>.html`, AWS Inspector docs, and `https://nvd.nist.gov/vuln/detail/<CVE>`).
3. **SLA Breach & Finding Age Reporting**: Prints an itemized terminal report (and saves `poam_transform_summary.md` for viewing in Cursor) telling you **exactly how many OPEN POA&M entries have a `Scheduled Completion Date` (SLA) that has passed** and **how many days old every entry is from its `Original Detection Date`**.
4. **Pure Standard-Library `.xlsx` Output**: Writes `OPEN FedRAMP-POAM.xlsx` (with live Excel SLA formulas supporting `Critical` 30d, `High` 30d, `Moderate` 90d, and `Low` 180d) and `CLOSED FedRAMP-POAM.xlsx` into the output directory.

#### How Windows Users Run `transform_scans.py`
Because `scripts/transform_scans.py` relies only on built-in Python 3 modules and automatically checks the **`scans\`** folder, Windows users can drop their files into `scans\` and run it in three ways without Docker:
* **Windows PowerShell or Command Prompt (`cmd.exe`)**:
  * Interactive Drop-In Mode (lists files in `scans\` by number): `python .\scripts\transform_scans.py` *(or `py -3 .\scripts\transform_scans.py`)*
  * Direct CLI Mode (using filenames in `scans\`): `python .\scripts\transform_scans.py --scan tenable_scan.csv --previous-open "OPEN FedRAMP-POAM.xlsx" --draft-remediations y`
* **Git Bash on Windows**:
  * `python scripts/transform_scans.py --scan tenable_scan.csv`
* **Windows Subsystem for Linux (WSL2)**:
  * `./grc transform --scan tenable_scan.csv`

---

## 2. System & Environment Commands

### `./grc`
Displays the **GRCx** ASCII system banner along with a summary of all available top-level subcommands. Use this any time you want a quick reminder of the CLI syntax right in your terminal.

### `./grc fetch` *(Aliases: `./grc info`, `./grc --version`, `./grc -v`)*
Prints the **GRCx** `neofetch`-style terminal banner showing the active release version and codename (`v1.3.3 — Sasebo`), target operating systems, air-gap isolation model (`--network none`, `:ro`), all 10 integrated scanning and transformation engines, and supported compliance frameworks.

### `./grc docker-build`
Builds the local `grc-scanner:local` Docker container image from `docker/Dockerfile.scanner`. This packages all containerized security scanners (Semgrep, Gitleaks, Checkov, Syft, Grype, Trivy, and OpenSCAP) along with pre-cached vulnerability databases so that all subsequent scans execute completely offline with zero network egress.

---

## 3. Git Bundle Lifecycle Commands (Phases 1, 2 & 5)

### `./grc bundle verify <file.bundle> [--sha256 <expected_hash>]`
Executes **Phase 1 (Pull & Verify)** on an incoming Git bundle file without extracting any code to disk. It computes the file's SHA-256 cryptographic digest, optionally compares it against an expected baseline hash to detect tampering in transit, and runs `git bundle verify` to confirm the internal Git object graph and contained branch/tag references are valid.

### `./grc bundle restore <file.bundle> --workspace <dir> [--ref <tag_or_branch>] [--sha256 <hash>] [--read-only] [--force]`
Executes **Phase 2 (Restore)** by first verifying the bundle's integrity and then extracting its repository contents into an isolated ephemeral workspace directory (`./ephemeral_workspace` by default). It writes a cryptographic chain-of-custody manifest (`bundle_provenance.json`) recording the commit hash, author, and SHA-256 digest, and—when `--read-only` is passed—locks all extracted source files to `chmod 0444` so scanners cannot mutate the target code. Pass `--force` (`-f`) to overwrite an existing ephemeral workspace from a prior run.

### `./grc bundle clean --workspace <dir> [--remove-bundle]`
Executes **Phase 5 (Ephemeral Teardown)** after an audit concludes. It unlocks any read-only file permissions and permanently deletes the extracted ephemeral workspace directory to uphold the zero-data-retention rule between reviews. Passing `--remove-bundle` also deletes the source `.bundle` archive after processing.

---

## 4. Cloud AMI Lifecycle Commands (Phases 1, 2 & 5)

### `./grc ami verify <ami-id> [--region <aws-region>] [--mock]`
Executes **Phase 1 (AMI Verification)** against an Amazon Machine Image (`AMI`) before mounting. It inspects the AMI's metadata, root EBS snapshot ID, architecture, and KMS encryption status—enforcing a hard compliance gate (`NIST SP 800-53 SC-28`) that rejects unencrypted snapshots before any volume is created. Passing `--mock` simulates this workflow locally without requiring live AWS credentials or EC2 infrastructure.

### `./grc ami restore <ami-id> --workspace <dir> [--region <aws-region>] [--mock] [--force]`
Executes **Phase 2 (Cold-Mount Restoration)** by creating an isolated EBS volume from the verified AMI snapshot, attaching it to the audit host, and cold-mounting the filesystem as strictly read-only (`mount -o ro,noload`) inside the target workspace without ever booting the guest operating system. It also generates `ami_provenance.json` to preserve cryptographic chain of custody.

### `./grc ami clean --workspace <dir> [--mock]`
Executes **Phase 5 (AMI Teardown)** by unmounting the cold-mounted guest filesystem, detaching and deleting the temporary EBS audit volume, and wiping the local ephemeral workspace directory so no snapshot data persists on the host.

---

## 5. Compliance Scanning Commands (Phase 3)

### `./grc scan --all -w <workspace> [-e <evidence_dir>]` *(Default: `./grc scan -w <workspace>`)*
Executes the **complete 9-engine compliance suite** against the restored workspace inside the air-gapped `grc-scanner:local` container (`--network none`), followed automatically by **Phase 4 report synthesis**. If `-e <evidence_dir>` is omitted, **GRCx** automatically creates a folder under `./evidence/<bundle-name>/` based on the workspace's provenance manifest.

### `./grc scan --semgrep -w <workspace> [-e <evidence_dir>]`
Runs only the **Semgrep Static Application Security Testing (SAST)** engine against the target workspace using the 37 custom compliance rules in `rules/custom-baseline-ruleset.yaml` (covering AOC-02 Weak Passwords, AOC-03 Weak Crypto, AOC-04 Command Injection, AOC-05 Improper TLS, AOC-06 Embedded Private Keys, AOC-09 Deprecated Crypto Imports, AOC-10 Unsafe Deserialization, AOC-11 STIG CAT I Violations, and AOC-140 Org Guardrails), writing raw findings to `semgrep_findings.json`.

### `./grc scan --gitleaks -w <workspace> [-e <evidence_dir>]`
Runs only the **Gitleaks** secret-detection engine (`--no-git`) across the target workspace to identify hardcoded API tokens, cloud access keys, asymmetric private keys, and high-entropy credentials (`NIST SP 800-53 IA-5` / `SC-12`), writing results to `gitleaks_findings.json`.

### `./grc scan --checkov -w <workspace> [-e <evidence_dir>]`
Runs only the **Checkov Infrastructure-as-Code (IaC)** policy engine across Terraform, Kubernetes, Dockerfile, and Ansible definitions in the workspace to detect cloud misconfigurations such as public S3 buckets, open SSH/RDP security groups, unencrypted EBS volumes, and wildcard IAM policies (`NIST SP 800-53 AC-3`, `AC-6`, `CM-6`, `SC-28`), writing results to `checkov_findings.json`.

### `./grc scan --syft -w <workspace> [-e <evidence_dir>]`
Runs only the **Syft** software composition analyzer to inventory every operating system package and language dependency (Python, Go, Java, JavaScript/Node.js) in the workspace, outputting a standardized CycloneDX Software Bill of Materials (`sbom.cdx.json`) for `NIST SP 800-53 CM-8` and `SR-4`.

### `./grc scan --grype -w <workspace> [-e <evidence_dir>]`
Runs only the **Grype** offline vulnerability scanner against the workspace's CycloneDX SBOM (`sbom.cdx.json`, automatically running Syft first if needed) to match dependencies against pre-cached CVE advisories (`NIST SP 800-53 RA-5` / `SI-2`), writing results to `grype_findings.json`.

### `./grc scan --trivy -w <workspace> [-e <evidence_dir>]`
Runs only the **Trivy** offline filesystem vulnerability scanner (`--offline-scan`) as a secondary, independent CVE verification engine across lockfiles and OS packages, writing results to `trivy_findings.json`.

### `./grc scan --oscap -w <workspace> [-e <evidence_dir>]` *(Alias: `--openscap`)*
Runs only the **OpenSCAP** configuration scanner (`oscap xccdf eval`) against cold-mounted Linux AMI root filesystems using DISA STIG / SCAP Security Guide XCCDF profiles, outputting `oscap_results.xml` and `oscap_report.html`.

### `./grc scan --crypto -w <workspace> [-e <evidence_dir>]`
Runs only the **Cryptographic Library & End-of-Life (EOL) Version Scanner** (`scripts/crypto_lib_scan.py`) against dependency manifests and shared binaries, checking discovered cryptographic libraries (`pycrypto`, `cryptography`, `OpenSSL`, `Bouncy Castle`) against `rules/crypto_catalog.json` for `AOC-09` (`NIST SP 800-53 SC-13` / `SI-7`).

### `./grc scan --sbom -w <workspace> [-e <evidence_dir>]` *(Alias: `--stig`)*
Runs only the **DISA STIG & DoD Cloud SRG Applicability Mapper** (`scripts/sbom_analyzer.py`) against `sbom.cdx.json` (automatically generating the SBOM via Syft first if not yet present), producing `stig_matrix.md` and `stig_applicability.json`.

### `./grc scan <engine> -w <workspace> --no-report`
Appending `--no-report` to any `./grc scan` command runs the requested scanner engine(s) and writes their raw JSON/XML telemetry to the evidence directory, but skips automatic Phase 4 report synthesis (`poam_data.md`, `controls.md`, `ruleset_validation.md`, `scr_scn_package.json`, and `sha256sum`). This is useful when running multiple individual engines sequentially before calling `./grc report` once at the end.

---

## 6. Direct Reporting & Standalone Analyzer Commands (Phase 4)

### `./grc report --evidence <evidence_dir> [--workspace <workspace_dir>] [--ruleset <ruleset.yaml>]`
Executes **Phase 4 (Compliance Deliverable Synthesis)** on an existing evidence directory containing raw scanner JSON files. It normalizes findings across all engines, maps every defect to **NIST SP 800-53 Rev. 5** controls and **DISA STIG** severity categories (`CAT I` / `CAT II` / `CAT III`), calculates FedRAMP remediation SLAs (30 / 60 / 90 / 180 days), and generates `poam_data.md`, `controls.md`, `ruleset_validation.md`, `scr_scn_package.json`, and the tamper-evident `sha256sum` manifest.

### `./grc sbom --sbom <path/to/sbom.cdx.json> [--format <markdown|json|csv>] [--output <file>]`
Provides direct standalone access to `scripts/sbom_analyzer.py` so you can analyze any external CycloneDX or SPDX SBOM file—even outside of a bundle scan—and generate a DISA STIG / DoD SRG applicability report in Markdown, JSON, or CSV format.

### `./grc crypto --workspace <dir> [--catalog <crypto_catalog.json>] [--format <json|markdown>] [--output <file>]`
Provides direct standalone access to `scripts/crypto_lib_scan.py` to audit any directory or repository for deprecated, unmaintained, or non-FIPS cryptographic libraries against the approved cryptographic catalog.
