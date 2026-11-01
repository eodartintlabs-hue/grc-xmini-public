# GRCx — Live Demo Runbook (`testing/live-demo.md`)

<p align="center">
  <a href="../README.md"><b>📖 README</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/ARCHITECTURE.md"><b>🏛️ Architecture & Tech Stack</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/DATAFLOW.md"><b>🔄 Data Flow</b></a> &nbsp;·&nbsp;
  <a href="../SECURITY.md"><b>🛡️ Security Policy</b></a> &nbsp;·&nbsp;
  <a href="../amplifying-info/GOVERNANCE.md"><b>⚖️ Governance & Mandates</b></a> &nbsp;·&nbsp;
  <a href="TESTING.md"><b>🧪 Verification Plan</b></a> &nbsp;·&nbsp;
  <a href="live-demo.md"><b>🎬 Live Demo</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/RELEASE_NOTES.md"><b>🚀 Release Notes</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/PATCH_LOG.md"><b>🩹 v1 Patch Log</b></a> &nbsp;·&nbsp;
  <a href="../hygiene/ROADMAP.md"><b>🗺️ Roadmap</b></a> &nbsp;·&nbsp;
  <a href="../docs/transform_scans-guide.md"><b>📊 Scan-to-POA&M Guide</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc_bundle-guide.md"><b>📑 Bundle Walkthrough</b></a> &nbsp;·&nbsp;
  <a href="../docs/grc-xtest-guide.md"><b>🎯 GRC-xTEST Guide</b></a>
</p>

> **Purpose**: Step-by-step live presentation script for demonstrating the 5-phase **GRCx** (*The GRC eXperience*) pipeline across **AOC-09 (EOL Cryptographic Libraries)**, **AOC-10 (Critical CVEs)**, and **AOC-04 (OS Command Injection)**.

---

## ⚠️ Pre-Demo Checklist (The 4 Common Gotchas)

1. **`./grc` vs `grc`**: Always prefix the command with **`./grc`** (not `grc`), otherwise macOS `zsh` will return `zsh: command not found: grc`.
2. **Docker Desktop Must Be Running**: The `scan` command runs inside the air-gapped `grc-scanner:local` container. Verify the **Docker Desktop** whale icon is running in your Mac menu bar before starting.
3. **Bundle Path Location**: The `.bundle` test fixtures live in the companion directory **`../GRC-Test-Dummies/bundles/`**, not inside `GRC-x`.
4. **Always Pass `-f` (`--force`) on Restore**: Because previous runs lock `./ephemeral_workspace` to read-only (`chmod 0444`), restoring a new bundle without `-f` will error out if `./ephemeral_workspace` wasn't cleaned first.

---

## Step 0: Initialize Terminal & Display System Banner

Open your terminal, navigate to the repository root, and display the `grcfetch` banner:

```bash
cd ~/Desktop/GRC-x
./grc fetch
```

---

## 1️⃣ Demo Run 1: AOC-09 — Unsupported & EOL Cryptographic Libraries (`NIST SP 800-53 SI-7`)

**What this demonstrates**: Detects deprecated, unmaintained, and End-of-Life (EOL) cryptographic libraries (`pycrypto`, `OpenSSL 1.1.1`, `Bouncy Castle < 1.70`) against [`rules/crypto_catalog.json`](../rules/crypto_catalog.json).

### Phase 1: Cryptographic Bundle Verification
```bash
./grc bundle verify ../GRC-Test-Dummies/bundles/aoc-09-eol-libraries.bundle
```

### Phase 2: Ephemeral Read-Only Restoration (`chmod 0444`)
```bash
./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-09-eol-libraries.bundle \
  -w ./ephemeral_workspace \
  -r v1.0.0 \
  -f \
  --read-only
```

*(Optional — Show generated cryptographic provenance manifest)*:
```bash
cat ./ephemeral_workspace/bundle_provenance.json
```

### Phases 3 & 4: Air-Gapped Scan, Crypto Audit & SCR/SCN Report Synthesis
```bash
# Run all 9 compliance engines (including crypto_lib_scan.py & sbom_analyzer.py) + Phase 4 report synthesis:
./grc scan --all -w ./ephemeral_workspace -e testing/demo-evidence/aoc-09-eol-libraries

# (Optional) Or invoke just the Crypto compliance engine independently:
# ./grc scan --engine crypto -w ./ephemeral_workspace -e testing/demo-evidence/aoc-09-eol-libraries
```

### Inspect AOC-09 Deliverables
```bash
# 1. View the detected EOL crypto libraries
cat testing/demo-evidence/aoc-09-eol-libraries/crypto_findings.json | jq '.findings[] | {library: .library_name, version: .detected_version, status: .compliance_status, remediation: .remediation}'

# 2. View the FedRAMP High POA&M Table & NIST 800-53 Controls Matrix
cat testing/demo-evidence/aoc-09-eol-libraries/poam_data.md
cat testing/demo-evidence/aoc-09-eol-libraries/controls.md
```

### Phase 5: Ephemeral Workspace Teardown
```bash
./grc bundle clean -w ./ephemeral_workspace
```

---

## 2️⃣ Demo Run 2: AOC-10 — CRITICAL Severity Vulnerabilities (`NIST SP 800-53 RA-5, SI-2`)

**What this demonstrates**: Generates a CycloneDX Software Bill of Materials (SBOM) via **Syft** and catches weaponized CVSS 9.8–10.0 CVEs offline via **Grype** and **Trivy** (**Log4Shell** `CVE-2021-44228`, **Spring4Shell** `CVE-2022-22965`, **Text4Shell** `CVE-2022-42889`).

### Phase 1: Cryptographic Bundle Verification
```bash
./grc bundle verify ../GRC-Test-Dummies/bundles/aoc-10-critical-cves.bundle
```

### Phase 2: Ephemeral Read-Only Restoration (`chmod 0444`)
```bash
./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-10-critical-cves.bundle \
  -w ./ephemeral_workspace \
  -r v1.0.0 \
  -f \
  --read-only
```

### Phases 3 & 4: Air-Gapped Scan & SCR/SCN Report Synthesis
```bash
./grc scan -w ./ephemeral_workspace -e testing/demo-evidence/aoc-10-critical-cves
```

### Inspect AOC-10 Deliverables
```bash
# 1. View the Critical CVEs matched against the CycloneDX SBOM
cat testing/demo-evidence/aoc-10-critical-cves/grype_findings.json | jq -r '.matches[] | select(.vulnerability.severity == "Critical") | "\(.vulnerability.id) | \(.artifact.name):\(.artifact.version)"'

# 2. View the FedRAMP High POA&M (30-Day SLA for Critical/High CVEs) & Controls Matrix
cat testing/demo-evidence/aoc-10-critical-cves/poam_data.md
cat testing/demo-evidence/aoc-10-critical-cves/controls.md
```

### Phase 5: Ephemeral Workspace Teardown
```bash
./grc bundle clean -w ./ephemeral_workspace
```

---

## 3️⃣ Demo Run 3: AOC-04 — OS Command Injection (`NIST SP 800-53 SI-4, SI-10`)

**What this demonstrates**: Uses the custom 37-rule **Semgrep AST ruleset** ([`rules/custom-baseline-ruleset.yaml`](../rules/custom-baseline-ruleset.yaml)) to catch unsanitized shell execution across Python (`os.system`, `subprocess.Popen(shell=True)`), Go (`exec.Command("bash", ...)`), and Java (`Runtime.getRuntime().exec()`).

### Phase 1: Cryptographic Bundle Verification
```bash
./grc bundle verify ../GRC-Test-Dummies/bundles/aoc-04-command-injection.bundle
```

### Phase 2: Ephemeral Read-Only Restoration (`chmod 0444`)
```bash
./grc bundle restore ../GRC-Test-Dummies/bundles/aoc-04-command-injection.bundle \
  -w ./ephemeral_workspace \
  -r v1.0.0 \
  -f \
  --read-only
```

### Phases 3 & 4: Air-Gapped Scan & SCR/SCN Report Synthesis
```bash
./grc scan -w ./ephemeral_workspace -e testing/demo-evidence/aoc-04-command-injection
```

### Inspect AOC-04 Deliverables
```bash
# 1. View the command injection findings caught by Semgrep AST rules
cat testing/demo-evidence/aoc-04-command-injection/semgrep_findings.json | jq -r '.results[] | "\(.extra.severity) | \(.path):\(.start.line) | \(.extra.message)"'

# 2. View the FedRAMP POA&M, NIST 800-53 Controls Matrix, 37-Rule Log, and Cryptographic Seal
cat testing/demo-evidence/aoc-04-command-injection/poam_data.md
cat testing/demo-evidence/aoc-04-command-injection/controls.md
cat testing/demo-evidence/aoc-04-command-injection/ruleset_validation.md
cat testing/demo-evidence/aoc-04-command-injection/sha256sum
```

### Phase 5: Final Ephemeral Workspace Teardown
```bash
./grc bundle clean -w ./ephemeral_workspace
```
