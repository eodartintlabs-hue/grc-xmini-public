# Releasing GRCx (`hygiene/RELEASING.md`)

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

This file explains how versions and codenames work and how to cut a release. What shipped is recorded in [`RELEASE_NOTES.md`](RELEASE_NOTES.md), commit and author accountability is tracked in [`PATCH_LOG.md`](PATCH_LOG.md), and planned work is in [`ROADMAP.md`](ROADMAP.md).

---

## 1. Version numbers

GRCx uses Semantic Versioning: `v<MAJOR>.<MINOR>.<PATCH>`.

| Part | When to bump it | Examples |
| :--- | :--- | :--- |
| **Major** | A lifecycle milestone | `v1.x` restricted beta → `v2.0.0` general availability |
| **Minor** | New, backward-compatible capability: a scanner engine, a CLI subcommand, a compliance framework, or a major platform change | `v1.2.0` added `./grc transform` |
| **Patch** | Bug fixes, rule tuning, CVE database refreshes, docs, and repo hygiene | `v1.0.4` fixed `./grc scan` engine dispatch |

### Release types used in the release notes

| Type | Version bump | Typical scope |
| :--- | :--- | :--- |
| Beta baseline | Major (`v1.0.0`) | First release of a major series |
| GA | Major (`v2.0.0`) | First production release |
| Minor | Minor | New capabilities, as above |
| Bug fix | Patch | CLI parsing, path handling, scanner flags; no breaking changes |
| Rule / catalog tuning | Patch | False-positive fixes in `rules/custom-baseline-ruleset.yaml`; updates to `rules/crypto_catalog.json` or `rules/cisa_kev_catalog.json` |
| Security / container | Patch | Rebuilding `grc-scanner:local` for new offline CVE databases or base image packages |
| Docs | Patch | Documentation, diagrams, file naming, `.gitignore`, formatting |

### Companion Repository Synchronization (`GRC-xTEST`)

The companion test corpus **`GRC-xTEST`** ([`https://github.com/eodartintlabs-hue/grc-xtest.git`](https://github.com/eodartintlabs-hue/grc-xtest.git)) is maintained on the **same Minor Release Schedule** as `GRC-x`:
* **Minor Alignment (`v<MAJOR>.<MINOR>.x`)**: Both repositories advance together across minor feature baselines (e.g., `v1.1.0 Kadena`, `v1.2.0 Misawa`, `v1.3.x Sasebo`, `v2.0.0 Pearl Harbor`).
* **Decoupled Patch Cadence**: `GRC-xTEST` does **not** need to sync down to individual patch releases. When `GRC-x` increments for bug fixes, documentation hygiene, or patch updates (e.g., `v1.3.1`, `v1.3.2`, `v1.3.3`, `v1.3.4`), `GRC-xTEST` remains stable on the active minor series (`v1.3.x`) unless new synthetic bundles, scan schemas, or negative test fixtures are specifically introduced.

---

## 2. Codenames

Each minor release gets a codename. Patch releases keep the codename of their minor release (for example, `v1.3.1` is still Sasebo).

| Series | Phase | Theme | Codenames |
| :--- | :--- | :--- | :--- |
| `v1.x` | Restricted beta and integration testing | U.S. military installations in Japan | Yokosuka (`v1.0.x`), Kadena (`v1.1.0`), Misawa (`v1.2.0`), Sasebo (`v1.3.x`) |
| `v2.x` | General availability | Hawaiian cities with U.S. military bases | Pearl Harbor (`v2.0.0`), Kaneohe (`v2.1.0`), Wahiawa (`v2.2.0`); unassigned: Kunia, Kekaha |

Tag annotations use this format: `Release v<MAJOR>.<MINOR>.<PATCH> - <Codename>: <Summary>`.

---

## 3. Cutting a release

The example below cuts `v1.3.1 — Sasebo`. Replace the version, codename, and summary as needed.

1. **Update the version string everywhere it appears.** Find every reference to the previous version:

   ```bash
   grep -rn "v1\.3\.0" --include="*.md" --include="*.py" --include="grc" .
   ```

   At minimum, check `./grc` (the `grcfetch` banner), `README.md`, `COMMANDS.md`, `INSTALL.md`, `docs/transform_scans-guide.md`, and `scripts/transform_scans.py` (its docstring and the report banner). Don't change historical mentions in `RELEASE_NOTES.md` or `PATCH_LOG.md`.

2. **Update the docs in `hygiene/`:**
   - In [`RELEASE_NOTES.md`](RELEASE_NOTES.md), add a row at the top of the summary table with `_TBD after tagging_` in the Commit column. Add a section for the release that describes only what actually shipped.
   - In the category-specific patch log ([`PATCH_LOG_BUG.md`](PATCH_LOG_BUG.md) for bug fixes/patches, [`PATCH_LOG_MINOR.md`](PATCH_LOG_MINOR.md) for minor releases, or [`PATCH_LOG_MAJOR.md`](PATCH_LOG_MAJOR.md) for major baselines) and master index [`PATCH_LOG.md`](PATCH_LOG.md), add a row to the running patch ledger recording the affected files, summary of changes, and `Author / POC` accountability.
   - In [`ROADMAP.md`](ROADMAP.md), remove the delivered items (or the whole section) and update the status table and the "Current release" line.

3. **Commit, tag, and push:**

   ```bash
   git add -A
   git commit -m "chore(release): v1.3.1 (Sasebo)"
   git tag -a v1.3.1 -m "Release v1.3.1 - Sasebo: Workstation portability and ./grc doctor"
   git push origin main --tags
   ```

4. **Record the commit.** A commit can't contain its own hash, so fill in the Commit column in [`RELEASE_NOTES.md`](RELEASE_NOTES.md), the category patch log ([`PATCH_LOG_BUG.md`](PATCH_LOG_BUG.md), [`PATCH_LOG_MINOR.md`](PATCH_LOG_MINOR.md), or [`PATCH_LOG_MAJOR.md`](PATCH_LOG_MAJOR.md)), and [`PATCH_LOG.md`](PATCH_LOG.md) afterward:

   ```bash
   git rev-parse --short v1.3.1^{commit}
   ```

   Put the result in the tables and commit with `docs(release): record v1.3.1 commit`. Do this before starting other work, so the row isn't left as `TBD`.

---

## 4. Rules that keep the docs consistent

- **Each fact has one home.** Shipped narrative release notes go in `RELEASE_NOTES.md`, commit/author accountability and file-level audit trail go in `PATCH_LOG.md`, planned work goes in `ROADMAP.md`, and conventions and procedure live in this file. Link between them instead of copying.
- **Nothing counts as delivered until it's in the release notes.** When a planned item ships, remove it from the roadmap in the same commit.
- **Release notes are historical.** Don't rewrite past entries to match later decisions. If something was later renamed or removed, add a short note such as "(removed in v1.1.0)".
- **Link to files that exist.** When a file is removed, turn links to it into plain text.
