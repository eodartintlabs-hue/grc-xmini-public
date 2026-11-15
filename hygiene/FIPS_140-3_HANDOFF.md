# FIPS 140-3 Assessment Capability — Coding Agent Handoff

> **Audience**: Coding agent implementing FIPS 140-3 assessment across `GRC-xBOT` and `GRC-xMINI`.
> **Baselines reviewed**: `grc-xbot` @ `9fe4680` (`v1.2.1 — Motegi`), `grc-xmini-public` @ `e2b17ed` (`v1.4.4 — Yokota`).
> **Date of review**: 2026-11-14.

---

## 1. Goal

Let an individual download GRC-xBOT to a personal device, point it at a **GitHub repository URL, a local checkout, or a `.bundle`**, and get an evidence-backed **FIPS 140-3 cryptographic conformance assessment** of the source code.

### 1.1 Framing (must be reflected in all output wording)

- FIPS 140-3 validates **cryptographic modules** through NIST CMVP. **Applications and repositories are not "FIPS 140-3 certified."**
- The question the tool answers is: **"Does this code perform all security-relevant cryptography through a FIPS 140-3 validated module, configured in its approved mode, using only approved algorithms and parameters?"** This is NIST SP 800-53 **SC-13** evidence (plus SC-12, SC-8(1), SC-28(1), IA-7).
- Every finding carries **evidence (file:line), a confidence level, and a determination**. When static analysis cannot decide, the determination is **`CANNOT_DETERMINE_STATICALLY`**, never PASS.
- Report wording must never say "compliant" or "certified". Use "conformance indicators" and "assessment findings".
- **FIPS 140-2 certificates moved to Historical status on 2026-09-21.** A dependency whose only validation is a 140-2 certificate is now a finding.

### 1.2 Non-negotiable design constraints (from existing project conventions)

1. **Deterministic verdicts.** All PASS/FAIL determinations come from rules and catalogs. Local Gemma 4 (Mode 2) may only produce `[AI-DRAFT (gemma4:…) — REQUIRES ISSO/ENGINEER REVIEW]` triage or explanatory text and never changes a verdict.
2. **The core FIPS path uses only the Python 3 standard library** (Python 3.9+). Docker, Semgrep and Gemma are optional enhancers, not requirements.
3. **Preview-first.** `--dry-run`/terminal preview before writing deliverables. `shell=False` argv execution only.
4. **Untrusted input.** Target repos are untrusted: no hooks, no build scripts, no package installs, read-only restore, guaranteed `finally:` teardown.
5. **Offline-first.** Network is used only to fetch the target repo and, on explicit request, to refresh data catalogs.
6. **Architecture.** Analysis engines live in **GRC-xMINI**; GRC-xBOT provides intake orchestration, the playbook, intent routing and walkthrough. For personal-device distribution, ship them as a single installable (see Phase 6).

---

## 2. Current-State Findings (verified by code review)

### 2.1 What exists

| Component | Location | Actual behavior |
|---|---|---|
| Crypto library scanner | `grc-xmini-public/scripts/crypto_lib_scan.py` (742 lines, stdlib-only) | Parses `requirements.txt`, `pyproject.toml`, `package.json`, `pom.xml`, `go.mod`, and finds `libssl*`/`libcrypto*`/`openssl` binaries. Matches against a catalog and reports `FAIL_DEPRECATED`, `WARN_UNRECOMMENDED`, `FAIL_EOL`, `WARN_OUTDATED`, `WARN_UNVERIFIED` or `PASS`. |
| Crypto policy catalog | `grc-xmini-public/rules/crypto_catalog.json` (plus embedded fallback `DEFAULT_CRYPTO_CATALOG` in `crypto_lib_scan.py`) | **Only 7 rules**: `openssl`, `pycrypto`, `cryptography`, `bouncycastle`, `crypto-js`, `node-forge`, `golang-x-crypto`. FIPS info is a single boolean, `fips_capable`. |
| Weak-crypto SAST | `grc-xmini-public/rules/custom-baseline-ruleset.yaml` (AOC-03 lines ~101–230; AOC-05 TLS ~322–390; AOC-09 ~408–460) | Semgrep patterns for MD5/SHA-1, DES/3DES/RC4/Blowfish, Java ECB, Node `createCipher`, disabled TLS verification. Python, Go, Java, JS/TS only. Runs inside the Docker scanner image (`docker/scan_orchestrator.sh`). |
| Bundle pipeline | `grc-xmini-public/scripts/grc_bundle.py` | `verify` (SHA-256 + `git bundle verify`), read-only `restore`, `clean`. Good, reusable intake. |
| Reporter | `grc-xmini-public/scripts/grc_reporter.py` | Has an SC-13 "Cryptographic Protection (FIPS 140 Validation)" control entry (~line 136); consumes `crypto_findings.json`. |
| xBOT routing | `grc-xbot/scripts/grc_bot.py` `IntentRouter.classify` (~line 307), `playbooks/workflows.json` `crypto` | The keyword `fips` routes to the generic `crypto` workflow. There is no dedicated FIPS workflow. |

### 2.2 Defects and inaccuracies to fix (Phase 0)

| # | Defect | Location | Fix |
|---|---|---|---|
| D1 | **AOC-12 "Lack of FIPS Mode" is documented but not implemented.** The README advertises checks for `fips=0`, crypto-policies `DEFAULT` and a missing `[fips_sect] activate = 1`, but no rule, script or config in the repo implements them (grep for `aoc-12`, `fips_sect`, `fips=0`, `crypto-policies` across `*.py`, `*.yaml`, `*.sh` and `*.json` returns nothing). | `grc-xmini-public/README.md:191` | Implement it in Phase 4 (see §4.4). Until then, mark the README row as "Planned". |
| D2 | **Wrong NIST control mapping.** Weak-crypto findings are labeled `SI-16: Cryptographic Protection`. In SP 800-53 Rev. 5, **SI-16 is Memory Protection**; **Cryptographic Protection is SC-13**. | `rules/custom-baseline-ruleset.yaml` lines 101, 106, 109, 122, 125, 139, 142, 155, 158, 170, 173, 187, 190, 205, 208, 221, 224; `README.md:183`; `scripts/grc_reporter.py:107–112` (SI-16 titled "Memory Protection / Cryptographic Hash Integrity" and described as prohibiting MD5/SHA-1/DES/RC4); `testing/TESTING.md:249`; `docs/grc-xtest-guide.md:43,234,415` | Remap AOC-03 weak hash/cipher findings to **SC-13** (and SC-12 where key material is involved). Restore the reporter's SI-16 entry to Memory Protection only, and remove "assessed_by: Semgrep, CryptoScan" for crypto there. Update the docs and tests that assert SI-16. |
| D3 | **`fips_capable: true` gets reported as a PASS-level reassurance.** `_audit_dependency` returns `PASS` with "Supported cryptographic library. FIPS Capable: True." "Capable" says nothing about a validated certificate, its status, or whether approved mode is configured. | `scripts/crypto_lib_scan.py:518–528`; catalog `fips_capable` fields | Replace the boolean with `fips_status` ∈ {`VALIDATED_MODULE`, `CAPABLE_IF_CONFIGURED`, `NOT_VALIDATED`, `UNKNOWN`} and, where applicable, a `cmvp_certs` list (Phase 4). A library that is merely capable yields `CANNOT_DETERMINE_STATICALLY` for SC-13, not PASS. |
| D4 | **`cryptography` (PyCA) marked `APPROVED` / `fips_capable: true`.** Standard PyPI wheels statically bundle their own OpenSSL build, which is **not** a FIPS-validated module. It is only FIPS-relevant when built against a system OpenSSL running a validated FIPS provider. | `rules/crypto_catalog.json:43`; `scripts/crypto_lib_scan.py:99` | Set status `CAPABLE_IF_CONFIGURED` with a note: "PyPI wheels bundle a non-validated OpenSSL; FIPS use requires building against the platform's validated OpenSSL FIPS provider." |
| D5 | **The pycrypto remediation recommends `pycryptodome`**, which has no FIPS validation. That is acceptable advice for maintenance but wrong for FIPS. | `rules/crypto_catalog.json:39`; `scripts/crypto_lib_scan.py:95` | Recommend `cryptography` linked against a validated OpenSSL 3 FIPS provider. Flag `pycryptodome`/`pycryptodomex` in the catalog as `NOT_VALIDATED`. |
| D6 | **`golang-x-crypto` marked `APPROVED`.** `golang.org/x/crypto` is outside the Go standard library and outside Go's FIPS 140-3 module boundary. | `rules/crypto_catalog.json:89`; `scripts/crypto_lib_scan.py:145` | Set `NOT_VALIDATED`. Usage of its subpackages (e.g. `chacha20poly1305`, `blowfish`, `bcrypt`, `ripemd160`) for security functions is a finding unless explicitly out of FIPS scope. |
| D7 | **The AOC-09 Semgrep message says "Migrate to standard hashlib or pyca/cryptography."** `hashlib` is only FIPS-relevant when Python is linked to a FIPS-enabled OpenSSL. | `rules/custom-baseline-ruleset.yaml:411` | Reword to: "…migrate to hashlib/pyca-cryptography backed by a FIPS-validated OpenSSL provider." |
| D8 | **The README advertises FIPS 140-3 coverage** ("crypto_lib_scan.py (EOL & FIPS 140-3)"). | `README.md:138` | Reword to "EOL & FIPS-capability inventory" until Phase 4 ships. |
| D9 | **No CMVP data.** Nothing maps library/version/platform to a CMVP certificate, status (Active/Historical/Revoked), sunset date or 140-2 vs 140-3. | catalog | Phase 4. |
| D10 | **Narrow coverage.** No C/C++ source, Rust (`Cargo.toml`/`Cargo.lock`), .NET (`*.csproj`, `packages.lock.json`), Gradle (`build.gradle[.kts]`), lockfiles (`package-lock.json`, `poetry.lock`, `go.sum`), or config files (`openssl.cnf`, `java.security`, Dockerfile `FROM`). | `DependencyExtractor` | Phases 2 and 4. |
| D11 | **No GitHub intake.** Neither repo can fetch a target from a GitHub URL. Input is a manually staged `.bundle` in `artifacts/drop-off/`. | `grc_bundle.py`, `grc_bot.py` | Phase 1. |
| D12 | **Weak-crypto detection depends on Docker + Semgrep**, which conflicts with the personal-device goal. | `docker/scan_orchestrator.sh` | Phase 2: native stdlib detector. Keep Semgrep as an optional second opinion. |

---

## 3. Phase 0 — Corrections (GRC-xMINI patch release)

Do D2–D8 now. They are low-risk and keep the existing tool from producing misleading SC-13 evidence.

**Acceptance criteria**
- No crypto rule, reporter entry, doc or test references SI-16 as cryptographic protection.
- No library reaches `PASS` solely because `fips_capable` is true.
- Catalog schema bumped (`catalog_metadata.version` → `1.1.0`). Embedded `DEFAULT_CRYPTO_CATALOG` kept in sync, or replaced by loading the JSON with a failing test if the two diverge.
- Regression tests: `cryptography` with no FIPS evidence → `CANNOT_DETERMINE_STATICALLY`; `pycryptodome` → `NOT_VALIDATED`; `golang.org/x/crypto` → `NOT_VALIDATED`.
- README AOC-12 row marked "Planned" (or implemented if Phase 4 lands in the same release).

---

## 4. Implementation Phases

### 4.1 Phase 1 — GitHub intake (GRC-xBOT + `grc_bundle.py`)

- New command: `./grc-bot fips <target>`, where `<target>` is a GitHub HTTPS URL (`https://github.com/<owner>/<repo>[@<ref>]`), a local path, or a `.bundle`.
- URL flow: `git clone --mirror` (or `--filter=blob:none`) into a temp dir → resolve and **pin the commit SHA** → `git bundle create` → reuse the existing `grc_bundle.py verify` → `restore --read-only` → scan → `clean` in `finally:`.
- Git safety for untrusted repos: `-c core.hooksPath=/dev/null`, `-c protocol.file.allow=never`, no submodule recursion by default (`--recurse-submodules` opt-in only), and `GIT_LFS_SKIP_SMUDGE=1`.
- Private repos: use the user's existing `git` credential helper or `gh auth`. **Never store, log or echo tokens.**
- Validate the URL strictly (scheme `https`, host allowlist default `github.com`, configurable for GHES). Reject `ext::`, `file://` and SSH command injection vectors.
- Write `fips_provenance.json` with repo URL, ref, commit SHA, bundle SHA-256, tool version and catalog versions.
- Add a `fips` workflow to `playbooks/workflows.json`. Route `fips`, `140-3`, `140-2`, `cmvp` and `validated module` to it in `IntentRouter` (currently they route to `crypto`). Add a `CommandPlanner` branch and tests mirroring the existing `crypto` restore→preview→clean chain test.

### 4.2 Phase 2 — Crypto discovery / CBOM (GRC-xMINI, stdlib-only)

New module, e.g. `scripts/fips_discovery.py`. It emits **CycloneDX 1.6 CBOM** (`cryptographic-asset` components) as `cbom.cdx.json`.

Detection targets (each hit records language, file:line, API, algorithm, mode, key size if literal, and purpose hints):

| Ecosystem | APIs / signals |
|---|---|
| Python | `hashlib.*`, `hmac`, `ssl.SSLContext`/`create_default_context`, `cryptography.hazmat.*`, `Crypto.*`/`Cryptodome.*`, `random` used for tokens/keys/nonces (vs `secrets`/`os.urandom`), `requests(..., verify=False)`. Use the `ast` module, not regex. |
| Go | `crypto/*` imports, `golang.org/x/crypto/*`, `tls.Config{MinVersion, CipherSuites, InsecureSkipVerify}`, `GODEBUG=fips140=on/only` (Go ≥ 1.24 native module), `GOEXPERIMENT=boringcrypto`, `//go:debug fips140=` directives, `crypto/fips140` usage |
| Java/Kotlin | `MessageDigest.getInstance`, `Cipher.getInstance` transformation strings, `KeyPairGenerator`/`KeyGenerator` `.initialize(n)`, `SecureRandom.getInstance`, `Security.addProvider`/`insertProviderAt`, BC (`bcprov-*`) vs BC-FIPS (`bc-fips`, `bctls-fips`) |
| JS/TS | `crypto.createHash/createCipheriv/createCipher/generateKeyPair`, `crypto.setFips`/`--enable-fips`/`--force-fips`, `crypto-js`, `node-forge`, `tls.connect({rejectUnauthorized:false})` |
| C/C++ | OpenSSL `EVP_*`, legacy `MD5_*`/`DES_*`/`RC4*`, `OSSL_PROVIDER_load(…"fips")`, `EVP_default_properties_enable_fips`, `FIPS_mode_set` (1.x API), wolfSSL, BoringSSL, mbedTLS includes |
| Rust | `ring`, `rustls` (+ `aws-lc-rs` with `fips` feature), `openssl` crate, `RustCrypto` crates (`md-5`, `sha1`, `des`, `chacha20poly1305`) |
| .NET | `MD5.Create`, `SHA1.Create`, `DES`/`TripleDES`/`RC2`, `RNGCryptoServiceProvider` vs `RandomNumberGenerator`, `enforceFIPSPolicy` |
| Config / infra | `openssl.cnf` (`.include fipsmodule.cnf`, `[fips_sect] activate = 1`, `default_properties = fips=yes`), `java.security` provider list, nginx/Apache `ssl_ciphers`/`ssl_protocols`, Dockerfile `FROM` (FIPS-enabled base images), K8s/Helm TLS settings |

Also extend `DependencyExtractor` with Cargo, Gradle, .NET and lockfiles (D10).

### 4.3 Phase 3 — Algorithm and parameter rules

Data-driven rule file, e.g. `rules/fips_algorithm_policy.json`, sourced from **NIST SP 800-131A Rev. 2**, **SP 800-140C** (approved security functions), **SP 800-140D** (approved key establishment), **SP 800-90A Rev. 1** (DRBGs), **FIPS 186-5**, and **SP 800-52 Rev. 2** (TLS). Each rule must carry its citation.

Minimum rule set:
- **Disallowed**: MD5, SHA-1 for digital signature generation, DES, 3DES/TDEA encryption, RC2, RC4, Blowfish, ChaCha20/ChaCha20-Poly1305, Salsa20, RIPEMD-160, non-approved PRNGs for security purposes.
- **Parameters**: RSA modulus < 2048; ECC curves outside P-224 (legacy-limited)/P-256/P-384/P-521 and Ed25519/Ed448 per FIPS 186-5; DH/FFC groups < 2048; AES-ECB for data; static or hardcoded IVs/nonces/keys; GCM nonce reuse patterns; PBKDF2 low iteration counts or short salts.
- **TLS**: versions below TLS 1.2; non-approved cipher suites; certificate verification disabled (also maps to SC-8/SC-23).
- **Context-dependent** (e.g. MD5/SHA-1 used for a non-security checksum, cache key or ETag): emit `NEEDS_REVIEW` with the evidence. Gemma 4 may attach an `[AI-DRAFT]` purpose triage, but the verdict stays `NEEDS_REVIEW` until a human dispositions it.

Before encoding them, verify the algorithm and curve lists against the current NIST publications. Do not rely on this handoff or on model memory for transition dates.

### 4.4 Phase 4 — CMVP certificate mapping and approved-mode checks

**CMVP catalog**: `rules/cmvp_catalog.json`, a signed, versioned, offline snapshot.
- Fields: `cert_number`, `standard` (140-2 / 140-3), `status` (Active / Historical / Revoked), `sunset_date`, `module_name`, `vendor`, `module_versions`, `tested_operational_environments`, `approved_algorithms` (CAVP cert refs where available), `source_url`, `retrieved_at`.
- Mapping table: `(library, version range, build/config condition) → cert_number(s)`. Typical entries: OpenSSL 3.x FIPS provider, BC-FIPS (Java), Go native FIPS module, AWS-LC FIPS, BoringCrypto, wolfCrypt FIPS, and OS vendor modules (RHEL/Ubuntu Pro/etc.).
- `./grc-bot update-data` refreshes the catalog from NIST CMVP on explicit user request only. Show a diff and record `retrieved_at`. The tool must warn when the snapshot is older than N days (default 90).
- Determinations: Active 140-3 cert matched + approved mode evidenced → `CONFORMANT_INDICATOR`; 140-2 only → `FAIL_HISTORICAL_CERT`; no cert → `NOT_VALIDATED`; capable, but mode not evidenced → `CANNOT_DETERMINE_STATICALLY`.

**Approved-mode evidence (implements AOC-12, fixes D1)**:
- OpenSSL 3: `openssl.cnf` includes `fipsmodule.cnf`, `[fips_sect] activate = 1`, `default_properties = fips=yes`; code calls `OSSL_PROVIDER_load(NULL,"fips")` / `EVP_default_properties_enable_fips`.
- Host/OS (when scanning bundles of IaC or images): kernel `fips=1`, `update-crypto-policies --set FIPS`, `/etc/crypto-policies/config`.
- Java: `java.security` provider order with a FIPS provider first; `-Djava.security.properties`.
- Go: `GODEBUG=fips140=on|only` in Dockerfiles, CI or env files; `//go:debug` directives.
- Node: `--enable-fips`/`--force-fips`, `crypto.setFips(true)`.
- Rust: `aws-lc-rs`/`aws-lc-fips-sys` with the `fips` feature enabled.
- Dockerfile base images known to ship validated modules.

Static analysis only shows *configuration intent*. Runtime confirmation is out of scope for v1, and the report must say so.

### 4.5 Phase 5 — Reporting and test corpus

- Deliverables in `artifacts/pick-up/<YYYY-MM-DD_HHMMSS>/`: `fips_assessment.md`, `fips_findings.json`, `fips_findings.sarif`, `cbom.cdx.json`, `cmvp_mapping.md`, `fips_provenance.json`, sealed with `sha256sum` (existing convention).
- `fips_assessment.md` sections: Scope & Limitations (framing from §1.1, verbatim), Summary by determination, CMVP Module Mapping, Findings (evidence, rule citation, control, severity, confidence, remediation), Items Needing Human Review, Data Catalog Versions.
- Control mapping: SC-13 (primary), SC-12, SC-8(1), SC-28(1), IA-7, SC-23 (TLS verification).
- Integrate with `grc_reporter.py` so FIPS findings flow into `controls.md`, `poam_data.md` and `scr_scn_package.json`.
- **GRC-xTEST fixtures**: one known-good and several known-bad mini repos per language (Python, Go, Java, Node, C, Rust, .NET), each with a `expected_findings.json`. Add a precision/recall test that fails CI if detection regresses.
- xBOT tests: intent routing for FIPS phrases, URL validation (including injection attempts), planner chain (fetch→verify→restore→scan→clean), and teardown on failure.

### 4.6 Phase 6 — Personal-device packaging

Current friction: three sibling repos, a bash-only `grc-bot` launcher (no native Windows), macOS-specific Docker PATH tweaks, and Docker + Cursor listed as prerequisites in xMINI's `INSTALL.md`.

- Replace the bash launcher with a Python entry point (`grc-bot = grcxbot.cli:main`). Keep `./grc-bot` as a thin wrapper.
- Ship **one installable** (`pipx install grc-xbot`, plus a `python -m zipapp` single-file build; optional PyInstaller binaries for macOS/Windows/Linux) that vendors the needed xMINI engines (`grc_bundle.py`, `crypto_lib_scan.py`, the new FIPS modules, catalogs).
- Core FIPS path requirements: **`python3` ≥ 3.9 and `git` only**. Optional extras: `[docker]` (9-engine scanner) and `[gemma]` (Mode 2). Document a smaller `gemma4` variant for laptops without the RAM for `26b`.
- Data catalogs ship inside the package, versioned and signed. `update-data` refreshes them in a user data dir.
- Releases: signed with Sigstore/cosign (already planned for `v2.2.0 — Daytona`), with published `SHA256SUMS`. A crypto-assessment tool must be verifiable itself.
- CI matrix: macOS, Windows and Linux × Python 3.9–3.13.

---

## 5. Suggested Release Mapping

| Release | Content |
|---|---|
| xMINI patch (`v1.4.5`) | Phase 0 corrections (D2–D8) |
| xBOT `v1.3.0` | Phase 1 intake + `fips` playbook; Phases 2–3 discovery and algorithm rules (minimum: "FIPS readiness" report) |
| xBOT `v1.4.0` | Phase 4 CMVP catalog + AOC-12 approved-mode checks; Phase 5 reporting and corpus |
| `v2.0.0` | Phase 6 single installable, signed releases, cross-OS CI |

This displaces or reorders the currently planned `v1.3.0 — Tsukuba` (POA&M drafter / IaC reviewer) and `v1.4.0 — Autopolis` items. The owner should confirm the ordering before `hygiene/ROADMAP.md` is updated.

---

## 6. Open Decisions for the Owner

1. Release ordering relative to the existing Tsukuba/Autopolis roadmap items.
2. Whether engines move physically into one repo, or stay in xMINI and are vendored at package-build time.
3. Default handling of submodules and Git LFS in target repos.
4. CMVP snapshot staleness threshold (default proposed: 90 days) and who signs catalog updates.
5. Whether GitHub Enterprise Server hosts should be supported in v1.

## 7. Out of Scope (v1)

- Runtime verification that a deployed binary is in FIPS mode.
- Validating cryptographic implementations themselves (that is CMVP/CAVP lab work).
- Any claim of certification or ATO-readiness. The tool produces assessment evidence only.
