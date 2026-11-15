# DRAFT: Normalized Finding Schema 1.0.0

> **Status**: Draft for owner review. No engine or reporter code has been changed.
> **Files**: [`rules/finding_schema.json`](../rules/finding_schema.json) (JSON Schema 2020-12) · [`rules/finding_schema.example.json`](../rules/finding_schema.example.json) (validates against it)
> **Proposed for**: Phase 0 of the FIPS 140-3 work, before `fips_discovery.py` exists.

---

## 1. Why

`grc_reporter.py` already has a normalized record, `NormalizedFinding`. But it is internal to the reporter, has no status field, and each `parse_*()` adapter decides on its own what counts as a finding. That implicit contract is the root of several defects in the FIPS design review:

| Defect | Cause in the current contract |
| :--- | :--- |
| D3: healthy libraries become POA&M items | `parse_crypto_scan()` skips only `PASS`; any other status is a POA&M item |
| D5: `NOT_VALIDATED` falls through to `PASS` | No shared status vocabulary between catalog, engine and reporter |
| D2: `SC-8(1)` → `SC-8`, second control dropped | `re.search(r"([A-Z]{2}-\d+)")` picks the first ID only |
| D12: duplicate Semgrep + FIPS findings | Dedup exists only for CVEs (`_seen_vuln_keys`) |
| SI-16 false `COMPLIANT` | "Assessed" comes from the static `assessed_by` catalog, not from what the run tested |

## 2. Three rules the schema enforces

1. **One finding answers one question.** If a library is outdated (`SI-7`) *and* its FIPS status is unknown (`SC-13`), that's two findings. This is how the schema separates lifecycle status from FIPS status (D3) without a two-status record.
2. **Engines conclude, the reporter decides consequences.** Engines emit a `determination` and a `severity`. CAT level, SLA days, target dates and POA&M placement all come from `rules/severity_policy.json` in the reporter, so they never come from engines.
3. **Engines declare their scope.** `scope.assessed_controls` says which controls the run actually tested. A control with zero findings rolls up as passing only if a loaded engine declared it.

## 3. Determination → reporter behaviour

| `determination` | POA&M? | SLA? | Where it appears | Control rollup contribution |
| :--- | :--- | :--- | :--- | :--- |
| `FAIL` | Yes | Yes | `poam_data.md` | Findings open |
| `WARN` | Yes | Yes | `poam_data.md` | Findings open |
| `NEEDS_REVIEW` | No | No | New "Requires Human / Runtime Verification" section | Indeterminate |
| `CANNOT_DETERMINE_STATICALLY` | No | No | Same section | Indeterminate |
| `PASS` | No | No | Evidence only ("conformant indicator" in FIPS deliverables, per handoff §1.1) | Supports passing |

**Control rollup**, evaluated per control ID. The first rule that matches wins:

1. Any `FAIL`/`WARN` → findings open (today `❌ NON-COMPLIANT`)
2. Any `NEEDS_REVIEW` / `CANNOT_DETERMINE_STATICALLY` → `INDETERMINATE` (**new**)
3. Listed in some loaded engine's `scope.assessed_controls` → no open findings (today `✅ COMPLIANT`)
4. Otherwise → `⚪ NOT ASSESSED`

Whether rows 1 and 3 keep the words "COMPLIANT" / "NON-COMPLIANT" is the open question in §4.2 Q2 of the review. The schema doesn't depend on that answer.

> For third-party tools, which emit no `scope`, the reporter keeps a per-adapter default scope until each engine declares its own. Semgrep's default scope would come from the controls in `custom-baseline-ruleset.yaml`, not from the static catalog. That removes the SI-16 false pass.

## 4. Cross-engine dedup key

```
(location.path, location.line_start, aoc.id, subject.kind, lower(subject.name))
```

When two findings share a key, keep the higher-`confidence` one. On a tie, prefer the native engine. Record the other engine in the kept finding's `extensions.dedup.also_reported_by`. Example: Semgrep `grc-aoc03-python-weak-hashing` and `fips_discovery.py` `fips-alg:md5` on `src/fips_bypass.py:13` → one POA&M row.

For this to work, Semgrep's adapter must fill in `subject.name` (e.g. `md5`). The cleanest way is a `subject` metadata key on each `custom-baseline-ruleset.yaml` rule, next to `aoc` and `nist_control`.

## 5. Field mapping from today's outputs

### 5.1 `crypto_findings.json` (`CryptoFinding.to_dict()`)

| Today | New | Note |
| :--- | :--- | :--- |
| `library_name` | `subject.name` | `subject.kind = "package"` |
| `detected_version` | `subject.version` | `"Unknown"` → omit the field |
| `ecosystem` | `subject.ecosystem` | |
| `manifest_file` | `location.path` | `location.kind = "manifest"`, or `"host"` for system libs |
| `compliance_status` | `determination` + `determination_detail` | `PASS`→`PASS`; `FAIL_EOL`/`FAIL_DEPRECATED`→`FAIL`; `WARN_*`→`WARN`; original value kept in `determination_detail` |
| `severity` | `severity` | Only on `FAIL`/`WARN` |
| `description` | `message` | |
| `remediation` | `remediation` | |
| `nist_controls` | `controls` | Full list kept |
| `area_of_concern` (`"AOC-09: …"`) | `aoc.id` + `aoc.title` | Split on the first `:` |
| `matched_rule` | `rule_id` | Prefixed `crypto:` |
| (none) | `detection` | `manifest`/`HIGH` when pinned, `MEDIUM` for ranges |
| (none) | `finding_id` | Today the reporter generates IDs; engines would now supply deterministic ones |
| `fips_capable` (catalog) | **separate** `SC-13` finding | With `extensions.fips.fips_status`, per rule 1 |

### 5.2 Semgrep (`semgrep_findings.json`, via the reporter adapter)

| Semgrep field | New |
| :--- | :--- |
| `check_id` | `rule_id` |
| `path`, `start.line`, `end.line`, `start.col` | `location.{path,line_start,line_end,column}`, `kind = "file"` |
| `extra.message` | `message`; `title` = text before the first `:` (as today) |
| `extra.severity` | `severity` via `normalize_severity_and_cat()` |
| `extra.metadata.aoc` | `aoc.{id,title}` |
| `extra.metadata.nist_control` | `controls`: **all** IDs found, with enhancements |
| `extra.metadata.subject` (**new**) | `subject` |
| `extra.lines` | `evidence.snippet` (truncated to 500 chars) |
| (constant) | `determination = "FAIL"`, `detection = {external_tool, HIGH}` |

### 5.3 `NormalizedFinding` → schema

`NormalizedFinding` becomes the in-memory form of a schema finding. It gains `determination`, `subject`, `detection` and `controls`, which replaces `nist_controls` without truncation. `sla_days`, `target_date` and `cat_level` stay as reporter-derived fields. `raw_data` stays adapter-only and is never written back out.

## 6. Migration plan (no big-bang)

1. Add `rules/finding_schema.json` and a small `Finding` dataclass + `validate_findings()` in `grc_common.py`. Keep it stdlib-only: hand-check the required fields and enums, and run full `jsonschema` validation only in `grc_test.py` when the package is available.
2. `crypto_lib_scan.py` emits the new envelope in `crypto_findings.json`. `parse_crypto_scan()` branches on whether `schema_version` is present, so the legacy format still loads. That keeps `testing/demo-evidence/*` readable until it is regenerated.
3. Make the reporter's adapters (Semgrep, Checkov, Grype, Trivy, Gitleaks) build the extended `NormalizedFinding`. Add the dedup pass and the scope-based rollup.
4. Write `fips_discovery.py` against the schema from its first commit.
5. Update `grc_test.py`: `test_crypto_scan` asserts on `determination`/`determination_detail` instead of `compliance_status == "PASS"`. Add a test that validates `finding_schema.example.json`.

## 7. Open questions for the owner

1. **`WARN` → POA&M?** Today every `WARN_*` becomes a POA&M item, and this draft keeps that. Should `WARN_UNVERIFIED` (version not pinned) move to `NEEDS_REVIEW` instead?
2. **File naming.** Should native engines keep `crypto_findings.json`, or move to `<engine>.findings.json` so the reporter can find new-format files by pattern?
3. **Positive findings volume.** Should `PASS` findings be required, or optional behind `--emit-pass`? They're useful for CBOM and FIPS evidence, but they make files bigger.
4. **Schema `$id`.** It's a placeholder URL. Should it be a repo-relative path instead?
