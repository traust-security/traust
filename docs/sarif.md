# SARIF — the emitter and the importer

The harness speaks SARIF 2.1.0 in both directions, through two independent
tools:

- **Emitter** — `python3 -m traust.cli reporting sarif` projects a harness
  report into a `.sarif` file for any SARIF consumer (code-scanning
  dashboards, viewers, aggregators).
- **Importer** — `traust triage intake` (traust-core's
  `AssessmentService.record_scan`) records SARIF from any producer as an
  assessment and its findings, which `/triage` then judges.

Neither round-trips the other, and neither is a store. The harness report and
the disposition ledger stay authoritative; a SARIF file is a derived view on
the way out and a set of unverified claims on the way in.

## The emitter

**Input.** Any report that conforms to `report.schema.json` — a code or rpm
`*-security-audit.json`, a `*-container-audit.json`, or the disposition-aware
`*-findings-current.json` — plus `*-cloud-config-audit.json`, which has its
own mapping arm. Prefer `findings-current` when it exists: it carries
dispositions, so false positives arrive as suppressions instead of re-alerting.

**Output.** One SARIF 2.1.0 log with one run. `tool.driver.name` is
`traust-engine`; `version`/`semanticVersion` come from the report's
`harness_version`. `informationUri` is omitted unless `HARNESS_SARIF_TOOL_URI`
is set, so no deployment URL is stamped into an artifact by default.

**Mapping, per finding**

| Harness field | SARIF |
|---|---|
| `category` | `ruleId` (one rule per category in `tool.driver.rules`); cloud-config: the Checkov `check_id` |
| `severity` (or `effective_severity` when a human override exists) | `level` + the `security-severity` property: critical → error / 9.5, high → error / 8.0, medium → warning / 5.0, low → note / 2.0, informational → note / 0.5 |
| `title`, `description`, `remediation` | `message.text` (concatenated; remediation prefixed "Remediation:") |
| `locations[]` with a file path and `lines` | `physicalLocation` with `artifactLocation.uri` and a parsed `region` (`startLine`/`endLine`) |
| `locations[]` with a pseudo-path (`pkg:…`, `oci-config:…`, `layer:…`, `sha256:…`) | `logicalLocations[].fullyQualifiedName` — consumers list these rather than render them inline |
| `id`, `fingerprint` | `partialFingerprints.harnessFindingId/v1` and `harnessFingerprint/v1` — stable across re-audits, so re-uploads update rather than duplicate |
| `cwes` | `properties.tags` (`security` plus each CWE id) |
| `cvss`, `validation_status`, `disposition` | `properties.harness/cvss`, `harness/validation_status`, `harness/disposition` (verbatim; the ledger's two-axis semantics do not round-trip) |
| `disposition.validity == false_positive` | a `suppressions[]` entry, `kind: external`, `status: accepted`, justification naming the ledger |
| `disposition.resolution == risk_accepted` | a second suppression, same shape |
| `disposition.resolution == resolved` | `baselineState: absent` — the finding is gone relative to the audited baseline |

**Run-level fields.** `properties.harness/*` carries the report title,
profile, repository, commit, date, and ref/ref_kind;
`versionControlProvenance` carries the repository URI and revision;
`invocations[0].executionSuccessful` is **false when the run was degraded** —
an explicit `metadata.additional.degraded` flag, or any deterministic step or
negative result recorded as skipped, unavailable, or not run. A consumer must
not read a degraded export as full coverage.

**Cloud-config arm.** For `*-cloud-config-audit.json`, rules are Checkov
check ids, locations carry the resource as a logical location beside the file
range, audit-time `status: suppressed` becomes a suppression carrying the
auditor's rationale, and `properties.harness/assessment_mode` is `declared` —
the export describes declared configuration, never an observation.

**Commands**

```bash
# one report -> <stem>.sarif beside it
python3 -m traust.cli reporting sarif <repo>-findings-current.json

# explicit output path; minified
python3 -m traust.cli reporting sarif report.json -o out.sarif --compact

# batch: walk a findings tree, prefer findings-current over the raw audit,
# mirror the tree layout under --out-dir (never beside the reports)
python3 -m traust.cli reporting sarif --results-root analysis-results/findings --out-dir /tmp/sarif-exports
```

The sweep skips symlink aliases and hidden/state directories, so a report
shared by several products exports once. Exported trees are disposable:
regenerate them on demand rather than committing them, and pair them with a
staleness check only if they ever become a maintained store.

**Consuming the export.** Any SARIF 2.1.0 consumer can ingest the file. Two
conventions matter to the common ones: `partialFingerprints` drives
de-duplication across uploads, and the `security-severity` property drives
severity filters (critical ≥ 9.0, high ≥ 7.0, medium ≥ 4.0). Give harness
uploads their own category or tool name on the consumer side so they stay
separate from the platform's native analyses. A dashboard that does not
ingest SARIF needs its own projection written against the harness report; the
repo carries one such projection for the GitLab security-report format under
`src/traust/migrations/export_gitlab_sast.py`, as an example of
the shape (deterministic ids, false positives excluded by default).

## The importer

**Input.** SARIF 2.x from any producer — CodeQL, Semgrep, Snyk, Trivy, Bandit,
Coverity, and the harness's own deterministic tools run standalone (opengrep
`--sarif`, gitleaks `-f sarif`, osv-scanner `--format sarif`, checkov
`-o sarif`, grype `-o sarif`, govulncheck `-format sarif`). The same script
also normalises Dependabot alert exports and govulncheck's native `-json`
stream; those arms are outside this page.

**Output.** A `scanner` assessment of the commit (assessor and version from
`tool.driver`) and its findings, through traust-core's finding intake: a
finding is matched by fingerprint, else created, and this assessment's
occurrence carries the reported severity, rule and locations. Every imported
finding is a **machine-static claim**: intake never sets a verdict, and
triage's adversarial vote applies regardless of what level the producer
asserted.

**Mapping, per result**

| SARIF | Harness field |
|---|---|
| `ruleId` | `rule` |
| `properties.security-severity` (result, then rule) | `severity` by band: ≥ 9 critical, ≥ 7 high, ≥ 4 medium, > 0 low, else informational |
| `level`, when no `security-severity` is present | `error` → high, `warning` → medium, `note`/`none` → informational (SARIF's default level is `warning`); a scanner giving no severity at all reports `unrated` |
| rule `shortDescription`, else `ruleId` | `title` |
| `message.text` + rule `fullDescription` + rule `help.text` | `description` |
| first `physicalLocation` | `file`, `line` |
| `tags` on rule and result matching `CWE-nnn` | `cwes` |
| `guid`, else `partialFingerprints.harnessFindingId/v1`, else `ruleId` | the finding's label in the scan |
| rule `properties.precision` (CodeQL convention) | `confidence` (very-high 0.95, high 0.85, medium 0.6, low 0.4) |
| `tool.driver.name` / `version` | the assessment's `assessor` / `assessor_version` |

Results carrying `suppressions[]` are **skipped**.
Importing the harness's own export therefore drops the findings the ledger had
dispositioned, which is the intended asymmetry: dispositions come from the
ledger, never from a file that passed through a third-party tool.

**Command**

```bash
python3 -m traust.cli triage intake scan.sarif --format sarif \
    --repo-url https://github.com/org/repo --sha <scanned commit>
```

It prints the new assessment's id; `/triage` takes it from there
(`traust triage prepare`), and the verdicts are recorded as decisions
(`traust triage record`).
The scanner name/version in SARIF supplies the assessment's source metadata; no
caller origin flag is accepted. Later observations do not replace the first
reporting assessor used for origin grouping.
