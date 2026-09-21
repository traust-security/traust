# Traust Opengrep Rule Pack

Traust-authored opengrep rules — the **default** ruleset for
python3 -m traust.cli adapters opengrep. Authored from the campaign's own
ledger-confirmed true-positive corpus (see
[`progress-tracker/plans/opengrep-ruleset-plan.md`](../../../../../progress-tracker/plans/opengrep-ruleset-plan.md))
and licensed with the harness itself: **our IP, no external restrictions**,
safe to vendor, redistribute, and commercialize.

## Layout & conventions

One YAML per language/category (`go/injection.yaml`, …), multiple rules per
file, each with a same-basename test file (`go/injection.go`) using the
standard `// ruleid: <id>` / `// ok: <id>` annotations. Run the tests with:

```bash
opengrep test harnessing/3-audit/secure-code-audit/opengrep-rules/<lang>
```

Rule requirements (checked in review; keep them true):

- ids: `traust-<lang>-<category>-<slug>`, category from the shared kebab-case
  vocabulary in [`docs/report-structure.md`](../../../../docs/report-structure.md).
- `metadata`: `cwe` (primary first — feeds the finding fingerprint),
  `category`, `asvs` chapter ref, `confidence`, and `references` naming the
  campaign pattern cluster the rule was mined from.
- Prefer `mode: taint`; pattern-only rules carry honest `confidence` so the
  judge protocol in the SKILL can weight them.
- Messages in our own words; framework citations by ID only.

## Provenance

Mined 2026-07-16 from the insecure-patterns dashboard — the clusters it
surfaced as both recurring and mechanically detectable: CWE-532 (sensitive
information in a log file), CWE-295 (improper certificate validation),
CWE-78 (OS command injection), CWE-22 (path traversal), CWE-918 (SSRF) and
CWE-214 (invocation exposing sensitive information), plus supporting
cryptography/debug/deserialization patterns. v1.1 (2026-07-17) added the bash tranche from the CWE-494/532 bash clusters. v1.2 (2026-07-18) added the cosign classical-signing inventory rules (bash + go), ported from the PQC pilot's calibrated HP_SIGN_COSIGN pattern (command-verb / quoted-import anchored; the bare-'sigstore' shape produced 38/38 FPs). v1.3 (2026-07-21) added the first AWX-FN-probe-seeded Python tranche (tar-extract-without-filter, startswith path containment, ssl.wrap_socket). v1.4 (2026-07-21) completed Python parity with Go (12 rules): raw-SQL taint, Jinja2 template taint, mark_safe/format_html XSS taint, pickle/marshal deserialization taint — see progress-tracker/plans/language-coverage-plan.md.
Calibration results live in the plan doc.

v1.5 (2026-07-23, error-correction plan item 3.1) added the **config/DSN
tranche** targeting the measured ~75%-FN config/DSN finding class
(progress-tracker/metrics/error-analysis/fn-analysis.md §4 + b-lite
sxs-2026-07 deltas): a new `yaml/` directory (shipped deployment defaults —
sslmode/TLS-verify disabled, default/empty passwords, auth-disable toggles
in helm values / docker-compose / CR samples; yaml-language rules use
`.test.yaml` fixture files) plus `*-insecure-dsn-transport` code rules in
`go/` and `python/`. The yaml tranche activates automatically via
run_opengrep.py's existing `.yaml`→`yaml` language mapping; its facts have
no `KHS-*` counterpart (see SKILL.md pre-scan contract item 5). The
companion DSN-with-embedded-credentials detector lives in the gitleaks
pack (`traust-dsn-url-credentials`) because gitleaks reads every file type
(.env, toml, properties), not just yaml/code. Each rule's comment cites
the measured miss it derives from.

v1.6 (2026-07-27, error-correction FP-persistence fix) recalibrated
`traust-python-path-traversal-tar-extractall-nofilter`: the untyped
`$T.extractall(...)` shape also matched **zipfile** receivers, mechanically
re-seeding a Precision-Gate-refuted FP class (zip-slip is tarfile-only —
Python's zipfile sanitizes member paths; leg-2 FP-persistence analysis,
`analysis-results/scan-testing/sxs-2026-07/fp-persistence-analysis.md`).
ZipFile receivers (assignment and `with` forms) are now excluded, with
`ok:` fixtures.

v1.7 (2026-07-29) — the **2026-07-29 mined tranche + precision
recalibration**, authored from the post-orphan-backfill ledger mine
(the confirmed-TP corpus, `progress-tracker/metrics/rule-mining/`; per-rule
proposals in the plan's "Backlog refresh — 2026-07-29" section). Six new
rules, every one specified by tp-corpus finding entries and calibrated by
re-cloning corpus repos at the recorded commits (matrix in the plan doc):

- `go/resource-management.yaml` (NEW category file, CWE-400/770 clusters —
  173+97 TPs): `traust-go-resource-management-http-client-no-timeout`,
  `-http-server-no-timeouts` (fires only when ALL of Read/ReadHeader/
  Write/Idle are absent, post-construction assignments sanitize),
  `-unbounded-request-body-read` (inbound receivers only,
  http.MaxBytesReader sanitizes). Ledger-confirmed server-hardening
  shapes; the audits' volumetric-DoS do-not-report boundary is the
  judge's business — rules emit facts. Calibration: 9/9 corpus repos
  rediscovered at the recorded locations.
- `go/authentication.yaml` (NEW, CWE-290 cluster — 135 TPs):
  `traust-go-authentication-forwarded-identity-passthrough` — forward-
  without-strip shapes only (wholesale header copy, explicit
  X-Forwarded-* Set-from-Get, and reverse-proxy construction in a file
  that traffics in identity headers but never deletes any); rediscovers
  oauth-proxy FIND-003 at oauthproxy.go:113/185. The x-rh-identity
  middleware variant (crc-caddy-plugin) is out of the narrow scope —
  judge-owned.
- `go/secrets-management.yaml` (NEW, CWE-522 cluster — 108 TPs):
  `traust-go-secrets-management-credential-in-metric-label` — credential-
  lexicon keys/values in prometheus.Labels / WithLabelValues, plus the
  URL-stringified-into-label shape ($U.String() where Redacted() is the
  fix); rediscovers configmap-reload:131 and s3-reload:122.
- `python/data-exposure.yaml` (NEW, CWE-532/python cluster — 72 TPs):
  `traust-python-data-exposure-secret-in-log`, **LOW confidence by design**
  (the go analog runs 0.10 precision): bare credential identifiers,
  credential f-string interpolations, and credential %-operands only;
  masked/metadata identifiers excluded. Rediscovers the mechanically
  expressible corpus subset (netobserv-perf-tests, assisted-test-infra,
  ceph-qe-scripts); dict/kwargs/header-map logging stays judge-owned.

Precision recalibration of the 2026-07-29 flagged rules (before→after
rationale in each rule's `references`; all known ledger TPs re-verified
firing post-tightening — downgrade-not-drop applies to rules too):

- `traust-bash-data-exposure-xtrace` (0.07/328): file-level co-occurrence —
  fires only in scripts that reference credential-lexicon identifiers or
  source/pipe remotely fetched scripts. Both confirmed-TP classes
  re-verified (in-script tokens; frontend-build `source <(curl ...)`).
- `traust-go-ssrf-request-taint` (0.07/62): generated clients (*.gen.go,
  *_gen.go, *generated*) path-excluded — 44/62 dismissals; url.Parse'd
  values sanitized (parse-then-validate idiom); confidence HIGH→MEDIUM.
  The generic `$C.Query()` source is deliberately kept: the confirmed
  TPs (cluster-version-operator cincinnati.go:103, argo-rollouts
  graphite/api.go:47 — both re-verified) fire through the same url.URL
  shape in hand-written code.
- `traust-python-input-validation-yaml-unsafe-load` (0.00/31): ruamel.yaml
  `yaml = YAML()` instances excluded, literal-path `open("...")` inputs
  excluded (trusted-input dismissal mass), ERROR/HIGH→WARNING/LOW; the
  ledger TP (insights-playbooks validate.py:13) re-verified.
- `traust-yaml-insecure-workload-config-auth-disabled` (0.00/11) +
  `traust-yaml-secrets-management-empty-password` (0.00/10): scoped to
  NON-k8s YAML — documents carrying `apiVersion` are excluded (KHS-*
  facts authoritative for manifests per SKILL.md; duplication was the
  entire dismissal mass). Scoping proved clean in multi-doc fixtures, so
  neither rule is retired. `default-password` (0.67) stays unscoped.
- `traust-java-input-validation-variable-format-string` (0.00/7): the 7
  dismissals POST-date the 2026-07-20 receiver-typing fix and are a new
  class — CONSTANT_CASE format references (kruize/autotune) — now
  excluded; all 7 sites re-verified silenced, TP shapes preserved.
- `traust-go-data-exposure-secret-in-log` (0.10): benign-metadata suffix
  exclusion extended from the dismissal corpus (expiry/scope/review/
  errors/file-path/image classes), confidence MEDIUM→LOW; the 3 promoted
  cluster-api-provider-azure sites re-verified firing.

Data-quality (same wave): `run_opengrep.py` now strips opengrep's dotted
path prefix from `check_id` (`bare_rule_id`), and the SKILL.md
correlation spec forbids pack-level aggregate rule_ids — the 2026-07-29
mine found 5 aggregate + 19 dotted-path correlation entries that
fragmented per-rule precision.

Engine notes (v1.7): `opengrep test` evaluates every fixture whose name
extends the rule file's basename (`data-exposure.nocred.sh` pairs with
`data-exposure.yaml`) but IGNORES `paths:` filters — path exclusions are
exercised at scan level only. File-level co-occurrence constraints
(`pattern-inside: pattern-regex:` with an anchored lookahead) scan
comments too — fixtures must not name the lexicon words they test.

v1.3 (2026-07-20) added the **java tranche** (`java/`): 8 seed rules keyed to
SEI CERT Oracle Coding Standard for Java rule IDs (`metadata.cert`; IDs cited
by reference only — patterns and text original to this pack), motivated by
the 2026-07 Java batch exposing zero Java coverage. Two rules encode
true-positive shapes from the commons-text spot-check (variable format
string, XXE-prone factory without hardening). Seed provenance, not mined.

v1.3.1 (2026-07-20) calibrated the java tranche from the 2026-07 Java batch's
863 judged decisions (`/mine-ledger`; table in the plan doc):
variable-format-string receiver typed `java.util.Formatter` (was 1%
precision from java.text over-match), xxe-factory gained test-path
excludes, weak-random demoted to LOW confidence. sql-concat flagged
(SQL-engine repo skew) but unchanged.
