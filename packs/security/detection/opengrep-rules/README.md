# Traust Opengrep Rule Pack

Traust-authored opengrep rules — the default ruleset for `traust adapters opengrep`.
Shipped with the security pack and safe to vendor or redistribute.

## Layout

One YAML per language and category (`go/injection.yaml`, …). Each rule file
has a same-basename test fixture (`go/injection.go`, `yaml/foo.test.yaml`)
using standard `// ruleid: <id>` / `// ok: <id>` annotations (or YAML
`# ruleid:` / `# ok:` comments).

```
opengrep-rules/
  go/           # Go rules + .go fixtures
  python/       # Python rules + .py fixtures
  java/         # Java rules + .java fixtures
  typescript/   # TypeScript/JavaScript rules + .ts fixtures
  ruby/         # Ruby rules + .rb fixtures
  rust/         # Rust rules + .rs fixtures
  bash/         # Shell rules + .sh fixtures
  yaml/         # YAML config-default rules + .test.yaml fixtures
```

YAML-language rules use `.test.yaml` fixture files because the rule files
themselves are `.yaml`.

## Running tests

From the traust repo root, with [opengrep](https://github.com/opengrep/opengrep) on `PATH`:

```bash
opengrep test packs/security/detection/opengrep-rules/<lang>
```

Run every language directory, or target one (`go`, `python`, `yaml`, …).

`opengrep test` evaluates every fixture whose name extends the rule file's
basename (`data-exposure.nocred.sh` pairs with `data-exposure.yaml`) but
**ignores** `paths:` filters — path exclusions are exercised at scan time
only. File-level co-occurrence constraints (`pattern-inside: pattern-regex:`
with an anchored lookahead) scan comments too; fixtures must not name the
lexicon words they test.

traust's pytest suite also exercises the pack end-to-end when opengrep
is available:

```bash
pytest tests/test_default_rule_packs.py -q
```

### Fixture sanity and confirmed-TP calibration

The calibration door can run scans as well as score recorded ones:

```bash
# No TP corpus needed: scan this pack's colocated fixtures.
traust impact calibrate-rule-pack traust --fixtures --out /tmp/pack-sanity

# An external pack's own tests/ tree; remote sources must name a full commit SHA.
traust impact calibrate-rule-pack candidate --fixtures \
  --rules /path/to/candidate-pack --out /tmp/candidate-sanity

# Check out the recorded commits of confirmed TPs and rescan with the candidate rules.
traust impact calibrate-rule-pack candidate --rules /path/to/candidate-pack \
  --limit 20 --timeout 900 --out /tmp/candidate-calibration

# Existing recorded-scan scoring remains available (no checkouts or new scans).
traust impact calibrate-rule-pack traust --scan <assessment-uuid> --scan <assessment-uuid>
```

Without `--scan` or `--fixtures`, Core acquires each distinct confirmed-TP
commit through its checkout service, scans it with its opengrep provider, and
releases every workspace. It never substitutes a repository's current HEAD for
the recorded commit. Missing commit bindings and an explicit `--limit` are
reported as skips; checkout/scanner failures retain their reasons. Findings
are not ingested and no vulnerability verdict is authored.

`--fixtures` scans the source's `tests/` directory, or the pack's colocated
annotated fixtures when it has no `tests/`. This is a scanner/pack sanity gate,
not the `ruleid:`/`ok:` assertion gate: continue to run `opengrep test` above.
An absent/empty fixture tree or unavailable scanner is refused, never reported
as a successful zero-hit run. A run with no files scanned, engine errors,
skipped rules, or a nonzero scanner exit is incomplete.

`--out` writes `calibration.json`, `summary.md`, and `review-samples.jsonl`.
Live results include per-commit scan counts/failures, path-level rediscovery,
novel hits for human review, and aggregate volume; fixture results include
their actual scan counts and a bounded sample of matches. Novel hits are
review candidates, not false positives or measured precision.
Completed runs exit 0; incomplete/failed runs emit their evidence and exit 1;
invalid inputs or unavailable prerequisites exit 2. `--opengrep-bin` can name
the scanner's executable path, subject to the configured Core process policy.


## Rule conventions

- **ids:** `traust-<lang>-<category>-<slug>` where `<category>` is a kebab-case
  security category (`injection`, `ssrf`, `cryptography`, `data-exposure`, …).
- **metadata:** `cwe` (primary CWE first — feeds finding fingerprints),
  `category`, `asvs` chapter ref, `confidence`, and optional `references`
  naming the vulnerability pattern cluster (CWE-oriented, no repo slugs).
  A rule that detects a hardening or defense-in-depth gap rather than a
  vulnerability declares `kind: weakness`. Its hits enter audits as
  weakness-kind candidates, and it covers rule-mining classes of confirmed
  weaknesses only. A rule without `kind` is a vulnerability rule.
- **taint mode:** prefer `mode: taint` for data-flow rules; pattern-only
  rules should carry an honest `confidence` tier.
- **messages:** original wording; framework and standard citations by ID only
  (e.g. SEI CERT rule IDs in `metadata.cert` for Java rules).

## Companion gitleaks pack

DSN URLs with embedded credentials are detected by the gitleaks extension in
`../gitleaks-rules/gitleaks-default.toml` (gitleaks reads every file type — `.env`,
`toml`, `properties`, not just code). The yaml tranche here covers the same
miss class in helm values, docker-compose, and operator CR samples.
v1.8 (2026-10-14) — the **authentication, ownership and crypto-hygiene
tranche**: credential acceptance, ownership resolution, security-relevant
configuration flags, and deserialization-sink completeness. These are
seeded rules, not mined ones: each encodes a defect shape that review
missed and no existing rule could surface. Their precision is unmeasured
until their facts are judged (`/mine-ledger`).

- `traust-python-injection-like-wildcard-unescaped`,
  `traust-go-injection-like-wildcard-unescaped` (CWE-155, class CWE-943):
  a LIKE/ILIKE pattern assembled from a run-time value, through an ORM
  pattern operator (SQLAlchemy `like`/`ilike`, peewee `**`), raw SQL text,
  or a bound argument that is itself a wildcard concatenation. An escape
  helper or an ESCAPE clause sanitizes. Pattern rules, not taint: a
  self-chosen account or namespace name is enough to widen the match.
- `traust-python-authentication-jwt-signature-unverified` (new
  `python/authentication.yaml`) and
  `traust-go-authentication-jwt-signature-unverified` (CWE-347): token
  decoding with signature verification switched off, including the
  conditional shape where an options dict is mutated under a test/debug
  flag, the legacy `verify=False` keyword, the `none` algorithm, a Go key
  function that returns no key, and `ParseUnverified` (MEDIUM: it has a
  legitimate key-selection use).
- `traust-python-input-validation-pickle-loads-taint` gained sinks
  (`Unpickler(...).load()` including subclasses, `dill`, `jsonpickle`,
  `shelve`), and `traust-python-input-validation-restricted-unpickler-inventory`
  (INFO, LOW) inventories every `Unpickler` subclass that overrides
  `find_class`. A restricted unpickler is still a deserialization site, so
  a negative result must name it rather than report the class absent.
- `traust-python-cryptography-secret-compare-not-constant-time`,
  `traust-go-cryptography-secret-compare-not-constant-time` (CWE-208,
  LOW): `==`/`!=` (and Go `bytes.Equal`) on token-, password-, digest-,
  signature-, MAC- or API-key-named operands. Literal and nil comparisons
  and metadata-named operands (`*_type`, `*_id`, `*_len`, …) are excluded.

v1.9 (2026-10-16): **two misses from a recall-fixture run.**
- `traust-python-injection-like-wildcard-unescaped` matches a bound
  argument that's an f-string with an interpolation and a `%` anywhere in
  it, inside a tuple or list: `(f"{owner}/{folder}/%",)`. Before this, only
  `f"{x}%"`-shaped arguments matched.
- `traust-python-ssrf-request-taint`:
  - sources add `request.get_json(...)`, `request.json.get(...)`,
    `request.values.get(...)` and `request.form[...]`
  - sinks add the remaining `requests` verbs and `httpx.post`/`request`
  - a database fetch (`fetchone`, `fetchall`, `first`, `one`, …) ends
    request taint, because the value now comes from storage
- New `traust-python-ssrf-stored-url` (CWE-918, WARNING, LOW): an outbound
  call whose URL argument is a database row subscript or a model field with
  a url-type name (`url`, `callback_url`, `webhookUrl`). A URL saved by one
  request and fetched by another never appears as taint. Excluded:
  - config, settings and environment lookups, because the operator sets
    them
  - API response objects (`links`, `resp`, `response`, `headers`)
  - values from a variable assigned from `request` (the taint rule's case)

  Whether anyone other than the operator can write the field is the
  review's judgement.

v1.10 (2026-10-22): **LLM-application tranche** (`<lang>/llm-application.yaml`
for Python, TypeScript and Go). Every rule carries `metadata.owasp_llm`
(OWASP Top 10 for LLM Applications IDs) next to its CWEs. Only shapes that
can be decided from the code itself are here. Whether a tool needs a
per-caller authorization check, how much agency a model should have, and
prompt-injection exposure are left to the review surface.
- **Model output is untrusted input (LLM05, CWE-1426 plus the sink's CWE).**
  Taint rules from SDK completion calls (OpenAI, Anthropic, Gemini,
  LiteLLM, Ollama, LangChain `invoke`, Vercel AI `generateText`, Go
  `openai-go`/`go-openai`/`anthropic-sdk-go`/langchaingo) and their response
  shapes (`choices[i].message.content`, `content[i].text`, `output_text`)
  to:
  - a shell (`output-to-shell-taint`, Go `output-to-exec-taint`)
  - code evaluation (`output-to-code-exec-taint`; Python and TypeScript)
  - SQL text (`output-to-sql-taint`)
  - file paths (`output-to-path-taint`; Python and Go)
- **Supply chain (LLM03, Python only):** `trust-remote-code`,
  `unsafe-model-deserialization` (`torch.load(weights_only=False)`),
  `model-load-default-pickle` (no `weights_only`; WARNING), and
  `unpinned-model-download` (`from_pretrained`/`hf_hub_download`/
  `snapshot_download` with no `revision`; local paths excluded).
- **`mcp-http-without-auth` (LLM06, CWE-306).** An MCP server on an HTTP or
  SSE transport, in a file that configures no authentication. Stdio servers
  and transports chosen at run time are not matched. FastMCP `auth=`,
  `token_verifier=` or `auth_server_provider=` clears a match, and so does
  any bearer/OAuth/JWT/auth-middleware construct in the file. A per-tool
  "handler has no auth call" rule was tried first and dropped: on
  modelcontextprotocol/servers, github/github-mcp-server and the TypeScript
  SDK examples it flagged almost every tool. Those servers are stdio-local,
  delegate to the user's own token, or authenticate at the transport.
- **`unbounded-agent-loop` (LLM10, CWE-834).** `while True` / `while (true)`
  / `for (;;)` / Go `for {}` whose body calls a model and names no step,
  budget, deadline or timeout bound.

Engine note (v1.8): `metavariable-regex` is anchored at the start of the
bound text, so a "contains" test needs a leading `.*` (`(?is).*\blike\b`),
and it cannot sit directly under `pattern-either` — wrap each branch in
its own `patterns:`.


v1.11 (2026-10-27): **TypeScript/JavaScript tranche, from the ledger.** The
rule-mining report's largest uncovered TS/JS clusters were XSS (CWE-79, 37
confirmed findings in about 30 repositories), path traversal (CWE-22, 10)
and open redirect (CWE-601, 4); each rule is written from the cited
findings' evidence. Test, spec, mock and mock-backend files are excluded.
- **XSS (`typescript/cross-site-scripting.yaml`).**
  - `xss-dangerously-set-inner-html`: a computed `__html` value with no
    sanitizer. Translation strings (`t(...)`, `i18n*`) and values named as
    sanitized are not matched.
  - `xss-dom-html-sink`: `innerHTML`/`outerHTML` assignment,
    `insertAdjacentHTML`, `document.write` (also on an opened window) and
    jQuery `.html()` with a computed, unsanitized value.
  - `xss-markdown-raw-html` (WARNING): `rehype-raw` without a later
    `rehype-sanitize`.
  - `xss-reflected-response-taint`: a request value in an Express
    `send`/`write`/`end` string body (sent as text/html).
- **Path traversal (`typescript/path-traversal.yaml`).**
  `path-traversal-fs-taint`: a request value (query, params, body, a
  destructured body field, or `req.url`/`req.path`) reaching the path
  argument of an fs read, write, stream or remove, or `res.sendFile` /
  `res.download`; `path.basename` and filename sanitizers clear it.
- **Open redirect (`typescript/open-redirect.yaml`).**
  `open-redirect-response-taint`: a request value as the target of
  `res.redirect` or a `Location` header. `open-redirect-client-navigation`
  (WARNING): an address-bar value (`URLSearchParams.get`, `location.search`,
  `location.hash`) as the URL of `location.assign/replace/href` or
  `window.open`.
- **SSRF (`typescript/ssrf.yaml`).** More outbound sinks: `http(s).request`,
  the remaining axios methods, got, superagent, needle and undici.

Measured on eight checkouts: 35 hits, including every confirmed TS/JS
finding present in them. Precision is unmeasured until the facts are judged
(`/mine-ledger`). Not covered:
`javascript:` URLs bound to `href`, markdown-to-jsx and marked renderer
overrides, and sanitize-then-transform pipelines; these stay with review.

v1.12 (2026-10-28): **TS/JS sources and one sanitizer, from review.** The
reflected-XSS, open-redirect and SSRF taint rules also take destructured
request fields (`const { x } = req.query`), request headers (`Referer`,
`Host`, any `req.get(...)`), and `req.url` / `req.path` as sources.
`JSON.stringify` is no longer an XSS sanitizer: it leaves `<` and `>` as they
are, and Express sends a string body as HTML, so `res.send(JSON.stringify(x))`
of request data is a sink. On the same eight checkouts this adds 5 hits and
loses none. Flows through helper functions are still not followed.

v1.13 (2026-10-29): **Java, Python, Ruby and Rust, from the ledger.** These
close the Vercel comparison gap plan's recall follow-ups. Each rule is
written from the cited confirmed findings' evidence. Classes with no
confirmed findings (Rust and Ruby SQL, shell interpolation, disabled JWT
verification) get no rule.
- **Java SQL (`java/injection.yaml`).** `injection-sql-concat` now also
  takes:
  - SQL built with `String.format`, `format` or `.formatted`;
  - query text held in a local variable before the call;
  - JPQL and HQL (`createQuery`, `createSQLQuery`) and `JdbcTemplate`'s
    `queryFor*` / `batchUpdate`.

  A literal, or a value declared `int`/`Integer`/`long`/`Long`/`short`, is
  not matched.
- **Python path traversal (`python/path-traversal.yaml`).**
  `path-traversal-file-response-taint`: a catch-all `{name:path}` route
  parameter, or Starlette `request.path_params` / `query_params`, reaching
  `FileResponse`, `open`, `read_bytes`/`read_text`, or returned from a
  `response_class=FileResponse` route. `basename`, `secure_filename` and
  `.name` clear it.
- **Ruby (`ruby/`, new).**
  - `deserialization-yaml-unsafe-load`: `YAML`/`Psych` `unsafe_load` and
    `load` of non-literal data, unless `permitted_classes:` is passed.
  - `deserialization-marshal-load` (WARNING).
  - `injection-kernel-open`: `Kernel#open` / `URI.open` on a non-literal.
    That covers command execution through `|` and SSRF; `File.open` is not
    matched.
  - `injection-erb-template` (WARNING): `ERB.new` on non-literal template
    text, not read from a file.
- **Rust (`rust/`, new).** `path-traversal-request-taint`: a gRPC message
  field (`into_inner()`, or a `…Request` parameter) or an axum/actix `Path`
  / `Query` extractor reaching `std::fs`, `tokio::fs`, `File::open` /
  `create` or `NamedFile::open`; `file_name()` clears it.

Measured on public sample projects (Spring, Rails, FastAPI, axum, tonic):
- `injection-sql-concat` gives 9 hits in one Spring sample, each
  concatenating an id held as a `String` or returned from `getId()`. These
  aren't exploitable but match the shape.
- `yaml-unsafe-load` gives 1 hit, on a maintenance script's local input.
- Nothing else fires.

Precision is unmeasured until the facts are judged (`/mine-ledger`).

v1.14 (2026-10-29): **classic classes for Rust and Ruby.** These rules
cover well-known vulnerability classes in every supported language, for
adopters' code, whether or not this deployment's ledger has seen them.
- **Rust (`rust/injection.yaml`, `rust/authentication.yaml`).**
  - `injection-sql-format`: format!-built SQL (inline or through a `let`)
    run through sqlx, diesel, rusqlite or the postgres client.
  - `injection-shell-format`: `sh -c` / `bash -c` / `cmd /C` with a
    format!-built command.
  - `authentication-jwt-validation-disabled`: jsonwebtoken's
    `insecure_disable_signature_validation`, `validate_exp = false`, or a
    `dangerous_insecure_decode`.
- **Ruby (`ruby/injection.yaml`).**
  - `injection-sql-interpolation`: interpolated SQL in ActiveRecord query
    methods (`where`, `order`, `joins`, `find_by_sql`,
    `connection.execute`, …), and a request parameter used as a raw
    `order`.
  - `injection-shell-interpolation`: interpolated command strings in
    `system`, `exec`, `spawn`, backticks, `%x`, `IO.popen` and `Open3`. The
    multi-argument form is not matched.

v1.15 (2026-10-29): **well-known classes across every application
language.** These rules are for adopters' code, so each supported language
covers the classic classes.
- **Go:**
  - `xss-reflected-response-taint`: request values written to the
    ResponseWriter.
  - `xss-template-trusted-type`: request values converted to
    `template.HTML` and the other trusted types.
  - `open-redirect-taint`: `http.Redirect`, `Location`, gin/echo.
  - `injection-template-parse-taint`: request text parsed as a template.
- **Python:**
  - `open-redirect-taint`: Flask, Django and Starlette redirects.
    Query-string building and `url_has_allowed_host_and_scheme` clear it.
  - `input-validation-xxe-parser`: lxml `resolve_entities=True` /
    `no_network=False`, SAX external entities.
  - `cryptography-weak-hash` (INFO): MD5/SHA-1, judged in context.
  - `cryptography-weak-random-secret`: `random` for secret-named values.
- **TypeScript/JavaScript:**
  - `input-validation-unsafe-deserialization`: node-serialize, js-yaml
    full schema.
  - `input-validation-xxe-noent`: libxmljs `noent: true`.
  - `authentication-jwt-verification-weakened`: the `none` algorithm, or
    `ignoreExpiration`.
  - `cryptography-weak-hash` (INFO).
  - `cryptography-weak-random-secret`: `Math.random`.
  - `cryptography-weak-cipher`: ECB, DES, RC4, `createCipher`.
- **Java:**
  - taint rules from Spring/JAX-RS parameters and servlet requests:
    `path-traversal-request-taint`, `ssrf-request-taint`,
    `xss-servlet-writer-taint`, `open-redirect-taint`;
  - `injection-expression-language`: SpEL, EL, OGNL, MVEL and script
    engines on dynamic text;
  - `authentication-jwt-unsigned-parse`: jjwt unsigned parse, auth0
    decode-only claims.
- **Ruby:**
  - `path-traversal-params-taint`;
  - `xss-html-safe`: params reaching `html_safe`, `raw` or
    `render html:`;
  - `injection-render-inline`;
  - `open-redirect-params`;
  - `authentication-jwt-verification-off`;
  - `cryptography-tls-verify-none`;
  - `cryptography-weak-hash` (INFO) and `cryptography-weak-random-secret`.
- **Rust:**
  - `ssrf-request-taint`: request values into reqwest;
  - `cryptography-tls-verify-off`: `danger_accept_invalid_*`, rustls
    custom verifiers;
  - `cryptography-weak-hash` (INFO).

Measured on twelve public projects (Go, Python, TypeScript, Java, Ruby,
Rust; sample apps through large production codebases):
- the injection, XSS, deserialization, XXE, JWT, TLS and SSRF rules fire
  0 times;
- the open-redirect rules fire twice, both explicitly allow-listed
  redirects a reviewer can close;
- the INFO weak-hash rules fire 14 times, mostly checksums.

Two first drafts were too broad and were changed before release. A rule
that flagged any non-literal `template.HTML(...)` or `.html_safe` fired 80
times on server-built HTML. Those two rules now follow request data only.


v1.16 (2026-10-29): **cross-origin, CSRF, mass assignment and Spring Boot
exposure.** Well-known classes the pack had no rule for, in every language
with a low-noise shape.
- **CORS, any origin with credentials (CWE-942), every language** (new
  `<lang>/cors.yaml`): `cors-any-origin-with-credentials`.
  - Java: a `"*"` origin pattern (`@CrossOrigin`, `CorsConfiguration`,
    `CorsRegistry`) beside `allowCredentials(true)`, or the Origin header
    echoed with credentials.
  - Python: Starlette/FastAPI `CORSMiddleware` (`["*"]` or a match-all
    regex), flask-cors with credentials and no origins (it echoes the
    caller), django-cors-headers allow-all with credentials, aiohttp-cors.
  - TypeScript/JavaScript: `origin: true`, a match-all regex or an
    always-allow callback beside `credentials: true` (cors, Nest, Fastify),
    or the Origin header echoed with credentials.
  - Go: rs/cors `"*"` or an always-true origin func with credentials,
    gin-contrib's always-true func, echo's unsafe wildcard option, or the
    Origin header echoed.
  - Ruby: rack-cors match-all regex or always-true block on a credentials
    resource.
  - Rust: tower-http `very_permissive` / `mirror_request`, actix-cors
    `permissive` / `allow_any_origin` with credentials.
- **CSRF (CWE-352)** (new `<lang>/csrf.yaml`):
  - Java `csrf-disabled-with-session-login`: CSRF disabled in a filter
    chain that also has form login, OAuth2 login or remember-me (a
    stateless token chain is not matched).
  - Python `csrf-protection-disabled`: `csrf_exempt`, Flask-WTF
    `exempt` and `WTF_CSRF_ENABLED = False` outside test configuration.
  - Ruby `csrf-protection-skipped` (INFO, LOW): skips and `except:`, outside
    webhook, callback and API controllers; most skips are deliberate.
- **Mass assignment (CWE-915)** (new `<lang>/mass-assignment.yaml`):
  - Java `mass-assignment-request-body-entity`: a `@RequestBody` entity
    saved or merged as received (types named like DTOs are excluded).
  - Python: `extra-allow` (Pydantic models that keep undeclared fields,
    settings excluded), `model-all-fields` (ModelForm/ModelSerializer
    `fields = "__all__"`), `request-splat` (request data unpacked into
    `objects.create/update`, or `setattr` over its items).
  - TypeScript/JavaScript `mass-assignment-request-body`: the whole
    request body into an ORM create/update, `Object.assign`, a spread, a
    Prisma `data:` or a model constructor.
  - Go `mass-assignment-bind-and-save`: a request body decoded into a
    struct that is then `Create`d, `Save`d or `Updates`d.
  - Ruby `mass-assignment-permit-all`: `permit!` or `to_unsafe_h` handed
    to a model write or returned by a `*_params` method (`slice` first, or a
    hash or keyword value, is not matched).
- **Ownership (CWE-639), Ruby** (new `ruby/authorization.yaml`):
  `authorization-unscoped-find-beside-scoped`: `Model.find(params[...])`
  in a controller whose other actions scope lookups to the signed-in user,
  unless the action authorizes (`authorize`, a guardian-style `ensure_*`,
  an `admin?`/`staff?` check). Ownership with no in-code signal stays with
  review.
- **Spring Boot exposure** (`java/data-exposure.yaml`,
  `yaml/data-exposure.yaml`):
  - `actuator-permit-all` (CWE-200): every actuator endpoint permitted in
    the filter chain;
  - `actuator-web-exposure-all`: `management.endpoints.web.exposure.include`
    of `*` or a sensitive endpoint, in `.properties` (a regex rule limited
    to `*.properties`) and `application.yml`;
  - `error-stacktrace-always` (CWE-209): `server.error.include-stacktrace`
    set to `always`.

Measured on seventeen public projects (sample apps through large
production codebases, all six languages), 24 hits:
- CORS (every language), Java CSRF, the Go and TypeScript mass-assignment
  rules and Pydantic `extra="allow"`: 0;
- Java request-body entities: 7, all in one generated CRUD sample that
  saves request bodies as received;
- Ruby CSRF skips (INFO): 10, deliberate ones a reviewer closes;
- Python CSRF exemptions: 2, both GraphQL views;
- the Ruby unscoped-lookup rule: 2; Ruby `permit!`/`to_unsafe_h`: 1;
  actuator exposure: 2.

Drafts were tightened before release: Ruby CSRF excludes webhook, callback
and API controllers (21 hits before), `permit!` needs a model write or a
returned strong-params value (sliced and nested hashes were matching), and
a listed `include:` reports once per setting rather than once per item.
