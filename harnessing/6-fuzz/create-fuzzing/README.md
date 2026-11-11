# Offline fuzz harnesses — top-10 audit-derived targets

Scaffolded from `analysis-results/findings/**/*security-audit.md` recommendations. Every target
is a **pure-function parser / decoder / templater** callable with only a Go
toolchain — no k8s cluster, no cloud creds, no service mocks.

## Layout

```
create-fuzzing/
├── targets.json         # machine-readable manifest (repo, commit, harness→dest, pkg, fuzz func)
├── Makefile             # clone / install / build / fuzz-<id> / fuzz-all
├── clones/              # service checkouts, symlinked @ pinned commit (git-ignored upstream)
└── (harness sources)    # moved 2026-08-27 to analysis-results/fuzz-harnesses/<repo>/;
                        # copied into clones/ by `make install` via $(HARNESSES)
                         # (crashers land in clones/<id>/<pkg>/testdata/fuzz/; curated
                         #  reproducers → analysis-results/findings/**/<id>/fuzz-corpus/<FuzzName>/)
```

## Quick start

```sh
cd traust/harnessing/6-fuzz/create-fuzzing
make clone install build          # verify everything compiles
make fuzz-kube-rbac-proxy         # highest reach (167 products)
make FUZZTIME=1h fuzz-all         # overnight sweep
```

Crashes are written by the Go fuzzer to
`clones/<id>/<pkg>/testdata/fuzz/<FuzzName>/<hash>` — copy interesting ones
into `analysis-results/findings/**/<id>/fuzz-corpus/<FuzzName>/` and reference
them from a follow-up finding.

## Targets

| # | Repo | Fuzz func(s) | Entry point | Reach | Audit ref |
|--:|---|---|---|--:|---|
| 1 | kube-rbac-proxy | `FuzzTemplateWithValue`, `FuzzWithAllowPaths`, `FuzzParseAuthorizationConfigFile` | `templateWithValue` (pkg/proxy/proxy.go:137), `WithAllowPaths` (pkg/filters/path.go:23), `parseAuthorizationConfigFile` (cmd/.../kube-rbac-proxy.go:531) | 167 | FIND-019 |
| 2 | oc | `FuzzApplyLayer`, `FuzzExtractTarStream` | `ApplyLayer` (pkg/cli/image/archive/archive.go:83), `(*stiTar).ExtractTarStream` (pkg/helpers/source-to-image/tar/tar.go:341) | 36 | FIND-015 |
| 3 | cluster-logging-operator | `FuzzGenerateConf` | `(*ConfigGenerator).GenerateConf` (internal/generator/forwarder/generator.go:26) | 1 | FIND-012 → would have caught FIND-001 |
| 4 | submariner | `FuzzParseAndHandleMessage`, `FuzzIPv6RE` | `(*natDiscovery).parseAndHandleMessageFromAddress` (pkg/natdiscovery/listener.go:127), `IPv6RE` (pkg/endpoint/public_ip.go:57) | 4 | FIND-015/016 |
| 5 | external-secrets | `FuzzExecute` | `execute` (runtime/template/v2/template.go:241) | 1 | FIND-009 |
| 6 | cluster-version-operator | `FuzzGraphUnmarshal` | `graph` + `(*edge).UnmarshalJSON` (pkg/cincinnati/cincinnati.go:402) | 5 | roadmap P3 |
| 7 | ocm-sdk-go | `FuzzReadKeys` | `(*Handler).readKeys` → `parseKey` (authentication/handler.go:622/701) | 4 | roadmap |
| 8 | cloud-credential-operator | `FuzzCredentialsRequestDecode` | `YAMLOrJSONDecoder` loop (pkg/cmd/provisioning/utils.go:169) + `DecodeProviderSpec` | 1 | roadmap |
| 9 | assisted-installer-agent | `FuzzParsePingCmd`, `FuzzNmapXML` | `parsePingCmd` (src/connectivity_check/ping_checker.go:60) | 1 | roadmap |
| 10 | go-template-utils | `FuzzResolveTemplate` | `(*TemplateResolver).ResolveTemplate` (pkg/templates/templates.go:607) — fake dyn/discovery clients | 4 | ACM policy surface |

## Design notes

- **In-package white-box tests.** 7 of the 14 entry points are unexported, so
  each `*_fuzz_test.go` declares the target's own `package` and is copied *into*
  the clone tree by `make install` (paths in `targets.json[].harnesses[].dest`).
- **Seed corpus.** Where the repo ships real fixtures they are loaded via
  `f.Add()` at init (e.g. CLO reads `docs/reference/samples/*.yaml`). Otherwise
  seeds are hand-rolled minimal-valid + minimal-invalid pairs.
- **No network at fuzz time.** `go-template-utils` is wired to
  `dynamic/fake` + `discovery/fake`; `ocm-sdk-go` bypasses `loadKeysURL` and
  drives `readKeys(io.Reader)` directly; `submariner` skips the UDP listener
  and calls the parse method with a synthetic `*net.UDPAddr`.
- **Compile status.** `make build` is expected to pass on go1.26+. Three
  harnesses touch unexported struct fields (`natDiscovery{}`, `Handler{keys:}`,
  `graph{}`) — if upstream refactors those, the compile error is the signal to
  re-scout; the manifest pins the audited commit so this is stable until then.

## Next 252 candidates

`findings/` contains **262** unique repos with named fuzz targets; this batch
covers the top-10 by product reach. To extend, add an entry to `targets.json`
and drop a harness under `analysis-results/fuzz-harnesses/<id>/` — `make` picks it up
automatically via `$(HARNESSES)`.
