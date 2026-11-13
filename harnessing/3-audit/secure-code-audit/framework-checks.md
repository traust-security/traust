# Per-technology review checks

Read the section for each technology the checkout uses. Every run verifies
the same questions, so two audits of the same code ask the same things.

**How to use the checks.** Each check is a question you answer from code,
with the CWE a confirmed finding files under and the standard requirement
it verifies: an OWASP ASVS 5.0 section and, for operator checks that one
fits, the OWASP Kubernetes Top 10 ID from this skill's K01–K10 table. A check is never a
conclusion:
- **Confirm it with evidence:** the deterministic fact named in the
  Evidence column where one exists, otherwise a cited `file:line` or a
  traced data flow.
- **No evidence either way** is a `coverage_gaps` entry, not a negative.
- **A tool that reports nothing is not a negative.** Zero opengrep facts
  or an empty matrix list only means the tool found none of the shapes it
  knows. The rules miss values that pass through helpers or are
  destructured first. Trace the flow yourself and say how you did.
- **Checks marked *judgement*** have no deterministic answer. Say how you
  decided.

These checks are Traust's own wording. Standards are cited by ID only.

## Selecting sections

| Section | Applies when |
|---|---|
| Kubernetes operators | `go.mod` requires `sigs.k8s.io/controller-runtime` or `k8s.io/client-go`, the code implements a `Reconcile` method, or the tree carries `+kubebuilder` markers |
| gRPC | `go.mod` requires `google.golang.org/grpc` and the code calls `grpc.NewServer`, or `traust adapters grpc-guards` reports servers or services |
| FastAPI and aiohttp | Python code imports `fastapi` or the aiohttp server (`aiohttp.web`), or `traust adapters route-guards` reports `fastapi` or `aiohttp` rows. A client-only `import aiohttp` doesn't select it |
| Express | `package.json` depends on `express` or `express-promise-router`, or `traust adapters route-guards` reports `express` rows. A Backstage backend plugin selects it too |
| Spring and JAX-RS | Java code imports `org.springframework.web.bind.annotation` or `javax.ws.rs` / `jakarta.ws.rs`, or `traust adapters route-guards` reports `spring` or `jax-rs` rows |
| axum and actix-web | Rust code uses `axum::` or `actix_web::`, or `traust adapters route-guards` reports `axum` or `actix-web` rows |
| tonic | Rust code uses `tonic::` and builds a `Server`, or `traust adapters grpc-guards` reports `tonic` services |
| Rails and Sinatra | the tree has `<app>/config/routes.rb`, Ruby code requires `sinatra` or subclasses `Sinatra::Base`, or `traust adapters route-guards` reports `rails` or `sinatra` rows |
| Django, DRF and Flask: route ownership | `traust adapters route-guards` reports `django-drf` or `flask` rows. This section covers route ownership only |
| Go: route ownership | `traust adapters route-guards` reports `go-http` rows (net/http, gorilla/mux, chi, gin, echo, fiber, PocketBase). This section covers route ownership only |

A checkout can select several. Record which sections ran (see Recording).
Route-guards rows from a family no section covers go in `coverage_gaps` with
tool `framework-checks`, so they are not mistaken for reviewed. Django, DRF
and Flask have an ownership section only: review their rows' ownership
under DF.1, and record the rest of those frameworks' review (authentication,
authorization beyond ownership, CSRF, mass assignment, debug settings) as a
`framework-checks` coverage gap. Go likewise: review `go-http` rows'
ownership under GO.1 and record the rest of a Go web review as a
`framework-checks` coverage gap.

## Route ownership (CWE-639)

`traust adapters route-guards` classifies each authenticated route with an
object id in its path (Spring, JAX-RS, FastAPI, Express, Rails, axum,
actix-web, Django/DRF, Flask, aiohttp and Go today) in the row's `ownership`, with the spans it read in `ownership_evidence`
(`lookup`, `caller`, `check`, `hop`, `record_type`, `owner_field`). The
values are `scoped`, `checked`, `caller-blind`, `unchecked`, `none`,
`unknown` and `n/a`. Rows marked `caller-blind` (the handler never sees the
caller) or `unchecked` (it sees the caller but loads an owner-bearing
record without tying it to the caller) are judged, so they set
`judgement_required`. Read them first for the ownership checks below (FA.4,
EX.4, JV.5, RW.4, RL.3, DF.1, GO.1). `unknown` means the reader couldn't follow the
handler: review it by hand. Protection is credited only from an allow-list
of exact shapes, so a `scoped` or `checked` row is still a claim: spot-check
one per controller or router. The axum/actix-web, Django/DRF, Flask,
aiohttp and Go readers never credit protection: their rows are only judged or `unknown`, so
an `unknown` row there includes reads the code does tie to the caller, and a
judged row includes ones it checks by hand after the read. Read each. A framework or handler the reader doesn't
classify is a `<family> ownership` coverage gap naming its routes, never a
blank: review those routes' ownership by hand and record the gap.

**The reader classifies ids in the route path only.** A route that takes the
object id from the query string or the body has no ownership classification
and no ownership gap, so it is not on that worklist: FastAPI query
parameters, `req.query` or `req.body`, `@RequestParam` / `@QueryParam`, Rails
`params[:id]` filled from the query. Find those routes by hand from the
handlers and answer the same check for each. List any you didn't review in
`coverage_gaps`. These are facts, not findings: only a confirmed row becomes
a finding.

## Django, DRF and Flask: route ownership

`traust adapters route-guards` reads Django URLconfs, DRF routers and
viewsets, and Flask blueprints, class views and flask-restful resources,
with each route's guards and, for authenticated id routes, its `ownership`.
This section covers route ownership only. The rest of a Django or Flask
review is a `framework-checks` coverage gap until a full section lands (see
[Selecting sections](#selecting-sections)).

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| DF.1 | Does a route that takes an object ID (a URLconf or router path converter, `<int:id>` in a Flask route, `self.kwargs`, `request.view_args`) check that the caller may act on that object, and is the ownership or tenant filter taken from the authenticated principal (`request.user`, flask-login's `current_user`, flask-jwt-extended's identity) rather than a value the caller sets? A DRF object permission (`has_object_permission`) counts only where `get_object()` runs it. | CWE-639 | ASVS V8.2 | the route-guards rows' `ownership` ([Route ownership](#route-ownership-cwe-639); these readers judge but never credit), `caller-blind` and `unchecked` first, then `unknown`; then the ORM read (`get_object_or_404`, `Model.query.get_or_404`, `db.session.get`, a viewset's `get_queryset`) and the filter on it, `file:line` |

## Go: route ownership

`traust adapters route-guards` reads Go routes registered on net/http
(`http.HandleFunc`, `mux.HandleFunc("GET /x/{id}", ..)`), gorilla/mux, chi,
gin, echo, fiber and PocketBase routers, through their groups, mounts and the
places they are served, with each route's guards (credited only where they
surely run first) and, for authenticated id routes, its `ownership`. This
section covers route ownership only. The rest of a Go web review is a
`framework-checks` coverage gap until a full section lands (see
[Selecting sections](#selecting-sections)).

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| GO.1 | Does a route that takes an object ID (`r.PathValue`, `chi.URLParam`, `mux.Vars`, `c.Param`, `c.Params`) check that the caller may act on that object, and is the ownership or tenant filter taken from the authenticated principal (a context value the auth middleware set, JWT claims, the session) rather than a value the caller sets (a query parameter, a header, the body)? | CWE-639 | ASVS V8.2 | the route-guards rows' `ownership` ([Route ownership](#route-ownership-cwe-639); this reader judges but never credits), `caller-blind` and `unchecked` first, then `unknown`; then the read (a gorm, sqlx or database/sql query, a repository or service call, an in-memory map) and the filter on it, `file:line`. A guard is credited only where it surely runs before the route, so an unguarded row there is judged too |

## Kubernetes operators

The operator reconciles custom resources (CRs) that tenants or users create,
using a service account that is usually far more privileged than they are.
Treat every CR field as untrusted input and the operator as a confused
deputy waiting to happen. `/operator-priv-profile` reviews the RBAC the
operator holds. These checks review what its code does with it.

A CR's author is whoever can create it. For a namespaced CR, that is anyone
with create rights in the namespace, often a tenant; for a cluster-scoped
CR, a cluster administrator. A finding needs the CR to be writable by
someone less privileged than the operator. Say which case applies.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| OP.1 | Does a CR spec field reach a command, file path, URL, template or query without validation (for example `spec.url` fetched by the operator, `spec.path` joined into a host path)? | CWE-20 | ASVS V2.2 | traced flow from the CR read (`r.Get(ctx, req.NamespacedName, &obj)`) to the sink, `file:line` at both ends |
| OP.2 | Does the operator build a Pod, Deployment or Job whose privilege comes from the CR: `privileged`, host namespaces, `hostPath`, added capabilities, a user-chosen image or service account? Not applicable when the operator creates no workloads; record that as the negative. | CWE-250 | ASVS V8.2; K01 | the workload template and the CR fields that feed it |
| OP.3 | Can a CR in one namespace make the operator read or write an object in another (`spec.secretRef.namespace`, a cross-namespace owner reference, a cluster-scoped target named by the CR)? | CWE-441 | ASVS V4.1; K02 | the client call whose namespace or name comes from the CR |
| OP.4 | Does a CR choose which objects the operator deletes, patches or adopts (a label selector or name taken from the spec) so that one tenant's CR can act on another's objects? | CWE-639 | ASVS V8.2; K02 | the selector or name in the delete, patch or ownership call |
| OP.5 | Does Secret data the operator reads reach a place it isn't meant for? Its intended targets are the Secret it generates and any external store the CR names. Credential Secrets it reads to authenticate (store or provider credentials) have no intended target outside the operator. Neither may reach CR status, events, logs, ConfigMaps or annotations, including through an error message (`err.Error()` passed to an event or status condition). | CWE-532 / CWE-200 | ASVS V16.2 / ASVS V14.2; K03 | the read, and each write or error path that carries it, `file:line` |
| OP.6 | Do validating or mutating webhook handlers allow the request on an error path: an `Allowed` response after a decode or lookup error, or a controller-runtime `CustomValidator` that returns a nil error when it couldn't evaluate the object? | CWE-755 | ASVS V16.5; K04 | the handler's error branches |
| OP.7 | Is a webhook that enforces a security rule registered with `failurePolicy: Ignore`, or scoped (namespace or object selector) so that a user can opt their objects out? | CWE-1188 | ASVS V13.2; K04 | the webhook configuration: kubebuilder markers, shipped manifests, or Helm templates and their default values |
| OP.8 | Does the CRD schema (or the controller) bound security-relevant fields: enums, patterns, lengths, immutability after creation? | CWE-20 | ASVS V2.2; K04 | the CRD's OpenAPI schema and `+kubebuilder:validation` markers; *judgement* when validation lives only in code |
| OP.9 | Is the manager's metrics, health or pprof endpoint served without authentication or on all interfaces (`metricsserver` without secure serving, `--metrics-bind-address=:8080`, `pprof` handlers registered)? | CWE-306 | ASVS V6.3; K05 | the manager options, the flag defaults and the Helm chart's default values, and any registered debug handlers |
| OP.10 | Are the webhook and API servers the operator runs served over TLS only? Whether a webhook must also authenticate its caller is a *judgement*, answered only when a client other than the API server can reach it. | CWE-319 | ASVS V12.2; K06 | the webhook server options and certificate wiring |
| OP.11 | Does the operator deploy images by tag, from the CR or from an environment variable, without a digest or a registry allow-list? Not applicable when it deploys no images. | CWE-494 | ASVS V15.2; K07 | the image reference in the workload template and where it comes from |
| OP.12 | Does the operator watch or cache cluster-wide (all namespaces, cluster-scoped informers) when its function needs one namespace? | CWE-250 | ASVS V8.2; K02 | the manager's cache and namespace options, against the RBAC it holds (`/operator-priv-profile`'s profile when it ran, otherwise the shipped Role and ClusterRole manifests) |
| OP.13 | Are tokens or credentials the operator mints or projects (service account tokens, cloud credentials) scoped to the CR's tenant and audience, and revoked or expired when the CR is deleted? | CWE-269 / CWE-613 | ASVS V8.2 / ASVS V7.3; K02 / K08 | the token request or credential write, and the finalizer. With many issuance sites (one per provider), sample up to three and record the rest as a coverage gap; *judgement* |

## gRPC

The service x interceptor matrix gives:
- `servers`: each `grpc.NewServer` call with its `interceptors` (each
  marked `guard` when auth-shaped), `unary_guarded`, `stream_guarded` and
  `credentials`;
- `services`: each registered service with its `methods` and `streams`,
  `judgement_required` and `judgement_reasons`;
- `exposures`: reflection, health, channelz and admin services;
- `method_references`: full method names (`/pkg.Service/Method`) in server
  code;
- `coverage_gaps`.

An empty list means the enumerator found none on the servers it resolved.
A guard-named interceptor is still read to confirm that it rejects. The
matrix doesn't list other server options (message sizes, keepalive), so
read those from the `grpc.NewServer` call. Produce the matrix with:

```bash
python3 -m traust.cli adapters grpc-guards <local-path> --out /tmp/<repo>-grpc-guards.json
```

Record `"grpc-guards": "ran"` (or `"skipped: <reason>"`) in
`metadata.additional.deterministic_steps`, and copy its `coverage_gaps`
into `metadata.additional.coverage_gaps` as
`{"tool": "grpc-guards", "system", "reason"}`.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| GR.1 | Does every service on a server reachable from outside the pod enforce authentication, in an interceptor or in each method? | CWE-306 | ASVS V6.3 | the servers' `unary_guarded` / `stream_guarded` and their `guard` interceptors (read to confirm they reject); the services' `judgement_required` and `judgement_reasons` |
| GR.2 | When the auth interceptor is unary-only, do the service's streams authenticate some other way? | CWE-306 | ASVS V6.3 | a server with `stream_guarded: false` serving a service that has `streams` |
| GR.3 | Once a caller is authenticated, are methods authorized individually (admin or write methods restricted) rather than all-or-nothing? Authorization delegated to another system (Kubernetes RBAC through a SubjectAccessReview, a policy engine) is a negative when it runs for every method; cite the call. | CWE-862 | ASVS V8.3 | the interceptor or handler code that branches on `info.FullMethod` or calls the delegate; the matrix's `method_references`; *judgement* |
| GR.4 | Do auth exemption lists match full method names exactly, rather than by prefix, `strings.Contains` or a service-wide wildcard that also exempts other methods? | CWE-288 | ASVS V6.3 | the matrix's `method_references` and the comparison at each; with none, say no exemption list exists and cite the auth interceptor |
| GR.5 | Are reflection, channelz or admin services registered on a server that is reachable from outside the pod or unauthenticated? | CWE-200 | ASVS V14.2 | the matrix's `exposures` (`guarded` is false, true, or null when the server is built elsewhere) |
| GR.6 | Does a server listening beyond loopback use TLS, whether set as server credentials or on its listener (`tls.NewListener`, or a TLS `http.Server` that multiplexes gRPC)? | CWE-319 | ASVS V12.2 | the server's `credentials`; when empty, the `net.Listener` and `tls.Config` it is served on, and the default of any flag that turns TLS off |
| GR.7 | Are authorization decisions based on caller-supplied metadata (`x-user`, `x-forwarded-*`, a tenant header) that nothing verifies? | CWE-807 | ASVS V2.3 | the `metadata.FromIncomingContext` reads that feed a decision |
| GR.8 | Is a gRPC-gateway registered in process with `Register…HandlerServer`? That variant calls the service directly and skips the gRPC interceptors, authentication included; `Register…HandlerFromEndpoint` dials the server and goes through them. For the dialling variant, check the dial's TLS settings (no `InsecureSkipVerify` beyond loopback). | CWE-288 | ASVS V6.3 | the gateway registration (the matrix leaves gateway registrations out of `services`) and where the gateway's HTTP server applies auth |
| GR.9 | Are message size, concurrent stream and keepalive limits set and sized for untrusted callers (`grpc.MaxRecvMsgSize`, `grpc.MaxConcurrentStreams`, `keepalive.EnforcementPolicy`)? The default receive limit is 4 MiB; a much larger limit needs a reason. | CWE-770 | ASVS V2.4 | the `grpc.NewServer` options, read directly |
| GR.10 | Do status errors returned to callers carry internal errors, stack traces or backend messages (`status.Error(codes.Internal, err.Error())`)? | CWE-209 | ASVS V16.5 | the handlers' error returns and any error-translation or panic-recovery interceptor |
| GR.11 | Where client certificates are the authentication, does the server's TLS configuration require and verify them (`tls.RequireAndVerifyClientCert` with a client CA)? Not applicable when callers authenticate with tokens. | CWE-295 | ASVS V12.3 | the `tls.Config` behind the server's credentials or listener |

## FastAPI and aiohttp

`traust adapters route-guards` lists each route with:
- its `method`, full `pattern` (router and mount prefixes applied) and
  `handler`;
- `guards`: the route's own dependencies, `Depends` / `Security`
  parameters, handler decorators and, for aiohttp, bare guard calls in the
  handler body (`call:check_authorized`). A dependency that isn't
  guard-named is followed into its own dependencies and shown as a chain
  (`get_current_user>oauth2_scheme`);
- `scope_guards`: router, app and `include_router` dependencies, and
  middleware that can refuse a request (`middleware:<name>`);
- `judgement_required`, asymmetry groups and `guard_family_gaps`, as for
  the other families.

Guards are matched by name, so a row with a guard is a claim, not proof.
**Before trusting any row, open each distinct guard once and confirm it
rejects a missing or bad credential with 401 or 403. Until you have, treat
its rows as unguarded, whatever `judgement_required` says.** A dependency
that only parses a caller-set header (a scope or tenant selector) is not
authentication. The matrix doesn't read request or response models, CORS,
docs endpoints or limits, so read those from the code. For FA.8, produce
the Python facts with `python3 -m traust.cli adapters opengrep <local-path>
--out /tmp/<repo>-opengrep.json`.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| FA.1 | Does every route that changes state or returns non-public data require authentication, through a dependency, a router or app dependency, a middleware that refuses unauthenticated requests, or a reverse proxy, ingress or sidecar in front of the app (nginx `auth_basic`, oauth-proxy, kube-rbac-proxy)? When it is the proxy, cite it and check whether the app's port can be reached around it (bind address, Service type, NetworkPolicy). | CWE-306 | ASVS V6.3 | each guard family confirmed to reject (see above), then the route-guards rows; for a proxy, its configuration and the deployment manifests |
| FA.2 | Does an auth or authorization dependency fail open: any `fastapi.security` scheme with `auto_error=False` (`OAuth2PasswordBearer`, `HTTPBearer`, `APIKeyHeader`, `APIKeyCookie`, `APIKeyQuery`) and no later check, a token-decode error caught and turned into an anonymous user, or a fallback to the widest scope or tenant instead of raising? | CWE-287 | ASVS V6.3 | the dependency named in the rows' `guards` / `scope_guards`, read to its error branches |
| FA.3 | Are admin and write routes restricted beyond "authenticated": `Security(..., scopes=[...])` with `SecurityScopes` actually checked, or a role check in the dependency? If FA.1 found no authentication, record FA.3 as covered by that finding. | CWE-862 | ASVS V8.3 | rows whose `guards` lack the role or scope family their siblings carry (`guard_family_gaps`; an empty list means nothing when no role family exists); the scope check in the dependency; *judgement* |
| FA.4 | Does a route that takes an object ID (path or query) check that the caller may act on that object, rather than only that the caller is logged in, and is that ownership or tenant filter taken from the authenticated principal rather than from a header, query or body value the caller sets? | CWE-639 | ASVS V8.2 | the route-guards rows' `ownership` ([Route ownership](#route-ownership-cwe-639)), `caller-blind` and `unchecked` first, then the handler's lookup and the filter on it, and where the filter's value comes from, `file:line`. aiohttp's reader judges but never credits, so its `unknown` rows are read too: they include reads tied to the caller, Postgres row-level security and ownership middleware |
| FA.5 | Can a route be reached without the guards its siblings get: a router included a second time without `dependencies=`, or a sub-application under `app.mount(...)` (mounted apps don't inherit FastAPI dependencies, only ASGI middleware)? | CWE-288 | ASVS V6.3 | the route-guards rows for the same handler under two patterns; the `mount` call and what the mounted app enforces itself |
| FA.6 | Do request bodies bind to models that let the caller set fields they shouldn't (`model_config = ConfigDict(extra="allow")`, an `owner_id`, `role` or `is_admin` field on a create or update model), or skip models entirely (`await request.json()`, `dict` / `Any` parameters)? | CWE-915 | ASVS V15.3 | the request models and the handler's write call |
| FA.7 | Do responses return ORM objects or dicts with fields the caller shouldn't see (password hashes, tokens, internal IDs) because the route has no `response_model` or returns a broader one? | CWE-200 | ASVS V15.3 | the route's `response_model` and what the handler returns |
| FA.8 | Does an uploaded file name (`UploadFile.filename`), a path parameter or a query value become part of a filesystem path that is read, written or served (`FileResponse`, `web.FileResponse`, `StaticFiles(follow_symlink=True)`)? | CWE-22 | ASVS V5.3 | the opengrep path-traversal facts for Python (command above); if they weren't produced, grep for `open(`, `FileResponse` and `StaticFiles` and say which you used; a traced flow, `file:line` at both ends |
| FA.9 | Does CORS allow credentials from any origin: `CORSMiddleware(allow_origins=["*"], allow_credentials=True)`, an `allow_origin_regex` broader than the deployment's hosts, or aiohttp-cors `"*"` with `allow_credentials=True`? | CWE-942 | ASVS V3.4 | the middleware or `aiohttp_cors.setup` call and its defaults |
| FA.10 | Does the shipped entry point (the Containerfile or Deployment, whatever is in front of it) serve `/docs`, `/redoc` and `/openapi.json` unauthenticated, or run with debug on (`FastAPI(debug=True)`, `aiohttp-debugtoolbar`, `uvicorn --reload`)? | CWE-489 | ASVS V13.4 | the `FastAPI(...)` arguments (`docs_url`, `openapi_url`), the entry point and its flag defaults |
| FA.11 | Are request sizes, result sizes and rates bounded for untrusted callers: aiohttp `client_max_size` raised, uploads read whole into memory, WebSocket `max_msg_size=0`, a route that loads a whole unpaginated result set (`fetchall()` with no `LIMIT`, a CSV or JSON export), no rate limit on login or token endpoints? | CWE-770 | ASVS V2.4 | the app and route options and the handlers' queries, read directly |
| FA.12 | Do error responses carry exception text or tracebacks (`HTTPException(detail=str(e))`, an exception handler returning `repr(exc)`, `debug=True`)? | CWE-209 | ASVS V16.5 | the exception handlers and the handlers' `except` branches |
| FA.13 | Do WebSocket routes authenticate on connect and check `Origin`, given that browsers send cookies on cross-site WebSocket handshakes? | CWE-1385 | ASVS V4.4 | the route-guards rows with method `WS` and their guards; the handshake code |
| FA.14 | Does the app take the caller's identity from a header an upstream proxy sets (`X-Forwarded-User`, `X-Remote-User`, a tenant or scope header)? Is the header trusted only when the request comes through that proxy? | CWE-290 | ASVS V6.3 | where the header is read and what sets it; the bind address, Service and NetworkPolicy |
| FA.15 | Do state-changing routes authenticated by cookies (`aiohttp_session`, a session cookie read in a dependency) reject cross-site requests: a CSRF token, `SameSite` cookies, or an `Origin` check? | CWE-352 | ASVS V3.5 | the session setup and the routes' method handling |

## Express

`traust adapters route-guards` lists each Express route (verb calls,
`route()` chains, verbs passed as values such as `registerHandler(app.get,
…)`, and routers mounted with `use()` across modules) with:
- `guards`: the middleware before the handler and the names of arguments
  passed to a handler factory called in the registration itself
  (`app.get(path, getPodLogsHandler(options, authorizeFn))`), plus an inline
  handler's bare guard calls. A handler built earlier and registered by
  name shows no factory guards, and a configuration flag passed to a
  factory can show up as a guard;
- `scope_guards`: `use()` middleware registered **before** the route on the
  same router, and the guards of every mount above it.

Session, passport-session, helmet, cors and cookie middleware only set up
state, so they never count as guards. The matrix doesn't list `use()` calls
that only add a handler or middleware (a block-list, `express.static`, a
rewrite): read those by hand. Express needs the JS/TS grammar
(`tree-sitter-javascript`); without it, the matrix reports Express as a coverage
gap. Record that gap and review routes by hand.

**Backstage.** A plugin's router mounted through the `httpRouter` service
is authenticated by the framework by default: its rows carry
`backstage:httpRouter` in `scope_guards`. For a path the plugin opens with
`httpRouter.addAuthPolicy({ path, allow })`, the row's `unguard_markers`
carries `backstage:allow-<policy>` and the row is judged (EX.2). Routers a plugin mounts any
other way get no default.

The opengrep TS/JS rules give evidence for EX.5–EX.8: `traust-ts-xss-*`,
`traust-ts-open-redirect-*`, `traust-ts-path-traversal-fs-taint` and
`traust-ts-ssrf-request-taint`. Produce them with `python3 -m traust.cli
adapters opengrep <local-path> --out /tmp/<repo>-opengrep.json`; zero facts
is not a negative (see the intro).

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| EX.1 | Does every route that changes state or returns non-public data require authentication? Middleware added with `use()` after a route doesn't guard it, and a router mounted before the auth `use()` isn't covered by it. For a row whose handler is a bare name (a handler built earlier), open the handler and look for an auth call before reading the row as unguarded. | CWE-306 | ASVS V6.3 | each guard family confirmed to end the request on failure rather than calling `next()`, then the route-guards rows (`judgement_required` and asymmetry rows first) |
| EX.2 | For a Backstage path opened with `addAuthPolicy` (`unauthenticated` or `user-cookie`), is the route safe to call without a caller identity, and does it avoid acting with the plugin's own service credentials on the caller's behalf? Also check, on routes meant for users only, `httpAuth.credentials(req, { allow: [...] })` calls that accept `service` or `none`, and bare `httpAuth.credentials(req)` calls, which accept service principals too. | CWE-306 | ASVS V6.3 | rows with `backstage:allow-*` in `unguard_markers`; the handler and the credentials it uses |
| EX.3 | Are admin and write routes authorized beyond "authenticated": a role check in middleware, or in Backstage a `permissions.authorize(...)` call whose result is checked as `!== AuthorizeResult.ALLOW` (a `CONDITIONAL` result must be applied as a filter, not let through)? | CWE-862 | ASVS V8.3 | the middleware or the `authorize` call and its result check, `file:line`; *judgement* |
| EX.4 | Does a route that takes an object ID (`req.params`, `req.query`) check that the caller may act on that object? | CWE-639 | ASVS V8.2 | the route-guards rows' `ownership` ([Route ownership](#route-ownership-cwe-639)), `caller-blind` and `unchecked` first, then the lookup and the ownership or tenant filter on it |
| EX.5 | Does request or stored data reach HTML unescaped: a request value in a `res.send` string body, an unescaped template output (`<%-`, `{{{ }}}`, `\| safe`), or a client sink (`dangerouslySetInnerHTML`, `innerHTML`, `document.write`, Markdown with raw HTML)? | CWE-79 | ASVS V1.2 | the `traust-ts-xss-*` facts, otherwise a traced flow to the sink |
| EX.6 | Is a URL from the request or from stored data used as a redirect target, a navigation target or (client bundles only) a link `href` without an allow-list of schemes and hosts (`javascript:` URLs run script; any host is an open redirect)? | CWE-79 / CWE-601 | ASVS V1.2 / ASVS V3.7 | the `traust-ts-open-redirect-*` facts; for `href` bound to data (no rule covers it), the component and where the value comes from |
| EX.7 | Does a request value become part of a filesystem path that is read, written, removed or served (`res.sendFile`, `res.download`, `fs.*`, `express.static` with `dotfiles: "allow"`)? | CWE-22 | ASVS V5.3 | the `traust-ts-path-traversal-fs-taint` facts, otherwise a traced flow |
| EX.8 | Does a route fetch or proxy a URL the caller controls (`http-proxy-middleware` with a request-derived `target` or `router`, `fetch`/`axios` with a request value), and does it forward the caller's or the service's credentials there? | CWE-918 | ASVS V1.3 | the `traust-ts-ssrf-request-taint` facts and the proxy configuration |
| EX.9 | Is request input compiled into a regular expression (`new RegExp(req.query.q)`) or matched by a pattern with nested quantifiers on caller-sized input? | CWE-1333 | ASVS V1.2 | the `RegExp` construction or the pattern, `file:line` |
| EX.10 | Are body and upload sizes and request rates bounded: `express.json({ limit })` or `bodyParser` raised far above the default, multer with no `limits`, no rate limit on login or token routes? | CWE-770 | ASVS V2.4 | the parser and upload options, read directly |
| EX.11 | Does CORS reflect any origin with credentials (`cors({ origin: true, credentials: true })`, an origin callback that allows everything), and are session cookies set without `httpOnly`, `secure` and `sameSite`? | CWE-942 / CWE-1004 | ASVS V3.4 / ASVS V3.3 | the `cors(...)` and `session(...)` or `res.cookie(...)` options |
| EX.12 | Do error responses carry `err.message` or stacks (`res.status(500).send(err.stack)`, the default error handler with `NODE_ENV` not `production`)? In Express 5 a rejected async handler reaches the default handler, so an `await` outside `try`/`catch` counts. | CWE-209 | ASVS V16.5 | the error-handling middleware, the handlers' `catch` blocks and their unguarded `await`s |
| EX.13 | Do logs capture secrets: whole request headers, whole axios error objects (their `config.headers` carry bearer tokens), or tokens and keys passed on the command line? | CWE-532 | ASVS V16.2 | the logger calls in request handlers and `catch` blocks, `file:line` |
| EX.14 | Is request JSON merged into objects (`_.merge`, `Object.assign(target, req.body)`, a deep-merge helper) in a way that lets `__proto__` or `constructor.prototype` keys set properties on every object? | CWE-1321 | ASVS V15.3 | the merge call and whether keys are filtered or the target has a null prototype |
| EX.15 | Does a create or update route pass request JSON straight to the model or ORM (`Model.create(req.body)`, `update(req.body)`), or into a Kubernetes object the server creates with its own service account (`podTemplateSpec`, `spec`), so callers can set fields such as `role`, `ownerId`, the image or the service account? | CWE-915 | ASVS V15.3 | the write call and the fields the model or object accepts |
| EX.16 | Does the server take the caller's identity from a header an upstream proxy sets (`X-Forwarded-User`, `X-Remote-User`, `X-Auth-Request-User`)? Is the header trusted only when the request comes through that proxy, and does authorization stay on when the deployment's default turns it off? | CWE-290 | ASVS V6.3 | where the header is read and what sets it; the bind address, Service and NetworkPolicy; the flag's default in config and manifests |
| EX.17 | Do state-changing routes authenticated by cookies or an upstream proxy reject cross-site requests: a CSRF token, `SameSite` cookies, or an `Origin` check? | CWE-352 | ASVS V3.5 | the session or proxy auth and the routes' method handling |
| EX.18 | Does a route return configuration, environment or secret values, and is the redaction default-deny (everything hidden unless marked safe) rather than hiding only what is marked secret? | CWE-200 | ASVS V13.4 | the handler and the redaction it applies, `file:line` |

## Spring and JAX-RS

`traust adapters route-guards` lists each Spring MVC or WebFlux route
(`@GetMapping` … `@RequestMapping` on a controller, with class, interface
and superclass mappings) and each JAX-RS resource method (`@Path` with a
verb annotation, prefixed by `@ApplicationPath` and `quarkus.rest.path`),
with:
- `guards`: the method's security annotations (`@PreAuthorize`,
  `@Secured`, `@RolesAllowed`, `@Authenticated`, `@PermissionsAllowed`,
  `@DenyAll`) and bare guard calls in the handler body;
- `scope_guards`: the class's annotations, the Spring Security rule that
  matches the route (`spring-security:<rule>`: first match wins, a
  `securityMatcher` chain before the catch-all), Quarkus HTTP permissions
  (`quarkus:<policy>`, the most specific path wins) and
  `deny-unannotated-endpoints` / `default-roles-allowed`. When the
  security starter is declared with no filter chain, every route carries
  `spring-security:default` (Spring Boot authenticates everything);
- `unguard_markers`, each judged:
  - `@PermitAll`, `spring-security:permitAll` and `quarkus:permit`: the
    route is opened;
  - `method-security-not-enabled`: method-security annotations with no
    `@EnableMethodSecurity` in the checkout, which Spring doesn't enforce;
  - `spring-security:conditional-config`: the deciding filter chain is a
    `@ConditionalOn*` or `@Profile` bean, so the row lists every
    candidate chain's rule and the deployment decides which applies.

Controllers that implement API interfaces generated at build time (an
OpenAPI generator's `interfaceOnly`) are a coverage gap: read the API
spec the generator uses and each controller's overrides by hand. Kotlin
controllers, Micronaut and Spring functional routes (`RouterFunctions`,
`coRouter`) are coverage gaps too. Java parsing needs `tree-sitter-java`,
a traust-core dependency.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| JV.1 | Does every route that changes state or returns non-public data require authentication: a filter-chain rule, an enforced method-security annotation, a JAX-RS role annotation, a Quarkus permission, or a proxy in front (cite it, and check the app's port can't be reached around it)? | CWE-306 | ASVS V6.3 | the route-guards rows, `judgement_required` and unguard-marked rows first |
| JV.2 | For a row marked `method-security-not-enabled`, is method security switched on somewhere the matrix doesn't see (a configuration class in another module, a starter that enables it)? If not, its annotations protect nothing. | CWE-862 | ASVS V8.3 | the `@Enable*MethodSecurity` search and the module layout |
| JV.3 | Do filter-chain rules leave a route open by order or shape: a broad `permitAll` (`/**`, `/api/**`) ahead of narrower rules, `anyRequest().permitAll()`, a verb-restricted guard rule (`requestMatchers(HttpMethod.POST, …)`) that leaves the other verbs on that path unmatched, or a matcher that misses a variant the dispatcher serves (trailing slash, an extension or a regex route)? | CWE-863 | ASVS V8.2 | the `SecurityFilterChain` rules in order and the rows whose `scope_guards` come from them |
| JV.4 | For a row marked `spring-security:conditional-config`, which chain does the shipped configuration activate (`application.properties`/`yaml` defaults, active profiles in the deployment manifests)? An insecure default is a finding even when a property can turn security on. | CWE-1188 | ASVS V13.2 | the condition, the property's shipped value and the manifests that set it |
| JV.5 | Does a route that takes an object ID (`@PathVariable`, `@PathParam`, `@QueryParam`) check that the caller may act on that object: a `@PreAuthorize` expression on the ID, an ownership or tenant filter in the query? | CWE-639 | ASVS V8.2 | the route-guards rows' `ownership` ([Route ownership](#route-ownership-cwe-639)), `caller-blind` and `unchecked` first, then the lookup and the check on it |
| JV.6 | Is CSRF protection disabled (`csrf().disable()`, `csrf(AbstractHttpConfigurer::disable)`) while sessions or cookies authenticate the browser? | CWE-352 | ASVS V3.5 | the filter chain's `csrf` and session settings |
| JV.7 | Does CORS allow any origin with credentials (`allowedOriginPatterns("*")` with `allowCredentials(true)`, `@CrossOrigin` with `*`, a Quarkus `quarkus.http.cors.origins=*` with credentials)? | CWE-942 | ASVS V3.4 | the CORS configuration, read directly |
| JV.8 | Does a create or update route bind request JSON straight to a persistence entity (`@RequestBody Entity`, a JAX-RS entity parameter) so callers can set fields such as `role`, `owner` or `enabled`? | CWE-915 | ASVS V15.3 | the parameter type and the entity's fields |
| JV.9 | Does request input reach an expression evaluator: SpEL `parseExpression`, a Thymeleaf `__${…}__` preprocessing expression, an EL or OGNL evaluation? | CWE-917 | ASVS V1.2 | a traced flow to the evaluator, `file:line` at both ends |
| JV.10 | Is SQL, JPQL or HQL built from request input by concatenation (`createQuery("… " + param)`, `createNativeQuery`, `JdbcTemplate` with a built string) instead of bound parameters? | CWE-89 | ASVS V1.2 | the query construction and where its parts come from |
| JV.11 | Are actuator or management endpoints (`/actuator/env`, `/heapdump`, `/threaddump`, Quarkus dev UI) exposed and reachable without authentication (`management.endpoints.web.exposure.include=*`, `EndpointRequest.toAnyEndpoint().permitAll()`)? | CWE-200 | ASVS V13.4 | the management properties and the filter-chain rule for them |
| JV.12 | Are untrusted bodies deserialized into arbitrary types: Jackson default typing (`activateDefaultTyping`, `@JsonTypeInfo(use = Id.CLASS)`), XStream, or `ObjectInputStream`? | CWE-502 | ASVS V1.5 | the mapper configuration and the endpoints that use it |
| JV.13 | Are XML bodies parsed with external entities left on (`DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory` or a JAXB unmarshaller without the secure-processing features)? | CWE-611 | ASVS V1.5 | the parser factory's feature settings |
| JV.14 | Does a request value become part of a filesystem path that is read, written or served (`Paths.get(base, param)`, `ResourceLoader.getResource(param)`, `FileSystemResource`) without normalizing and checking it stays under the base? | CWE-22 | ASVS V5.3 | a traced flow to the file call |
| JV.15 | Does a route fetch a URL the caller controls (`RestTemplate`, `WebClient`, `HttpClient`, a JAX-RS client) and forward credentials there? | CWE-918 | ASVS V1.3 | a traced flow to the client call and its headers |
| JV.16 | Do error responses carry stack traces or exception messages (`server.error.include-stacktrace=always`, `include-message`, an `ExceptionMapper` or `@ExceptionHandler` that returns `e.getMessage()`)? | CWE-209 | ASVS V16.5 | the error properties and handlers |

## axum and actix-web

`traust adapters route-guards` lists each axum route (`Router` `route`,
`nest`, `merge` and `route_service` chains, across functions and modules)
and each actix-web route (`App` and `web::scope` `service`, `route` and
`configure` calls, and the `#[get]`-style route macros), with:
- `guards`: auth-shaped handler extractors (`extractor:AuthUser`,
  `extractor:Claims`; payload extractors such as `Json<…>` don't count),
  a method router's own `layer`, actix-web-grants attributes
  (`#[protect(…)]`) and bare guard calls in the handler body;
- `scope_guards`: for axum, each `layer`/`route_layer` added **after** the
  route on its router or a router above it (a layer wraps the routes
  added before it, never later ones); for actix-web, each `wrap` on the
  route's app or scope (it wraps everything registered there);
- `unguard_markers`: `actix:registration-not-found` for a route macro no
  `service` call registers (it may be registered in a way the matrix
  doesn't follow, or not at all).

Session, cookie, identity-store, CORS and trace middleware only set up
state, so they never count as guards. Routes built by helper functions
that take the path and handler as parameters aren't followed: the
framework shows as a coverage gap. Rust parsing needs `tree-sitter-rust`,
a traust-core dependency.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| RW.1 | Does every route that changes state or returns non-public data require authentication: an auth layer wrapping it, an extractor that rejects, a `wrap` on its scope, or a proxy in front? In axum, a route added after the auth layer, or a router merged after it, isn't wrapped. | CWE-306 | ASVS V6.3 | the route-guards rows, `judgement_required` and asymmetry rows first |
| RW.2 | Does each guard-named extractor reject a missing or bad credential (its `FromRequestParts` / `FromRequest` returns a rejection), rather than defaulting to an anonymous user? An `Option<AuthUser>` parameter makes it optional. | CWE-287 | ASVS V6.3 | the extractor's implementation, `file:line` |
| RW.3 | Are admin and write routes authorized beyond "authenticated" (a role or permission check, `#[protect]`, a claim check in the handler)? | CWE-862 | ASVS V8.3 | the check, `file:line`; *judgement* |
| RW.4 | Does a route that takes an object ID (`Path<Id>`, `web::Path`) check that the caller may act on that object? | CWE-639 | ASVS V8.2 | the route-guards rows' `ownership` ([Route ownership](#route-ownership-cwe-639); this reader judges but never credits), `caller-blind` and `unchecked` first, then the `unknown` rows, then the lookup and the ownership or tenant filter on it |
| RW.5 | Is SQL built from request input with `format!` or concatenation (`sqlx::query(&format!(…))`, diesel `sql_query`) instead of bound parameters or the query macros? | CWE-89 | ASVS V1.2 | the query construction |
| RW.6 | Does request input reach a process (`Command::new` with request-derived arguments, or `sh -c` with a built string)? | CWE-78 | ASVS V1.2 | a traced flow to the `Command` |
| RW.7 | Does a request value become part of a filesystem path (`PathBuf::join` with `Path<String>`, `NamedFile::open`, `ServeDir` over a directory that holds more than public assets)? | CWE-22 | ASVS V5.3 | a traced flow to the file call |
| RW.8 | Does a route fetch a URL the caller controls (`reqwest`, `hyper` client) and forward credentials there? | CWE-918 | ASVS V1.3 | a traced flow to the client call |
| RW.9 | Are body sizes and request time bounded: axum `DefaultBodyLimit::disable()` or a large limit, actix `PayloadConfig` / `JsonConfig::limit` raised, no `TimeoutLayer` on slow routes? | CWE-770 | ASVS V2.4 | the limit and timeout configuration |
| RW.10 | Does CORS allow any origin with credentials (`CorsLayer::permissive()` / `very_permissive()`, `allow_credentials(true)` with a mirrored origin, actix `Cors::permissive()`)? | CWE-942 | ASVS V3.4 | the CORS layer or `wrap` |
| RW.11 | Is JWT validation weakened: `insecure_disable_signature_validation`, `validate_exp = false`, algorithms not pinned, or a hard-coded secret? | CWE-347 | ASVS V9.1 | the `Validation` and `DecodingKey` construction |
| RW.12 | Do error responses carry internal errors (`e.to_string()` or an `anyhow` chain in the body)? | CWE-209 | ASVS V16.5 | the error types' `IntoResponse` / `ResponseError` implementations |
| RW.13 | Do request logs capture secrets (`TraceLayer` or `Logger` formats that include the `Authorization` header or bodies)? | CWE-532 | ASVS V16.2 | the logging layer's configuration |

## tonic

`traust adapters grpc-guards` lists tonic servers next to Go ones
(`framework: tonic`): each `Server::builder()` chain with its tower
`layer`s as `interceptors` (marked `guard` when auth-shaped), each
`add_service` as a service with its own `interceptors` (`with_interceptor`,
`InterceptedService::new`) and the methods of its trait `impl`, and
reflection and health services as `exposures`. A service is judged unless
an auth-shaped layer or interceptor covers it. Rust parsing needs
`tree-sitter-rust`.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| TN.1 | Does every service reachable from outside the pod authenticate its callers, in a server layer, a service interceptor or each method? | CWE-306 | ASVS V6.3 | the services' `judgement_required` and their `interceptors`, each read to confirm it returns `Status::unauthenticated` on failure |
| TN.2 | Once a caller is authenticated, are methods authorized individually (claims from `request.extensions()` checked per method) rather than all-or-nothing? | CWE-862 | ASVS V8.3 | the methods' checks; *judgement* |
| TN.3 | Are reflection or health services added to a server that is reachable from outside the pod or unauthenticated? | CWE-200 | ASVS V14.2 | the matrix's `exposures` |
| TN.4 | Does a server listening beyond loopback use TLS (`tls_config(ServerTlsConfig…)`), and, where client certificates are the authentication, does it require them (`client_ca_root`)? | CWE-319 | ASVS V12.2 | the server's `credentials` and its listener address |
| TN.5 | Are message size, concurrency and timeouts set for untrusted callers (`max_decoding_message_size`, `concurrency_limit_per_connection`, `timeout`)? | CWE-770 | ASVS V2.4 | the builder and service settings |
| TN.6 | Do status errors returned to callers carry internal errors (`Status::internal(e.to_string())`)? | CWE-209 | ASVS V16.5 | the methods' error returns |
| TN.7 | Are authorization decisions based on caller-supplied metadata (`x-user-id`, a tenant key) that nothing verifies? | CWE-807 | ASVS V2.3 | the `metadata()` reads that feed a decision |

## Rails and Sinatra

`traust adapters route-guards` lists each Rails route from
`<app>/config/routes.rb` (and the files it `draw`s): `resources`/`resource` with
`only`/`except`, `namespace`, `scope`, `member`/`collection`, explicit
verbs, `match`, `root` and `mount`, resolved to the controller action,
with:
- `guards`: the action's `before_action` chain through the controller
  hierarchy (`only`/`except` applied; `http_basic_authenticate_with` and
  `load_and_authorize_resource` included) and bare guard calls in the
  action (`call:authorize`);
- `scope_guards`: a Devise `authenticate` or `authenticated` block around
  the route;
- `unguard_markers`: `skip_before_action:<callback>` when a skip removes a
  guard for that action, judged;
- asymmetry rows: an action missing a guard callback the controller's other
  actions run (the `before_action :x, except: [...]` shape).

Sinatra routes (`get '/path' do`) carry `before` filters whose block calls a
guard (`before:<name>`, matched by path pattern), a guard-shaped `use`
middleware (`Rack::Auth::Basic`), and bare guard calls in the block.
`concern`s aren't expanded. Ruby parsing needs `tree-sitter-ruby`,
a traust-core dependency.

| ID | Check | CWE | Requirement | Evidence |
|---|---|---|---|---|
| RL.1 | Does every action that changes state or returns non-public data require authentication: a `before_action` that halts (`authenticate_user!` redirects or returns 401), a Devise route block, or a proxy in front? A callback that only loads a user when a token is present is not enforcement. | CWE-306 | ASVS V6.3 | the route-guards rows, skip-marked and asymmetry rows first; each guard callback's definition |
| RL.2 | Is each action authorized for the caller (Pundit `authorize` with `verify_authorized`, CanCanCan `load_and_authorize_resource`, `policy_scope` on listings)? | CWE-862 | ASVS V8.3 | the callbacks and calls in the action |
| RL.3 | Are records looked up through the caller's scope (`current_user.projects.find(params[:id])`) rather than globally (`Project.find(params[:id])`)? | CWE-639 | ASVS V8.2 | the route-guards rows' `ownership` ([Route ownership](#route-ownership-cwe-639)), `caller-blind` and `unchecked` first, then the lookups in the actions; Sinatra routes are an ownership coverage gap |
| RL.4 | Do strong parameters let callers set privileged fields (`permit!`, `permit(:role, :admin)`, `to_unsafe_h`, attributes assigned from `params` directly)? | CWE-915 | ASVS V15.3 | the `permit` lists and the model's attributes |
| RL.5 | Is SQL built from request input (`where("… #{params[:x]}")`, `order(params[:sort])`, `find_by_sql`, `pluck` or `select` with raw strings)? | CWE-89 | ASVS V1.2 | the query construction |
| RL.6 | Does request or stored data reach HTML unescaped (`html_safe`, `raw`, `<%==`, `render inline:` with request data, `link_to` with a caller-set URL)? | CWE-79 | ASVS V1.2 | a traced flow to the view |
| RL.7 | Is a caller-set URL a redirect target (`redirect_to params[:url]`, `allow_other_host: true`)? | CWE-601 | ASVS V3.7 | the redirect and where its target comes from |
| RL.8 | Is forgery protection off for cookie-authenticated controllers (`skip_forgery_protection`, `skip_before_action :verify_authenticity_token`, `protect_from_forgery with: :null_session` on a browser controller)? | CWE-352 | ASVS V3.5 | the controller hierarchy's forgery settings |
| RL.9 | Does request input reach a shell (`system`, backticks, `%x`, `Open3` with interpolation)? | CWE-78 | ASVS V1.2 | a traced flow to the call |
| RL.10 | Does request input choose a class or method (`constantize`, `safe_constantize`, `send`, `public_send` with `params`)? | CWE-470 | ASVS V1.2 | the call and its argument's source |
| RL.11 | Does a request value become part of a file path that is read or served (`send_file params[:path]`, `File.read(Rails.root.join(params[...]))`)? | CWE-22 | ASVS V5.3 | a traced flow to the file call |
| RL.12 | Is untrusted data deserialized unsafely (`YAML.load` instead of `safe_load`, `Marshal.load`, `Oj.load` in object mode)? | CWE-502 | ASVS V1.5 | the call and its input's source |
| RL.13 | Does production show error details (`consider_all_requests_local = true` in `<app>/config/environments/production.rb`, `rescue_from` handlers that render the exception message)? | CWE-209 | ASVS V16.5 | the environment config and handlers |
| RL.14 | Do logs keep secrets (`filter_parameters` missing tokens, passwords or keys the app accepts)? | CWE-532 | ASVS V16.2 | `<app>/config/initializers/filter_parameter_logging.rb` against the params the controllers take |
| SN.1 | Does every Sinatra route that changes state or returns non-public data require authentication: a `before` filter whose pattern covers it (`/admin/*` doesn't cover `/admin`), auth `use` middleware, or a guard call in the block? | CWE-306 | ASVS V6.3 | the route-guards rows and the filters' patterns |
| SN.2 | Does the auth helper (`protected!`, `authorized?`) halt with 401 or 403 on failure and compare credentials in constant time (`Rack::Utils.secure_compare`)? | CWE-287 | ASVS V6.3 | the helper's definition |
| SN.3 | Is the session secret hard-coded, short or left to the default (`set :session_secret`, `enable :sessions`)? | CWE-798 | ASVS V13.3 | the session settings |
| SN.4 | Does request data reach HTML unescaped (string bodies built from `params`, ERB without `escape_html`)? | CWE-79 | ASVS V1.2 | a traced flow to the response |
| SN.5 | Does a request value become part of a file path that is read or served (`send_file`, `File.join(settings.public_folder, params[:splat])`)? | CWE-22 | ASVS V5.3 | a traced flow to the file call |
| SN.6 | Is `Rack::Protection` disabled or narrowed (`disable :protection`, `set :protection, except: …`) for a browser-facing app? | CWE-352 | ASVS V3.5 | the protection settings |
| SN.7 | Does production show exceptions (`set :show_exceptions, true`, `raise_errors`)? | CWE-209 | ASVS V16.5 | the environment settings |

## Recording the review

- **Coverage:** in `metadata.additional.deterministic_steps`, record
  `"framework-checks": "ran: <sections>"` (for example
  `"ran: operators, grpc"`, `"ran: fastapi-aiohttp, express"`,
  `"ran: spring-jaxrs"`, `"ran: axum-actix, tonic"` or `"ran: rails-sinatra"`), or
  `"ran: none"` when no section applies.
- **A check you couldn't answer** is a `coverage_gaps` entry:
  `{"tool": "framework-checks", "system": "<check ID>", "reason": "…"}`.
- **Findings** carry:
  - the check's CWE in `cwes`;
  - its ASVS section in `asvs_references`.

  Name the check ID, and for operators the K-ID, in the `description`, for
  example "check OP.3, K02".
- **`/vuln-scan` findings** (the `vuln-findings` format) name the check ID,
  the ASVS section and, for operators, the K-ID in the `description`.
- **Negative results** state the check ID, what was examined and the
  evidence, for example "GR.1: every service on `cmd/server/main.go:42` is
  behind `authUnary`, and `authUnary` rejects a missing token at
  `internal/auth/grpc.go:31`".
