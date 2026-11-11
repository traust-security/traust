# LLM, agent and MCP application review

Read this when the LLM application pre-scan (`traust adapters llm-app`,
traust-core's `code_facts.llm_app`) reports `llm_application: true`. Review the files it tags, plus the
call paths that lead into and out of them. Read only the sections for the
`kinds` it reports, plus the sections that apply to every LLM application
(LLM01, LLM02, LLM05, LLM07, LLM10).

**How to use the checks.** Each check is a question you answer from code,
with the CWE a confirmed finding files under and the OWASP Top 10 for LLM
Applications category (2025) it verifies. A check is never a conclusion:
- **Confirm it with evidence:** a rule hit, a cited `file:line`, a route
  from the route×guard matrix, or a traced data flow.
- **No evidence either way** is a `coverage_gaps` entry, not a negative.
- **Items marked *threat model*** are design questions that code can't
  settle. Raise them as open questions in the threat model, never as
  findings.

The model is an untrusted component: treat what it returns like input from
an anonymous user, and treat anything it reads (documents, web pages,
email, tool results) as attacker-controlled.

Category IDs are cited from the OWASP Top 10 for LLM Applications 2025.
These checks are Traust's own wording; no OWASP text is reproduced.

## LLM01 — Prompt injection

Applies to: every LLM application.

| # | Check | CWE |
|---|---|---|
| 01.1 | Does untrusted content (user input, retrieved documents, web pages, email, file contents, tool results) enter a prompt without structural separation from the instructions, such as distinct message roles or delimited, labelled data blocks? | CWE-1427 |
| 01.2 | Can content the model *reads* (retrieval, browsing, tool output) reach a context where the model can call tools? That indirect path is the high-impact shape: trace it from the ingestion point to the tool call. | CWE-1427 |
| 01.3 | Is any security decision (allow, deny, route, escalate) taken on the strength of the model's own output, where injected text could change it? | CWE-1427 / CWE-807 |
| 01.4 | *Threat model:* which inputs an attacker controls, and what the model can do once steered. | — |

## LLM02 — Sensitive information disclosure

Applies to: every LLM application.

| # | Check | CWE |
|---|---|---|
| 02.1 | Do prompts or context carry secrets (API keys, tokens, connection strings) or personal data the model doesn't need for the task? | CWE-200 / CWE-359 |
| 02.2 | Are prompts, completions or tool arguments logged, traced or sent to analytics with personal data or secrets, and without redaction? | CWE-532 |
| 02.3 | Can conversation history, memory or cached context from one user or tenant reach another (shared memory keys, global caches, a missing tenant filter)? | CWE-200 / CWE-668 |
| 02.4 | Does a training, fine-tuning or evaluation pipeline collect user data without scrubbing or consent checks? | CWE-359 |

## LLM03 — Supply chain

Applies to: `model-sdk`, `agent-framework`.

| # | Check | CWE |
|---|---|---|
| 03.1 | Are models or adapters downloaded without a pinned revision or hash (a hub name with no `revision`, a "latest" tag)? | CWE-494 |
| 03.2 | Is remote code execution allowed while loading a model (`trust_remote_code=True` or an equivalent)? | CWE-494 / CWE-829 |
| 03.3 | Are model files deserialized with a format that runs code (pickle; `torch.load` without `weights_only=True`), from a source that isn't fully trusted? | CWE-502 |
| 03.4 | Are adapters or plugins merged from sources with no provenance check? | CWE-829 |

## LLM04 — Data and model poisoning

Applies to: code that trains, fine-tunes or builds embeddings.

| # | Check | CWE |
|---|---|---|
| 04.1 | Do training, fine-tuning or embedding pipelines ingest sources an outsider can write to, without authentication or validation? | CWE-345 |
| 04.2 | Is there no record of where each training or embedding input came from? | CWE-345 / CWE-1039 |
| 04.3 | *Threat model:* who can influence training data, and how a poisoned model would be noticed. | — |

## LLM05 — Improper output handling

Applies to: every LLM application.

| # | Check | CWE |
|---|---|---|
| 05.1 | Does model output reach a shell, `exec`/`eval`, or dynamic code loading? | CWE-1426 / CWE-78 / CWE-94 |
| 05.2 | Does model output reach a SQL, NoSQL or query-language statement without parameterization? | CWE-1426 / CWE-89 |
| 05.3 | Does model output choose a file path, URL or host that the service then reads, writes or fetches? | CWE-1426 / CWE-22 / CWE-918 |
| 05.4 | Is model output rendered as HTML or Markdown without encoding, including images or links that load automatically (a data-exfiltration channel)? | CWE-1426 / CWE-79 |
| 05.5 | Does model output fill email, message or document templates sent to other people without validation? | CWE-1426 |

## LLM06 — Excessive agency

Applies to: `agent-framework`, `mcp-server`, and any code that gives the
model tools.

| # | Check | CWE |
|---|---|---|
| 06.1 | Are the model's tools broader than its task needs (a generic shell, a generic URL fetch, unrestricted file access, arbitrary SQL)? | CWE-250 |
| 06.2 | Do tools run with credentials more privileged than the user they act for (a service account instead of the user's own authority)? | CWE-269 / CWE-250 |
| 06.3 | Is authorization for a tool action decided by the model, instead of being enforced in the tool or the service behind it on every call? | CWE-862 / CWE-285 |
| 06.4 | Can the agent take destructive or irreversible actions (delete, pay, send, deploy) with no human approval step? | CWE-862 |
| 06.5 | Do MCP tool or resource handlers run without checking who the caller is and what they may do? | CWE-862 / CWE-306 |
| 06.6 | Is an MCP server reachable over HTTP or SSE with no client authentication at the transport (no bearer/OAuth verification, no auth middleware, no authenticating proxy)? | CWE-306 |

## LLM07 — System prompt leakage

Applies to: every LLM application.

| # | Check | CWE |
|---|---|---|
| 07.1 | Do system prompts or instruction templates contain credentials, connection strings or internal endpoints? | CWE-798 / CWE-200 |
| 07.2 | Is a security control (an access rule, a role check, a content restriction) implemented only as an instruction to the model, with nothing enforcing it in code? | CWE-284 |

## LLM08 — Vector and embedding weaknesses

Applies to: `vector-store`.

| # | Check | CWE |
|---|---|---|
| 08.1 | Is a vector store or index shared across tenants or users without partitioning, or without filtering retrieval by the caller's permissions? | CWE-284 / CWE-668 |
| 08.2 | Does document ingestion accept unvalidated sources, or keep hidden text (invisible HTML, white-on-white text, metadata fields) that later reaches prompts? | CWE-1427 / CWE-345 |
| 08.3 | Can a caller read the embeddings or raw stored chunks directly, bypassing the application's access checks? | CWE-200 / CWE-284 |

## LLM09 — Misinformation

Applies to: code that acts on model suggestions.

| # | Check | CWE |
|---|---|---|
| 09.1 | Are packages, commands or code the model suggests installed or executed automatically, without verification? | CWE-829 / CWE-494 |
| 09.2 | *Threat model:* where users rely on model output without checking it, and what a wrong answer costs. | — |

## LLM10 — Unbounded consumption

Applies to: every LLM application.

| # | Check | CWE |
|---|---|---|
| 10.1 | Is there no limit on input size (prompt length, file size, number of documents) before a model call? | CWE-770 |
| 10.2 | Is there no per-user or per-tenant rate limit or quota on model calls? | CWE-770 |
| 10.3 | Do model calls run with no `max_tokens`, timeout or retry cap? | CWE-400 |
| 10.4 | Do agent loops run with no step, time or cost ceiling? | CWE-400 / CWE-834 |
| 10.5 | Are raw model internals (`logprobs`, `logit_bias`, full embeddings) exposed to callers, enabling model extraction? | CWE-200 |

## Rule evidence

The engine's `llm-application` opengrep rules (Python, TypeScript, Go)
decide the code-level shapes of some checks. Their hits arrive with the
other opengrep facts, and each fact carries the category in `owasp_llm`.
A hit is evidence for the check, and you still confirm it in context. A
promoted fact's `owasp_llm` goes into the finding's
`owasp_llm_references`. No hit is not a negative, because the rules see
only the SDK call shapes they name.

| Rule (`traust-<lang>-llm-application-…`) | Check |
|---|---|
| `output-to-shell-taint`, `output-to-exec-taint`, `output-to-code-exec-taint` | 05.1 |
| `output-to-sql-taint` | 05.2 |
| `output-to-path-taint` | 05.3 |
| `unpinned-model-download` | 03.1 |
| `trust-remote-code` | 03.2 |
| `unsafe-model-deserialization`, `model-load-default-pickle` | 03.3 |
| `mcp-http-without-auth` | 06.6 |
| `unbounded-agent-loop` | 10.4 |

`mcp-http-without-auth` is file-scoped: it clears when the same file wires
authentication. If auth is applied somewhere else, such as a reverse proxy
or middleware in another module, record where: that is a negative result
for 06.6, not a finding. Per-tool authorization (06.3, 06.5) has no rule,
because in MCP it usually lives at the transport or in the service behind
the tool, so judge it from the code.

## Recording the review

- **Coverage:** in `metadata.additional.deterministic_steps`, record the
  pre-scan as `"llm-app": "ran: <kinds>"`, or `"ran: none"`.
- **The tagged files:** list the ones you reviewed. A tagged file you
  didn't review is a `coverage_gaps` entry (`{"tool": "llm-app", "system":
  "<file>", "reason": "tagged, not reviewed"}`).
- **Findings** carry:
  - the check's CWE in `cwes`;
  - the OWASP category ID in `owasp_llm_references`, for example
    `["LLM06"]`;
  - any ASVS requirement they also break in `asvs_references`.

  Name the check number in the `description`, for example "check 06.5".
- **`/vuln-scan` findings** (the `vuln-findings` format) have no reference
  fields, so they name the category and check number in the
  `description`, for example "OWASP LLM06, check 06.5".
- **Negative results** state the check number, what was examined and the
  evidence, for example "06.5: every MCP tool handler in `server/tools.py`
  calls `require_scope()` before acting".
