# Architecture

`redacted-context-mcp` exposes a private local knowledgebase through a narrow
redaction layer. The default MCP surface is read-only; controlled writes are
available only when the server is started with explicit write flags. The project
is intentionally small: it avoids runtime dependencies, stores no persistent
index, and keeps all sensitive configuration local.

## Data Flow

```text
agent workspace
  -> MCP client or redctx CLI
    -> redaction boundary (Redactor + rendering)
      -> source registry
        -> filesystem source (private root)    -> raw text + @p_<id> refs
        -> GitHub source (configured aliases)  -> raw issue records + alias#N refs
  <- redacted text plus opaque references
```

The agent should start from a neutral workspace that does not contain the raw
private context files. The MCP server receives tool calls: file tools use the
filesystem source directly, which resolves paths inside the configured root and
reads allowed text files, and GitHub tools call the GitHub source, which
fetches issues for configured aliases. Sources return raw text plus opaque
references, and the server or CLI redacts every content field before returning
only the redacted result. If controlled writes are enabled, generated redacted text
can be rehydrated locally and written under a configured private-root
subdirectory.

## Core Boundaries

- The server is read-only by default.
- Controlled MCP writes require `--enable-writes` and are constrained to
  `--write-subdir`.
- Path resolution is constrained to the configured root.
- Known private/cache paths and binary-like files are excluded by default.
- File navigation uses local-salted HMAC ids such as `@p_1a2b3c4d5e6f`.
- Filesystem traversal starts from validated paths, skips symlink and reparse
  entries, and revalidates paths before content reads and opaque-id resolution.
- Content reads compare file metadata before and after reading to detect common
  substitutions, but the project remains a guardrail rather than a hard
  concurrent-mutation sandbox.
- Redacted files are available as MCP resources with `redctx://p_<id>` URIs.
- MCP resource content is cached only after redaction and is bounded by byte
  limits.
- The stdio server supports both stateless MCP `2026-07-28` requests and the
  legacy initialization-based protocol through `2025-11-25`.
- Opaque path references are explicit request arguments rather than implicit
  protocol-session state. In-memory path and content indexes are reconstructable
  caches; the persistent vault salt is durable server configuration.
- Redaction happens before file content, file paths, search results, bundles,
  and GitHub issue text are returned.

## Source Adapters

Every private data source implements the small `ContextSource` protocol in
`sources.py`. The layering rule is:

- **Sources own identity and reference opaqueness.** A source decides how its
  private identifiers become neutral references (`@p_<id>` / `redctx://p_<id>`
  path ids, `<alias>#<number>` issue refs, `user_<hex>` author aliases) and
  enforces its own containment, exclusion, and never-serve policy.
- **The redaction boundary owns content redaction.** Sources never redact.
  Everything a source yields (file text, file paths used as locators, issue
  titles, bodies, labels, timestamps) is raw and is redacted by the CLI/MCP
  layer (`Redactor`, `rendering.py`, the command functions in `core.py`)
  before it leaves the process.

The protocol surface is deliberately small:

- `name`: stable registry key (`"filesystem"`, `"github"`).
- `untrusted_content`: true for text outside the operator's control, such as
  GitHub issues. Ranked retrieval appends `untrusted_external` to the passage
  header of every passage from such a source. GitHub rendering does not read
  the flag; it labels issue text with fixed field names (`untrusted_title=`,
  `body_untrusted_external:`, `comment_untrusted_external:`).
- `supports_document_iteration`: whether `iter_documents` yields documents for
  source-agnostic scans such as ranked retrieval. (This is unrelated to
  `RedactedContext.documents`, which enables Office/PDF extraction.)
- `owns_reference(ref)` and `resolve_reference(ref)`: syntactic ownership and
  resolution of the source's own opaque references. Raw paths, foreign
  references, and malformed or unknown references are refused with messages
  that never echo raw identifiers. MCP `redctx://p_<id>` resource URIs are
  resolved through the filesystem source's `resolve_reference`.
- `iter_documents(budget, scope=..., patterns=...)`: yield raw
  `SourceDocument(ref, locator, text)` items while charging traversal, file,
  byte, and deadline limits to the shared `OperationBudget`. Exceeding a limit
  fails closed with `OperationLimitError`. Sources that do not declare
  `supports_document_iteration` refuse before any I/O.

`RedactedContext` is the filesystem source. `GitHubSource` serves GitHub
issues as structured `GitHubIssue` / `GitHubComment` records whose authors are
already opaque aliases; it does not offer document iteration, so it cannot be
crawled by ranked retrieval. `build_sources` assembles a `SourceRegistry`:
the filesystem source is always present and GitHub appears only when the
config defines `[github.repos.<alias>]`. The MCP server rebuilds the registry
together with the `Redactor` on every accepted policy reload.

Ranked retrieval consumes `iter_documents` from any source, so it does not
walk the filesystem itself. The controlled-write rehydration scan and Ollama
discovery remain filesystem-specific because they need directory entries,
write-subdirectory pruning, and operator-only raw output.

### Adding a Source

1. Implement `ContextSource` (`name`, `untrusted_content`,
   `supports_document_iteration`, `owns_reference`, `resolve_reference`,
   `iter_documents`) in its own module.
   Do not import `redaction` or `rendering` from it.
2. Return raw text plus opaque references only. Derive references with the
   vault salt (HMAC) or neutral operator-chosen aliases, and never place raw
   identifiers such as paths, addresses, logins, or upstream names in them.
3. Declare `untrusted_content = True` for anything the operator does not
   control, and label that content in rendered output.
4. Charge every entry, document, byte, and deadline check to the supplied
   `OperationBudget` (`consume_entry`, `consume_file`, `consume_document`,
   `check_deadline`) and fail closed when a limit is exceeded.
   `consume_document` is the hook for documents that are not standalone files
   (the in-memory test source uses it); the filesystem source uses
   `consume_file`. GitHub does not iterate documents: its fetches are bounded
   by the response-size cap and per-request page and result limits rather than
   `OperationBudget`.
5. Register it in `build_sources` so live policy reload rebuilds it with the
   redactor, and render its output through the redaction boundary.
6. Add it to `tests/test_sources.py` by subclassing `SourceConformance`, and
   keep error messages on the server's safe-message list.

## Module Layout

- `core.py`: CLI commands, parser setup, and compatibility re-exports.
- `server.py`: minimal stdio MCP JSON-RPC server.
- `sources.py`: `ContextSource` protocol, `SourceRegistry`, and
  `build_sources`.
- `rendering.py`: redaction boundary for structured source records (GitHub
  issue summaries and details), shared by the CLI and MCP server.
- `defaults.py`: default limits, allow lists, exclude lists, and compiled
  patterns.
- `models.py`: shared dataclasses.
- `redaction.py`: text/path redaction logic.
- `config.py`: local TOML config loading and validation.
- `config_reload.py`: request-boundary policy change detection, stable reloads,
  and fail-closed handling of invalid or missing policy inputs.
- `paths.py`: root-constrained path resolution and opaque path ids.
- `filesystem.py`: filesystem source (`RedactedContext`): read-only
  traversal, text-file detection, and document iteration.
- `documents.py`: optional local MarkItDown extraction through explicitly
  selected format converters and a bounded worker process.
- `retrieval.py`: transient passage tokenization and ranking over redacted
  text from any source that supports document iteration.
- `discovery.py`: local Ollama discovery workflow and post-processing.
- `github.py`: GitHub source (`GitHubSource`): read-only issue fetching
  through neutral aliases, structured records, and author aliases.

## Retrieval and Documents

`RedactedContext.read_text` is the shared input path for context reads. With
`--documents`, supported local binary documents are read as verified bytes and
passed to a short-lived worker. That worker invokes the selected MarkItDown
converter directly, without auto-detection, plugins, URLs, or cloud clients.
Raw extracted Markdown returns over a local pipe and is redacted before tool
output or resource caching. Source bytes, expanded OOXML size, extracted text,
and worker duration are bounded. No raw extraction cache or persistent index is
created. Plain-text reads do not import MarkItDown.

`redctx_retrieve` scans the filesystem source's documents under existing
traversal/read budgets, redacts whole documents while preserving line counts, and splits the result
into bounded passages. It orders matches by query-term coverage, then BM25,
with deterministic opaque-reference/line tie-breaking. Only matching redacted
passages and query statistics are retained for the request. Result count and
character limits bound the returned context; exhausted scan budgets fail closed.

## Controlled Write Path

`redctx_submit_doc` is hidden unless the server starts with `--enable-writes`.
When enabled, it accepts generated redacted text, rebuilds the local
rehydration map from the private source root, rejects unresolved placeholders,
and writes the restored document only under `--write-subdir`.

The write tool does not accept arbitrary workspace file paths. It accepts text
content directly and a relative target path. Overwrites require an explicit
`overwrite` argument. Tool results return only redacted path metadata and opaque
ids.

No-overwrite writes are published from a same-directory temporary file without
replacing an existing target where hard-link publication is available. Explicit
overwrites use same-directory `os.replace`. Directory durability fsync is
best-effort and POSIX-only.

## Redaction Model

Redaction combines configured exact terms with conservative generic patterns:

- configured clients, organizations, people, and sensitive terms;
- email addresses, URLs, phone numbers, handles, secrets, tokens, common
  personal identifiers, IP addresses, UUIDs, and domains;
- organization suffix patterns;
- multi-token proper names;
- stricter titlecase/acronym handling in `strict` mode.

The allow list prevents common public technologies and generic vocabulary from
being over-redacted. Project-specific allow-list entries belong in the local
`.agent-context-redactor.toml`, not in source control.

Placeholders are deterministic 128-bit HMAC aliases derived from the local
salt, for example `[PERSON_1a2b3c4d5e6f7890a1b2c3d4e5f60718]`. The same raw
value maps to the same placeholder for one private config without exposing the
raw value. Placeholder collisions are detected and fail closed instead of
building an ambiguous rehydration map.

## Configuration

The local `.agent-context-redactor.toml` file is intentionally ignored by git.
It may contain exact client names, stakeholder names, project codenames, private
repo names, and token environment variable names.

If a config or environment salt is not supplied, the loader creates or reuses a
random 256-bit vault salt in user-local state. Missing state creates a new
random salt. Existing empty, malformed, or root-contained state fails closed
instead of rotating aliases silently. `redctx doctor` reports the salt source.

`redctx discover` can draft that file with a local Ollama model. It is a setup
command for a human operator, not an MCP tool, because its output intentionally
contains raw sensitive terms.

The MCP server probes config and term-file metadata before tool execution and
resource listing/reads. Unchanged requests keep the existing policy and cache.
Changed inputs are loaded twice around dependency snapshots, including newly
referenced term files. A validated policy replaces the source registry and
redactor together and clears cached content, path indexes, and rehydration
state. Adding or removing `[github.repos.<alias>]` tables therefore adds or
removes the GitHub source on the next request.
Invalid, unreadable, unstable, or removed previously loaded inputs block
context requests and clear the content cache; the next request retries. Public
protocol discovery and tool schemas remain available during recovery.

Live reload refuses salt rotation to avoid silently invalidating references.
Environment, launch-option, and external salt-state changes require a restart.
Metadata checks are a local workflow guardrail, not a concurrent-mutation
sandbox, and do not revoke content already returned to a client.

## GitHub Issue Access

GitHub repositories are configured by neutral aliases under
`[github.repos.<alias>]`. The alias is what the agent sees. Raw owner/repo names
and author logins are not printed in tool output. Author aliases are HMACs over
the local vault salt, repo alias, and login so they are not linkable across
vaults or repo aliases.

The GitHub source is read-only and uses the token environment variable
named in local config. It returns structured issue records with raw,
untrusted text and opaque author aliases; `rendering.py` redacts titles,
bodies, labels, states, and timestamps when formatting them for the CLI and
MCP tools, which share the same code path. Issue numbers and comment counts
are kept only when upstream sends non-negative integers (otherwise they print
as `?` and `0`). Each upstream response body is capped at 8 MiB; larger
responses fail with an input-free error.

## Security Posture

This project is a privacy guardrail, not a hard isolation boundary. If the agent
process can read the private source folder directly, prompts and MCP routing
are not enough. For stronger enforcement, run the agent as a separate OS user or
inside a container that cannot access the private folder directly, and expose
only the redacted MCP server.
