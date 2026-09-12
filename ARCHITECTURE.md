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
    -> redaction layer
      -> private source root
        -> redacted text plus opaque path references
```

The agent should start from a neutral workspace that does not contain the raw
private context files. The MCP server receives tool calls, resolves paths inside
the configured root, reads allowed text files, redacts output, and returns only
the redacted result. If controlled writes are enabled, generated redacted text
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

## Module Layout

- `core.py`: CLI commands, parser setup, and compatibility re-exports.
- `server.py`: minimal stdio MCP JSON-RPC server.
- `defaults.py`: default limits, allow lists, exclude lists, and compiled
  patterns.
- `models.py`: shared dataclasses.
- `redaction.py`: text/path redaction logic.
- `config.py`: local TOML config loading and validation.
- `config_reload.py`: request-boundary policy change detection, stable reloads,
  and fail-closed handling of invalid or missing policy inputs.
- `paths.py`: root-constrained path resolution and opaque path ids.
- `filesystem.py`: read-only filesystem traversal and text-file detection.
- `documents.py`: optional local MarkItDown extraction through explicitly
  selected format converters and a bounded worker process.
- `retrieval.py`: transient passage tokenization and ranking over redacted text.
- `discovery.py`: local Ollama discovery workflow and post-processing.
- `github.py`: read-only GitHub issue access through neutral aliases.

## Retrieval and Documents

`RedactedContext.read_text` is the shared input path for context reads. With
`--documents`, supported local binary documents are read as verified bytes and
passed to a short-lived worker. That worker invokes the selected MarkItDown
converter directly, without auto-detection, plugins, URLs, or cloud clients.
Raw extracted Markdown returns over a local pipe and is redacted before tool
output or resource caching. Source bytes, expanded OOXML size, extracted text,
and worker duration are bounded. No raw extraction cache or persistent index is
created. Plain-text reads do not import MarkItDown.

`redctx_retrieve` scans readable files under existing traversal/read budgets,
redacts whole documents while preserving line counts, and splits the result
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
referenced term files. A validated policy replaces the context and redactor
together and clears cached content, path indexes, and rehydration state.
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

The GitHub integration is read-only and uses the token environment variable
named in local config.

## Security Posture

This project is a privacy guardrail, not a hard isolation boundary. If the agent
process can read the private source folder directly, prompts and MCP routing
are not enough. For stronger enforcement, run the agent as a separate OS user or
inside a container that cannot access the private folder directly, and expose
only the redacted MCP server.
