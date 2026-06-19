# Redacted Agent Workspace

This workspace intentionally does not contain private project context. Use the
`redacted_context` MCP server for all project context.

Prefer these read-only MCP tools:

- `redctx_tree`
- `redctx_list`
- `redctx_read`
- `redctx_search`
- `redctx_stat`
- `redctx_bundle`
- `redctx_doctor`
- `redctx_github_repos`
- `redctx_github_list_issues`
- `redctx_github_read_issue`
- `redctx_github_search_issues`

Use `redctx_submit_doc` only if the MCP server exposes it and the user asks you
to create or update a generated document in the private context repo. Submit
generated redacted text and a relative `target_path`; do not use absolute paths,
`..`, or overwrite unless the user explicitly requested replacement.

Do not inspect the private source folder directly with `Read`, `Grep`, `Glob`,
`cat`, `rg`, `grep`, `sed`, `awk`, `head`, `tail`, `less`, `more`, `find`, or
ad-hoc scripts.

Carry opaque `@p_<id>` references between MCP calls instead of raw filenames.
For GitHub issue context, use only configured neutral repo aliases such as
`context`; do not ask for or print raw GitHub owner/repo names.
