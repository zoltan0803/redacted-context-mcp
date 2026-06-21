# Security Policy

`redacted-context-mcp` is a practical redaction and workflow guardrail. It is
not a formal anonymization system and does not guarantee irreversible
de-identification.

Assume that anything returned by an MCP tool may be visible to the agent and to
the model provider behind that agent. The tool is designed to reduce exposure
by replacing configured sensitive terms, common identifiers, and raw filenames
before returning text.

For hard isolation, run the coding agent as a separate OS user or inside a
container that cannot read the private source folder directly. Expose only the
MCP server or a separate redaction service to that agent.

Do not rely on prompts alone to protect sensitive files if the agent can still
read the raw private folder through shell commands or built-in file tools.

See `SECURITY_INVARIANTS.md` for the specific containment, output-safety,
unlinkability, determinism, bijection, write-confinement, bounded-operation, and
protocol-compatibility invariants this project aims to keep tested.

Please report security issues privately through the repository's security
advisory flow when available. If no advisory flow is available yet, contact the
maintainer directly before opening a public issue.
