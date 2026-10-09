"""Shared data models for redacted context access."""

from __future__ import annotations

from dataclasses import dataclass, field

# Safe, input-free messages shared by source adapters and the MCP/CLI error
# sanitizer. They must never interpolate references, paths, or upstream text.
UNKNOWN_REFERENCE_MESSAGE = "Unknown source reference."
DOCUMENTS_UNSUPPORTED_MESSAGE = "Source does not support document iteration."
# Detector failures at request time. They never relay detector, library, or
# model text, and never include the input that was being analyzed.
DETECTOR_FAILED_MESSAGE = "Detector failed."
DETECTOR_CATEGORY_MESSAGE = "Detector returned an unsupported category."
DETECTOR_SPAN_MESSAGE = "Detector returned an invalid span."
DETECTOR_LIMIT_MESSAGE = "Detector nomination limit exceeded."
# Controlled writes never replace the config, term files, detector inputs, or
# never-serve files, even when they lie under the write subdirectory.
WRITE_TARGET_PROTECTED_MESSAGE = "Write target is protected."

# Startup-only, operator-facing message (never produced at request time).
UNKNOWN_DETECTOR_MESSAGE = "Unknown detector."


@dataclass(frozen=True)
class SourceDocument:
    """One raw document yielded by a context source.

    ``ref`` is the source's opaque reference and is safe to emit as-is.
    ``locator`` (for files, the root-relative path) and ``text`` are raw
    private data: callers must pass both through the redaction boundary
    before anything leaves the process.
    """

    ref: str
    locator: str
    text: str


@dataclass(frozen=True)
class GitHubRepoConfig:
    owner: str
    repo: str
    api_url: str = "https://api.github.com"
    token_env: str = "GITHUB_TOKEN"


@dataclass(frozen=True)
class RedactionConfig:
    clients: tuple[str, ...] = ()
    organizations: tuple[str, ...] = ()
    people: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()
    exclude_dirs: tuple[str, ...] = ()
    exclude_globs: tuple[str, ...] = ()
    github_repos: dict[str, GitHubRepoConfig] = field(default_factory=dict)
    salt: str = ""
    salt_source: str = "local-state"
    root_terms: tuple[str, ...] = ()
    environment_terms: tuple[str, ...] = ()
    explicit_clients: tuple[str, ...] = ()
    explicit_organizations: tuple[str, ...] = ()
    explicit_people: tuple[str, ...] = ()
    explicit_terms: tuple[str, ...] = ()
    detector_profile: str = "default"
    term_files: tuple[str, ...] = ()
    protected_paths: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiscoveryResult:
    clients: tuple[str, ...] = ()
    organizations: tuple[str, ...] = ()
    people: tuple[str, ...] = ()
    terms: tuple[str, ...] = ()
    allow: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, tuple[str, ...]]:
        return {
            "clients": self.clients,
            "organizations": self.organizations,
            "people": self.people,
            "terms": self.terms,
            "allow": self.allow,
        }


@dataclass(frozen=True)
class DiscoveryDocument:
    """Raw local document supplied to the discovery API."""

    path: str
    text: str
    sha256: str = ""


@dataclass(frozen=True)
class DiscoveryUpdate:
    """Result of discovering documents and merging a redaction config."""

    discovery: DiscoveryResult
    config_text: str
    changed: bool


class DiscoveryParseError(ValueError):
    """Raised when a local model response cannot be parsed as discovery JSON."""
