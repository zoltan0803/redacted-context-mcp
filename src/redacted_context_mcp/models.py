"""Shared data models for redacted context access."""

from __future__ import annotations

from dataclasses import dataclass, field

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


class DiscoveryParseError(ValueError):
    """Raised when a local model response cannot be parsed as discovery JSON."""
