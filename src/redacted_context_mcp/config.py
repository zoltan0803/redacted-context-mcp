"""Local redaction configuration loading."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None

from .defaults import LOCAL_CONFIG, RESERVED_PLACEHOLDER_WORDS
from .models import GitHubRepoConfig, RedactionConfig
from .paths import resolve_under_root

def load_config(root: Path, config_path: Path | None) -> RedactionConfig:
    values: dict[str, list[str]] = {
        "clients": [],
        "organizations": [],
        "people": [],
        "terms": [],
        "allow": [],
        "exclude_dirs": [],
        "exclude_globs": [],
    }
    github_repos: dict[str, GitHubRepoConfig] = {}

    for term in derive_root_terms(root):
        values["clients"].append(term)

    default_config = root / LOCAL_CONFIG
    path = config_path if config_path is not None else default_config
    if path.exists():
        data = read_toml(path)
        redaction = data.get("redaction", data)
        for key in values:
            values[key].extend(as_string_list(redaction.get(key, [])))
        for term_file in as_string_list(redaction.get("term_files", [])):
            term_path = resolve_under_root(root, term_file, allow_missing=True)
            if term_path.exists():
                values["terms"].extend(read_term_file(term_path))
        github_repos.update(parse_github_repos(data.get("github", {})))

    env_terms = os.environ.get("REDACTED_CONTEXT_TERMS")
    if env_terms:
        values["terms"].extend(split_env_terms(env_terms))

    return RedactionConfig(
        clients=dedupe(values["clients"]),
        organizations=dedupe(values["organizations"]),
        people=dedupe(expand_person_terms(values["people"])),
        terms=dedupe(values["terms"]),
        allow=dedupe(values["allow"]),
        exclude_dirs=dedupe(values["exclude_dirs"]),
        exclude_globs=dedupe(values["exclude_globs"]),
        github_repos=github_repos,
    )


def read_toml(path: Path) -> dict:
    if tomllib is None:
        raise SystemExit("TOML config requires Python 3.11+ or no config file.")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def as_string_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    raise SystemExit(f"Expected string or list in redaction config, got {type(value).__name__}.")


def parse_github_repos(value: object) -> dict[str, GitHubRepoConfig]:
    if not isinstance(value, dict):
        return {}
    repos = value.get("repos", {})
    if not isinstance(repos, dict):
        raise SystemExit("Expected [github.repos.<alias>] tables in redaction config.")

    parsed: dict[str, GitHubRepoConfig] = {}
    for alias, raw_config in repos.items():
        alias_value = str(alias).strip()
        if not alias_value:
            continue
        if not isinstance(raw_config, dict):
            raise SystemExit("Expected each GitHub repo config to be a table.")
        owner = str(raw_config.get("owner", "")).strip()
        repo = str(raw_config.get("repo", "")).strip()
        if not owner or not repo:
            raise SystemExit("GitHub repo config requires owner and repo.")
        parsed[alias_value] = GitHubRepoConfig(
            owner=owner,
            repo=repo,
            api_url=str(raw_config.get("api_url", "https://api.github.com")).strip()
            or "https://api.github.com",
            token_env=str(raw_config.get("token_env", "GITHUB_TOKEN")).strip() or "GITHUB_TOKEN",
        )
    return parsed


def read_term_file(path: Path) -> list[str]:
    terms: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            terms.append(line)
    return terms


def split_env_terms(value: str) -> list[str]:
    return [part.strip() for part in re.split(r"[\n,]", value) if part.strip()]


def dedupe(values: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        cleaned = re.sub(r"\s+", " ", str(value).strip())
        key = cleaned.casefold()
        if cleaned and key not in seen:
            result.append(cleaned)
            seen.add(key)
    return tuple(result)


def derive_root_terms(root: Path) -> list[str]:
    name = root.name.strip()
    if not name:
        return []
    terms = {name, name.replace("-", " "), name.replace("_", " ")}
    parts = [part for part in re.split(r"[-_\s]+", name) if len(part) >= 3]
    terms.update(parts)
    if len(parts) >= 2:
        acronym = "".join(part[0] for part in parts)
        if len(acronym) >= 2:
            terms.add(acronym)
            terms.add(acronym.upper())
        first_part_plus_initial = f"{parts[0]}{parts[1][0]}"
        terms.add(first_part_plus_initial)
        terms.add(first_part_plus_initial.upper())
    return sorted(terms, key=len, reverse=True)


def expand_person_terms(people: Iterable[str]) -> list[str]:
    expanded: list[str] = []
    for person in people:
        expanded.append(person)
        parts = [part for part in re.split(r"[\s_-]+", person) if len(part) >= 3]
        expanded.extend(parts)
    return expanded
