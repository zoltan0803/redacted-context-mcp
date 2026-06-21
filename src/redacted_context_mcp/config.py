"""Local redaction configuration loading."""

from __future__ import annotations

import os
import re
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterable

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback
    tomllib = None

from .defaults import (
    DETECTOR_PROFILE_ENV,
    LOCAL_CONFIG,
    SALT_ENV,
    STATE_DIR_ENV,
    TERMS_ENV,
)
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
    explicit_values: dict[str, list[str]] = {
        "clients": [],
        "organizations": [],
        "people": [],
        "terms": [],
    }
    github_repos: dict[str, GitHubRepoConfig] = {}
    salt = ""
    salt_source = "local-state"
    detector_profile = "default"

    root_terms = derive_root_terms(root)
    for term in root_terms:
        values["clients"].append(term)

    default_config = root / LOCAL_CONFIG
    path = config_path if config_path is not None else default_config
    if path.exists():
        data = read_toml(path)
        redaction = data.get("redaction", data)
        for key in values:
            loaded_values = as_string_list(redaction.get(key, []))
            values[key].extend(loaded_values)
            if key in explicit_values:
                explicit_values[key].extend(loaded_values)
        salt = str(redaction.get("salt", "")).strip()
        if salt:
            salt_source = "config"
        detector_profile = str(redaction.get("detector_profile", detector_profile)).strip() or detector_profile
        for term_file in as_string_list(redaction.get("term_files", [])):
            term_path = resolve_under_root(root, term_file, allow_missing=True)
            if term_path.exists():
                term_file_values = read_term_file(term_path)
                values["terms"].extend(term_file_values)
                explicit_values["terms"].extend(term_file_values)
        github_repos.update(parse_github_repos(data.get("github", {})))

    environment_terms: list[str] = []
    env_terms = os.environ.get(TERMS_ENV)
    if env_terms:
        environment_terms = split_env_terms(env_terms)
        values["terms"].extend(environment_terms)
    env_salt = os.environ.get(SALT_ENV, "").strip()
    if env_salt:
        salt = env_salt
        salt_source = "environment"
    if not salt:
        salt, salt_source = load_or_create_vault_salt(root)
    detector_profile = os.environ.get(DETECTOR_PROFILE_ENV, "").strip() or detector_profile
    if detector_profile not in {"default", "extended"}:
        raise SystemExit("detector_profile must be default or extended.")

    return RedactionConfig(
        clients=dedupe(values["clients"]),
        organizations=dedupe(values["organizations"]),
        people=dedupe(expand_person_terms(values["people"])),
        terms=dedupe(values["terms"]),
        allow=dedupe(values["allow"]),
        exclude_dirs=dedupe(values["exclude_dirs"]),
        exclude_globs=dedupe(values["exclude_globs"]),
        github_repos=github_repos,
        salt=salt,
        salt_source=salt_source,
        root_terms=dedupe(root_terms),
        environment_terms=dedupe(environment_terms),
        explicit_clients=dedupe(explicit_values["clients"]),
        explicit_organizations=dedupe(explicit_values["organizations"]),
        explicit_people=dedupe(expand_person_terms(explicit_values["people"])),
        explicit_terms=dedupe(explicit_values["terms"]),
        detector_profile=detector_profile,
    )


def read_toml(path: Path) -> dict:
    if tomllib is None:
        raise SystemExit("TOML config requires Python 3.11+ or no config file.")
    return tomllib.loads(path.read_text(encoding="utf-8-sig"))


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


def load_or_create_vault_salt(root: Path) -> tuple[str, str]:
    state_file = vault_salt_path(root)
    ensure_state_outside_root(root, state_file)
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(state_file.parent, 0o700)
        except OSError:
            pass
        lock_path = state_file.with_suffix(state_file.suffix + ".lock")
        with exclusive_file_lock(lock_path):
            if state_file.exists():
                return read_vault_salt(state_file), "local-state"
            salt = secrets.token_hex(32)
            tmp_path = state_file.with_name(f".{state_file.name}.{os.getpid()}.tmp")
            with open(tmp_path, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(salt + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
            os.replace(tmp_path, state_file)
            fsync_directory(state_file.parent)
            return read_vault_salt(state_file), "local-state"
    except SystemExit:
        raise
    except OSError as exc:
        raise SystemExit("Could not initialize redacted-context vault salt.") from exc


def vault_salt_path(root: Path) -> Path:
    import hashlib

    base = os.environ.get(STATE_DIR_ENV, "").strip()
    if base:
        state_root = Path(base).expanduser()
    elif os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        state_root = Path(os.environ["LOCALAPPDATA"]) / "redacted-context-mcp"
    else:
        state_root = Path.home() / ".local" / "state" / "redacted-context-mcp"
    vault_id = hashlib.sha256(str(root.resolve()).encode("utf-8")).hexdigest()
    return state_root / "vaults" / f"{vault_id}.salt"


def ensure_state_outside_root(root: Path, state_file: Path) -> None:
    root_raw = root.expanduser()
    root_resolved = root.resolve()
    root_candidates = (root_raw, root_resolved)
    candidates = [state_file, *state_file.parents]
    for candidate in candidates:
        raw = candidate.expanduser()
        if any(raw == root_candidate or is_relative_to(raw, root_candidate) for root_candidate in root_candidates):
            raise SystemExit("The redacted-context state directory must be outside the served context root.")
        resolved = raw.resolve(strict=False)
        if any(
            resolved == root_candidate or is_relative_to(resolved, root_candidate)
            for root_candidate in root_candidates
        ):
            raise SystemExit("The redacted-context state directory must be outside the served context root.")


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def read_vault_salt(path: Path) -> str:
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise SystemExit("Could not read redacted-context vault salt.") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise SystemExit(
            "The redacted-context vault salt is malformed. Restore a backup or delete it intentionally to rotate aliases."
        )
    return value


@contextmanager
def exclusive_file_lock(path: Path) -> Iterable[BinaryIO]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield handle
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield handle
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


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
