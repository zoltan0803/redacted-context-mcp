#!/usr/bin/env python3
"""CLI facade for redacted local context access.

Most implementation details live in focused modules. This module intentionally
keeps the historical public imports and console-script entry point stable.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

if __package__ in {None, ""}:  # pragma: no cover - direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "redacted_context_mcp"

from .config import (
    as_string_list,
    dedupe,
    derive_root_terms,
    expand_person_terms,
    load_config,
    parse_github_repos,
    read_term_file,
    read_toml,
    split_env_terms,
)
from .defaults import (
    DEFAULT_DISCOVERY_MAX_CHARS,
    DEFAULT_DISCOVERY_MAX_FILES,
    DEFAULT_DISCOVERY_MODEL,
    DEFAULT_MAX_CHARS,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_RAW_BYTES_PER_FILE,
    DEFAULT_MAX_RESOURCE_BYTES,
    DEFAULT_MAX_SEARCH_RESULTS,
    DEFAULT_MAX_TOTAL_RAW_BYTES,
    DEFAULT_MAX_TRAVERSAL_ENTRIES,
    DEFAULT_OLLAMA_ENDPOINT,
    LOCAL_CONFIG,
    PLACEHOLDER_RE,
    REPO_ROOT,
)
from .discovery import (
    OllamaDiscoveryClient,
    build_discovery_prompt,
    build_strict_discovery_prompt,
    clean_discovered_terms,
    discover_entities,
    extract_ollama_error,
    format_discovery_toml,
    format_toml_array,
    is_country_or_region_only,
    is_generic_discovery_term,
    is_generic_org_value,
    is_likely_tool_or_package_name,
    is_name_token,
    is_probable_person,
    is_public_or_allowed_term,
    is_role_or_title,
    merge_discovery_results,
    normalize_discovery_value,
    normalize_person_name,
    parse_discovery_response,
    parse_json_object,
    postprocess_discovery_result,
    should_drop_discovered_value,
    write_discovery_output,
)
from .filesystem import (
    RedactedContext,
    is_probably_text,
    is_probably_text_bytes,
    is_reparse_point,
    iter_target_files,
    read_text_file,
)
from .limits import OperationBudget, OperationLimitError
from .github import (
    count_github_assignees,
    default_ssl_paths_have_certs,
    extract_github_error,
    format_github_issue_detail,
    format_github_issue_summary,
    format_github_labels,
    format_github_url_error,
    get_github_repo_config,
    github_api_request,
    github_list_issues,
    github_read_issue,
    github_read_issue_comments,
    github_search_issues,
    github_ssl_context,
    opaque_github_user,
    truncate_text,
    validate_github_state,
    validate_nonnegative_limit,
    validate_positive_limit,
)
from .models import DiscoveryParseError, DiscoveryResult, GitHubRepoConfig, RedactionConfig
from .paths import display_ref, path_id, rel_posix, resolve_under_root
from .redaction import Redactor, compile_literal_pattern, normalize_alias


PLACEHOLDER_QUERY_RE = re.compile(
    r"(?:\[|_|(?:CLIENT|ORG|PERSON|SENSITIVE|ENTITY|EMAIL|PHONE|URL|HANDLE|SECRET|SSN|CARD|IP|ID|DOMAIN)|[0-9a-fA-F]{8,})"
)


def operation_budget_from_args(args: argparse.Namespace) -> OperationBudget:
    seconds = getattr(args, "max_seconds", None)
    return OperationBudget.from_seconds(
        max_files=getattr(args, "max_files", None),
        max_raw_bytes_per_file=getattr(args, "max_raw_bytes_per_file", DEFAULT_MAX_RAW_BYTES_PER_FILE),
        max_total_raw_bytes=getattr(args, "max_total_raw_bytes", DEFAULT_MAX_TOTAL_RAW_BYTES),
        max_entries=getattr(args, "max_entries", DEFAULT_MAX_TRAVERSAL_ENTRIES),
        max_output_chars=getattr(args, "max_output_chars", None),
        seconds=seconds,
    )


def can_use_raw_search_prefilter(query: str, *, regex: bool, ignore_case: bool) -> bool:
    del ignore_case
    stripped = query.strip()
    if regex or len(stripped) < 2:
        return False
    return PLACEHOLDER_QUERY_RE.search(stripped) is None


def format_entry(path: Path, ctx: RedactedContext, redactor: Redactor) -> str:
    rel = rel_posix(path, ctx.root)
    kind = "dir " if path.is_dir() else "file"
    size = "-" if path.is_dir() else str(path.stat().st_size)
    return f"{ctx.display_ref(rel)}\t{kind}\t{size}\t{redactor.redact_path(rel)}"


def command_ls(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    path = ctx.resolve_ref(args.path)
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")

    if args.recursive:
        for child in ctx.walk(path, include_dirs=True, max_depth=args.max_depth, budget=budget):
            print(format_entry(child, ctx, redactor))
        return 0

    for child in ctx.child_entries(path, budget=budget):
        print(format_entry(child, ctx, redactor))
    return 0


def command_tree(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    root = ctx.resolve_ref(args.path)
    if ctx.is_excluded(root):
        raise SystemExit("Path is excluded by policy.")
    if root.is_file():
        print(format_entry(root, ctx, redactor))
        return 0
    base_depth = len(root.relative_to(ctx.root).parts)
    for path in ctx.walk(root, include_dirs=True, max_depth=args.max_depth, budget=budget):
        depth = len(path.relative_to(ctx.root).parts) - base_depth
        rel = rel_posix(path, ctx.root)
        name = "." if path == root else path.name
        indent = "  " * depth
        suffix = "/" if path.is_dir() else ""
        print(f"{indent}{ctx.display_ref(rel)} {redactor.redact_path(name)}{suffix}")
    return 0


def command_cat(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    path = ctx.resolve_ref(args.path, expected="text")
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")
    path = ctx.validate_path(path, expected="text")
    text = read_text_file(path, budget=budget)
    lines = text.splitlines(keepends=True)
    start = max(args.start_line or 1, 1)
    end = args.end_line or len(lines)
    if end < start:
        raise SystemExit("--end-line must be greater than or equal to --start-line.")
    selected = "".join(lines[start - 1 : end])
    redacted = redactor.redact(selected)
    if len(redacted) > args.max_chars:
        redacted = redacted[: args.max_chars] + "\n[TRUNCATED]\n"

    rel = rel_posix(path, ctx.root)
    print(f"--- {ctx.display_ref(rel)} {redactor.redact_path(rel)} lines {start}-{min(end, len(lines))} ---")
    if args.line_numbers:
        for offset, line in enumerate(redacted.splitlines(), start=start):
            print(f"{offset:>6}\t{line}")
    else:
        print(redacted, end="" if redacted.endswith("\n") else "\n")
    return 0


def command_head(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    args.start_line = 1
    args.end_line = args.lines
    args.max_chars = args.max_chars or DEFAULT_MAX_CHARS
    args.line_numbers = args.line_numbers
    return command_cat(args, ctx, redactor)


def command_tail(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    path = ctx.resolve_ref(args.path, expected="text")
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")
    text = read_text_file(ctx.validate_path(path, expected="text"))
    line_count = len(text.splitlines())
    args.start_line = max(1, line_count - args.lines + 1)
    args.end_line = line_count
    args.max_chars = args.max_chars or DEFAULT_MAX_CHARS
    args.line_numbers = args.line_numbers
    return command_cat(args, ctx, redactor)


def command_grep(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    flags = re.IGNORECASE if args.ignore_case else 0
    matcher: re.Pattern[str] | None = None
    query = args.query
    if args.regex:
        try:
            matcher = re.compile(query, flags)
        except re.error as exc:
            raise SystemExit("Invalid regex.") from exc
    elif args.ignore_case:
        query = query.casefold()

    use_prefilter = can_use_raw_search_prefilter(args.query, regex=args.regex, ignore_case=args.ignore_case)
    results = 0
    for path in iter_target_files(ctx, args.paths, args.glob, budget=budget, text_only=not use_prefilter):
        if use_prefilter:
            path = ctx.validate_path(path, expected="file")
            budget.consume_file(path)
            raw_bytes = path.read_bytes()
            if args.query.isascii():
                needle = args.query.encode("utf-8")
                if args.ignore_case:
                    if needle.lower() not in raw_bytes.lower():
                        continue
                elif needle not in raw_bytes:
                    continue
                if not is_probably_text_bytes(raw_bytes[:4096]):
                    continue
                raw = raw_bytes.decode("utf-8-sig", errors="replace")
            else:
                if not is_probably_text_bytes(raw_bytes[:4096]):
                    continue
                raw = raw_bytes.decode("utf-8-sig", errors="replace")
                raw_haystack = raw.casefold() if args.ignore_case else raw
                raw_query = args.query.casefold() if args.ignore_case else args.query
                if raw_query not in raw_haystack:
                    continue
        else:
            path = ctx.validate_path(path, expected="text")
            raw = read_text_file(path, budget=budget)
        redacted_lines = redactor.redact(raw, preserve_line_count=True).splitlines()
        matches: list[int] = []
        for index, line in enumerate(redacted_lines):
            haystack = line if args.regex or not args.ignore_case else line.casefold()
            found = bool(matcher.search(line)) if matcher else query in haystack
            if found:
                matches.append(index)

        if not matches:
            continue

        emitted: set[int] = set()
        rel = rel_posix(path, ctx.root)
        for match_index in matches:
            for line_index in range(
                max(0, match_index - args.context),
                min(len(redacted_lines), match_index + args.context + 1),
            ):
                if line_index in emitted:
                    continue
                emitted.add(line_index)
                marker = ":" if line_index == match_index else "-"
                print(
                    f"{ctx.display_ref(rel)}{marker}{line_index + 1}:"
                    f"{redactor.redact_path(rel)}:{redacted_lines[line_index]}"
                )
                results += 1
                if results >= args.max_results:
                    print("[TRUNCATED]")
                    return 0
    return 0 if results else 1


def command_stat(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    path = ctx.resolve_ref(args.path)
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")
    rel = rel_posix(path, ctx.root)
    print(f"id: {ctx.display_ref(rel)}")
    print(f"path: {redactor.redact_path(rel)}")
    print(f"type: {'directory' if path.is_dir() else 'file'}")
    print(f"size_bytes: {path.stat().st_size}")
    if path.is_file() and is_probably_text(path):
        print(f"lines: {len(read_text_file(ctx.validate_path(path, expected='text')).splitlines())}")
    return 0


def command_bundle(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    count = 0
    total_chars = 0
    for path in iter_target_files(ctx, args.paths, args.glob, budget=budget):
        if count >= args.max_files or total_chars >= args.max_total_chars:
            print("[TRUNCATED: file or total character limit reached]")
            return 0
        raw = read_text_file(ctx.validate_path(path, expected="text"), budget=budget)
        redacted = redactor.redact(raw)
        if len(redacted) > args.max_chars_per_file:
            redacted = redacted[: args.max_chars_per_file] + "\n[TRUNCATED FILE]\n"
        rel = rel_posix(path, ctx.root)
        print(f"\n--- BEGIN {ctx.display_ref(rel)} {redactor.redact_path(rel)} ---")
        print(redacted, end="" if redacted.endswith("\n") else "\n")
        print(f"--- END {ctx.display_ref(rel)} ---")
        total_chars += len(redacted)
        count += 1
    return 0


def build_rehydration_map(
    ctx: RedactedContext,
    redactor: Redactor,
    *,
    budget: OperationBudget | None = None,
) -> dict[str, str]:
    for path in ctx.walk(include_dirs=True, budget=budget):
        rel = rel_posix(path, ctx.root)
        redactor.redact_path(rel)
        ref = ctx.display_ref(rel)
        redactor.raw_aliases.setdefault(ref, rel)
        redactor.raw_aliases.setdefault(f"redctx://{ctx.path_id(rel)}", rel)
        if path.is_file() and is_probably_text(path):
            redactor.redact(read_text_file(ctx.validate_path(path, expected="text"), budget=budget))
    return redactor.rehydration_map()


def rehydrate_text(text: str, replacements: dict[str, str]) -> str:
    return rehydrate_text_with_count(text, replacements)[0]


def rehydrate_text_with_count(text: str, replacements: dict[str, str]) -> tuple[str, int]:
    replacement_count = 0
    for placeholder, value in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        count = text.count(placeholder)
        if count:
            replacement_count += count
            text = text.replace(placeholder, value)
    return text, replacement_count


OPAQUE_PATH_REF_RE = re.compile(r"(?:@|redctx://)p_[0-9a-f]{12}")


def unresolved_rehydration_tokens(text: str) -> list[str]:
    return sorted(set(PLACEHOLDER_RE.findall(text)) | set(OPAQUE_PATH_REF_RE.findall(text)))


def atomic_write_text(path: Path, text: str, *, overwrite: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise SystemExit("Output already exists.") from exc
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
            raise
        return

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def write_rehydrated_file(input_path: Path, output_path: Path, replacements: dict[str, str], *, force: bool) -> None:
    if output_path.is_symlink():
        raise SystemExit("Refusing to write through a symlink.")
    atomic_write_text(
        output_path,
        rehydrate_text(read_text_file(input_path), replacements),
        overwrite=force,
    )


def command_rehydrate(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    if not args.allow_raw_output:
        raise SystemExit("rehydrate emits private raw text; pass --allow-raw-output to continue.")
    input_path = Path(args.path).expanduser().resolve(strict=False)
    if not input_path.exists():
        raise SystemExit("Rehydrate input does not exist.")

    replacements = build_rehydration_map(ctx, redactor)
    output = Path(args.output).expanduser().resolve(strict=False) if args.output else None
    if input_path.is_file():
        if output is None:
            print(rehydrate_text(read_text_file(input_path), replacements), end="")
        else:
            write_rehydrated_file(input_path, output, replacements, force=args.force)
        return 0

    if output is None:
        raise SystemExit("--output is required when rehydrating a folder.")
    if output.exists() and not output.is_dir():
        raise SystemExit("--output must be a directory when rehydrating a folder.")
    try:
        output.relative_to(input_path)
    except ValueError:
        pass
    else:
        raise SystemExit("--output must not be inside the input folder.")

    count = 0
    for child in sorted(input_path.rglob("*")):
        if not child.is_file() or not is_probably_text(child):
            continue
        rel = child.relative_to(input_path)
        write_rehydrated_file(child, output / rel, replacements, force=args.force)
        count += 1
    print(f"Rehydrated {count} text file(s).")
    return 0


def command_doctor(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    config_path = args.config or (args.root / LOCAL_CONFIG)
    print("root: .")
    print(f"config_loaded: {config_path.exists()}")
    print(f"mode: {redactor.mode}")
    print(f"detector_profile: {redactor.config.detector_profile}")
    print(f"salt_source: {redactor.config.salt_source}")
    print(f"random_vault_salt: {str(redactor.config.salt_source == 'local-state').lower()}")
    print(f"clients: {len(redactor.config.clients)}")
    print(f"organizations: {len(redactor.config.organizations)}")
    print(f"people_terms: {len(redactor.config.people)}")
    print(f"other_terms: {len(redactor.config.terms)}")
    print(f"allow_terms: {len(redactor.allow_terms)}")
    print(f"excluded_dirs: {len(ctx.exclude_dirs)}")
    print(f"excluded_globs: {len(ctx.exclude_globs)}")
    return 0


def command_audit(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    checks = audit_checks(ctx, redactor, budget=operation_budget_from_args(args))
    if args.format == "json":
        print(json.dumps({"checks": checks}, indent=2, ensure_ascii=False))
    else:
        for check in checks:
            detail = f"  {check['detail']}" if check.get("detail") else ""
            print(f"{check['category']}: {check['name']} {check['status']}{detail}")
            refs = check.get("refs", [])
            if isinstance(refs, list):
                for ref in refs[:10]:
                    print(f"  - {ref}")
                if len(refs) > 10:
                    print(f"  - and {len(refs) - 10} more")
    return 1 if any(check["status"] == "FAIL" for check in checks) else 0


def audit_checks(
    ctx: RedactedContext,
    redactor: Redactor,
    *,
    budget: OperationBudget | None = None,
) -> list[dict[str, object]]:
    link_paths, broken_symlinks = ctx.scan_link_entries(budget=budget)
    symlink_refs = [
        f"{ctx.display_ref(rel_posix(path, ctx.root))} {redactor.redact_path(rel_posix(path, ctx.root))}"
        for path in link_paths
    ]

    explicit_counts = {
        "clients": len(redactor.config.explicit_clients),
        "organizations": len(redactor.config.explicit_organizations),
        "people_terms": len(redactor.config.explicit_people),
        "terms": len(redactor.config.explicit_terms),
        "root_terms": len(redactor.config.root_terms),
        "environment_terms": len(redactor.config.environment_terms),
    }
    private_term_count = (
        explicit_counts["clients"]
        + explicit_counts["organizations"]
        + explicit_counts["people_terms"]
        + explicit_counts["terms"]
        + explicit_counts["environment_terms"]
    )
    broad_allow = [term for term in redactor.config.allow if len(term.strip()) < 3 or "*" in term]
    synthetic_values = [
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD",
        "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
        "4111 1111 1111 1111",
        "10.12.30.4",
    ]
    synthetic_text = "\n".join(synthetic_values)
    synthetic_redactor = Redactor(redactor.config, mode=redactor.mode)
    synthetic_redacted = synthetic_redactor.redact(synthetic_text)
    leaked = [value for value in synthetic_values if value in synthetic_redacted]

    salt_status = "PASS" if redactor.config.salt_source == "local-state" else "WARN"

    return [
        {
            "category": "containment",
            "name": "symlink and reparse entries",
            "status": "FAIL" if symlink_refs else "PASS",
            "detail": f"{len(symlink_refs)} found",
            "refs": symlink_refs,
        },
        {
            "category": "containment",
            "name": "broken or looping symlinks",
            "status": "WARN" if broken_symlinks else "PASS",
            "detail": f"{broken_symlinks} found",
        },
        {
            "category": "configuration",
            "name": "random vault salt",
            "status": salt_status,
            "detail": redactor.config.salt_source,
        },
        {
            "category": "configuration",
            "name": "explicit private terms",
            "status": "PASS" if private_term_count else "WARN",
            "detail": json.dumps(explicit_counts, separators=(",", ":")),
        },
        {
            "category": "configuration",
            "name": "overly broad allow entries",
            "status": "WARN" if broad_allow else "PASS",
            "detail": f"{len(broad_allow)} candidates",
        },
        {
            "category": "redaction",
            "name": "synthetic leak suite",
            "status": "FAIL" if leaked else "PASS",
            "detail": f"{len(leaked)} raw values escaped",
        },
        {
            "category": "redaction",
            "name": "placeholder collisions",
            "status": "PASS",
            "detail": "collision detection enabled",
        },
        {
            "category": "redaction",
            "name": "global placeholder collision absence",
            "status": "NOT_TESTED",
            "detail": "collisions are detected when placeholders are generated",
        },
        {
            "category": "exposure",
            "name": "read-only default",
            "status": "PASS",
            "detail": "controlled writes require explicit MCP --enable-writes",
        },
    ]


def command_benchmark(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    start = time.perf_counter()
    dirs = 0
    files = 0
    text_files: list[Path] = []
    visible_bytes = 0
    for path in ctx.walk(include_dirs=True, budget=budget):
        if path.is_dir():
            dirs += 1
            continue
        files += 1
        visible_bytes += path.stat().st_size
        if is_probably_text(path):
            text_files.append(path)
    walk_seconds = time.perf_counter() - start

    text_characters = 0
    start = time.perf_counter()
    for path in text_files:
        text_characters += len(read_text_file(ctx.validate_path(path, expected="text"), budget=budget))
    read_seconds = time.perf_counter() - start

    query = args.query.casefold() if args.ignore_case else args.query
    matches = 0
    chunk_redactor = Redactor(redactor.config, mode=redactor.mode)
    redact_seconds = 0.0
    search_seconds = 0.0
    for path in text_files:
        text = read_text_file(ctx.validate_path(path, expected="text"))
        start = time.perf_counter()
        redacted = chunk_redactor.redact(text)
        redact_seconds += time.perf_counter() - start
        start = time.perf_counter()
        haystack = redacted.casefold() if args.ignore_case else redacted
        if query in haystack:
            matches += 1
        search_seconds += time.perf_counter() - start

    result = {
        "root": ".",
        "directories": dirs,
        "files": files,
        "text_files": len(text_files),
        "visible_bytes": visible_bytes,
        "text_characters": text_characters,
        "matches": matches,
        "timings_seconds": {
            "walk_and_text_detection": round(walk_seconds, 6),
            "read_all_text_files": round(read_seconds, 6),
            "redact_each_file_as_one_chunk": round(redact_seconds, 6),
            "search_redacted_text": round(search_seconds, 6),
        },
    }
    if args.format == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    print(f"root: {result['root']}")
    print(f"directories: {result['directories']}")
    print(f"files: {result['files']}")
    print(f"text_files: {result['text_files']}")
    print(f"visible_bytes: {result['visible_bytes']}")
    print(f"text_characters: {result['text_characters']}")
    print(f"matches: {result['matches']}")
    for name, seconds in result["timings_seconds"].items():
        print(f"{name}: {seconds:.6f}s")
    return 0


def command_discover(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    if args.provider != "ollama":
        raise SystemExit("Only the ollama discovery provider is currently supported.")
    client = OllamaDiscoveryClient(
        endpoint=args.endpoint,
        model=args.model,
        timeout=args.timeout,
        postprocess=not args.raw_discovery,
    )
    result = discover_entities(
        ctx,
        paths=args.paths,
        globs=args.glob,
        client=client,
        max_files=args.max_files,
        max_chars_per_file=args.max_chars_per_file,
        postprocess=not args.raw_discovery,
    )
    if args.format == "json":
        output = json.dumps(result.as_dict(), indent=2, ensure_ascii=False) + "\n"
    else:
        output = format_discovery_toml(
            result,
            source_note=f"provider=ollama model={args.model} root=.",
        )
    write_discovery_output(ctx, output, args.output, force=args.force)
    return 0


def command_github_repos(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    for alias in sorted(redactor.config.github_repos):
        print(alias)
    return 0


def command_github_issues(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    issues = github_list_issues(
        redactor.config,
        repo_alias=args.repo_alias,
        state=validate_github_state(args.state),
        labels=args.label,
        limit=validate_positive_limit(args.limit, "--limit"),
    )
    for issue in issues:
        print(format_github_issue_summary(args.repo_alias, issue, redactor))
    return 0 if issues else 1


def command_github_issue(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    issue = github_read_issue(
        redactor.config,
        repo_alias=args.repo_alias,
        number=args.number,
    )
    comments: list[dict[str, object]] = []
    max_comments = validate_nonnegative_limit(args.max_comments, "--max-comments")
    if args.comments and max_comments > 0:
        comments = github_read_issue_comments(
            redactor.config,
            repo_alias=args.repo_alias,
            number=args.number,
            limit=max_comments,
        )
    print(
        format_github_issue_detail(
            args.repo_alias,
            issue,
            comments,
            redactor,
            max_body_chars=validate_positive_limit(args.max_body_chars, "--max-body-chars"),
        ),
        end="",
    )
    return 0


def command_github_search(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    issues = github_search_issues(
        redactor.config,
        repo_alias=args.repo_alias,
        query=args.query,
        state=validate_github_state(args.state),
        limit=validate_positive_limit(args.limit, "--limit"),
    )
    for issue in issues:
        print(format_github_issue_summary(args.repo_alias, issue, redactor))
    return 0 if issues else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read local knowledgebase context through deterministic redaction.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="knowledgebase/context root")
    parser.add_argument("--config", type=Path, help=f"TOML config path, defaults to {LOCAL_CONFIG}")
    parser.add_argument(
        "--mode",
        choices=("balanced", "strict"),
        default="strict",
        help="redaction aggressiveness; strict also redacts unallowlisted proper tokens",
    )
    parser.add_argument(
        "--detector-profile",
        choices=("default", "extended"),
        help="detector set to use; extended adds more identifiers and prompt-injection markers",
    )
    parser.add_argument(
        "--include-private",
        action="store_true",
        help="include normally excluded private/cache paths",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ls_parser = subparsers.add_parser("ls", help="list files/directories with opaque ids")
    ls_parser.add_argument("path", nargs="?", default=".")
    ls_parser.add_argument("-r", "--recursive", action="store_true")
    ls_parser.add_argument("--max-depth", type=int)
    add_budget_arguments(ls_parser, include_files=False, include_bytes=False)
    ls_parser.set_defaults(func=command_ls)

    tree_parser = subparsers.add_parser("tree", help="show a redacted file tree")
    tree_parser.add_argument("path", nargs="?", default=".")
    tree_parser.add_argument("--max-depth", type=int, default=3)
    add_budget_arguments(tree_parser, include_files=False, include_bytes=False)
    tree_parser.set_defaults(func=command_tree)

    cat_parser = subparsers.add_parser("cat", aliases=["read"], help="print a redacted text file")
    cat_parser.add_argument("path")
    cat_parser.add_argument("--start-line", type=int)
    cat_parser.add_argument("--end-line", type=int)
    cat_parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    cat_parser.add_argument("-n", "--line-numbers", action="store_true")
    add_budget_arguments(cat_parser, include_files=False)
    cat_parser.set_defaults(func=command_cat)

    head_parser = subparsers.add_parser("head", help="print the first lines of a redacted text file")
    head_parser.add_argument("path")
    head_parser.add_argument("-n", "--lines", type=int, default=40)
    head_parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    head_parser.add_argument("--line-numbers", action="store_true")
    add_budget_arguments(head_parser, include_files=False)
    head_parser.set_defaults(func=command_head)

    tail_parser = subparsers.add_parser("tail", help="print the last lines of a redacted text file")
    tail_parser.add_argument("path")
    tail_parser.add_argument("-n", "--lines", type=int, default=40)
    tail_parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    tail_parser.add_argument("--line-numbers", action="store_true")
    add_budget_arguments(tail_parser, include_files=False)
    tail_parser.set_defaults(func=command_tail)

    grep_parser = subparsers.add_parser("grep", aliases=["search"], help="search redacted text")
    grep_parser.add_argument("query")
    grep_parser.add_argument("paths", nargs="*")
    grep_parser.add_argument("-i", "--ignore-case", action="store_true")
    grep_parser.add_argument("-E", "--regex", action="store_true")
    grep_parser.add_argument("-C", "--context", type=int, default=0)
    grep_parser.add_argument("--glob", action="append", default=[])
    grep_parser.add_argument("--max-results", type=int, default=DEFAULT_MAX_SEARCH_RESULTS)
    add_budget_arguments(grep_parser)
    grep_parser.set_defaults(func=command_grep)

    stat_parser = subparsers.add_parser("stat", help="show redacted path metadata")
    stat_parser.add_argument("path")
    stat_parser.set_defaults(func=command_stat)

    bundle_parser = subparsers.add_parser("bundle", help="concatenate redacted text files")
    bundle_parser.add_argument("paths", nargs="*")
    bundle_parser.add_argument("--glob", action="append", default=[])
    bundle_parser.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    bundle_parser.add_argument("--max-chars-per-file", type=int, default=30_000)
    bundle_parser.add_argument("--max-total-chars", type=int, default=300_000)
    add_budget_arguments(bundle_parser, include_files=False)
    bundle_parser.set_defaults(func=command_bundle)

    rehydrate_parser = subparsers.add_parser(
        "rehydrate",
        help="restore redacted text using the private source root",
    )
    rehydrate_parser.add_argument("path", help="redacted text file or folder to rehydrate")
    rehydrate_parser.add_argument("--output", help="write rehydrated output to a file or folder")
    rehydrate_parser.add_argument("--force", action="store_true", help="overwrite existing output files")
    rehydrate_parser.add_argument(
        "--allow-raw-output",
        action="store_true",
        help="acknowledge that this command writes or prints private raw text",
    )
    rehydrate_parser.set_defaults(func=command_rehydrate)

    doctor_parser = subparsers.add_parser("doctor", help="show redaction setup without printing terms")
    doctor_parser.set_defaults(func=command_doctor)

    audit_parser = subparsers.add_parser("audit", help="run safe local redaction and containment checks")
    audit_parser.add_argument("--format", choices=("text", "json"), default="text")
    add_budget_arguments(audit_parser, include_files=False, include_bytes=False)
    audit_parser.set_defaults(func=command_audit)

    benchmark_parser = subparsers.add_parser("benchmark", help="measure traversal, read, redaction, and search timing")
    benchmark_parser.add_argument("--query", default="__redctx_no_match_benchmark__")
    benchmark_parser.add_argument("--ignore-case", action=argparse.BooleanOptionalAction, default=True)
    benchmark_parser.add_argument("--format", choices=("text", "json"), default="text")
    add_budget_arguments(benchmark_parser)
    benchmark_parser.set_defaults(func=command_benchmark)

    discover_parser = subparsers.add_parser(
        "discover",
        help="use a local LLM to draft raw redaction terms for human review",
    )
    discover_parser.add_argument(
        "paths",
        nargs="*",
        help="paths to scan; empty scans the root",
    )
    discover_parser.add_argument("--provider", choices=("ollama",), default="ollama")
    discover_parser.add_argument("--endpoint", default=DEFAULT_OLLAMA_ENDPOINT)
    discover_parser.add_argument("--model", default=DEFAULT_DISCOVERY_MODEL)
    discover_parser.add_argument("--timeout", type=float, default=120.0)
    discover_parser.add_argument("--glob", action="append", default=[])
    discover_parser.add_argument("--max-files", type=int, default=DEFAULT_DISCOVERY_MAX_FILES)
    discover_parser.add_argument("--max-chars-per-file", type=int, default=DEFAULT_DISCOVERY_MAX_CHARS)
    discover_parser.add_argument("--format", choices=("toml", "json"), default="toml")
    discover_parser.add_argument(
        "--raw-discovery",
        action="store_true",
        help="skip category cleanup and emit the model's categories after basic dedupe",
    )
    discover_parser.add_argument(
        "--output",
        help=f"write output under the root, for example {LOCAL_CONFIG}",
    )
    discover_parser.add_argument("--force", action="store_true", help="overwrite --output if it exists")
    discover_parser.set_defaults(func=command_discover)

    github_parser = subparsers.add_parser(
        "github",
        aliases=["gh"],
        help="read GitHub issues through configured repo aliases and redaction",
    )
    github_subparsers = github_parser.add_subparsers(dest="github_command", required=True)

    github_repos_parser = github_subparsers.add_parser("repos", help="list configured GitHub repo aliases")
    github_repos_parser.set_defaults(func=command_github_repos)

    github_issues_parser = github_subparsers.add_parser("issues", help="list redacted GitHub issues")
    github_issues_parser.add_argument("repo_alias", help="configured GitHub repo alias, for example context")
    github_issues_parser.add_argument("--state", choices=("open", "closed", "all"), default="open")
    github_issues_parser.add_argument("--label", action="append", default=[], help="GitHub label filter")
    github_issues_parser.add_argument("--limit", type=int, default=30)
    github_issues_parser.set_defaults(func=command_github_issues)

    github_issue_parser = github_subparsers.add_parser("issue", help="read one redacted GitHub issue")
    github_issue_parser.add_argument("repo_alias", help="configured GitHub repo alias, for example context")
    github_issue_parser.add_argument("number", type=int)
    github_issue_parser.add_argument("--comments", action="store_true", help="include issue comments")
    github_issue_parser.add_argument("--max-comments", type=int, default=20)
    github_issue_parser.add_argument("--max-body-chars", type=int, default=30_000)
    github_issue_parser.set_defaults(func=command_github_issue)

    github_search_parser = github_subparsers.add_parser("search", help="search redacted GitHub issues")
    github_search_parser.add_argument("repo_alias", help="configured GitHub repo alias, for example context")
    github_search_parser.add_argument("query", help="GitHub issue search query")
    github_search_parser.add_argument("--state", choices=("open", "closed", "all"), default="open")
    github_search_parser.add_argument("--limit", type=int, default=30)
    github_search_parser.set_defaults(func=command_github_search)

    return parser


def add_budget_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_files: bool = True,
    include_bytes: bool = True,
) -> None:
    if include_files:
        parser.add_argument("--max-files", type=int, default=None, help="maximum input files to inspect")
    if include_bytes:
        parser.add_argument(
            "--max-raw-bytes-per-file",
            type=int,
            default=DEFAULT_MAX_RAW_BYTES_PER_FILE,
            help="maximum raw bytes allowed per input file",
        )
        parser.add_argument(
            "--max-total-raw-bytes",
            type=int,
            default=DEFAULT_MAX_TOTAL_RAW_BYTES,
            help="maximum total raw bytes allowed for the operation",
        )
    parser.add_argument(
        "--max-entries",
        type=int,
        default=DEFAULT_MAX_TRAVERSAL_ENTRIES,
        help="maximum traversal entries to inspect",
    )
    parser.add_argument("--max-seconds", type=float, help="soft operation deadline in seconds")


def configure_stdio_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")


def main(argv: list[str] | None = None) -> int:
    configure_stdio_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit("Root must be an existing directory.")
    config = load_config(root, args.config.expanduser().resolve() if args.config else None)
    if args.detector_profile:
        config = replace(config, detector_profile=args.detector_profile)
    ctx = RedactedContext(root, config, include_private=args.include_private)
    redactor = Redactor(config, mode=args.mode)
    return args.func(args, ctx, redactor)


if __name__ == "__main__":
    raise SystemExit(main())
