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
from collections.abc import Mapping
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
    with_protected_paths,
)
from .defaults import (
    ALIAS_FORM_SEPARATOR,
    DEFAULT_DISCOVERY_MAX_CHARS,
    DEFAULT_DISCOVERY_MAX_FILES,
    DEFAULT_DISCOVERY_MAX_MESSAGES,
    DEFAULT_DISCOVERY_MODEL,
    DEFAULT_MAX_CHARS,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_RAW_BYTES_PER_FILE,
    DEFAULT_MAX_RESOURCE_BYTES,
    DEFAULT_MAX_SEARCH_RESULTS,
    DEFAULT_MCP_SEARCH_SECONDS,
    DEFAULT_MAX_TOTAL_RAW_BYTES,
    DEFAULT_REGEX_MATCH_SECONDS,
    DEFAULT_MAX_TRAVERSAL_ENTRIES,
    DEFAULT_OLLAMA_ENDPOINT,
    GENERIC_PROBE_STOPWORDS,
    LOCAL_CONFIG,
    PLACEHOLDER_CATEGORIES,
    PLACEHOLDER_RE,
    REPO_ROOT,
)
from .detectors import (
    Detector,
    DetectorError,
    Span,
    detector_protected_paths,
    load_detectors,
)
from .discovery import (
    DetectorDiscoveryClient,
    MailSample,
    OllamaDiscoveryClient,
    build_discovery_update,
    build_discovery_prompt,
    build_strict_discovery_prompt,
    clean_discovered_terms,
    config_people,
    discover_documents,
    discover_entities,
    discover_mail_entities,
    extract_ollama_error,
    filter_discovery_to_source,
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
    mail_document_label,
    mail_header_aliases,
    merge_discovery_toml,
    merge_discovery_results,
    normalize_discovery_value,
    normalize_person_name,
    parse_discovery_documents_jsonl,
    parse_discovery_response,
    parse_json_object,
    postprocess_discovery_result,
    propose_alias_groups,
    resolve_discovery_output,
    sample_mail,
    should_drop_discovered_value,
    with_header_people,
    write_discovery_update,
    write_discovery_output,
)
from .filesystem import (
    RedactedContext,
    is_probably_text,
    is_probably_text_bytes,
    is_reparse_point,
    iter_target_files,
    read_file_bytes_verified,
    read_text_file,
)
from .limits import OperationBudget, OperationLimitError
from .github import (
    GitHubSource,
    count_github_assignees,
    default_ssl_paths_have_certs,
    extract_github_error,
    format_github_url_error,
    get_github_repo_config,
    github_api_request,
    github_list_issues,
    github_read_issue,
    github_read_issue_comments,
    github_search_issues,
    github_ssl_context,
    opaque_github_user,
    validate_github_state,
    validate_nonnegative_limit,
    validate_positive_limit,
)
from .models import (
    DETECTOR_CATEGORY_MESSAGE,
    DETECTOR_FAILED_MESSAGE,
    DETECTOR_LIMIT_MESSAGE,
    DETECTOR_SPAN_MESSAGE,
    DOCUMENTS_UNSUPPORTED_MESSAGE,
    UNKNOWN_REFERENCE_MESSAGE,
    WRITE_TARGET_PROTECTED_MESSAGE,
    DiscoveryDocument,
    DiscoveryParseError,
    DiscoveryResult,
    DiscoveryUpdate,
    GitHubRepoConfig,
    RedactionConfig,
)
from .paths import display_ref, path_id, rel_posix, resolve_under_root
from .redaction import Redactor, compile_literal_pattern, normalize_alias, placeholder_digest
from .regex_safety import (
    QUANTIFIER_REPETITION_FLOOR,
    UNSAFE_REGEX_MESSAGE,
    _alternation_overlap,
    _branch_first_chars,
    _regex_quantifier_at,
    _regex_match_worker,
    _split_top_level_alternation,
    match_regex_lines,
    regex_backtracking_violation,
)
from .mail import (
    GLOB_MESSAGE,
    MAIL_FORMATS,
    MAIL_LIST_MAX_LIMIT,
    MAIL_MAX_NESTED_DEPTH,
    MAIL_SAFE_MESSAGES,
    MAIL_THREAD_MAX_MESSAGES,
    UNKNOWN_MAILBOX_MESSAGE,
    MailSource,
)
from .rendering import (
    MAIL_RETRIEVE_MAX_MESSAGES,
    MAIL_RETRIEVE_MAX_TOTAL_BYTES,
    MailRedactorCache,
    github_issue_detail_text,
    github_issue_list_text,
    github_issue_search_text,
    github_repos_text,
    mail_attachment_text,
    mail_list_text,
    mail_read_text,
    mail_retrieve_text,
    mail_sources_text,
    mail_thread_text,
    require_mail_source,
    truncate_redacted,
    truncate_text,
)
from .retrieval import retrieve
from .sources import SourceRegistry, build_sources
from .documents import DOCUMENT_EXTENSIONS


HEX_QUERY_RE = re.compile(r"[0-9a-fA-F]+")
# Hex digits around one alias-form separator may be a fragment of a linked
# placeholder (`<entity>.<form>`), which exists only in redacted text.
LINKED_HEX_QUERY_RE = re.compile(rf"[0-9a-fA-F]*{re.escape(ALIAS_FORM_SEPARATOR)}[0-9a-fA-F]*")
PLACEHOLDER_STRUCTURAL_CHARS = frozenset("[]_")


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
    stripped = query.strip()
    if regex or not stripped:
        return False
    if any(char in PLACEHOLDER_STRUCTURAL_CHARS for char in stripped):
        return False
    if HEX_QUERY_RE.fullmatch(stripped) or LINKED_HEX_QUERY_RE.fullmatch(stripped):
        return False
    if ignore_case:
        folded = stripped.casefold()
        return not any(folded in category.casefold() for category in PLACEHOLDER_CATEGORIES)
    return not any(stripped in category for category in PLACEHOLDER_CATEGORIES)


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
    text = ctx.read_text(path, budget=budget)
    lines = redactor.redact(text, preserve_line_count=True).splitlines(keepends=True)
    start = max(args.start_line or 1, 1)
    end = args.end_line or len(lines)
    if end < start:
        if args.end_line:
            raise SystemExit("--end-line must be greater than or equal to --start-line.")
        raise SystemExit("--start-line is beyond the end of the file.")
    selected = "".join(lines[start - 1 : end])
    redacted = selected
    redacted = truncate_redacted(redacted, args.max_chars)

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
    budget = operation_budget_from_args(args)
    path = ctx.resolve_ref(args.path, expected="text")
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")
    path = ctx.validate_path(path, expected="text")
    text = ctx.read_text(path, budget=budget)
    all_lines = redactor.redact(text, preserve_line_count=True).splitlines(keepends=True)
    start = max(1, len(all_lines) - args.lines + 1)
    selected = "".join(all_lines[start - 1 :])
    redacted = selected
    redacted = truncate_redacted(redacted, args.max_chars or DEFAULT_MAX_CHARS)
    rel = rel_posix(path, ctx.root)
    print(f"--- {ctx.display_ref(rel)} {redactor.redact_path(rel)} lines {start}-{len(all_lines)} ---")
    if args.line_numbers:
        for offset, line in enumerate(redacted.splitlines(), start=start):
            print(f"{offset:>6}\t{line}")
    else:
        print(redacted, end="" if redacted.endswith("\n") else "\n")
    return 0


def command_grep(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    flags = re.IGNORECASE if args.ignore_case else 0
    matcher: re.Pattern[str] | None = None
    query = args.query
    if args.regex:
        if regex_backtracking_violation(query) is not None:
            raise SystemExit(UNSAFE_REGEX_MESSAGE)
        try:
            matcher = re.compile(query, flags)
        except re.error as exc:
            raise SystemExit("Invalid regex.") from exc
    elif args.ignore_case:
        query = query.casefold()

    use_prefilter = can_use_raw_search_prefilter(args.query, regex=args.regex, ignore_case=args.ignore_case)
    results = 0
    if matcher is not None:
        return _grep_regex(args, ctx, redactor, budget)
    for path in iter_target_files(ctx, args.paths, args.glob, budget=budget, text_only=not use_prefilter):
        budget.check_deadline()
        if use_prefilter and not ctx.is_document(path):
            path = ctx.validate_path(path, expected="file")
            raw_bytes = read_file_bytes_verified(path, budget=budget)
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
            raw = ctx.read_text(path, budget=budget)
        redacted_lines = redactor.redact(raw, preserve_line_count=True).splitlines()
        matches: list[int] = []
        for index, line in enumerate(redacted_lines):
            budget.check_deadline()
            haystack = line if args.regex or not args.ignore_case else line.casefold()
            found = query in haystack
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


def _grep_regex(
    args: argparse.Namespace,
    ctx: RedactedContext,
    redactor: Redactor,
    budget: OperationBudget,
) -> int:
    files: list[tuple[str, list[str]]] = []
    for path in iter_target_files(ctx, args.paths, args.glob, budget=budget, text_only=True):
        budget.check_deadline()
        path = ctx.validate_path(path, expected="text")
        raw = ctx.read_text(path, budget=budget)
        redacted_lines = redactor.redact(raw, preserve_line_count=True).splitlines()
        files.append((rel_posix(path, ctx.root), redacted_lines))

    if budget.deadline is not None:
        timeout = max(0.001, budget.deadline - time.monotonic())
    else:
        timeout = DEFAULT_REGEX_MATCH_SECONDS
    flags = re.IGNORECASE if args.ignore_case else 0
    matched = match_regex_lines(args.query, flags, [lines for _, lines in files], timeout)

    results = 0
    for (rel, redacted_lines), indices in zip(files, matched):
        if not indices:
            continue
        emitted: set[int] = set()
        for match_index in indices:
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
    budget = operation_budget_from_args(args)
    path = ctx.resolve_ref(args.path)
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")
    path = ctx.validate_path(path)
    rel = rel_posix(path, ctx.root)
    print(f"id: {ctx.display_ref(rel)}")
    print(f"path: {redactor.redact_path(rel)}")
    print(f"type: {'directory' if path.is_dir() else 'file'}")
    print(f"size_bytes: {path.stat().st_size}")
    if path.is_file() and is_probably_text(path):
        budget.consume_file(path)
        print(f"lines: {count_text_lines(path)}")
    return 0

def command_retrieve(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    if getattr(args, "source", "filesystem") == "mail":
        # Mail has its own message, byte, and deadline budget; the filesystem
        # file and byte limits do not apply.
        print(mail_retrieve_text(
            mail_source_from_args(args, redactor),
            redactor, args.query, paths=args.paths, globs=args.glob,
            max_results=args.max_results, max_chars=args.max_chars, seconds=getattr(args, "max_seconds", None),
        ), end="")
        return 0
    print(retrieve(
        ctx, redactor, args.query, paths=args.paths, globs=args.glob,
        budget=operation_budget_from_args(args), max_results=args.max_results, max_chars=args.max_chars,
    ), end="")
    return 0


def count_text_lines(path: Path) -> int:
    lines = 0
    saw_any = False
    ends_with_newline = False
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 64)
            if not chunk:
                break
            saw_any = True
            lines += chunk.count(b"\n")
            ends_with_newline = chunk.endswith(b"\n")
    if saw_any and not ends_with_newline:
        lines += 1
    return lines


def command_bundle(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    budget = operation_budget_from_args(args)
    count = 0
    total_chars = 0
    for path in iter_target_files(ctx, args.paths, args.glob, budget=budget):
        if count >= args.max_files or total_chars >= args.max_total_chars:
            print("[TRUNCATED: file or total character limit reached]")
            return 0
        raw = ctx.read_text(path, budget=budget)
        redacted = redactor.redact(raw)
        redacted = truncate_redacted(redacted, args.max_chars_per_file)
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
    exclude_roots: tuple[Path, ...] = (),
) -> dict[str, str]:
    """Build a rehydration map solely from the scanned source corpus.

    The redactor's persistent alias table is swapped out for the duration of
    the walk so aliases created by earlier interactive reads (for example of
    write-subdirectory files) cannot leak into the map, and agent-written
    content under ``exclude_roots`` cannot extend or poison rehydration.
    """
    original_aliases = redactor.raw_aliases
    redactor.raw_aliases = {}
    try:
        for path in ctx.walk(
            include_dirs=True,
            budget=budget,
            prune_roots=exclude_roots,
        ):
            rel = rel_posix(path, ctx.root)
            redactor.redact_path(rel)
            ref = ctx.display_ref(rel)
            redactor.raw_aliases.setdefault(ref, rel)
            redactor.raw_aliases.setdefault(f"redctx://{ctx.path_id(rel)}", rel)
            if path.is_file() and ctx.is_readable(path):
                redactor.redact(ctx.read_text(path, budget=budget))
        return dict(redactor.raw_aliases)
    finally:
        redactor.raw_aliases = original_aliases


def applied_rehydration_values(text: str, replacements: Mapping[str, str]) -> tuple[list[str], list[str]]:
    """Return raw values a rehydration pass would substitute into text.

    The first list holds values sourced from redaction placeholders (sensitive
    content values); the second holds values sourced from opaque path
    references (relative paths).
    """
    placeholder_values: list[str] = []
    path_values: list[str] = []
    for token in set(PLACEHOLDER_RE.findall(text)):
        value = replacements.get(token)
        if value is not None:
            placeholder_values.append(value)
    for token in set(OPAQUE_PATH_REF_RE.findall(text)):
        value = replacements.get(token)
        if value is not None:
            path_values.append(value)
    return placeholder_values, path_values


def rehydrate_text(text: str, replacements: dict[str, str]) -> str:
    return rehydrate_text_with_count(text, replacements)[0]


OPAQUE_PATH_REF_RE = re.compile(r"(?:@|redctx://)p_[0-9a-f]{12}")
REHYDRATION_TOKEN_RE = re.compile(rf"(?:{PLACEHOLDER_RE.pattern}|{OPAQUE_PATH_REF_RE.pattern})")


def rehydrate_text_with_count(text: str, replacements: Mapping[str, str]) -> tuple[str, int]:
    replacement_count = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal replacement_count
        token = match.group(0)
        replacement = replacements.get(token)
        if replacement is None:
            return token
        replacement_count += 1
        return replacement

    return REHYDRATION_TOKEN_RE.sub(replace, text), replacement_count


def unresolved_rehydration_tokens(text: str) -> list[str]:
    return sorted(set(PLACEHOLDER_RE.findall(text)) | set(OPAQUE_PATH_REF_RE.findall(text)))


def atomic_write_text(path: Path, text: str, *, overwrite: bool = True) -> None:
    """Write ``text`` to ``path`` through a temporary file in the same directory.

    The temporary file is removed on every failure. Its name never contains
    ``:``, so on Windows it cannot become an alternate data stream of a
    stray base file. A failed publication raises the input-free
    ``Could not publish output atomically.``.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_prefix = f".{path.name.replace(':', '_')}."
    if not overwrite:
        fd, tmp_name = tempfile.mkstemp(
            prefix=tmp_prefix,
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
            try:
                os.link(tmp_path, path)
            except FileExistsError as exc:
                raise SystemExit("Output already exists.") from exc
            except OSError as exc:
                raise SystemExit("Could not publish output atomically.") from exc
            fsync_directory(path.parent)
        except Exception:
            raise
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass
        return

    fd, tmp_name = tempfile.mkstemp(
        prefix=tmp_prefix,
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
        try:
            os.replace(tmp_path, path)
        except OSError as exc:
            raise SystemExit("Could not publish output atomically.") from exc
        fsync_directory(path.parent)
    except BaseException:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


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
    print(f"alias_groups: {len(redactor.config.alias_groups)}")
    print(f"aliases: {sum(len(group.aliases) for group in redactor.config.alias_groups)}")
    print(f"allow_terms: {len(redactor.allow_terms)}")
    print(f"excluded_dirs: {len(ctx.exclude_dirs)}")
    print(f"excluded_globs: {len(ctx.exclude_globs)}")
    # Counts only: mailbox aliases and paths are never printed here.
    mailboxes = list(redactor.config.mail_sources.values())
    print(f"mail_sources: {len(mailboxes)}")
    for mail_format in MAIL_FORMATS:
        print(f"mail_sources_{mail_format}: {sum(1 for mailbox in mailboxes if mailbox.format == mail_format)}")
    if redactor.detectors:
        # Names and versions only: detector arguments may be private paths.
        listed = ", ".join(f"{detector.name} {detector.version}" for detector in redactor.detectors)
        print(f"detectors: {listed}")
    return 0


def command_audit(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    checks = audit_checks(
        ctx,
        redactor,
        budget=operation_budget_from_args(args),
        writes_enabled=getattr(args, "writes_enabled", False),
        write_subdir_confined=getattr(args, "write_subdir_confined", True),
    )
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
    writes_enabled: bool = False,
    write_subdir_confined: bool = True,
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
    synthetic_redactor = Redactor(redactor.config, mode=redactor.mode, detectors=redactor.detectors)
    synthetic_redacted = synthetic_redactor.redact(synthetic_text)
    leaked = [value for value in synthetic_values if value in synthetic_redacted]

    salt_status = "PASS" if redactor.config.salt_source == "local-state" else "WARN"

    checks: list[dict[str, object]] = [
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
        {
            "category": "exposure",
            "name": "controlled writes currently enabled" if writes_enabled else "controlled writes currently disabled",
            "status": "WARN" if writes_enabled else "PASS",
            "detail": "enabled by current MCP server" if writes_enabled else "disabled",
        },
        {
            "category": "exposure",
            "name": "write subdirectory confinement",
            "status": "PASS" if write_subdir_confined else "FAIL",
            "detail": "raw write path not reported",
        },
    ]
    # Keep the configuration checks together: right after the allow-list
    # check (or at the end if that check is ever renamed).
    anchor = next(
        (index + 1 for index, check in enumerate(checks) if check["name"] == "overly broad allow entries"),
        len(checks),
    )
    if redactor.config.alias_groups:
        groups = redactor.config.alias_groups
        unlinked = unlinked_alias_forms(redactor)
        checks.insert(
            anchor,
            {
                "category": "configuration",
                "name": "alias groups",
                "status": "WARN" if unlinked else "PASS",
                "detail": (
                    f"{len(groups)} groups, {sum(len(group.aliases) for group in groups)} aliases, "
                    f"{unlinked} forms not redacted as one linked placeholder on their own"
                ),
            },
        )
        anchor += 1
    if redactor.detectors:
        checks.insert(
            anchor,
            {
                "category": "configuration",
                "name": "plugged detectors",
                "status": "PASS",
                "detail": f"{len(redactor.detectors)} active in addition to the built-in baseline",
            },
        )
    return checks


def unlinked_alias_forms(redactor: Redactor) -> int:
    """Count alias-group forms that do not redact, standing alone, as one linked placeholder.

    Each canonical value must become its ordinary placeholder in the group's
    category and each alias one placeholder carrying the group's entity hex.
    A form a built-in stage only partly claims (for example a canonical value
    that an extended-profile detector matches) is counted. The probe uses the
    built-in baseline only and reports a count, never a value.
    """
    probe = Redactor(redactor.config, mode=redactor.mode)
    unlinked = 0
    for group in redactor.config.alias_groups:
        entity = placeholder_digest(redactor.config.salt, group.category, normalize_alias(group.canonical))
        if probe.redact(group.canonical) != f"[{group.category}_{entity}]":
            unlinked += 1
        for alias in group.aliases:
            redacted = probe.redact(alias)
            if not PLACEHOLDER_RE.fullmatch(redacted) or f"_{entity}{ALIAS_FORM_SEPARATOR}" not in redacted:
                unlinked += 1
    return unlinked


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
        if ctx.is_readable(path):
            text_files.append(path)
    walk_seconds = time.perf_counter() - start

    text_characters = 0
    start = time.perf_counter()
    for path in text_files:
        text_characters += len(ctx.read_text(path, budget=budget))
    read_seconds = time.perf_counter() - start

    query = args.query.casefold() if args.ignore_case else args.query
    matches = 0
    chunk_redactor = Redactor(redactor.config, mode=redactor.mode, detectors=redactor.detectors)
    redact_seconds = 0.0
    search_seconds = 0.0
    redaction_read_bytes = 0
    for path in text_files:
        text = ctx.read_text(path)
        redaction_read_bytes += path.stat().st_size
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
        "redaction_read_bytes": redaction_read_bytes,
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
    print(f"redaction_read_bytes: {result['redaction_read_bytes']}")
    print(f"matches: {result['matches']}")
    for name, seconds in result["timings_seconds"].items():
        print(f"{name}: {seconds:.6f}s")
    return 0


def discovery_detectors(args: argparse.Namespace) -> tuple[Detector, ...]:
    """Detectors selected by the ``discover``/``discover-update`` subcommand's own ``--detector``.

    The global ``--detector`` configures serving and never switches discovery
    away from Ollama. Combining the subcommand ``--detector`` with an explicit
    ``--model`` or ``--endpoint`` is an error, because those only apply to
    Ollama discovery.
    """
    loaded = getattr(args, "loaded_discovery_detectors", None)
    detectors = tuple(loaded) if loaded is not None else load_detectors(getattr(args, "subcommand_detector", None) or [])
    if detectors and (getattr(args, "model", None) is not None or getattr(args, "endpoint", None) is not None):
        raise SystemExit(
            "--model and --endpoint apply only to Ollama discovery; "
            "remove them when drafting terms with --detector."
        )
    return detectors


def ollama_model(args: argparse.Namespace) -> str:
    return args.model if getattr(args, "model", None) is not None else DEFAULT_DISCOVERY_MODEL


def ollama_endpoint(args: argparse.Namespace) -> str:
    return args.endpoint if getattr(args, "endpoint", None) is not None else DEFAULT_OLLAMA_ENDPOINT


def mail_discovery_source(args: argparse.Namespace, config: RedactionConfig) -> MailSource:
    """The mail source for ``discover``/``discover-update --source mail``.

    Validated exactly like ``retrieve --source mail``: ``--glob`` is refused,
    and positional paths must be configured mailbox aliases or ``@m_`` refs.
    With no mailbox configured every alias is unknown.
    """
    if getattr(args, "glob", None):
        raise SystemExit(GLOB_MESSAGE)
    source = require_mail_source(
        MailSource.from_config(config, documents=getattr(args, "documents", False)),
        UNKNOWN_MAILBOX_MESSAGE,
    )
    for item in getattr(args, "paths", None) or []:
        if not isinstance(item, str) or not (item in source.config.mail_sources or item.startswith("@m_")):
            raise SystemExit(UNKNOWN_MAILBOX_MESSAGE)
    return source


def discovery_total_raw_bytes(args: argparse.Namespace, default: int) -> int:
    """``--max-total-raw-bytes``, or ``default`` when it is not given.

    The default depends on the source: the files budget for files, the mail
    retrieval budget for mail.
    """
    value = getattr(args, "max_total_raw_bytes", None)
    return default if value is None else value


def mail_discovery_documents(
    args: argparse.Namespace, ctx: RedactedContext
) -> tuple[MailSample, tuple[DiscoveryDocument, ...]]:
    """The mail sample and model inputs of ``discover-update --source mail``.

    Messages are read under the mail budget and never truncated: one over
    ``--max-chars-per-document`` is skipped whole and counted, like one
    dated more than a day ahead or one over its mailbox's
    ``max_message_bytes``. Reaching ``--max-total-raw-bytes`` stops sampling.
    """
    sample = sample_mail(
        mail_discovery_source(args, ctx.config),
        scope=list(args.paths),
        max_messages=getattr(args, "max_messages", DEFAULT_DISCOVERY_MAX_MESSAGES),
        max_total_raw_bytes=discovery_total_raw_bytes(args, MAIL_RETRIEVE_MAX_TOTAL_BYTES),
        max_chars=args.max_chars_per_document,
    )
    documents = tuple(
        DiscoveryDocument(path=mail_document_label(document), text=document.text) for document in sample.documents
    )
    return sample, documents


def command_discover(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    detectors = discovery_detectors(args)
    if getattr(args, "output", None) is not None:
        # Refuse a protected target before any model call, not after.
        resolve_discovery_output(ctx, args.output)
    mail = None
    if getattr(args, "source", "filesystem") == "mail":
        mail = mail_discovery_source(args, redactor.config)
    client: OllamaDiscoveryClient | DetectorDiscoveryClient
    if detectors:
        # Local detectors replace the Ollama model; no network call is made.
        client = DetectorDiscoveryClient(*detectors, postprocess=not args.raw_discovery)
        provider_note = f"provider=detector detectors={','.join(detector.name for detector in detectors)}"
    else:
        if args.provider != "ollama":
            raise SystemExit("Only the ollama discovery provider is currently supported.")
        model = ollama_model(args)
        client = OllamaDiscoveryClient(
            endpoint=ollama_endpoint(args),
            model=model,
            timeout=args.timeout,
            postprocess=not args.raw_discovery,
            allow_remote=getattr(args, "allow_remote_endpoint", False),
        )
        provider_note = f"provider=ollama model={model}"
    if mail is not None:
        return command_discover_mail(args, ctx, redactor, mail, client, provider_note)
    source_note = f"{provider_note} root=."
    result = discover_entities(
        ctx,
        paths=args.paths,
        globs=args.glob,
        client=client,
        max_files=args.max_files,
        max_chars_per_file=args.max_chars_per_file,
        max_total_raw_bytes=discovery_total_raw_bytes(args, DEFAULT_MAX_TOTAL_RAW_BYTES),
        postprocess=not args.raw_discovery,
        fail_on_truncation=getattr(args, "fail_on_truncation", False),
        # Raw discovery keeps the model's own alias suggestions (still
        # source-checked and validated) but skips the deterministic ones.
        propose_aliases=not args.raw_discovery,
        known_people=redactor.config.explicit_people if redactor is not None else (),
    )
    if args.format == "json":
        payload: dict[str, object] = dict(result.as_dict())
        payload["aliases"] = {canonical: list(aliases) for canonical, aliases in result.aliases}
        payload["dropped_alias_proposals"] = result.dropped_aliases
        output = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    else:
        output = format_discovery_toml(
            result,
            source_note=source_note,
        )
    write_discovery_output(ctx, output, args.output, force=args.force)
    return 0


def command_discover_mail(
    args: argparse.Namespace,
    ctx: RedactedContext,
    redactor: Redactor,
    source: MailSource,
    client: OllamaDiscoveryClient | DetectorDiscoveryClient,
    provider_note: str,
) -> int:
    """``discover --source mail``: draft terms from the newest messages of the scope.

    ``--max-files`` does not apply; ``--max-messages`` caps the messages
    read and classified, and ``--max-total-raw-bytes`` defaults to the mail
    retrieval budget. The source note names no mailbox path; it counts the
    messages read and skipped, and says when the byte budget stopped
    sampling.
    """
    discovery = discover_mail_entities(
        source,
        scope=list(args.paths),
        client=client,
        max_messages=getattr(args, "max_messages", DEFAULT_DISCOVERY_MAX_MESSAGES),
        max_chars_per_message=args.max_chars_per_file,
        max_total_raw_bytes=discovery_total_raw_bytes(args, MAIL_RETRIEVE_MAX_TOTAL_BYTES),
        postprocess=not args.raw_discovery,
        fail_on_truncation=getattr(args, "fail_on_truncation", False),
        # As for files: raw discovery skips the deterministic proposals,
        # including the mail header step.
        propose_aliases=not args.raw_discovery,
        known_people=redactor.config.explicit_people,
    )
    result = discovery.result
    if args.format == "json":
        payload: dict[str, object] = dict(result.as_dict())
        payload["aliases"] = {canonical: list(aliases) for canonical, aliases in result.aliases}
        payload["dropped_alias_proposals"] = result.dropped_aliases
        payload["header_aliases"] = {canonical: list(aliases) for canonical, aliases in discovery.header_aliases}
        payload["messages"] = discovery.messages
        payload["skipped_messages"] = discovery.skipped
        payload["byte_cap_reached"] = discovery.byte_cap_reached
        output = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    else:
        source_note = f"{provider_note} source=mail messages={discovery.messages} skipped={discovery.skipped}"
        if discovery.byte_cap_reached:
            source_note += " byte_cap=reached"
        output = format_discovery_toml(result, source_note=source_note, header_aliases=discovery.header_aliases)
    write_discovery_output(ctx, output, args.output, force=args.force)
    return 0


def command_discover_update(
    args: argparse.Namespace,
    ctx: RedactedContext,
    redactor: Redactor | None,
) -> int:
    del redactor
    detectors = discovery_detectors(args)
    from_mail = getattr(args, "source", "filesystem") == "mail"
    sample: MailSample | None = None
    try:
        if from_mail and args.input_jsonl:
            raise ValueError("--source mail cannot be combined with --input-jsonl.")
        if from_mail and args.merge_only:
            raise ValueError("--source mail cannot be combined with --merge-only.")
        if not from_mail and getattr(args, "paths", None):
            raise ValueError("Mailbox aliases and @m_ refs are accepted only with --source mail.")
        if args.merge_only and args.input_jsonl:
            raise ValueError("--merge-only cannot be combined with --input-jsonl.")
        documents: tuple[DiscoveryDocument, ...]
        if from_mail:
            sample, documents = mail_discovery_documents(args, ctx)
        elif args.merge_only:
            documents = ()
        else:
            if not args.input_jsonl:
                raise ValueError("--input-jsonl is required unless --merge-only is used.")
            if args.input_jsonl == "-":
                raw_input = sys.stdin.read()
            else:
                raw_input = Path(args.input_jsonl).expanduser().read_text(encoding="utf-8")
            documents = parse_discovery_documents_jsonl(raw_input)
        if not documents and not args.merge_only:
            raise ValueError("Discovery input contains no documents.")
        if not from_mail and len(documents) > args.max_files:
            raise ValueError(f"Discovery input exceeds --max-files={args.max_files}.")
        oversized = next(
            (
                document
                for document in documents
                if len(document.text) > args.max_chars_per_document
            ),
            None,
        )
        if oversized is not None:
            raise ValueError(
                f"{oversized.path} exceeds "
                f"--max-chars-per-document={args.max_chars_per_document}; "
                "refusing to classify a partial model input."
            )
        total_characters = sum(len(document.text) for document in documents)
        if total_characters > args.max_total_chars:
            raise ValueError(
                f"Discovery input exceeds --max-total-chars={args.max_total_chars}."
            )

        config_path = resolve_under_root(
            ctx.root,
            args.output_config or LOCAL_CONFIG,
            allow_missing=True,
        )
        existing_text = (
            config_path.read_text(encoding="utf-8-sig") if config_path.exists() else ""
        )
        seed_text = None
        if args.seed_config:
            seed_path = resolve_under_root(ctx.root, args.seed_config)
            seed_text = seed_path.read_text(encoding="utf-8-sig")
        # Discovered alias groups are merged only on explicit request: a
        # wrong link would tell the agent that two people are one.
        include_aliases = getattr(args, "include_discovered_aliases", False)
        alias_people = config_people(seed_text, existing_text) if include_aliases else ()
        header_people: tuple[str, ...] = ()
        if sample is not None:
            # From names of the same messages. Their alias groups are for a
            # reviewed draft only (discover) and are never merged here.
            header_people = mail_header_aliases(sample.identities)[0]
            if include_aliases:
                alias_people = (*alias_people, *header_people)

        if documents and detectors:
            # Local detectors replace the Ollama model; no network call is made.
            result = discover_documents(
                documents,
                client=DetectorDiscoveryClient(*detectors, postprocess=True),
                postprocess=True,
                propose_aliases=include_aliases,
                alias_people=alias_people,
            )
        elif documents:
            client = OllamaDiscoveryClient(
                endpoint=ollama_endpoint(args),
                model=ollama_model(args),
                timeout=args.timeout,
                postprocess=True,
                allow_remote=getattr(args, "allow_remote_endpoint", False),
            )
            result = discover_documents(
                documents,
                client=client,
                postprocess=True,
                propose_aliases=include_aliases,
                alias_people=alias_people,
            )
        else:
            result = DiscoveryResult()
        if sample is not None:
            # Header names join the discovered people whatever the model
            # allowed; --include-discovered-allow never un-redacts them.
            result = with_header_people(result, header_people)
        update = build_discovery_update(
            existing_text,
            result,
            seed_text=seed_text,
            include_discovered_allow=args.include_discovered_allow,
            include_discovered_aliases=include_aliases,
        )
    except (OSError, ValueError, OperationLimitError) as exc:
        raise SystemExit(str(exc)) from exc

    if args.dry_run:
        print(update.config_text, end="" if update.config_text.endswith("\n") else "\n")
        return 0
    if args.check:
        print(f"config_current: {str(not update.changed).lower()}")
        return 1 if update.changed else 0

    write_discovery_update(config_path, update)
    counts = {key: len(values) for key, values in result.as_dict().items() if key != "allow"}
    print(f"documents: {len(documents)}")
    if sample is not None:
        print(f"skipped_messages: {sample.skipped}")
        print(f"byte_cap_reached: {str(sample.byte_cap_reached).lower()}")
    if detectors:
        print("model: skipped")
        print(f"detectors: {','.join(detector.name for detector in detectors)}")
    else:
        print(f"model: {ollama_model(args) if documents else 'skipped'}")
    print(f"discovered_counts: {json.dumps(counts, sort_keys=True, separators=(',', ':'))}")
    print(f"alias_counts: {json.dumps(update.alias_counts, sort_keys=True, separators=(',', ':'))}")
    print(f"config_changed: {str(update.changed).lower()}")
    return 0


def command_github_repos(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    print(github_repos_text(GitHubSource.from_config(redactor.config)), end="")
    return 0


def command_github_issues(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    text = github_issue_list_text(
        GitHubSource.from_config(redactor.config),
        redactor,
        repo_alias=args.repo_alias,
        state=args.state,
        labels=args.label,
        limit=args.limit,
    )
    print(text, end="")
    return 0 if text else 1


def command_github_issue(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    text = github_issue_detail_text(
        GitHubSource.from_config(redactor.config),
        redactor,
        repo_alias=args.repo_alias,
        number=args.number,
        comments=args.comments,
        max_comments=args.max_comments,
        max_body_chars=args.max_body_chars,
    )
    print(text, end="")
    return 0


def command_github_search(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    text = github_issue_search_text(
        GitHubSource.from_config(redactor.config),
        redactor,
        repo_alias=args.repo_alias,
        query=args.query,
        state=args.state,
        limit=args.limit,
    )
    print(text, end="")
    return 0 if text else 1


def mail_source_from_args(args: argparse.Namespace, redactor: Redactor) -> MailSource | None:
    return MailSource.from_config(redactor.config, documents=getattr(args, "documents", False))


def command_mail_sources(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    print(mail_sources_text(mail_source_from_args(args, redactor)), end="")
    return 0


def command_mail_list(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    mailbox = args.mailbox
    if args.mailbox_option is not None:
        if mailbox is not None and mailbox != args.mailbox_option:
            raise SystemExit("Pass the mailbox alias once.")
        mailbox = args.mailbox_option
    text = mail_list_text(
        mail_source_from_args(args, redactor),
        redactor,
        mailbox=mailbox,
        limit=args.limit,
        offset=args.offset,
        since=args.since,
        until=args.until,
    )
    if not text:
        print("No matches.")
        return 1
    print(text, end="")
    return 0


def command_mail_read(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    print(mail_read_text(
        mail_source_from_args(args, redactor),
        redactor,
        ref=args.ref,
        include_quoted=args.include_quoted,
        max_body_chars=args.max_body_chars,
    ), end="")
    return 0


def command_mail_thread(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    print(mail_thread_text(
        mail_source_from_args(args, redactor),
        redactor,
        ref=args.ref,
        max_messages=args.max_messages,
        include_quoted=args.include_quoted,
        max_body_chars=args.max_body_chars,
    ), end="")
    return 0


def command_mail_attachment(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    print(mail_attachment_text(
        mail_source_from_args(args, redactor),
        redactor,
        ref=args.ref,
        include_quoted=args.include_quoted,
        max_chars=args.max_chars,
    ), end="")
    return 0


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
    parser.add_argument("--documents", action="store_true", help="enable local document extraction; requires the documents extra")
    add_detector_argument(parser)

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

    retrieve_parser = subparsers.add_parser("retrieve", help="rank redacted passages by keyword relevance")
    retrieve_parser.add_argument("query")
    retrieve_parser.add_argument("paths", nargs="*")
    retrieve_parser.add_argument("--glob", action="append", default=[])
    retrieve_parser.add_argument("--max-results", type=int, default=8)
    retrieve_parser.add_argument("--max-chars", type=int, default=12_000)
    retrieve_parser.add_argument(
        "--source",
        choices=("filesystem", "mail"),
        default="filesystem",
        help="documents to rank; for mail, paths are mailbox aliases or @m_ refs and --glob is refused",
    )
    add_budget_arguments(retrieve_parser)
    retrieve_parser.set_defaults(func=command_retrieve, max_files=DEFAULT_MAX_FILES, max_seconds=DEFAULT_MCP_SEARCH_SECONDS)

    stat_parser = subparsers.add_parser("stat", help="show redacted path metadata")
    stat_parser.add_argument("path")
    add_budget_arguments(stat_parser, include_files=False)
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
        help="paths to scan; empty scans the root; for mail, mailbox aliases or @m_ refs (empty: every mailbox)",
    )
    discover_parser.add_argument(
        "--source",
        choices=("filesystem", "mail"),
        default="filesystem",
        help="documents to classify; for mail, --glob and --max-files do not apply",
    )
    discover_parser.add_argument("--provider", choices=("ollama",), default="ollama")
    discover_parser.add_argument("--endpoint", default=None, help=OLLAMA_ENDPOINT_HELP)
    discover_parser.add_argument(
        "--allow-remote-endpoint",
        action="store_true",
        help="allow non-loopback plain-http endpoints (sends private text off-machine)",
    )
    discover_parser.add_argument("--model", default=None, help=OLLAMA_MODEL_HELP)
    discover_parser.add_argument("--timeout", type=float, default=120.0)
    discover_parser.add_argument("--glob", action="append", default=[])
    discover_parser.add_argument("--max-files", type=int, default=DEFAULT_DISCOVERY_MAX_FILES)
    discover_parser.add_argument(
        "--max-messages",
        type=int,
        default=DEFAULT_DISCOVERY_MAX_MESSAGES,
        help="mail only: newest messages to read, one model call each",
    )
    discover_parser.add_argument("--max-chars-per-file", type=int, default=DEFAULT_DISCOVERY_MAX_CHARS)
    discover_parser.add_argument(
        "--max-total-raw-bytes",
        type=int,
        default=None,
        help=(
            f"raw bytes read in all (default: {DEFAULT_MAX_TOTAL_RAW_BYTES} for files, "
            f"{MAIL_RETRIEVE_MAX_TOTAL_BYTES} for mail, where reaching it stops sampling)"
        ),
    )
    discover_parser.add_argument(
        "--fail-on-truncation",
        action="store_true",
        help="fail instead of classifying a truncated file sample",
    )
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
    add_detector_argument(discover_parser, dest="subcommand_detector", help=DISCOVERY_DETECTOR_HELP)
    discover_parser.set_defaults(func=command_discover)

    discover_update_parser = subparsers.add_parser(
        "discover-update",
        help="classify caller-supplied documents and safely merge the redaction config",
    )
    discover_update_parser.add_argument(
        "paths",
        nargs="*",
        help="with --source mail: mailbox aliases or @m_ refs (empty: every mailbox)",
    )
    discover_update_parser.add_argument(
        "--source",
        choices=("filesystem", "mail"),
        default="filesystem",
        help="filesystem reads --input-jsonl; mail reads configured mailboxes instead",
    )
    discover_update_parser.add_argument(
        "--input-jsonl",
        help="JSONL file containing path/text objects, or - for stdin",
    )
    discover_update_parser.add_argument("--endpoint", default=None, help=OLLAMA_ENDPOINT_HELP)
    discover_update_parser.add_argument(
        "--allow-remote-endpoint",
        action="store_true",
        help="allow non-loopback plain-http endpoints (sends private text off-machine)",
    )
    discover_update_parser.add_argument("--model", default=None, help=OLLAMA_MODEL_HELP)
    discover_update_parser.add_argument("--timeout", type=float, default=120.0)
    discover_update_parser.add_argument("--max-files", type=int, default=DEFAULT_DISCOVERY_MAX_FILES)
    discover_update_parser.add_argument(
        "--max-messages",
        type=int,
        default=DEFAULT_DISCOVERY_MAX_MESSAGES,
        help="with --source mail: newest messages to read, one model call each",
    )
    discover_update_parser.add_argument(
        "--max-total-raw-bytes",
        type=int,
        default=None,
        help=(
            f"with --source mail: raw message bytes read in all (default: {MAIL_RETRIEVE_MAX_TOTAL_BYTES}); "
            "reaching it stops sampling"
        ),
    )
    discover_update_parser.add_argument(
        "--max-chars-per-document",
        type=int,
        default=DEFAULT_DISCOVERY_MAX_CHARS,
        help=(
            "fail when any document exceeds this size (with --source mail, skip the message); "
            "documents are never truncated"
        ),
    )
    discover_update_parser.add_argument("--max-total-chars", type=int, default=DEFAULT_MAX_TOTAL_RAW_BYTES)
    discover_update_parser.add_argument(
        "--output-config",
        default=LOCAL_CONFIG,
        help=f"config path under the root; defaults to {LOCAL_CONFIG}",
    )
    discover_update_parser.add_argument(
        "--seed-config",
        help="optional reviewed config under the root; its policy settings are authoritative",
    )
    discover_update_parser.add_argument(
        "--include-discovered-allow",
        action="store_true",
        help="allow model-discovered public terms to expand the allow-list",
    )
    discover_update_parser.add_argument(
        "--include-discovered-aliases",
        action="store_true",
        help=(
            "merge proposed alias groups found in the documents; only adds valid, non-conflicting "
            "aliases (seed config aliases are always merged)"
        ),
    )
    discover_update_parser.add_argument(
        "--merge-only",
        action="store_true",
        help="merge the seed and existing config without reading documents or calling a model",
    )
    add_detector_argument(discover_update_parser, dest="subcommand_detector", help=DISCOVERY_DETECTOR_HELP)
    discover_update_mode = discover_update_parser.add_mutually_exclusive_group()
    discover_update_mode.add_argument(
        "--dry-run",
        action="store_true",
        help="print the merged config without writing it",
    )
    discover_update_mode.add_argument(
        "--check",
        action="store_true",
        help="exit 1 when the merged config would change",
    )
    discover_update_parser.set_defaults(func=command_discover_update)

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

    mail_parser = subparsers.add_parser(
        "mail",
        help="read local mailbox exports through configured mailbox aliases and redaction",
    )
    mail_subparsers = mail_parser.add_subparsers(dest="mail_command", required=True)

    mail_sources_parser = mail_subparsers.add_parser("sources", help="list configured mailbox aliases and formats")
    mail_sources_parser.set_defaults(func=command_mail_sources)

    mail_list_parser = mail_subparsers.add_parser("list", help="list redacted messages, newest first")
    mail_list_parser.add_argument("mailbox", nargs="?", help="configured mailbox alias; default all mailboxes")
    mail_list_parser.add_argument("--mailbox", dest="mailbox_option", help="configured mailbox alias")
    mail_list_parser.add_argument("--limit", type=int, default=30)
    mail_list_parser.add_argument("--offset", type=int, default=0)
    mail_list_parser.add_argument("--since", default="", help="first UTC day to include, YYYY-MM-DD")
    mail_list_parser.add_argument("--until", default="", help="last UTC day to include, YYYY-MM-DD")
    mail_list_parser.set_defaults(func=command_mail_list)

    mail_read_parser = mail_subparsers.add_parser("read", help="read one redacted message by @m_ ref")
    mail_read_parser.add_argument("ref", help="opaque @m_<hex> message ref")
    mail_read_parser.add_argument("--include-quoted", action="store_true", help="keep quoted replies and signatures")
    mail_read_parser.add_argument("--max-body-chars", type=int, default=30_000)
    mail_read_parser.set_defaults(func=command_mail_read)

    mail_thread_parser = mail_subparsers.add_parser("thread", help="read the redacted thread of one message")
    mail_thread_parser.add_argument("ref", help="opaque @m_<hex> message ref")
    mail_thread_parser.add_argument("--max-messages", type=int, default=20)
    mail_thread_parser.add_argument("--include-quoted", action="store_true", help="keep quoted replies and signatures")
    mail_thread_parser.add_argument("--max-body-chars", type=int, default=30_000)
    mail_thread_parser.set_defaults(func=command_mail_thread)

    mail_attachment_parser = mail_subparsers.add_parser(
        "attachment", help="read one redacted text attachment or forwarded message"
    )
    mail_attachment_parser.add_argument("ref", help="opaque @m_<hex>/<n> attachment ref (or @m_<hex>/<n>/<k>)")
    mail_attachment_parser.add_argument(
        "--include-quoted", action="store_true", help="keep quoted replies and signatures of a forwarded message"
    )
    mail_attachment_parser.add_argument("--max-chars", type=int, default=30_000)
    mail_attachment_parser.set_defaults(func=command_mail_attachment)

    return parser


DETECTOR_HELP = (
    "enable an additional local detector on top of the built-in baseline; "
    "repeatable, NAME or NAME=ARGUMENT (for example patterns=rules.toml)"
)
DISCOVERY_DETECTOR_HELP = (
    "draft terms with a local detector instead of the Ollama model; "
    "repeatable, NAME or NAME=ARGUMENT; the global --detector does not apply to discovery"
)
OLLAMA_ENDPOINT_HELP = f"Ollama endpoint (Ollama discovery only; {DEFAULT_OLLAMA_ENDPOINT} when omitted)"
OLLAMA_MODEL_HELP = f"Ollama model (Ollama discovery only; {DEFAULT_DISCOVERY_MODEL} when omitted)"


def add_detector_argument(
    parser: argparse.ArgumentParser,
    *,
    dest: str = "detector",
    help: str = DETECTOR_HELP,
) -> None:
    parser.add_argument("--detector", dest=dest, action="append", metavar="SPEC", default=None, help=help)


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
    # Detectors load once per invocation; startup errors go to the operator.
    # The global --detector serves redaction; only the discover subcommands'
    # own --detector selects detector-based discovery.
    detectors = load_detectors(args.detector or [])
    discovery = load_detectors(getattr(args, "subcommand_detector", None) or [])
    args.loaded_discovery_detectors = discovery
    if args.func is command_discover_update:
        # Hook-facing discovery updates do not read redacted context and must
        # not require or initialize vault-salt state. Mail updates are the
        # exception: mailbox tables and @m_ refs need the loaded config.
        update_config = RedactionConfig()
        if getattr(args, "source", "filesystem") == "mail":
            update_config = load_config(root, args.config.expanduser().resolve() if args.config else None)
        return command_discover_update(
            args,
            RedactedContext(root, update_config),
            None,
        )
    config = load_config(root, args.config.expanduser().resolve() if args.config else None)
    if detectors or discovery:
        config = with_protected_paths(config, root, detector_protected_paths((*detectors, *discovery)))
    if args.detector_profile:
        config = replace(config, detector_profile=args.detector_profile)
    ctx = RedactedContext(
        root,
        config,
        include_private=args.include_private,
        documents=args.documents,
        max_index_entries=getattr(args, "max_entries", DEFAULT_MAX_TRAVERSAL_ENTRIES),
    )
    redactor = Redactor(config, mode=args.mode, detectors=detectors)
    return args.func(args, ctx, redactor)


if __name__ == "__main__":
    raise SystemExit(main())
