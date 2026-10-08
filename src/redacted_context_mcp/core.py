#!/usr/bin/env python3
"""CLI facade for redacted local context access.

Most implementation details live in focused modules. This module intentionally
keeps the historical public imports and console-script entry point stable.
"""

from __future__ import annotations

import argparse
import json
import math
import multiprocessing
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
from .discovery import (
    OllamaDiscoveryClient,
    build_discovery_update,
    build_discovery_prompt,
    build_strict_discovery_prompt,
    clean_discovered_terms,
    discover_documents,
    discover_entities,
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
    merge_discovery_toml,
    merge_discovery_results,
    normalize_discovery_value,
    normalize_person_name,
    parse_discovery_documents_jsonl,
    parse_discovery_response,
    parse_json_object,
    postprocess_discovery_result,
    should_drop_discovered_value,
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
    DOCUMENTS_UNSUPPORTED_MESSAGE,
    UNKNOWN_REFERENCE_MESSAGE,
    DiscoveryDocument,
    DiscoveryParseError,
    DiscoveryResult,
    DiscoveryUpdate,
    GitHubRepoConfig,
    RedactionConfig,
)
from .paths import display_ref, path_id, rel_posix, resolve_under_root
from .redaction import Redactor, compile_literal_pattern, normalize_alias
from .rendering import (
    format_github_issue_detail,
    format_github_issue_summary,
    format_github_labels,
    github_issue_detail_text,
    github_issue_list_text,
    github_issue_search_text,
    github_repos_text,
    truncate_text,
)
from .retrieval import retrieve
from .sources import SourceRegistry, build_sources
from .documents import DOCUMENT_EXTENSIONS


HEX_QUERY_RE = re.compile(r"[0-9a-fA-F]+")
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
    if HEX_QUERY_RE.fullmatch(stripped):
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


def truncate_redacted(text: str, max_chars: int) -> str:
    """Truncate redacted output without splitting a placeholder token."""
    if len(text) <= max_chars:
        return text
    cut_at = max(0, max_chars)
    for match in PLACEHOLDER_RE.finditer(text):
        if match.start() < cut_at < match.end():
            cut_at = match.start()
            break
        if match.start() >= cut_at:
            break
    return text[:cut_at] + "\n[TRUNCATED]\n"


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
        raise SystemExit("--end-line must be greater than or equal to --start-line.")
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


UNSAFE_REGEX_MESSAGE = "Unsafe regex: potentially catastrophic backtracking pattern."

# A quantified group whose repetition upper bound exceeds this is treated as
# effectively unbounded; below it, bounded backtracking is cheap enough.
QUANTIFIER_REPETITION_FLOOR = 8


def _regex_quantifier_at(pattern: str, index: int) -> tuple[str, int, float]:
    """Classify the quantifier starting at pattern[index].

    Returns ("none"|"bounded"|"unbounded", token_length, max_repetitions)
    where max_repetitions is inf for unbounded quantifiers.
    """
    n = len(pattern)
    if index >= n:
        return "none", 0, 0.0
    char = pattern[index]
    if char in "*+":
        if index + 1 < n and pattern[index + 1] == "+":
            return "unbounded", 2, math.inf
        return "unbounded", 1, math.inf
    if char == "?":
        if index + 1 < n and pattern[index + 1] in {"?", "+"}:
            return "bounded", 2, 1
        return "bounded", 1, 1
    if char == "{":
        end = pattern.find("}", index + 1)
        if end == -1 or end - index > 12:
            return "none", 0, 0.0
        body = pattern[index + 1 : end]
        if not re.fullmatch(r"\d*,\d*|\d+", body):
            return "none", 0, 0.0
        if "," in body and body.partition(",")[2] == "":
            return "unbounded", end - index + 1, math.inf
        parts = body.split(",")
        maximum = max(int(part) for part in parts if part)
        return "bounded", end - index + 1, float(maximum)
    return "none", 0, 0.0


def _split_top_level_alternation(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    n = len(body)
    while index < n:
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = index + 1
            if close < n and body[close] == "^":
                close += 1
            if close < n and body[close] == "]":
                close += 1
            while close < n and body[close] != "]":
                if body[close] == "\\":
                    close += 1
                close += 1
            index = close + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "|" and depth == 0:
            parts.append(body[start:index])
            start = index + 1
        index += 1
    parts.append(body[start:])
    return parts


def _branch_first_chars(branch: str) -> frozenset[str] | None:
    """Approximate set of literal first characters a branch can start with.

    Returns None when the estimate is unknown (escapes, dot, any class with
    negation or ranges, groups); callers must treat unknown as potentially
    overlapping.
    """
    branch = branch.lstrip("^")
    if not branch:
        return None
    if branch[0] == "\\":
        return None
    if branch[0] == ".":
        return None
    if branch[0] == "[":
        end = branch.find("]")
        if end == -1:
            return None
        inner = branch[1:end]
        if inner.startswith("^"):
            # Negated classes match almost anything; they cannot be narrowed
            # to the literal characters written inside the brackets.
            return None
        if inner.startswith("]"):
            inner = inner[1:]
        if "-" in inner or "\\" in inner:
            return None
        return frozenset(inner)
    if branch[0] == "(":
        close = branch.find(")")
        if close == -1:
            return None
        inner = branch[1:close]
        if inner.startswith("?"):
            return None
        branch_sets = [_branch_first_chars(part) for part in _split_top_level_alternation(inner)]
        if any(value is None for value in branch_sets):
            return None
        combined: set[str] = set()
        for value in branch_sets:
            combined.update(value)
        return frozenset(combined)
    return frozenset(branch[0])


def _alternation_overlap(body: str) -> bool:
    branches = _split_top_level_alternation(body)
    if len(branches) < 2:
        return False
    first_sets = [_branch_first_chars(branch) for branch in branches]
    for index in range(len(first_sets)):
        for other in range(index + 1, len(first_sets)):
            left, right = first_sets[index], first_sets[other]
            if left is None or right is None or left & right:
                return True
    return False


def regex_backtracking_violation(pattern: str) -> str | None:
    """Return a violating snippet when a pattern can backtrack explosively.

    Conservative screen over user-supplied regexes. A group is hazardous when
    its body contains any quantifier or an ambiguous top-level alternation;
    hazards propagate outward through nesting. A hazardous group quantified
    beyond QUANTIFIER_REPETITION_FLOOR repetitions (or unbounded) is rejected.
    Unknown shapes fail closed. The screen is a fast-fail layer; process-level
    match isolation enforces the actual wall-clock bound.
    """
    n = len(pattern)
    index = 0
    # Each stack entry: [group_open_position, has_quantifier_inside, hazard]
    groups: list[list[object]] = []

    while index < n:
        char = pattern[index]
        if char == "\\":
            index += 2
            kind, length, _maximum = _regex_quantifier_at(pattern, index)
            if kind != "none":
                index += length
                if groups:
                    groups[-1][1] = True
            continue
        if char == "[":
            close = index + 1
            if close < n and pattern[close] == "^":
                close += 1
            if close < n and pattern[close] == "]":
                close += 1
            while close < n and pattern[close] != "]":
                if pattern[close] == "\\":
                    close += 1
                close += 1
            index = close + 1
            kind, length, _maximum = _regex_quantifier_at(pattern, index)
            if kind != "none":
                index += length
                if groups:
                    groups[-1][1] = True
            continue
        if char == "(":
            groups.append([index, False, False])
            index += 1
            if index < n and pattern[index] == "?":
                index += 1
                if index < n and pattern[index] == "P":
                    index += 1
                    if index < n and pattern[index] == "<":
                        gt = pattern.find(">", index)
                        index = gt + 1 if gt != -1 else n
            continue
        if char == ")":
            if not groups:
                index += 1
                continue
            open_position, has_quantifier, inner_hazard = groups.pop()
            close_position = index
            index += 1
            kind, length, maximum = _regex_quantifier_at(pattern, index)
            if kind != "none":
                index += length
            body = pattern[open_position + 1 : close_position]
            if body.startswith("?P") or body.startswith("?<"):
                gt = body.find(">")
                body = body[gt + 1 :] if gt != -1 else ""
            elif body.startswith("?"):
                body = body[2:]
            group_hazard = has_quantifier or inner_hazard or _alternation_overlap(body)
            if kind != "none" and maximum > QUANTIFIER_REPETITION_FLOOR and group_hazard:
                return pattern[max(0, open_position - 12) : min(n, index + 4)]
            if groups and (kind != "none" or group_hazard):
                groups[-1][1] = groups[-1][1] or kind != "none"
                groups[-1][2] = True if group_hazard else groups[-1][2]
            continue
        # Plain atom.
        index += 1
        kind, length, _maximum = _regex_quantifier_at(pattern, index)
        if kind != "none":
            index += length
            if groups:
                groups[-1][1] = True
    return None


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


def _regex_match_worker(connection: object, pattern: str, flags: int, job: list[list[str]], seconds: float) -> None:
    """Apply a compiled pattern to redacted lines in an isolated process.

    Runs only redacted text and cannot outlive the parent's kill timeout, so
    catastrophic-backtracking patterns cannot hang the serving process.
    """
    import time as time_module

    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        connection.send(("error", None))
        return
    deadline = time_module.monotonic() + seconds if seconds > 0 else None
    matched: list[list[int]] = []
    for lines in job:
        indices: list[int] = []
        for index, line in enumerate(lines):
            if deadline is not None and time_module.monotonic() > deadline:
                connection.send(("deadline", None))
                return
            if compiled.search(line):
                indices.append(index)
        matched.append(indices)
    connection.send(("ok", matched))


def match_regex_lines(
    pattern: str,
    flags: int,
    job: list[list[str]],
    timeout_seconds: float,
) -> list[list[int]]:
    """Match redacted lines with a user regex in a killable child process."""
    if not job:
        return []
    methods = multiprocessing.get_all_start_methods()
    context = multiprocessing.get_context("fork" if "fork" in methods else None)
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_regex_match_worker,
        args=(sender, pattern, flags, job, timeout_seconds),
        daemon=True,
    )
    process.start()
    sender.close()
    try:
        if not receiver.poll(timeout_seconds + 5):
            process.terminate()
            process.join(2)
            raise SystemExit("Operation deadline exceeded.")
        try:
            status, payload = receiver.recv()
        except (EOFError, OSError):
            process.terminate()
            process.join(2)
            raise SystemExit("Operation deadline exceeded.")
        if status == "deadline":
            raise SystemExit("Operation deadline exceeded.")
        if status == "error":
            raise SystemExit("Invalid regex.")
        return payload
    finally:
        process.terminate()
        process.join(1)


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
    path.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite:
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
        fsync_directory(path.parent)
    except Exception:
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
    print(f"allow_terms: {len(redactor.allow_terms)}")
    print(f"excluded_dirs: {len(ctx.exclude_dirs)}")
    print(f"excluded_globs: {len(ctx.exclude_globs)}")
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
    chunk_redactor = Redactor(redactor.config, mode=redactor.mode)
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


def command_discover(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    if args.provider != "ollama":
        raise SystemExit("Only the ollama discovery provider is currently supported.")
    client = OllamaDiscoveryClient(
        endpoint=args.endpoint,
        model=args.model,
        timeout=args.timeout,
        postprocess=not args.raw_discovery,
        allow_remote=getattr(args, "allow_remote_endpoint", False),
    )
    result = discover_entities(
        ctx,
        paths=args.paths,
        globs=args.glob,
        client=client,
        max_files=args.max_files,
        max_chars_per_file=args.max_chars_per_file,
        max_total_raw_bytes=getattr(args, "max_total_raw_bytes", DEFAULT_MAX_TOTAL_RAW_BYTES),
        postprocess=not args.raw_discovery,
        fail_on_truncation=getattr(args, "fail_on_truncation", False),
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


def command_discover_update(
    args: argparse.Namespace,
    ctx: RedactedContext,
    redactor: Redactor | None,
) -> int:
    del redactor
    try:
        if args.merge_only and args.input_jsonl:
            raise ValueError("--merge-only cannot be combined with --input-jsonl.")
        if args.merge_only:
            documents: tuple[DiscoveryDocument, ...] = ()
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
        if len(documents) > args.max_files:
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

        if documents:
            client = OllamaDiscoveryClient(
                endpoint=args.endpoint,
                model=args.model,
                timeout=args.timeout,
                postprocess=True,
                allow_remote=getattr(args, "allow_remote_endpoint", False),
            )
            result = discover_documents(documents, client=client, postprocess=True)
        else:
            result = DiscoveryResult()
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
        update = build_discovery_update(
            existing_text,
            result,
            seed_text=seed_text,
            include_discovered_allow=args.include_discovered_allow,
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
    print(f"model: {args.model if documents else 'skipped'}")
    print(f"discovered_counts: {json.dumps(counts, sort_keys=True, separators=(',', ':'))}")
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
        help="paths to scan; empty scans the root",
    )
    discover_parser.add_argument("--provider", choices=("ollama",), default="ollama")
    discover_parser.add_argument("--endpoint", default=DEFAULT_OLLAMA_ENDPOINT)
    discover_parser.add_argument(
        "--allow-remote-endpoint",
        action="store_true",
        help="allow non-loopback plain-http endpoints (sends private text off-machine)",
    )
    discover_parser.add_argument("--model", default=DEFAULT_DISCOVERY_MODEL)
    discover_parser.add_argument("--timeout", type=float, default=120.0)
    discover_parser.add_argument("--glob", action="append", default=[])
    discover_parser.add_argument("--max-files", type=int, default=DEFAULT_DISCOVERY_MAX_FILES)
    discover_parser.add_argument("--max-chars-per-file", type=int, default=DEFAULT_DISCOVERY_MAX_CHARS)
    discover_parser.add_argument("--max-total-raw-bytes", type=int, default=DEFAULT_MAX_TOTAL_RAW_BYTES)
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
    discover_parser.set_defaults(func=command_discover)

    discover_update_parser = subparsers.add_parser(
        "discover-update",
        help="classify caller-supplied documents and safely merge the redaction config",
    )
    discover_update_parser.add_argument(
        "--input-jsonl",
        help="JSONL file containing path/text objects, or - for stdin",
    )
    discover_update_parser.add_argument("--endpoint", default=DEFAULT_OLLAMA_ENDPOINT)
    discover_update_parser.add_argument(
        "--allow-remote-endpoint",
        action="store_true",
        help="allow non-loopback plain-http endpoints (sends private text off-machine)",
    )
    discover_update_parser.add_argument("--model", default=DEFAULT_DISCOVERY_MODEL)
    discover_update_parser.add_argument("--timeout", type=float, default=120.0)
    discover_update_parser.add_argument("--max-files", type=int, default=DEFAULT_DISCOVERY_MAX_FILES)
    discover_update_parser.add_argument(
        "--max-chars-per-document",
        type=int,
        default=DEFAULT_DISCOVERY_MAX_CHARS,
        help="fail when any document exceeds this size; documents are never truncated",
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
        "--merge-only",
        action="store_true",
        help="merge the seed and existing config without reading documents or calling a model",
    )
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
    if args.func is command_discover_update:
        # Hook-facing discovery updates do not read redacted context and must
        # not require or initialize vault-salt state.
        return command_discover_update(
            args,
            RedactedContext(root, RedactionConfig()),
            None,
        )
    config = load_config(root, args.config.expanduser().resolve() if args.config else None)
    if args.detector_profile:
        config = replace(config, detector_profile=args.detector_profile)
    ctx = RedactedContext(root, config, include_private=args.include_private, documents=args.documents)
    redactor = Redactor(config, mode=args.mode)
    return args.func(args, ctx, redactor)


if __name__ == "__main__":
    raise SystemExit(main())
