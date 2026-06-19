#!/usr/bin/env python3
"""CLI facade for redacted local context access.

Most implementation details live in focused modules. This module intentionally
keeps the historical public imports and console-script entry point stable.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
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
    DEFAULT_MAX_SEARCH_RESULTS,
    DEFAULT_OLLAMA_ENDPOINT,
    LOCAL_CONFIG,
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
from .filesystem import RedactedContext, is_probably_text, iter_target_files, read_text_file
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


def format_entry(path: Path, ctx: RedactedContext, redactor: Redactor) -> str:
    rel = rel_posix(path, ctx.root)
    kind = "dir " if path.is_dir() else "file"
    size = "-" if path.is_dir() else str(path.stat().st_size)
    return f"{ctx.display_ref(rel)}\t{kind}\t{size}\t{redactor.redact_path(rel)}"


def command_ls(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    path = ctx.resolve_ref(args.path)
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")

    if args.recursive:
        for child in ctx.walk(path, include_dirs=True):
            depth = len(child.relative_to(path).parts) if child != path else 0
            if args.max_depth is not None and depth > args.max_depth:
                continue
            print(format_entry(child, ctx, redactor))
        return 0

    for child in ctx.child_entries(path):
        print(format_entry(child, ctx, redactor))
    return 0


def command_tree(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    root = ctx.resolve_ref(args.path)
    if ctx.is_excluded(root):
        raise SystemExit("Path is excluded by policy.")
    if root.is_file():
        print(format_entry(root, ctx, redactor))
        return 0
    base_depth = len(root.relative_to(ctx.root).parts)
    for path in ctx.walk(root, include_dirs=True):
        depth = len(path.relative_to(ctx.root).parts) - base_depth
        if args.max_depth is not None and depth > args.max_depth:
            continue
        rel = rel_posix(path, ctx.root)
        name = "." if path == root else path.name
        indent = "  " * depth
        suffix = "/" if path.is_dir() else ""
        print(f"{indent}{ctx.display_ref(rel)} {redactor.redact_path(name)}{suffix}")
    return 0


def command_cat(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    path = ctx.resolve_ref(args.path)
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")
    text = read_text_file(path)
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
    path = ctx.resolve_ref(args.path)
    if ctx.is_excluded(path):
        raise SystemExit("Path is excluded by policy.")
    text = read_text_file(path)
    line_count = len(text.splitlines())
    args.start_line = max(1, line_count - args.lines + 1)
    args.end_line = line_count
    args.max_chars = args.max_chars or DEFAULT_MAX_CHARS
    args.line_numbers = args.line_numbers
    return command_cat(args, ctx, redactor)


def command_grep(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    flags = re.IGNORECASE if args.ignore_case else 0
    matcher: re.Pattern[str] | None = None
    query = args.query
    if args.regex:
        try:
            matcher = re.compile(query, flags)
        except re.error as exc:
            raise SystemExit(f"Invalid regex: {exc}") from exc
    elif args.ignore_case:
        query = query.casefold()

    results = 0
    for path in iter_target_files(ctx, args.paths, args.glob):
        raw_lines = read_text_file(path).splitlines()
        redacted_lines = [redactor.redact(line) for line in raw_lines]
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
        print(f"lines: {len(read_text_file(path).splitlines())}")
    return 0


def command_bundle(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    count = 0
    total_chars = 0
    for path in iter_target_files(ctx, args.paths, args.glob):
        if count >= args.max_files or total_chars >= args.max_total_chars:
            print("[TRUNCATED: file or total character limit reached]")
            return 0
        raw = read_text_file(path)
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


def command_doctor(args: argparse.Namespace, ctx: RedactedContext, redactor: Redactor) -> int:
    config_path = args.config or (args.root / LOCAL_CONFIG)
    print("root: .")
    print(f"config_loaded: {config_path.exists()}")
    print(f"mode: {redactor.mode}")
    print(f"clients: {len(redactor.config.clients)}")
    print(f"organizations: {len(redactor.config.organizations)}")
    print(f"people_terms: {len(redactor.config.people)}")
    print(f"other_terms: {len(redactor.config.terms)}")
    print(f"allow_terms: {len(redactor.allow_terms)}")
    print(f"excluded_dirs: {len(ctx.exclude_dirs)}")
    print(f"excluded_globs: {len(ctx.exclude_globs)}")
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
        "--include-private",
        action="store_true",
        help="include normally excluded private/cache paths",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    ls_parser = subparsers.add_parser("ls", help="list files/directories with opaque ids")
    ls_parser.add_argument("path", nargs="?", default=".")
    ls_parser.add_argument("-r", "--recursive", action="store_true")
    ls_parser.add_argument("--max-depth", type=int)
    ls_parser.set_defaults(func=command_ls)

    tree_parser = subparsers.add_parser("tree", help="show a redacted file tree")
    tree_parser.add_argument("path", nargs="?", default=".")
    tree_parser.add_argument("--max-depth", type=int, default=3)
    tree_parser.set_defaults(func=command_tree)

    cat_parser = subparsers.add_parser("cat", aliases=["read"], help="print a redacted text file")
    cat_parser.add_argument("path")
    cat_parser.add_argument("--start-line", type=int)
    cat_parser.add_argument("--end-line", type=int)
    cat_parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    cat_parser.add_argument("-n", "--line-numbers", action="store_true")
    cat_parser.set_defaults(func=command_cat)

    head_parser = subparsers.add_parser("head", help="print the first lines of a redacted text file")
    head_parser.add_argument("path")
    head_parser.add_argument("-n", "--lines", type=int, default=40)
    head_parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    head_parser.add_argument("--line-numbers", action="store_true")
    head_parser.set_defaults(func=command_head)

    tail_parser = subparsers.add_parser("tail", help="print the last lines of a redacted text file")
    tail_parser.add_argument("path")
    tail_parser.add_argument("-n", "--lines", type=int, default=40)
    tail_parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS)
    tail_parser.add_argument("--line-numbers", action="store_true")
    tail_parser.set_defaults(func=command_tail)

    grep_parser = subparsers.add_parser("grep", aliases=["search"], help="search redacted text")
    grep_parser.add_argument("query")
    grep_parser.add_argument("paths", nargs="*")
    grep_parser.add_argument("-i", "--ignore-case", action="store_true")
    grep_parser.add_argument("-E", "--regex", action="store_true")
    grep_parser.add_argument("-C", "--context", type=int, default=0)
    grep_parser.add_argument("--glob", action="append", default=[])
    grep_parser.add_argument("--max-results", type=int, default=DEFAULT_MAX_SEARCH_RESULTS)
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
    bundle_parser.set_defaults(func=command_bundle)

    doctor_parser = subparsers.add_parser("doctor", help="show redaction setup without printing terms")
    doctor_parser.set_defaults(func=command_doctor)

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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = args.root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit("Root must be an existing directory.")
    config = load_config(root, args.config.expanduser().resolve() if args.config else None)
    ctx = RedactedContext(root, config, include_private=args.include_private)
    redactor = Redactor(config, mode=args.mode)
    return args.func(args, ctx, redactor)


if __name__ == "__main__":
    raise SystemExit(main())
