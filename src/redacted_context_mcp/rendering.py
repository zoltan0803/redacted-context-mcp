"""Redaction boundary for structured source records.

Sources return raw text and opaque references; this module turns structured
records into output text and redacts every content field on the way out. It
is shared by the ``redctx`` CLI and the MCP server so both surfaces render
identical, already-redacted text.

The ``*_text`` entry points validate every argument before any upstream
request, make one ``GitHubSource`` call, and format the returned records.
The ``render_*`` functions only format.
"""

from __future__ import annotations

from .github import (
    UNKNOWN_REPO_ALIAS_MESSAGE,
    GitHubComment,
    GitHubIssue,
    GitHubSource,
    validate_github_state,
    validate_nonnegative_limit,
    validate_positive_limit,
)
from .redaction import Redactor


def truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[TRUNCATED]\n"


def render_github_labels(labels: tuple[str, ...], redactor: Redactor) -> str:
    rendered = [redactor.redact(label) for label in labels]
    return ", ".join(rendered) if rendered else "-"


def render_github_issue_summary(issue: GitHubIssue, redactor: Redactor) -> str:
    state = redactor.redact(issue.state)
    updated = redactor.redact(issue.updated_at)
    title = redactor.redact(issue.title)
    labels = render_github_labels(issue.labels, redactor)
    return (
        f"{issue.ref}\tstate={state}\tupdated={updated}\tcomments={issue.comment_count}"
        f"\tlabels={labels}\tuntrusted_title={title}"
    )


def render_github_issue_detail(
    issue: GitHubIssue,
    comments: list[GitHubComment],
    redactor: Redactor,
    *,
    max_body_chars: int,
) -> str:
    title = redactor.redact(issue.title)
    body = truncate_text(redactor.redact(issue.body), max_body_chars)
    lines = [
        f"repo: {issue.repo_alias}",
        f"issue: #{issue.display_number}",
        f"state: {redactor.redact(issue.state)}",
        f"title: {title}",
        f"created_at: {redactor.redact(issue.created_at)}",
        f"updated_at: {redactor.redact(issue.updated_at)}",
        f"labels: {render_github_labels(issue.labels, redactor)}",
        f"assignees: {issue.assignee_count}",
        "",
        "body_untrusted_external:",
        body,
    ]
    for index, comment in enumerate(comments, start=1):
        comment_body = truncate_text(redactor.redact(comment.body), max_body_chars)
        lines.extend(
            [
                "",
                f"comment {index}:",
                f"created_at: {redactor.redact(comment.created_at)}",
                f"author: {comment.author}",
                "comment_untrusted_external:",
                comment_body,
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def require_github_source(source: GitHubSource | None) -> GitHubSource:
    # With no configured repos every alias is unknown; keep the same message
    # the per-alias lookup uses so callers cannot distinguish the two cases.
    if source is None:
        raise SystemExit(UNKNOWN_REPO_ALIAS_MESSAGE)
    return source


def github_repos_text(source: GitHubSource | None) -> str:
    if source is None:
        return ""
    return "".join(f"{alias}\n" for alias in source.repo_aliases())


def github_issue_list_text(
    source: GitHubSource | None,
    redactor: Redactor,
    *,
    repo_alias: str,
    state: str,
    labels: list[str],
    limit: int,
) -> str:
    """Return redacted issue summaries, one per line, or ``""`` when none match."""
    state = validate_github_state(state)
    limit = validate_positive_limit(limit, "--limit")
    issues = require_github_source(source).list_issues(repo_alias, state=state, labels=labels, limit=limit)
    return "".join(render_github_issue_summary(issue, redactor) + "\n" for issue in issues)


def github_issue_search_text(
    source: GitHubSource | None,
    redactor: Redactor,
    *,
    repo_alias: str,
    query: str,
    state: str,
    limit: int,
) -> str:
    """Return redacted search summaries, one per line, or ``""`` when none match."""
    state = validate_github_state(state)
    limit = validate_positive_limit(limit, "--limit")
    issues = require_github_source(source).search_issues(repo_alias, query=query, state=state, limit=limit)
    return "".join(render_github_issue_summary(issue, redactor) + "\n" for issue in issues)


def github_issue_detail_text(
    source: GitHubSource | None,
    redactor: Redactor,
    *,
    repo_alias: str,
    number: int,
    comments: bool,
    max_comments: int,
    max_body_chars: int,
) -> str:
    max_comments = validate_nonnegative_limit(max_comments, "--max-comments")
    max_body_chars = validate_positive_limit(max_body_chars, "--max-body-chars")
    issue, comment_records = require_github_source(source).issue_detail(
        repo_alias, number, comments=comments, max_comments=max_comments
    )
    return render_github_issue_detail(issue, comment_records, redactor, max_body_chars=max_body_chars)
