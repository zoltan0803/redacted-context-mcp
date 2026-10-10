"""Read-only GitHub issue source through neutral repo aliases.

This module is the ``github`` source adapter. It owns GitHub identity and
reference opaqueness: repo aliases instead of owner/repo, ``<alias>#<number>``
issue references, and salted ``user_<hex>`` author aliases. It returns raw,
untrusted issue text in structured records and never redacts content itself;
``rendering`` is the redaction boundary that formats those records for output.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

from .defaults import SYSTEM_CA_CANDIDATES
from .limits import OperationBudget
from .models import (
    DOCUMENTS_UNSUPPORTED_MESSAGE,
    UNKNOWN_REFERENCE_MESSAGE,
    GitHubRepoConfig,
    RedactionConfig,
    SourceDocument,
)

ISSUE_NUMBER_RE = re.compile(r"[1-9][0-9]{0,9}")
UNKNOWN_REPO_ALIAS_MESSAGE = "Unknown GitHub repo alias."
# Upper bound on one upstream response body. Larger responses fail closed
# with an input-free message instead of being buffered without limit.
GITHUB_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
GITHUB_RESPONSE_TOO_LARGE_MESSAGE = "GitHub response too large."


@dataclass(frozen=True)
class GitHubComment:
    """One issue comment. ``author`` is an opaque alias; ``body`` is raw untrusted text."""

    created_at: str
    author: str
    body: str


@dataclass(frozen=True)
class GitHubIssue:
    """One issue as raw untrusted fields plus neutral identifiers.

    ``repo_alias`` is the operator-chosen neutral alias, never owner/repo.
    ``title``, ``body``, ``state``, timestamps, and ``labels`` are raw
    upstream text and must be redacted before output. ``number`` and the
    counts are validated non-negative integers, so they are safe to print;
    ``number`` is ``None`` when upstream sent no valid issue number.
    """

    repo_alias: str
    number: int | None
    state: str
    title: str
    created_at: str
    updated_at: str
    body: str
    labels: tuple[str, ...]
    comment_count: int
    assignee_count: int

    @property
    def display_number(self) -> str:
        return "?" if self.number is None else str(self.number)

    @property
    def ref(self) -> str:
        return f"{self.repo_alias}#{self.display_number}"


def nonnegative_int(value: object) -> int | None:
    """Return ``value`` only if it is a real non-negative integer.

    Upstream numeric fields are printed without redaction, so anything else
    (strings, floats, booleans, nested values) is discarded rather than
    stringified into output.
    """
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def github_issue_from_api(repo_alias: str, issue: dict[str, object]) -> GitHubIssue:
    return GitHubIssue(
        repo_alias=repo_alias,
        number=nonnegative_int(issue.get("number")),
        state=str(issue.get("state", "")),
        title=str(issue.get("title", "")),
        created_at=str(issue.get("created_at", "")),
        updated_at=str(issue.get("updated_at", "")),
        body=str(issue.get("body") or ""),
        labels=github_label_names(issue),
        comment_count=nonnegative_int(issue.get("comments")) or 0,
        assignee_count=count_github_assignees(issue),
    )


def github_comment_from_api(comment: dict[str, object], config: RedactionConfig, repo_alias: str) -> GitHubComment:
    return GitHubComment(
        created_at=str(comment.get("created_at", "")),
        author=opaque_github_user(comment.get("user"), config, repo_alias),
        body=str(comment.get("body") or ""),
    )


class GitHubSource:
    """Read-only GitHub issue source for the configured ``[github.repos.*]`` aliases."""

    name = "github"
    untrusted_content = True
    # Issue text is fetched on demand per tool call. Bulk document iteration
    # is deliberately not offered: no tool needs it, and it would turn ranked
    # retrieval into an upstream crawl over untrusted text.
    supports_document_iteration = False

    def __init__(self, config: RedactionConfig) -> None:
        self.config = config

    @classmethod
    def from_config(cls, config: RedactionConfig) -> "GitHubSource | None":
        return cls(config) if config.github_repos else None

    def repo_aliases(self) -> list[str]:
        return sorted(self.config.github_repos)

    def owns_reference(self, ref: str) -> bool:
        if not isinstance(ref, str):
            return False
        alias, separator, number = ref.rpartition("#")
        return (
            bool(separator)
            and alias in self.config.github_repos
            and ISSUE_NUMBER_RE.fullmatch(number) is not None
        )

    def resolve_reference(self, ref: str) -> tuple[str, int]:
        """Resolve ``<repo_alias>#<number>`` to its alias and issue number."""
        if not isinstance(ref, str):
            raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
        alias, separator, number = ref.rpartition("#")
        if not separator or ISSUE_NUMBER_RE.fullmatch(number) is None:
            raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
        get_github_repo_config(self.config, alias)
        return alias, int(number)

    def iter_documents(
        self,
        budget: OperationBudget,
        *,
        scope: Sequence[str] = (),
        patterns: Sequence[str] = (),
    ) -> Iterator[SourceDocument]:
        raise SystemExit(DOCUMENTS_UNSUPPORTED_MESSAGE)

    def list_issues(self, repo_alias: str, *, state: str, labels: list[str], limit: int) -> list[GitHubIssue]:
        issues = github_list_issues(self.config, repo_alias=repo_alias, state=state, labels=labels, limit=limit)
        return [github_issue_from_api(repo_alias, issue) for issue in issues]

    def search_issues(self, repo_alias: str, *, query: str, state: str, limit: int) -> list[GitHubIssue]:
        issues = github_search_issues(self.config, repo_alias=repo_alias, query=query, state=state, limit=limit)
        return [github_issue_from_api(repo_alias, issue) for issue in issues]

    def read_issue(self, repo_alias: str, number: int) -> GitHubIssue:
        return github_issue_from_api(repo_alias, github_read_issue(self.config, repo_alias=repo_alias, number=number))

    def read_comments(self, repo_alias: str, number: int, *, limit: int) -> list[GitHubComment]:
        comments = github_read_issue_comments(self.config, repo_alias=repo_alias, number=number, limit=limit)
        return [github_comment_from_api(comment, self.config, repo_alias) for comment in comments]

    def issue_detail(
        self,
        repo_alias: str,
        number: int,
        *,
        comments: bool,
        max_comments: int,
    ) -> tuple[GitHubIssue, list[GitHubComment]]:
        """Fetch one issue and, when requested, up to ``max_comments`` comments.

        Callers validate limits before calling; this performs the upstream
        requests only.
        """
        issue = self.read_issue(repo_alias, number)
        comment_records: list[GitHubComment] = []
        if comments and max_comments > 0:
            comment_records = self.read_comments(repo_alias, number, limit=max_comments)
        return issue, comment_records


def get_github_repo_config(config: RedactionConfig, alias: str) -> GitHubRepoConfig:
    repo_config = config.github_repos.get(alias)
    if repo_config is None:
        raise SystemExit(UNKNOWN_REPO_ALIAS_MESSAGE)
    return repo_config


def validate_github_state(state: str) -> str:
    if state not in {"open", "closed", "all"}:
        raise SystemExit("GitHub state must be open, closed, or all.")
    return state


def validate_positive_limit(value: int, name: str) -> int:
    if value < 1:
        raise SystemExit(f"{name} must be at least 1.")
    return value


def validate_nonnegative_limit(value: int, name: str) -> int:
    if value < 0:
        raise SystemExit(f"{name} must be at least 0.")
    return value


def github_api_request(repo_alias: str, repo_config: GitHubRepoConfig, path: str, query: dict[str, object]) -> object:
    query_items = {
        key: value
        for key, value in query.items()
        if value is not None and value != "" and value != []
    }
    url = f"{repo_config.api_url.rstrip('/')}{path}"
    if query_items:
        url = f"{url}?{urllib.parse.urlencode(query_items, doseq=True)}"

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "redacted-context-mcp",
    }
    token = os.environ.get(repo_config.token_env)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30, context=github_ssl_context()) as response:
            raw_body = response.read(GITHUB_MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.read(GITHUB_MAX_RESPONSE_BYTES + 1)
        # This message reaches the agent verbatim. The repo alias is the
        # neutral, agent-visible name; the configured token_env name is
        # private local config and stays out.
        raise SystemExit(
            f"GitHub request failed for repo alias '{repo_alias}' ({exc.code}). "
            "Check that the repo alias is configured and its token environment variable (token_env) has access."
        ) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(format_github_url_error(exc)) from exc
    if len(raw_body) > GITHUB_MAX_RESPONSE_BYTES:
        raise SystemExit(GITHUB_RESPONSE_TOO_LARGE_MESSAGE)
    body = raw_body.decode("utf-8", errors="replace")

    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise SystemExit("GitHub returned invalid JSON.") from exc


def extract_github_error(body: str) -> str:
    if not body.strip():
        return ""
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return ""
    if isinstance(data, dict) and data.get("message"):
        return "GitHub returned an error. "
    return ""


def github_ssl_context() -> ssl.SSLContext:
    if os.environ.get("SSL_CERT_FILE") or os.environ.get("SSL_CERT_DIR") or default_ssl_paths_have_certs():
        return ssl.create_default_context()
    for candidate in SYSTEM_CA_CANDIDATES:
        if Path(candidate).exists():
            return ssl.create_default_context(cafile=candidate)
    return ssl.create_default_context()


def default_ssl_paths_have_certs() -> bool:
    paths = ssl.get_default_verify_paths()
    return bool(
        (paths.cafile and Path(paths.cafile).exists())
        or (paths.capath and Path(paths.capath).exists())
    )


def format_github_url_error(exc: urllib.error.URLError) -> str:
    reason = getattr(exc, "reason", None)
    reason_text = str(reason) if reason is not None else str(exc)
    if "CERTIFICATE_VERIFY_FAILED" in reason_text:
        return (
            "Could not verify GitHub's TLS certificate. Python does not have a usable CA bundle. "
            "On macOS, run `/Applications/Python 3.14/Install Certificates.command`, or start "
            "`redctx` with `SSL_CERT_FILE=/etc/ssl/cert.pem`."
        )
    return "Could not reach GitHub API."


def github_list_issues(
    config: RedactionConfig,
    *,
    repo_alias: str,
    state: str,
    labels: list[str],
    limit: int,
) -> list[dict[str, object]]:
    repo_config = get_github_repo_config(config, repo_alias)
    issues: list[dict[str, object]] = []
    page = 1
    while len(issues) < limit:
        data = github_api_request(
            repo_alias,
            repo_config,
            f"/repos/{urllib.parse.quote(repo_config.owner, safe='')}/{urllib.parse.quote(repo_config.repo, safe='')}/issues",
            {
                "state": state,
                "labels": ",".join(labels),
                "per_page": min(100, max(1, limit - len(issues))),
                "page": page,
            },
        )
        if not isinstance(data, list) or not data:
            break
        for item in data:
            if isinstance(item, dict) and "pull_request" not in item:
                issues.append(item)
                if len(issues) >= limit:
                    break
        if len(data) < 100:
            break
        page += 1
    return issues


def github_search_issues(
    config: RedactionConfig,
    *,
    repo_alias: str,
    query: str,
    state: str,
    limit: int,
) -> list[dict[str, object]]:
    repo_config = get_github_repo_config(config, repo_alias)
    search_query = f"{query} repo:{repo_config.owner}/{repo_config.repo} is:issue"
    if state != "all":
        search_query = f"{search_query} state:{state}"
    data = github_api_request(
        repo_alias,
        repo_config,
        "/search/issues",
        {"q": search_query, "per_page": min(100, max(1, limit))},
    )
    if not isinstance(data, dict):
        return []
    items = data.get("items", [])
    if not isinstance(items, list):
        return []
    return [item for item in items[:limit] if isinstance(item, dict) and "pull_request" not in item]


def github_read_issue(
    config: RedactionConfig,
    *,
    repo_alias: str,
    number: int,
) -> dict[str, object]:
    repo_config = get_github_repo_config(config, repo_alias)
    data = github_api_request(
        repo_alias,
        repo_config,
        f"/repos/{urllib.parse.quote(repo_config.owner, safe='')}/{urllib.parse.quote(repo_config.repo, safe='')}/issues/{number}",
        {},
    )
    if not isinstance(data, dict) or "pull_request" in data:
        raise SystemExit("GitHub issue was not found.")
    return data


def github_read_issue_comments(
    config: RedactionConfig,
    *,
    repo_alias: str,
    number: int,
    limit: int,
) -> list[dict[str, object]]:
    repo_config = get_github_repo_config(config, repo_alias)
    data = github_api_request(
        repo_alias,
        repo_config,
        f"/repos/{urllib.parse.quote(repo_config.owner, safe='')}/{urllib.parse.quote(repo_config.repo, safe='')}/issues/{number}/comments",
        {"per_page": min(100, max(1, limit))},
    )
    if not isinstance(data, list):
        return []
    return [item for item in data[:limit] if isinstance(item, dict)]


def github_label_names(issue: dict[str, object]) -> tuple[str, ...]:
    raw_labels = issue.get("labels", [])
    labels: list[str] = []
    if isinstance(raw_labels, list):
        for label in raw_labels:
            if isinstance(label, dict):
                name = str(label.get("name", "")).strip()
            else:
                name = str(label).strip()
            if name:
                labels.append(name)
    return tuple(labels)


def count_github_assignees(issue: dict[str, object]) -> int:
    assignees = issue.get("assignees", [])
    return len(assignees) if isinstance(assignees, list) else 0


def opaque_github_user(user: object, config: RedactionConfig, repo_alias: str) -> str:
    if not isinstance(user, dict):
        return "user_unknown"
    login = str(user.get("login", "")).strip()
    if not login:
        return "user_unknown"
    digest = hmac.new(
        config.salt.encode("utf-8"),
        f"github-user:{repo_alias}:{login}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()[:16]
    return f"user_{digest}"
