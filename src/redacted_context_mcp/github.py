"""Read-only GitHub issue access through neutral repo aliases."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .defaults import SYSTEM_CA_CANDIDATES
from .models import GitHubRepoConfig, RedactionConfig
from .redaction import Redactor

def get_github_repo_config(config: RedactionConfig, alias: str) -> GitHubRepoConfig:
    repo_config = config.github_repos.get(alias)
    if repo_config is None:
        raise SystemExit("Unknown GitHub repo alias.")
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
            body = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        exc.read()
        raise SystemExit(
            f"GitHub request failed for repo alias '{repo_alias}' ({exc.code}). "
            f"Check that the repo alias is configured and {repo_config.token_env} has access."
        ) from exc
    except urllib.error.URLError as exc:
        raise SystemExit(format_github_url_error(exc)) from exc

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


def format_github_issue_summary(repo_alias: str, issue: dict[str, object], redactor: Redactor) -> str:
    number = str(issue.get("number", "?"))
    state = redactor.redact(str(issue.get("state", "")))
    updated = redactor.redact(str(issue.get("updated_at", "")))
    title = redactor.redact(str(issue.get("title", "")))
    labels = format_github_labels(issue, redactor)
    comments = str(issue.get("comments", 0))
    return f"{repo_alias}#{number}\tstate={state}\tupdated={updated}\tcomments={comments}\tlabels={labels}\tuntrusted_title={title}"


def format_github_issue_detail(
    repo_alias: str,
    issue: dict[str, object],
    comments: list[dict[str, object]],
    redactor: Redactor,
    *,
    max_body_chars: int,
) -> str:
    number = str(issue.get("number", "?"))
    title = redactor.redact(str(issue.get("title", "")))
    body = truncate_text(redactor.redact(str(issue.get("body") or "")), max_body_chars)
    lines = [
        f"repo: {repo_alias}",
        f"issue: #{number}",
        f"state: {redactor.redact(str(issue.get('state', '')))}",
        f"title: {title}",
        f"created_at: {redactor.redact(str(issue.get('created_at', '')))}",
        f"updated_at: {redactor.redact(str(issue.get('updated_at', '')))}",
        f"labels: {format_github_labels(issue, redactor)}",
        f"assignees: {count_github_assignees(issue)}",
        "",
        "body_untrusted_external:",
        body,
    ]
    for index, comment in enumerate(comments, start=1):
        comment_body = truncate_text(redactor.redact(str(comment.get("body") or "")), max_body_chars)
        lines.extend(
            [
                "",
                f"comment {index}:",
                f"created_at: {redactor.redact(str(comment.get('created_at', '')))}",
                f"author: {opaque_github_user(comment.get('user'), redactor.config, repo_alias)}",
                "comment_untrusted_external:",
                comment_body,
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def format_github_labels(issue: dict[str, object], redactor: Redactor) -> str:
    raw_labels = issue.get("labels", [])
    labels: list[str] = []
    if isinstance(raw_labels, list):
        for label in raw_labels:
            if isinstance(label, dict):
                name = str(label.get("name", "")).strip()
            else:
                name = str(label).strip()
            if name:
                labels.append(redactor.redact(name))
    return ", ".join(labels) if labels else "-"


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


def truncate_text(text: str, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n[TRUNCATED]\n"
