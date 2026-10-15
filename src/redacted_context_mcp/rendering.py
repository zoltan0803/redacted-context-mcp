"""Redaction boundary for structured source records.

Sources return raw text and opaque references; this module turns structured
records into output text and redacts every content field on the way out. It
is shared by the ``redctx`` CLI and the MCP server so both surfaces render
identical, already-redacted text.

The ``*_text`` entry points validate every argument before touching the
source, make the source call, and format the returned records. The
``render_*`` functions only format.

Mail content is always redacted with a mail redactor derived from the active
``Redactor`` (``Redactor.for_mail``) over every identity harvested from the
configured mailboxes, never with the base redactor, so a correspondent's name
is caught wherever it appears. ``MailRedactorCache`` lets a long-running
server reuse one mail redactor until the identities or the policy change. A
call that reads through a forwarded message adds that message's identities
as body terms for that call only, in an uncached redactor.
"""

from __future__ import annotations

import threading
from typing import Sequence

from .defaults import PLACEHOLDER_RE
from .github import (
    UNKNOWN_REPO_ALIAS_MESSAGE,
    GitHubComment,
    GitHubIssue,
    GitHubSource,
    validate_github_state,
    validate_nonnegative_limit,
    validate_positive_limit,
)
from .limits import OperationBudget
from .mail import (
    GLOB_MESSAGE,
    LIMIT_MAX_MESSAGE,
    LIMIT_MIN_MESSAGE,
    MAIL_LIST_MAX_LIMIT,
    MAIL_THREAD_MAX_MESSAGES,
    OFFSET_MESSAGE,
    THREAD_MAX_MESSAGE,
    THREAD_MIN_MESSAGE,
    UNKNOWN_MAILBOX_MESSAGE,
    MailAddress,
    MailMessage,
    MailSource,
    MailSummary,
    parse_date_filter,
)
from .models import UNKNOWN_REFERENCE_MESSAGE
from .redaction import Redactor
from .retrieval import retrieve, validate_retrieval_arguments

# Mail retrieval limits: messages and total raw bytes read per call. The
# per-message cap is the largest configured ``max_message_bytes``; each
# mailbox still enforces its own cap when a message is read.
MAIL_RETRIEVE_MAX_MESSAGES = 5_000
MAIL_RETRIEVE_MAX_TOTAL_BYTES = 500_000_000


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


# Historical name, kept importable as an alias of the placeholder-safe version.
truncate_text = truncate_redacted


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
    body = truncate_redacted(redactor.redact(issue.body), max_body_chars)
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
        comment_body = truncate_redacted(redactor.redact(comment.body), max_body_chars)
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


# Mail -------------------------------------------------------------------------


class MailRedactorCache:
    """One mail redactor per (base redactor, harvested identities).

    Building a mail redactor compiles a pattern over every harvested identity,
    which is slow for large mailboxes. The MCP server keeps one cache and
    clears it whenever the policy reloads; the CLI builds one per call.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._base: Redactor | None = None
        self._identities: tuple[tuple[str, str], ...] | None = None
        self._mail: Redactor | None = None

    def get(self, redactor: Redactor, identities: tuple[tuple[str, str], ...]) -> Redactor:
        with self._lock:
            if self._mail is not None and self._base is redactor and self._identities == identities:
                return self._mail
        mail = redactor.for_mail(identities)
        with self._lock:
            self._base, self._identities, self._mail = redactor, identities, mail
        return mail

    def clear(self) -> None:
        with self._lock:
            self._base = self._identities = self._mail = None


def mail_redactor(
    source: MailSource,
    redactor: Redactor,
    cache: MailRedactorCache | None = None,
    budget: OperationBudget | None = None,
    *,
    nested: Sequence[tuple[str, str]] = (),
) -> Redactor:
    """The mail redactor over every identity in every configured mailbox.

    ``nested`` pairs come from the forwarded messages one call reads. Any
    that are not already harvested are added as unlinked body terms in a
    call-local redactor that is never cached; otherwise the usual mail
    redactor is returned.
    """
    identities = source.identities(budget)
    extra = tuple(sorted(set(nested) - set(identities)))
    if extra:
        return redactor.for_mail(identities, unlinked=extra)
    if cache is None:
        return redactor.for_mail(identities)
    return cache.get(redactor, identities)


def collapse_whitespace(value: str) -> str:
    """Join whitespace runs (newlines and tabs included) into single spaces."""
    return " ".join(value.split())


def render_mail_identity(identity: MailAddress, redactor: Redactor) -> str:
    """``<name> <<address>>`` from structural placeholders; either part may be absent."""
    name = redactor.mail_name_placeholder(identity.name) if identity.name else ""
    address = redactor.mail_address_placeholder(identity.address) if identity.address else ""
    if name and address:
        return f"{name} <{address}>"
    if address:
        return f"<{address}>"
    return name


def render_mail_identities(value: tuple[MailAddress, ...] | None, redactor: Redactor) -> str:
    """Comma-separated identities, ``[unparsed]`` for a header that did not parse, ``-`` for none."""
    if value is None:
        return "[unparsed]"
    rendered = [text for text in (render_mail_identity(identity, redactor) for identity in value) if text]
    return ", ".join(rendered) if rendered else "-"


def render_mail_subject(subject: str, redactor: Redactor) -> str:
    # Collapse first so a folded or hostile subject stays on one line.
    return redactor.redact(collapse_whitespace(subject))


def render_mail_summary(summary: MailSummary, redactor: Redactor) -> str:
    sender = render_mail_identities(summary.sender, redactor)
    subject = render_mail_subject(summary.subject, redactor)
    return (
        f"{summary.ref}\tmailbox={summary.mailbox}\tdate={summary.date}\tfrom={sender}"
        f"\tthread={summary.thread}\tuntrusted_subject={subject}"
    )


def render_mail_message(message: MailMessage, redactor: Redactor, *, max_body_chars: int) -> str:
    if message.nested_depth:
        # A forwarded message is addressed only by its attachment ref: it has
        # no message ref, mailbox, or thread links of its own.
        lines = [f"attachment: {message.ref}", f"nested_message_depth: {message.nested_depth}"]
    else:
        lines = [f"message: {message.ref}", f"mailbox: {message.mailbox}"]
    lines.append(f"date: {message.date}")
    for field_name, value in message.addresses:
        lines.append(f"{field_name}: {render_mail_identities(value, redactor)}")
    if not message.nested_depth:
        lines.append(f"thread: {message.thread}")
        if message.in_reply_to:
            lines.append(f"in_reply_to: {', '.join(message.in_reply_to)}")
        if message.references:
            lines.append(f"references: {', '.join(message.references)}")
    lines.append(f"untrusted_subject: {render_mail_subject(message.subject, redactor)}")
    lines.append(f"attachments: {len(message.attachments)}")
    for number, attachment in enumerate(message.attachments, start=1):
        filename = collapse_whitespace(attachment.filename)
        name = redactor.mail_filename(filename) if filename else "-"
        # The MIME type is syntactically validated but sender-chosen, so it
        # is redacted as content like the subject.
        content_type = redactor.redact(attachment.content_type)
        lines.append(
            f"attachment {number}: {attachment.ref} type={content_type} "
            f"size={attachment.size} name={name}"
        )
    body = truncate_redacted(redactor.redact(message.body), max_body_chars)
    lines.extend(["", "body_untrusted_external:", body])
    return "\n".join(lines).rstrip() + "\n"


def render_mail_thread(messages: list[MailMessage], total: int, redactor: Redactor, *, max_body_chars: int) -> str:
    parts = [f"thread_messages: {len(messages)} of {total}\n"]
    for index, message in enumerate(messages, start=1):
        parts.append(f"--- message {index} ---\n")
        parts.append(render_mail_message(message, redactor, max_body_chars=max_body_chars))
    if total > len(messages):
        parts.append(f"[more: {total - len(messages)} messages in thread; increase max_messages]\n")
    return "".join(parts)


def require_mail_source(source: MailSource | None, message: str) -> MailSource:
    # With no configured mailboxes every alias and ref is unknown; keep the
    # messages the per-alias and per-ref lookups use.
    if source is None:
        raise SystemExit(message)
    return source


def validate_mail_list_arguments(limit: int, offset: int, since: str, until: str) -> None:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise SystemExit(LIMIT_MIN_MESSAGE)
    if limit > MAIL_LIST_MAX_LIMIT:
        raise SystemExit(LIMIT_MAX_MESSAGE)
    if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        raise SystemExit(OFFSET_MESSAGE)
    parse_date_filter(since)
    parse_date_filter(until)


def validate_mail_thread_limit(max_messages: int) -> None:
    if not isinstance(max_messages, int) or isinstance(max_messages, bool) or max_messages < 1:
        raise SystemExit(THREAD_MIN_MESSAGE)
    if max_messages > MAIL_THREAD_MAX_MESSAGES:
        raise SystemExit(THREAD_MAX_MESSAGE)


def mail_sources_text(source: MailSource | None) -> str:
    """``<alias>\\tformat=<format>`` per configured mailbox, or ``""`` when none."""
    if source is None:
        return ""
    return "".join(f"{alias}\tformat={mail_format}\n" for alias, mail_format in source.mailboxes())


def mail_list_text(
    source: MailSource | None,
    redactor: Redactor,
    *,
    mailbox: str | None,
    limit: int,
    offset: int,
    since: str = "",
    until: str = "",
    cache: MailRedactorCache | None = None,
) -> str:
    """Redacted message summaries, newest first, or ``""`` when the page is empty."""
    validate_mail_list_arguments(limit, offset, since, until)
    source = require_mail_source(source, UNKNOWN_MAILBOX_MESSAGE)
    page, total = source.list_messages(mailbox, limit=limit, offset=offset, since=since, until=until)
    if not page:
        return ""
    mail = mail_redactor(source, redactor, cache)
    lines = [render_mail_summary(summary, mail) + "\n" for summary in page]
    shown = offset + len(page)
    if total > shown:
        lines.append(f"[more: {total - shown} messages; next offset={shown}]\n")
    return "".join(lines)


def mail_read_text(
    source: MailSource | None,
    redactor: Redactor,
    *,
    ref: str,
    include_quoted: bool = False,
    max_body_chars: int,
    cache: MailRedactorCache | None = None,
) -> str:
    max_body_chars = validate_positive_limit(max_body_chars, "--max-body-chars")
    source = require_mail_source(source, UNKNOWN_REFERENCE_MESSAGE)
    message = source.read_message(ref, include_quoted=include_quoted)
    return render_mail_message(message, mail_redactor(source, redactor, cache), max_body_chars=max_body_chars)


def mail_thread_text(
    source: MailSource | None,
    redactor: Redactor,
    *,
    ref: str,
    max_messages: int,
    include_quoted: bool = False,
    max_body_chars: int,
    cache: MailRedactorCache | None = None,
) -> str:
    validate_mail_thread_limit(max_messages)
    max_body_chars = validate_positive_limit(max_body_chars, "--max-body-chars")
    source = require_mail_source(source, UNKNOWN_REFERENCE_MESSAGE)
    messages, total = source.thread_messages(ref, max_messages=max_messages, include_quoted=include_quoted)
    mail = mail_redactor(source, redactor, cache)
    return render_mail_thread(messages, total, mail, max_body_chars=max_body_chars)


def mail_attachment_text(
    source: MailSource | None,
    redactor: Redactor,
    *,
    ref: str,
    include_quoted: bool = False,
    max_chars: int,
    cache: MailRedactorCache | None = None,
) -> str:
    """One attachment's redacted text, or a forwarded message rendered like ``mail_read_text``.

    ``include_quoted`` only affects forwarded messages; ``max_chars`` caps
    the attachment text or the forwarded message's body.
    """
    max_chars = validate_positive_limit(max_chars, "--max-chars")
    source = require_mail_source(source, UNKNOWN_REFERENCE_MESSAGE)
    content, nested = source.read_attachment_with_identities(ref, include_quoted=include_quoted)
    mail = mail_redactor(source, redactor, cache, nested=nested)
    if isinstance(content, MailMessage):
        return render_mail_message(content, mail, max_body_chars=max_chars)
    redacted = truncate_redacted(mail.redact(content), max_chars)
    # ``ref`` resolved above, so it is a well-formed opaque attachment ref.
    return f"attachment: {ref}\n\nattachment_untrusted_external:\n{redacted}".rstrip() + "\n"


def mail_retrieval_budget(source: MailSource, seconds: float | None) -> OperationBudget:
    caps = [mailbox.max_message_bytes for mailbox in source.config.mail_sources.values()]
    return OperationBudget.from_seconds(
        max_files=MAIL_RETRIEVE_MAX_MESSAGES,
        max_raw_bytes_per_file=max(caps) if caps else None,
        max_total_raw_bytes=MAIL_RETRIEVE_MAX_TOTAL_BYTES,
        seconds=seconds,
    )


def mail_retrieve_text(
    source: MailSource | None,
    redactor: Redactor,
    query: str,
    *,
    paths: Sequence[str],
    globs: Sequence[str],
    max_results: int,
    max_chars: int,
    seconds: float | None,
    cache: MailRedactorCache | None = None,
) -> str:
    """Ranked retrieval over mail, redacted with the mail redactor.

    ``paths`` are mailbox aliases or ``@m_`` message refs (default: every
    mailbox); glob patterns are refused. The scan is charged to the mail
    retrieval budget and fails closed when it is exceeded.
    """
    validate_retrieval_arguments(query, max_results=max_results, max_chars=max_chars)
    if globs:
        raise SystemExit(GLOB_MESSAGE)
    source = require_mail_source(source, UNKNOWN_MAILBOX_MESSAGE)
    for item in paths:
        if not isinstance(item, str) or not (item in source.config.mail_sources or item.startswith("@m_")):
            raise SystemExit(UNKNOWN_MAILBOX_MESSAGE)
    budget = mail_retrieval_budget(source, seconds)
    mail = mail_redactor(source, redactor, cache, budget)
    aliases = source.config.mail_sources

    def mailbox_alias(locator: str) -> str:
        # Mail locators are the configured aliases the agent already sees;
        # anything else is path-redacted like a file locator.
        return locator if locator in aliases else mail.redact_path(locator)

    return retrieve(
        source, mail, query, paths=list(paths), globs=[], budget=budget,
        max_results=max_results, max_chars=max_chars, display_locator=mailbox_alias,
    )
