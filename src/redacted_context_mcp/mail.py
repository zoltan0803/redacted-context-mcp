"""Read-only local mailbox source: mbox files, Maildir directories, and .eml files.

This module is the ``mail`` source adapter. It owns mail identity and
reference opaqueness: operator-chosen mailbox aliases instead of paths,
salted ``@m_<hex>`` message refs, and ``@m_<hex>/<n>`` attachment refs, with
``@m_<hex>/<n>/<k>`` paths into forwarded (``message/rfc822``) messages. It
opens mailbox files ``rb`` only and never locks, renames, flags, or writes
anything. It returns raw, untrusted header values, bodies, and attachment
text in structured records and never redacts content itself; ``rendering``
is the redaction boundary that formats those records for output.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import re
import stat
import threading
import time
from dataclasses import dataclass, field
from email import policy
from email.errors import ObsoleteHeaderDefect
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import BinaryIO, Callable, Iterator, Sequence

from . import documents
from .filesystem import is_reparse_point
from .limits import OperationBudget, OperationLimitError
from .models import UNKNOWN_REFERENCE_MESSAGE, MailSourceConfig, RedactionConfig, SourceDocument

MAIL_FORMATS = ("mbox", "maildir", "eml")
MAIL_ALIAS_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
DEFAULT_MAIL_MAX_MESSAGES = 50_000
MAX_MAIL_MAX_MESSAGES = 1_000_000
DEFAULT_MAIL_MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_MAIL_MAX_MESSAGE_BYTES = 1024 * 1024 * 1024
# Index limits: at most this much of each message's header block is read,
# the whole index build is bounded by a total header-byte cap and a deadline.
MAIL_HEADER_READ_BYTES = 256 * 1024
MAIL_INDEX_MAX_HEADER_BYTES = 1024 * 1024 * 1024
MAIL_INDEX_SECONDS = 120.0
MAIL_LIST_MAX_LIMIT = 500
MAIL_THREAD_MAX_MESSAGES = 50
MAIL_MAX_ATTACHMENTS = 9999
# Forwarded messages are readable this many levels deep; an attachment ref
# holds at most one more segment, for a leaf attachment of the deepest one.
MAIL_MAX_NESTED_DEPTH = 3
# Thread ids kept per In-Reply-To / References header, so one hostile header
# cannot blow up the in-memory index.
MAIL_MAX_THREAD_IDS = 256
MBOX_LINE_CHUNK = 64 * 1024

MESSAGE_REF_RE = re.compile(r"@m_([0-9a-f]{12})")
ATTACHMENT_REF_RE = re.compile(rf"@m_([0-9a-f]{{12}})((?:/[1-9][0-9]{{0,3}}){{1,{MAIL_MAX_NESTED_DEPTH + 1}}})")
# Attachment types read as a nested (forwarded) message.
NESTED_MESSAGE_TYPES = ("message/rfc822", "message/global")
# Transfer encodings RFC 2046 forbids on ``message/rfc822`` but some clients emit.
ENCODED_TRANSFER_ENCODINGS = ("base64", "quoted-printable")

MAILBOX_UNREADABLE_MESSAGE = "Mailbox could not be read."
MAILBOX_CHANGED_MESSAGE = "Mailbox changed during read. Retry."
UNKNOWN_MAILBOX_MESSAGE = "Unknown mailbox alias."
MESSAGE_LIMIT_MESSAGE = "Mailbox message limit exceeded."
HEADER_LIMIT_MESSAGE = "Mailbox header byte limit exceeded."
MESSAGE_BYTES_MESSAGE = "Mail message byte limit exceeded."
INDEX_DEADLINE_MESSAGE = "Operation deadline exceeded."
COLLISION_MESSAGE = "Mail reference collision."
DATE_FILTER_MESSAGE = "Mail date filters must be YYYY-MM-DD."
GLOB_MESSAGE = "Glob patterns are not supported for mail."
UNSUPPORTED_ATTACHMENT_MESSAGE = "Unsupported attachment type."
NESTED_DEPTH_MESSAGE = "Nested message depth limit exceeded."
NESTED_HEADER_MESSAGE = "Nested message header limit exceeded."
LIMIT_MIN_MESSAGE = "--limit must be at least 1."
LIMIT_MAX_MESSAGE = f"--limit must be at most {MAIL_LIST_MAX_LIMIT}."
OFFSET_MESSAGE = "--offset must be at least 0."
THREAD_MIN_MESSAGE = "--max-messages must be at least 1."
THREAD_MAX_MESSAGE = f"--max-messages must be at most {MAIL_THREAD_MAX_MESSAGES}."

# Every fixed message this module can raise (directly, from the caller's
# budget, or from document extraction). None of them interpolate input.
MAIL_SAFE_MESSAGES = frozenset({
    UNKNOWN_REFERENCE_MESSAGE,
    MAILBOX_UNREADABLE_MESSAGE,
    MAILBOX_CHANGED_MESSAGE,
    UNKNOWN_MAILBOX_MESSAGE,
    MESSAGE_LIMIT_MESSAGE,
    HEADER_LIMIT_MESSAGE,
    MESSAGE_BYTES_MESSAGE,
    INDEX_DEADLINE_MESSAGE,
    COLLISION_MESSAGE,
    DATE_FILTER_MESSAGE,
    GLOB_MESSAGE,
    UNSUPPORTED_ATTACHMENT_MESSAGE,
    NESTED_DEPTH_MESSAGE,
    NESTED_HEADER_MESSAGE,
    LIMIT_MIN_MESSAGE,
    LIMIT_MAX_MESSAGE,
    OFFSET_MESSAGE,
    THREAD_MIN_MESSAGE,
    THREAD_MAX_MESSAGE,
    "File limit exceeded.",
    "Raw file byte limit exceeded.",
    "Total raw byte limit exceeded.",
    documents.DISABLED_MESSAGE,
    *documents.SAFE_ERROR_MESSAGES,
})

ADDRESS_HEADERS = (
    ("from", "From"),
    ("sender", "Sender"),
    ("reply_to", "Reply-To"),
    ("to", "To"),
    ("cc", "Cc"),
    ("bcc", "Bcc"),
)
CONTENT_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}")
DOCUMENT_CONTENT_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel": ".xls",
}
# Invisible characters that could hide text or split a name or address:
# zero-width and bidi format characters, the soft hyphen, the combining
# grapheme joiner, the Arabic letter mark, invisible fillers, the Mongolian
# vowel separator, variation selectors, interlinear annotation characters,
# and tag characters.
INVISIBLE_RE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u180f\u200b-\u200f\u202a-\u202e"
    "\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
MESSAGE_ID_RE = re.compile(r"<([^<>]*)>")
DATE_FILTER_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
MBOXRD_ESCAPE_RE = re.compile(rb"^>(>*From )", re.MULTILINE)
BLANK_LINES = (b"\n", b"\r\n")


@dataclass(frozen=True)
class MailAddress:
    """One raw address-header identity. ``address`` is "" for a group label."""

    name: str
    address: str


@dataclass(frozen=True)
class MailAttachment:
    """One attachment part: opaque ref, validated MIME type, decoded size, raw filename."""

    ref: str
    content_type: str
    size: int
    filename: str


@dataclass(frozen=True)
class MailSummary:
    """One listed message. ``sender`` is ``None`` when From did not parse."""

    ref: str
    mailbox: str
    date: str
    timestamp: float | None
    thread: str
    sender: tuple[MailAddress, ...] | None
    subject: str
    size: int


@dataclass(frozen=True)
class MailMessage:
    """One read message: neutral refs plus raw, untrusted allow-listed fields.

    A forwarded message read through an attachment ref has ``nested_depth``
    1 or more, its attachment ref as ``ref``, and no mailbox, thread, or
    In-Reply-To and References refs.
    """

    ref: str
    mailbox: str
    date: str
    timestamp: float | None
    thread: str
    in_reply_to: tuple[str, ...]
    references: tuple[str, ...]
    addresses: tuple[tuple[str, tuple[MailAddress, ...] | None], ...]
    subject: str
    body: str
    attachments: tuple[MailAttachment, ...]
    size: int
    nested_depth: int = 0


@dataclass(frozen=True)
class MailIndexEntry:
    """One indexed message. Storage fields are private and never output."""

    ref: str
    mailbox: str
    position: int
    size: int
    timestamp: float | None
    date: str
    thread: str
    addresses: tuple[tuple[str, tuple[MailAddress, ...] | None], ...]
    subject: str
    # Normalized Message-ID, or a header-hash key for messages without one.
    identity: str = field(repr=False)
    in_reply_to_ids: tuple[str, ...] = field(repr=False)
    reference_ids: tuple[str, ...] = field(repr=False)
    storage: str = field(repr=False)
    offset: int = field(repr=False)
    stamp: tuple[int, int] = field(repr=False)


@dataclass(frozen=True)
class _MailboxIndex:
    fingerprint: tuple
    entries: tuple[MailIndexEntry, ...]


@dataclass(frozen=True)
class _MailView:
    indexes: tuple[_MailboxIndex, ...]
    # Unique refs, first occurrence in config order then storage order.
    ordered: tuple[MailIndexEntry, ...]
    by_ref: dict[str, MailIndexEntry]


class _IndexBudget:
    """Internal limits for one mailbox index build."""

    def __init__(self, max_messages: int, budget: OperationBudget | None) -> None:
        self.max_messages = max_messages
        self.budget = budget
        self.deadline = time.monotonic() + MAIL_INDEX_SECONDS
        self.messages = 0
        self.header_bytes = 0

    def tick(self) -> None:
        if time.monotonic() > self.deadline:
            raise OperationLimitError(INDEX_DEADLINE_MESSAGE)
        if self.budget is not None:
            self.budget.check_deadline()

    def message(self) -> None:
        self.tick()
        self.messages += 1
        if self.messages > self.max_messages:
            raise OperationLimitError(MESSAGE_LIMIT_MESSAGE)

    def headers(self, size: int) -> None:
        self.header_bytes += size
        if self.header_bytes > MAIL_INDEX_MAX_HEADER_BYTES:
            raise OperationLimitError(HEADER_LIMIT_MESSAGE)


class MailSource:
    """Read-only mail source for the configured ``[mail.sources.*]`` aliases."""

    name = "mail"
    untrusted_content = True
    supports_document_iteration = True

    def __init__(self, config: RedactionConfig, *, documents: bool = False) -> None:
        self.config = config
        self.documents = documents
        self._lock = threading.Lock()
        self._indexes: dict[str, _MailboxIndex] = {}
        self._view: _MailView | None = None

    @classmethod
    def from_config(cls, config: RedactionConfig, *, documents: bool = False) -> "MailSource | None":
        return cls(config, documents=documents) if config.mail_sources else None

    def mailboxes(self) -> list[tuple[str, str]]:
        return sorted((alias, source.format) for alias, source in self.config.mail_sources.items())

    # Reference contract ---------------------------------------------------

    def owns_reference(self, ref: str) -> bool:
        if not isinstance(ref, str):
            return False
        return MESSAGE_REF_RE.fullmatch(ref) is not None or ATTACHMENT_REF_RE.fullmatch(ref) is not None

    def resolve_reference(
        self, ref: str
    ) -> MailIndexEntry | tuple[MailIndexEntry, int] | tuple[MailIndexEntry, tuple[int, ...]]:
        """Resolve a message ref to its index entry, an attachment ref to ``(entry, n)``,
        or a nested attachment ref ``@m_<hex>/<n1>/<n2>...`` to ``(entry, (n1, n2, ...))``."""
        if not isinstance(ref, str):
            raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
        if MESSAGE_REF_RE.fullmatch(ref) is not None:
            return self._resolve_message(ref)
        entry, numbers, _part, _path = self._resolve_attachment(ref)
        return (entry, numbers[0]) if len(numbers) == 1 else (entry, numbers)

    def _resolve_attachment(
        self, ref: object
    ) -> tuple[MailIndexEntry, tuple[int, ...], Message, tuple[Message, ...]]:
        """Resolve an attachment ref; the message is read to check the part exists.

        Returns the entry, the ref's attachment numbers, the part, and the
        nested messages the path passes through, outermost first. Every
        segment but the last must name a readable nested message.
        """
        match = ATTACHMENT_REF_RE.fullmatch(ref) if isinstance(ref, str) else None
        if match is None:
            raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
        entry = self._resolve_message(f"@m_{match.group(1)}")
        numbers = tuple(int(segment) for segment in match.group(2)[1:].split("/"))
        message = parse_message(self._read_raw(entry))
        path: list[Message] = []
        for number in numbers[:-1]:
            message = nested_message(numbered_attachment(message, number))
            if message is None:
                raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
            check_nested_headers(message)
            path.append(message)
        return entry, numbers, numbered_attachment(message, numbers[-1]), tuple(path)

    def _resolve_message(self, ref: object, budget: OperationBudget | None = None) -> MailIndexEntry:
        if not isinstance(ref, str) or MESSAGE_REF_RE.fullmatch(ref) is None:
            raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
        entry = self._current_view(budget).by_ref.get(ref)
        if entry is None:
            raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
        return entry

    # Operations -------------------------------------------------------------

    def identities(self, budget: OperationBudget | None = None) -> tuple[tuple[str, str], ...]:
        """Every raw ``(display name, address)`` pair in every indexed message, sorted."""
        view = self._current_view(budget)
        pairs: set[tuple[str, str]] = set()
        for index in view.indexes:
            for entry in index.entries:
                pairs.update(address_pairs(entry.addresses))
        return tuple(sorted(pairs))

    def message_identities(
        self,
        refs: Sequence[str],
        *,
        headers: Sequence[str],
        budget: OperationBudget | None = None,
    ) -> tuple[tuple[str, str], ...]:
        """Raw ``(display name, address)`` pairs from the ``headers`` of the given messages.

        ``headers`` are ``ADDRESS_HEADERS`` keys such as ``"from"``. Pairs
        come in ``refs`` order, then header and address order; refs that are
        not indexed are skipped, and an unparsed header yields nothing. One
        index view serves every ref.
        """
        view = self._current_view(budget)
        pairs: list[tuple[str, str]] = []
        for ref in refs:
            entry = view.by_ref.get(ref)
            if entry is None:
                continue
            for name, value in entry.addresses:
                if name in headers:
                    pairs.extend((address.name, address.address) for address in value or ())
        return tuple(pairs)

    def list_messages(
        self,
        mailbox: str | None,
        *,
        limit: int,
        offset: int,
        since: str = "",
        until: str = "",
    ) -> tuple[list[MailSummary], int]:
        """List messages newest first. Returns the page and the matching total."""
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise SystemExit(LIMIT_MIN_MESSAGE)
        if limit > MAIL_LIST_MAX_LIMIT:
            raise SystemExit(LIMIT_MAX_MESSAGE)
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise SystemExit(OFFSET_MESSAGE)
        start = parse_date_filter(since)
        end = parse_date_filter(until)
        if mailbox is not None:
            self._config_for(mailbox)
        view = self._current_view(None)
        selected: list[MailIndexEntry] = []
        for entry in view.ordered:
            if mailbox is not None and entry.mailbox != mailbox:
                continue
            if start is not None or end is not None:
                if entry.timestamp is None:
                    continue
                if start is not None and entry.timestamp < start:
                    continue
                if end is not None and entry.timestamp >= end + 86400:
                    continue
            selected.append(entry)
        selected.sort(key=newest_first)
        page = selected[offset : offset + limit]
        return [summary_from_entry(entry) for entry in page], len(selected)

    def read_message(self, ref: str, *, include_quoted: bool = False) -> MailMessage:
        return self._message(self._resolve_message(ref), include_quoted=include_quoted)

    def thread_messages(
        self, ref: str, *, max_messages: int, include_quoted: bool = False
    ) -> tuple[list[MailMessage], int]:
        """Read the connected thread component of ``ref``, oldest first.

        Returns at most ``max_messages`` messages plus the component size.
        """
        if not isinstance(max_messages, int) or isinstance(max_messages, bool) or max_messages < 1:
            raise SystemExit(THREAD_MIN_MESSAGE)
        if max_messages > MAIL_THREAD_MAX_MESSAGES:
            raise SystemExit(THREAD_MAX_MESSAGE)
        entry = self._resolve_message(ref)
        view = self._current_view(None)
        members = thread_component(view.ordered, entry)
        members.sort(key=oldest_first)
        messages = [self._message(member, include_quoted=include_quoted) for member in members[:max_messages]]
        return messages, len(members)

    def read_attachment(self, ref: str, *, include_quoted: bool = False) -> str | MailMessage:
        """Return one attachment as raw text (text parts or extracted documents), or a nested message."""
        return self.read_attachment_with_identities(ref, include_quoted=include_quoted)[0]

    def read_attachment_with_identities(
        self, ref: str, *, include_quoted: bool = False
    ) -> tuple[str | MailMessage, tuple[tuple[str, str], ...]]:
        """``read_attachment`` plus the raw ``(display name, address)`` pairs of its nested path.

        The pairs come from the address headers of every nested message the
        ref passes through, the one read included, sorted. They never join
        ``identities``: a forwarded copy is sender-controlled, so the caller
        uses them for this call only.
        """
        _entry, numbers, part, path = self._resolve_attachment(ref)
        pairs: set[tuple[str, str]] = set()
        for message in path:
            pairs.update(address_pairs(header_fields(message)[2]))
        if safe_content_type(part) not in NESTED_MESSAGE_TYPES:
            return self._attachment_text(part), tuple(sorted(pairs))
        if len(numbers) > MAIL_MAX_NESTED_DEPTH:
            raise OperationLimitError(NESTED_DEPTH_MESSAGE)
        nested = nested_message(part)
        if nested is None:
            raise SystemExit(UNSUPPORTED_ATTACHMENT_MESSAGE)
        check_nested_headers(nested)
        record = nested_record(
            nested, ref, len(numbers), len(part_payload_bytes(part)), include_quoted=include_quoted
        )
        pairs.update(address_pairs(record.addresses))
        return record, tuple(sorted(pairs))

    def iter_documents(
        self,
        budget: OperationBudget,
        *,
        scope: Sequence[str] = (),
        patterns: Sequence[str] = (),
    ) -> Iterator[SourceDocument]:
        """Yield ``subject + collapsed body`` per message, newest first.

        ``scope`` entries are mailbox aliases or message refs (default: every
        mailbox). Each message is charged ``consume_document(raw size)``
        before it is read; exceeding a limit raises ``OperationLimitError``.
        """
        if patterns:
            raise SystemExit(GLOB_MESSAGE)
        aliases: set[str] = set()
        refs: list[str] = []
        for item in scope:
            if isinstance(item, str) and item in self.config.mail_sources:
                aliases.add(item)
            elif isinstance(item, str) and item.startswith("@m_"):
                refs.append(item)
            else:
                raise SystemExit(UNKNOWN_MAILBOX_MESSAGE)
        view = self._current_view(budget)
        if scope:
            chosen: dict[str, MailIndexEntry] = {}
            for ref in refs:
                entry = self._resolve_message(ref, budget)
                chosen[entry.ref] = entry
            for entry in view.ordered:
                if entry.mailbox in aliases:
                    chosen.setdefault(entry.ref, entry)
            selected = list(chosen.values())
        else:
            selected = list(view.ordered)
        selected.sort(key=newest_first)
        for entry in selected:
            budget.consume_document(entry.size)
            message = self._message(entry, include_quoted=False)
            yield SourceDocument(ref=entry.ref, locator=entry.mailbox, text=f"{message.subject}\n\n{message.body}")

    # Internals ----------------------------------------------------------------

    def _config_for(self, alias: object) -> MailSourceConfig:
        source = self.config.mail_sources.get(alias) if isinstance(alias, str) else None
        if source is None:
            raise SystemExit(UNKNOWN_MAILBOX_MESSAGE)
        return source

    def _attachment_text(self, part: Message) -> str:
        content_type = safe_content_type(part)
        if content_type.startswith("text/"):
            return clean_text(decode_text_part(part, charset_first=True))
        extension = document_extension(safe_filename(part), content_type)
        if extension is None:
            raise SystemExit(UNSUPPORTED_ATTACHMENT_MESSAGE)
        if not self.documents:
            raise SystemExit(documents.DISABLED_MESSAGE)
        return documents.extract_document(part_payload_bytes(part), extension)

    def _message(self, entry: MailIndexEntry, *, include_quoted: bool) -> MailMessage:
        message = parse_message(self._read_raw(entry))
        body, attachments = message_content(message, entry.ref, include_quoted=include_quoted)
        return MailMessage(
            ref=entry.ref,
            mailbox=entry.mailbox,
            date=entry.date,
            timestamp=entry.timestamp,
            thread=entry.thread,
            in_reply_to=self._id_refs(entry.in_reply_to_ids),
            references=self._id_refs(entry.reference_ids),
            addresses=entry.addresses,
            subject=entry.subject,
            body=body,
            attachments=attachments,
            size=entry.size,
        )

    def _id_refs(self, ids: Sequence[str]) -> tuple[str, ...]:
        refs: list[str] = []
        for value in ids:
            ref = message_ref(self.config.salt, value)
            if ref not in refs:
                refs.append(ref)
        return tuple(refs)

    def _current_view(self, budget: OperationBudget | None) -> _MailView:
        """Probe every mailbox, rebuilding changed indexes, and return the merged view."""
        with self._lock:
            indexes = tuple(
                self._mailbox_index_locked(alias, source, budget) for alias, source in self.config.mail_sources.items()
            )
            cached = self._view
            if cached is not None and len(cached.indexes) == len(indexes) and all(
                old is new for old, new in zip(cached.indexes, indexes)
            ):
                return cached
            view = build_view(indexes)
            self._view = view
            return view

    def _mailbox_index_locked(
        self, alias: str, source: MailSourceConfig, budget: OperationBudget | None
    ) -> _MailboxIndex:
        limits = _IndexBudget(source.max_messages, budget)
        fingerprint, listing = probe_mailbox(source, limits)
        cached = self._indexes.get(alias)
        if cached is not None and cached.fingerprint == fingerprint:
            return cached
        # Drop the stale index first: a failed rebuild must not leave it in use.
        self._indexes.pop(alias, None)
        self._view = None
        if source.format == "mbox":
            entries = index_mbox(alias, source, fingerprint, self.config.salt, limits)
        else:
            entries = index_files(alias, listing, self.config.salt, limits)
        index = _MailboxIndex(fingerprint=fingerprint, entries=tuple(entries))
        self._indexes[alias] = index
        return index

    def _read_raw(self, entry: MailIndexEntry) -> bytes:
        source = self._config_for(entry.mailbox)
        if entry.size > source.max_message_bytes:
            raise OperationLimitError(MESSAGE_BYTES_MESSAGE)
        path = Path(entry.storage)
        try:
            before = os.lstat(path)
        except OSError as exc:
            raise SystemExit(MAILBOX_CHANGED_MESSAGE) from exc
        if (
            not stat.S_ISREG(before.st_mode)
            or is_reparse_point(path)
            or stamp_of(before) != entry.stamp
        ):
            raise SystemExit(MAILBOX_CHANGED_MESSAGE)
        try:
            with open(path, "rb") as handle:
                opened = os.fstat(handle.fileno())
                if stamp_of(opened) != entry.stamp or not same_file(before, opened):
                    raise SystemExit(MAILBOX_CHANGED_MESSAGE)
                if source.format == "mbox":
                    handle.seek(entry.offset)
                    data = handle.read(entry.size)
                else:
                    data = handle.read(source.max_message_bytes + 1)
            after = os.lstat(path)
        except OSError as exc:
            raise SystemExit(MAILBOX_CHANGED_MESSAGE) from exc
        if stamp_of(after) != entry.stamp or not same_file(before, after):
            raise SystemExit(MAILBOX_CHANGED_MESSAGE)
        if len(data) > source.max_message_bytes:
            raise OperationLimitError(MESSAGE_BYTES_MESSAGE)
        if len(data) != entry.size:
            raise SystemExit(MAILBOX_CHANGED_MESSAGE)
        if source.format == "mbox":
            data = unescape_mboxrd(data)
        return data


# References -----------------------------------------------------------------


def mail_digest(salt: str, message: str) -> str:
    """First 12 hex digits of ``HMAC-SHA256(salt, message)``."""
    return hmac.new(
        salt.encode("utf-8"),
        message.encode("utf-8", "surrogatepass"),
        hashlib.sha256,
    ).hexdigest()[:12]


def message_ref(salt: str, message_id: str) -> str:
    """Ref for a normalized Message-ID, whether or not that message is indexed."""
    return f"@m_{mail_digest(salt, 'mail-message:' + message_id)}"


def header_block_ref(salt: str, header_sha256: str) -> str:
    """Fallback ref for a message without a usable Message-ID."""
    return f"@m_{mail_digest(salt, 'mail-message-headers:' + header_sha256)}"


def normalize_message_id(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value.startswith("<") and value.endswith(">"):
        value = value[1:-1].strip()
    return value


def build_view(indexes: tuple[_MailboxIndex, ...]) -> _MailView:
    """Merge mailbox indexes: first occurrence of a ref wins; collisions fail closed."""
    identities: dict[str, str] = {}
    by_ref: dict[str, MailIndexEntry] = {}
    ordered: list[MailIndexEntry] = []
    for index in indexes:
        for entry in index.entries:
            known = identities.setdefault(entry.ref, entry.identity)
            if known != entry.identity:
                raise SystemExit(COLLISION_MESSAGE)
            if entry.ref not in by_ref:
                by_ref[entry.ref] = entry
                ordered.append(entry)
    return _MailView(indexes=indexes, ordered=tuple(ordered), by_ref=by_ref)


def thread_component(entries: Sequence[MailIndexEntry], target: MailIndexEntry) -> list[MailIndexEntry]:
    """Entries connected to ``target`` through Message-ID, In-Reply-To, and References ids."""
    parent: dict[str, str] = {}

    def find(node: str) -> str:
        parent.setdefault(node, node)
        root = node
        while parent[root] != root:
            root = parent[root]
        while parent[node] != root:
            parent[node], node = root, parent[node]
        return root

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[right_root] = left_root

    for entry in entries:
        find(entry.identity)
        for linked in (*entry.in_reply_to_ids, *entry.reference_ids):
            union(entry.identity, linked)
    root = find(target.identity)
    return [entry for entry in entries if find(entry.identity) == root]


def newest_first(entry: MailIndexEntry) -> tuple[bool, float, str]:
    return (entry.timestamp is None, -(entry.timestamp or 0.0), entry.ref)


def oldest_first(entry: MailIndexEntry) -> tuple[bool, float, str]:
    return (entry.timestamp is None, entry.timestamp or 0.0, entry.ref)


def summary_from_entry(entry: MailIndexEntry) -> MailSummary:
    sender: tuple[MailAddress, ...] | None = ()
    for name, value in entry.addresses:
        if name == "from":
            sender = value
            break
    return MailSummary(
        ref=entry.ref,
        mailbox=entry.mailbox,
        date=entry.date,
        timestamp=entry.timestamp,
        thread=entry.thread,
        sender=sender,
        subject=entry.subject,
        size=entry.size,
    )


def parse_date_filter(value: str) -> float | None:
    """UTC midnight timestamp for a ``YYYY-MM-DD`` filter, or ``None`` when empty."""
    if value == "":
        return None
    if not isinstance(value, str) or DATE_FILTER_RE.fullmatch(value) is None:
        raise SystemExit(DATE_FILTER_MESSAGE)
    try:
        day = dt.date.fromisoformat(value)
    except ValueError as exc:
        raise SystemExit(DATE_FILTER_MESSAGE) from exc
    return dt.datetime(day.year, day.month, day.day, tzinfo=dt.timezone.utc).timestamp()


# Reading ----------------------------------------------------------------------


def safe_lstat(path: Path) -> os.stat_result:
    """``lstat`` that refuses links and reparse points with an input-free message."""
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise SystemExit(MAILBOX_UNREADABLE_MESSAGE) from exc
    if stat.S_ISLNK(info.st_mode) or is_reparse_point(path):
        raise SystemExit(MAILBOX_UNREADABLE_MESSAGE)
    return info


def stamp_of(info: os.stat_result) -> tuple[int, int]:
    return (int(info.st_size), int(info.st_mtime_ns))


def same_file(left: os.stat_result, right: os.stat_result) -> bool:
    # Some platforms report zero inode numbers; only compare real ones.
    if left.st_ino and right.st_ino:
        return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)
    return True


def probe_mailbox(source: MailSourceConfig, limits: _IndexBudget) -> tuple[tuple, list[tuple[str, str, int, int]]]:
    """Return the mailbox metadata fingerprint plus, for directories, the message files.

    The listing holds ``(relative name, path, size, mtime_ns)`` in storage
    order. Nothing is opened for reading here.
    """
    path = Path(source.path)
    info = safe_lstat(path)
    if source.format == "mbox":
        if not stat.S_ISREG(info.st_mode):
            raise SystemExit(MAILBOX_UNREADABLE_MESSAGE)
        return ("mbox", *stamp_of(info)), []
    if source.format == "maildir":
        if not stat.S_ISDIR(info.st_mode):
            raise SystemExit(MAILBOX_UNREADABLE_MESSAGE)
        listing = list_maildir(path, limits)
    elif stat.S_ISREG(info.st_mode):
        listing = [(path.name, str(path), *stamp_of(info))]
    elif stat.S_ISDIR(info.st_mode):
        listing = list_eml_tree(path, limits)
    else:
        raise SystemExit(MAILBOX_UNREADABLE_MESSAGE)
    fingerprint = (source.format, tuple((rel, size, mtime) for rel, _path, size, mtime in listing))
    return fingerprint, listing


def scan_directory(path: Path, limits: _IndexBudget) -> list[tuple[str, Path, os.stat_result]]:
    """Plain entries of one directory: no dot-entries, links, or reparse points."""
    found: list[tuple[str, Path, os.stat_result]] = []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                limits.tick()
                if entry.name.startswith("."):
                    continue
                child = Path(entry.path)
                if entry.is_symlink() or is_reparse_point(child):
                    continue
                found.append((entry.name, child, entry.stat(follow_symlinks=False)))
    except OSError as exc:
        raise SystemExit(MAILBOX_UNREADABLE_MESSAGE) from exc
    return found


def list_maildir(path: Path, limits: _IndexBudget) -> list[tuple[str, str, int, int]]:
    """Regular files directly in ``cur/`` and ``new/`` (never ``tmp/``), sorted by name."""
    items: list[tuple[str, str, str, int, int]] = []
    for folder in ("cur", "new"):
        folder_path = path / folder
        try:
            info = os.lstat(folder_path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise SystemExit(MAILBOX_UNREADABLE_MESSAGE) from exc
        if not stat.S_ISDIR(info.st_mode) or is_reparse_point(folder_path):
            continue
        for name, child, child_info in scan_directory(folder_path, limits):
            if stat.S_ISREG(child_info.st_mode):
                items.append((name, folder, str(child), *stamp_of(child_info)))
    items.sort(key=lambda item: (item[0], item[1]))
    return [(f"{folder}/{name}", child, size, mtime) for name, folder, child, size, mtime in items]


def list_eml_tree(path: Path, limits: _IndexBudget) -> list[tuple[str, str, int, int]]:
    """``*.eml`` files under ``path`` (recursive, case-insensitive), sorted by relative path."""
    items: list[tuple[str, str, int, int]] = []
    pending: list[tuple[Path, str]] = [(path, "")]
    while pending:
        folder, prefix = pending.pop()
        for name, child, info in scan_directory(folder, limits):
            rel = f"{prefix}{name}"
            if stat.S_ISDIR(info.st_mode):
                pending.append((child, f"{rel}/"))
            elif stat.S_ISREG(info.st_mode) and name.casefold().endswith(".eml"):
                items.append((rel, str(child), *stamp_of(info)))
    items.sort(key=lambda item: item[0])
    return items


def index_mbox(
    alias: str, source: MailSourceConfig, fingerprint: tuple, salt: str, limits: _IndexBudget
) -> list[MailIndexEntry]:
    path = Path(source.path)
    stamp = (int(fingerprint[1]), int(fingerprint[2]))
    entries: list[MailIndexEntry] = []
    try:
        with open(path, "rb") as handle:
            if stamp_of(os.fstat(handle.fileno())) != stamp:
                raise SystemExit(MAILBOX_CHANGED_MESSAGE)
            for offset, length, header in scan_mbox(handle, limits):
                limits.headers(len(header))
                entries.append(
                    index_entry(alias, len(entries), str(path), offset, length, stamp, unescape_mboxrd(header), salt)
                )
        after = os.lstat(path)
    except OSError as exc:
        raise SystemExit(MAILBOX_UNREADABLE_MESSAGE) from exc
    if stamp_of(after) != stamp:
        raise SystemExit(MAILBOX_CHANGED_MESSAGE)
    return entries


def scan_mbox(handle: BinaryIO, limits: _IndexBudget) -> Iterator[tuple[int, int, bytes]]:
    """Split an mbox at ``From `` lines, yielding ``(offset, length, header block)``.

    The ``From `` line is not part of a message, and the single blank line
    before the next ``From `` line (or end of file) is dropped, like the
    stdlib reader. Leading blank lines are tolerated; any other content
    before the first ``From `` line makes the file unreadable.
    """
    position = 0
    at_line_start = True
    in_from_line = False
    start: int | None = None
    last_blank = -1
    header = bytearray()
    header_open = False
    lines = 0
    while True:
        chunk = handle.readline(MBOX_LINE_CHUNK)
        if not chunk:
            break
        chunk_start = position
        position += len(chunk)
        line_start = at_line_start
        at_line_start = chunk.endswith(b"\n")
        lines += 1
        if lines % 4096 == 0:
            limits.tick()
        if in_from_line:
            # Remainder of an over-long ``From `` line.
            start = position
            in_from_line = not at_line_start
            continue
        if line_start and chunk.startswith(b"From "):
            if start is not None:
                end = last_blank if last_blank != -1 else chunk_start
                yield start, end - start, bytes(header)
            limits.message()
            start = position
            in_from_line = not at_line_start
            last_blank = -1
            header = bytearray()
            header_open = True
            continue
        blank = line_start and chunk in BLANK_LINES
        if start is None:
            if not blank:
                raise SystemExit(MAILBOX_UNREADABLE_MESSAGE)
            continue
        last_blank = chunk_start if blank else -1
        if header_open:
            if blank:
                header_open = False
            else:
                header.extend(chunk)
                if len(header) >= MAIL_HEADER_READ_BYTES:
                    del header[MAIL_HEADER_READ_BYTES:]
                    header_open = False
    if start is not None:
        end = last_blank if last_blank != -1 else position
        yield start, end - start, bytes(header)


def unescape_mboxrd(data: bytes) -> bytes:
    """Unescape ``>From `` lines (``^>+From ``) by one level."""
    return MBOXRD_ESCAPE_RE.sub(rb"\1", data)


def index_files(
    alias: str, listing: list[tuple[str, str, int, int]], salt: str, limits: _IndexBudget
) -> list[MailIndexEntry]:
    entries: list[MailIndexEntry] = []
    for _rel, path, size, mtime in listing:
        limits.message()
        header = read_header_block(Path(path), (size, mtime))
        limits.headers(len(header))
        entries.append(index_entry(alias, len(entries), path, 0, size, (size, mtime), header, salt))
    return entries


def read_header_block(path: Path, stamp: tuple[int, int]) -> bytes:
    """Read at most ``MAIL_HEADER_READ_BYTES`` of one message file's header block."""
    before = safe_lstat(path)
    if not stat.S_ISREG(before.st_mode) or stamp_of(before) != stamp:
        raise SystemExit(MAILBOX_CHANGED_MESSAGE)
    data = bytearray()
    try:
        with open(path, "rb") as handle:
            while len(data) < MAIL_HEADER_READ_BYTES:
                chunk = handle.read(min(16 * 1024, MAIL_HEADER_READ_BYTES - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if data.startswith(BLANK_LINES) or b"\n\n" in data or b"\n\r\n" in data:
                    break
    except OSError as exc:
        raise SystemExit(MAILBOX_UNREADABLE_MESSAGE) from exc
    return header_block(bytes(data[:MAIL_HEADER_READ_BYTES]))


def header_block(data: bytes) -> bytes:
    """Header lines of ``data`` up to (not including) the first blank line."""
    kept: list[bytes] = []
    for line in data.splitlines(keepends=True):
        if line.rstrip(b"\r\n") == b"":
            break
        kept.append(line)
    return b"".join(kept)


# Header policy ------------------------------------------------------------------


def index_entry(
    alias: str,
    position: int,
    storage: str,
    offset: int,
    size: int,
    stamp: tuple[int, int],
    header: bytes,
    salt: str,
) -> MailIndexEntry:
    """Build one index entry from a raw header block, keeping only allow-listed fields."""
    message = parse_headers(header)
    message_id = ""
    in_reply_to: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    timestamp: float | None = None
    date = "?"
    subject = ""
    addresses: tuple[tuple[str, tuple[MailAddress, ...] | None], ...] = ()
    if message is not None:
        message_id = normalize_message_id(clean_text(first_header_text(message, "Message-ID")))
        in_reply_to = message_id_list(message, "In-Reply-To")
        references = message_id_list(message, "References")
        timestamp, date, addresses, subject = header_fields(message)
    if message_id:
        identity = message_id
        ref = message_ref(salt, message_id)
    else:
        digest = hashlib.sha256(header.replace(b"\r\n", b"\n")).hexdigest()
        # The NUL prefix keeps header keys apart from real Message-IDs.
        identity = f"\0headers:{digest}"
        ref = header_block_ref(salt, digest)
    if references:
        thread = message_ref(salt, references[0])
    elif in_reply_to:
        thread = message_ref(salt, in_reply_to[0])
    else:
        thread = ref
    return MailIndexEntry(
        ref=ref,
        mailbox=alias,
        position=position,
        size=size,
        timestamp=timestamp,
        date=date,
        thread=thread,
        addresses=addresses,
        subject=subject,
        identity=identity,
        in_reply_to_ids=in_reply_to,
        reference_ids=references,
        storage=storage,
        offset=offset,
        stamp=stamp,
    )


def header_fields(
    message: Message,
) -> tuple[float | None, str, tuple[tuple[str, tuple[MailAddress, ...] | None], ...], str]:
    """The allow-listed fields of a parsed header block: ``(timestamp, date, addresses, subject)``.

    Indexed and nested messages both take their fields from here, so the two
    header policies cannot drift apart. ``addresses`` holds each present
    address header in ``ADDRESS_HEADERS`` order.
    """
    timestamp, date = parse_date_header(message)
    addresses: list[tuple[str, tuple[MailAddress, ...] | None]] = []
    for key, header_name in ADDRESS_HEADERS:
        present, value = parse_address_header(message, header_name)
        if present:
            addresses.append((key, value))
    subject = clean_text(first_header_text(message, "Subject"))
    return timestamp, date, tuple(addresses), subject


def address_pairs(addresses: Sequence[tuple[str, tuple[MailAddress, ...] | None]]) -> set[tuple[str, str]]:
    """Raw ``(display name, address)`` pairs of parsed address headers; unparsed ones add nothing."""
    return {(address.name, address.address) for _name, value in addresses for address in value or ()}


def parse_headers(header: bytes) -> Message | None:
    try:
        return BytesParser(policy=policy.default).parsebytes(header.rstrip(b"\r\n") + b"\n\n", headersonly=True)
    except Exception:
        return None


def first_header_text(message: Message, name: str) -> str:
    try:
        values = message.get_all(name)
        return str(values[0]) if values else ""
    except Exception:
        return ""


def message_id_list(message: Message, name: str) -> tuple[str, ...]:
    """Normalized ids from every instance of ``name``, order kept, deduplicated."""
    try:
        values = [str(value) for value in message.get_all(name) or ()]
    except Exception:
        return ()
    ids: list[str] = []
    for value in values:
        value = clean_text(value)
        candidates = MESSAGE_ID_RE.findall(value) or [token for token in value.split() if "@" in token]
        for candidate in candidates:
            normalized = normalize_message_id(candidate)
            if normalized and normalized not in ids:
                ids.append(normalized)
    if len(ids) > MAIL_MAX_THREAD_IDS:
        # Keep the root (first) and the direct parent (last).
        ids = [*ids[: MAIL_MAX_THREAD_IDS - 1], ids[-1]]
    return tuple(ids)


def parse_date_header(message: Message) -> tuple[float | None, str]:
    """Parsed ``Date`` as a UTC timestamp and generated ISO string, or ``(None, "?")``."""
    try:
        values = message.get_all("Date")
        if not values:
            return None, "?"
        when = getattr(values[0], "datetime", None)
        if when is None:
            when = parsedate_to_datetime(str(values[0]))
    except Exception:
        return None, "?"
    return normalize_datetime(when)


def normalize_datetime(when: object) -> tuple[float | None, str]:
    if not isinstance(when, dt.datetime):
        return None, "?"
    try:
        if when.tzinfo is None:
            when = when.replace(tzinfo=dt.timezone.utc)
        when = when.astimezone(dt.timezone.utc)
        if not 1970 <= when.year <= 9999:
            return None, "?"
        return when.timestamp(), when.strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError, OSError):
        return None, "?"


def parse_address_header(message: Message, name: str) -> tuple[bool, tuple[MailAddress, ...] | None]:
    """Return ``(present, identities)``; identities are ``None`` when the header did not parse.

    The stdlib parser recovers from malformed input differently across
    Python versions (raising on one, returning ``<>`` placeholders on
    another), so a header counts as parsed only when it reports no defects
    other than obsolete syntax and every address has a local part and a
    domain. Valid group labels such as ``undisclosed-recipients:;`` stay.
    """
    try:
        values = message.get_all(name)
    except Exception:
        return True, None
    if not values:
        return False, None
    try:
        found: list[MailAddress] = []
        for value in values:
            if any(not isinstance(defect, ObsoleteHeaderDefect) for defect in value.defects):
                return True, None
            for group in value.groups:
                if group.display_name:
                    found.append(MailAddress(name=clean_text(group.display_name), address=""))
                for address in group.addresses:
                    if not address.username or not address.domain or address.addr_spec in ("", "<>"):
                        return True, None
                    display = clean_text(address.display_name or "")
                    spec = clean_text(address.addr_spec)
                    found.append(MailAddress(name=display, address=spec))
        return True, tuple(found)
    except Exception:
        return True, None


def clean_text(value: str) -> str:
    """Repair undecodable header bytes, drop invisible format characters, and use ``\\n`` newlines."""
    value = repair_surrogates(value)
    value = INVISIBLE_RE.sub("", value)
    return value.replace("\r\n", "\n").replace("\r", "\n")


def repair_surrogates(value: str) -> str:
    try:
        value.encode("utf-8")
        return value
    except UnicodeEncodeError:
        pass
    try:
        # Raw 8-bit header bytes arrive surrogate-escaped; most are UTF-8.
        return value.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    except UnicodeEncodeError:
        return value.encode("utf-8", "surrogatepass").decode("utf-8", "replace")


# Bodies and attachments -----------------------------------------------------------


class _ParsedMessage(EmailMessage):
    """An ``EmailMessage`` that leaves a transfer-encoded ``message/*`` part unparsed.

    The stdlib parser walks into every ``message/*`` part. When a client
    base64- or quoted-printable-encodes a forwarded message anyway, that
    parses the still-encoded text as a message without headers. Reporting
    such a part's main type as ``application`` keeps its encoded text as the
    payload, so ``get_payload(decode=True)`` recovers the forwarded message's
    bytes (see ``nested_message``). Its content type is unchanged.
    """

    def get_content_maintype(self) -> str:
        maintype = super().get_content_maintype()
        if maintype == "message" and transfer_encoded(self):
            return "application"
        return maintype


def parse_message(raw: bytes) -> Message | None:
    try:
        return BytesParser(_ParsedMessage, policy=policy.default).parsebytes(raw)
    except Exception:
        return None


def transfer_encoded(part: Message) -> bool:
    """Whether ``part`` declares a base64 or quoted-printable transfer encoding."""
    try:
        value = str(part.get("Content-Transfer-Encoding", "")).strip().lower()
    except Exception:
        return False
    return value in ENCODED_TRANSFER_ENCODINGS


def nested_message(part: Message) -> Message | None:
    """The forwarded message a ``message/rfc822`` or ``message/global`` part holds, or ``None``.

    A transfer-encoded part is decoded and parsed on its own. Reading a
    nested message and resolving a ref through it both go through here, so
    refs into a decoded message resolve against what it renders.
    """
    if safe_content_type(part) not in NESTED_MESSAGE_TYPES:
        return None
    try:
        if transfer_encoded(part):
            data = part.get_payload(decode=True)
            return parse_message(data) if isinstance(data, bytes) and data.strip() else None
        payload = part.get_payload()
    except Exception:
        return None
    if isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], Message):
        return payload[0]
    return None


def check_nested_headers(message: Message) -> None:
    """Fail closed when a nested message's header block exceeds ``MAIL_HEADER_READ_BYTES``.

    Top-level headers are bounded by the index's header read; nested headers
    come from the full parse of their outer message, so they get the same
    cap here, measured as raw header name and value bytes.
    """
    total = 0
    for name, value in message.raw_items():
        total += raw_header_length(name) + raw_header_length(value)
        if total > MAIL_HEADER_READ_BYTES:
            raise OperationLimitError(NESTED_HEADER_MESSAGE)


def raw_header_length(value: object) -> int:
    # Raw 8-bit header bytes arrive surrogate-escaped.
    text = str(value)
    try:
        return len(text.encode("utf-8", "surrogateescape"))
    except UnicodeEncodeError:
        return len(text.encode("utf-8", "surrogatepass"))


def message_content(
    message: Message | None, ref: str, *, include_quoted: bool
) -> tuple[str, tuple[MailAttachment, ...]]:
    """Body text, quotes collapsed unless ``include_quoted``, and attachments with ``<ref>/<n>`` refs."""
    body = ""
    attachments: tuple[MailAttachment, ...] = ()
    if message is not None:
        body_part = select_body_part(message)
        body = body_text(body_part)
        attachments = tuple(
            attachment_record(part, f"{ref}/{number}")
            for number, part in enumerate(attachment_parts(message, body_part), start=1)
        )
    if not include_quoted:
        body = collapse_quotes(body)
    return body, attachments


def nested_record(message: Message, ref: str, depth: int, size: int, *, include_quoted: bool) -> MailMessage:
    """A nested message addressed only by its attachment ref.

    Its Message-ID, In-Reply-To, and References are never read: a forwarded
    copy is sender-controlled, so refs minted from them would let it pose as,
    or thread into, an indexed message.
    """
    timestamp, date, addresses, subject = header_fields(message)
    body, attachments = message_content(message, ref, include_quoted=include_quoted)
    return MailMessage(
        ref=ref,
        mailbox="",
        date=date,
        timestamp=timestamp,
        thread="",
        in_reply_to=(),
        references=(),
        addresses=addresses,
        subject=subject,
        body=body,
        attachments=attachments,
        size=size,
        nested_depth=depth,
    )


def select_body_part(message: Message) -> Message | None:
    try:
        return message.get_body(preferencelist=("plain", "html"))  # type: ignore[attr-defined]
    except Exception:
        return None


def body_text(part: Message | None) -> str:
    if part is None:
        return ""
    text = decode_text_part(part)
    try:
        is_html = part.get_content_type() == "text/html"
    except Exception:
        is_html = False
    if is_html:
        text = html_to_text(text)
    return clean_text(text)


def decode_text_part(part: Message, *, charset_first: bool = False) -> str:
    try:
        content = part.get_content()  # type: ignore[attr-defined]
        if isinstance(content, str):
            return content
    except Exception:
        pass
    payload = part_payload_bytes(part)
    if charset_first:
        try:
            charset = part.get_content_charset() or "utf-8"
            return payload.decode(charset, errors="replace")
        except Exception:
            pass
    return payload.decode("utf-8", errors="replace")


def part_payload_bytes(part: Message) -> bytes:
    try:
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            return payload
        inner = part.get_payload()
        if isinstance(inner, list) and inner:
            return inner[0].as_bytes()
    except Exception:
        pass
    return b""


def leaf_parts(message: Message) -> list[Message]:
    """Non-multipart parts in MIME walk order; ``message/rfc822`` parts are leaves."""
    leaves: list[Message] = []
    pending: list[Message] = [message]
    while pending:
        part = pending.pop()
        try:
            children = part.get_payload() if part.get_content_maintype() == "multipart" else None
        except Exception:
            children = None
        if isinstance(children, list):
            pending.extend(reversed([child for child in children if isinstance(child, Message)]))
        else:
            leaves.append(part)
    return leaves


def attachment_parts(message: Message, body_part: Message | None) -> list[Message]:
    parts: list[Message] = []
    for part in leaf_parts(message):
        if part is body_part:
            continue
        try:
            is_attachment = part.get_content_disposition() == "attachment" or bool(part.get_filename())
        except Exception:
            is_attachment = False
        if is_attachment:
            parts.append(part)
            if len(parts) >= MAIL_MAX_ATTACHMENTS:
                break
    return parts


def numbered_attachment(message: Message | None, number: int) -> Message:
    """Attachment ``number`` (1-based) of ``message``; any other number is an unknown reference."""
    parts = attachment_parts(message, select_body_part(message)) if message is not None else []
    if number > len(parts):
        raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
    return parts[number - 1]


def attachment_record(part: Message, ref: str) -> MailAttachment:
    return MailAttachment(
        ref=ref,
        content_type=safe_content_type(part),
        size=len(part_payload_bytes(part)),
        filename=safe_filename(part),
    )


def safe_content_type(part: Message) -> str:
    try:
        value = part.get_content_type().lower()
    except Exception:
        value = ""
    return value if CONTENT_TYPE_RE.fullmatch(value) else "application/octet-stream"


def safe_filename(part: Message) -> str:
    try:
        return clean_text(part.get_filename() or "")
    except Exception:
        return ""


def document_extension(filename: str, content_type: str) -> str | None:
    suffix = os.path.splitext(filename.lower())[1]
    if suffix in documents.DOCUMENT_EXTENSIONS:
        return suffix
    return DOCUMENT_CONTENT_TYPES.get(content_type)


# HTML to text ---------------------------------------------------------------------

VOID_ELEMENTS = frozenset(
    {"br", "img", "hr", "meta", "link", "input", "wbr", "area", "base", "col", "embed", "source", "track", "param"}
)
SKIPPED_ELEMENTS = frozenset({"script", "style", "head", "title", "template", "noscript"})
BLOCK_ELEMENTS = frozenset({
    "p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "ul", "ol",
    "section", "article", "header", "footer", "blockquote", "pre", "hr",
})
PARAGRAPH_ELEMENTS = frozenset({"p", "h1", "h2", "h3", "h4", "h5", "h6"})
HIDDEN_STYLE_RE = re.compile(r"display:none|visibility:hidden")
WHITESPACE_RE = re.compile(r"\s+")
LINK_SCHEMES = ("http://", "https://", "mailto:")
# Rendered ``> `` prefixes per line; deeper HTML quote nesting is flattened.
MAX_HTML_QUOTE_DEPTH = 32


@dataclass
class _OpenElement:
    tag: str
    hidden: bool
    quote: bool
    pre: bool
    block: bool
    href: str = ""
    text: list[str] = field(default_factory=list)
    # A link that contains another link (invalid HTML) keeps no text of its
    # own, so emitted text only ever goes to the innermost open link.
    nested: bool = False


class _HtmlText(HTMLParser):
    """Visible text of an HTML body with block breaks, list bullets, links, and quote levels."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[_OpenElement] = []
        # Open elements per tag name, so an end tag or ``<body>`` with no
        # matching open element costs O(1) instead of a scan of a deep stack.
        self.open_tags: dict[str, int] = {}
        self.links: list[_OpenElement] = []
        self.hidden = 0
        self.quote = 0
        self.pre = 0
        self.lines: list[str] = []
        self.current: list[str] = []
        self.current_level = 0
        self.pending = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, push=tag not in VOID_ELEMENTS)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self._start(tag, attrs, push=False)

    def handle_endtag(self, tag: str) -> None:
        if not self.open_tags.get(tag):
            return
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index].tag == tag:
                while len(self.stack) > index:
                    self._pop()
                return

    def handle_data(self, data: str) -> None:
        if self.hidden:
            return
        if self.pre:
            for number, segment in enumerate(data.split("\n")):
                if number:
                    self._break(1)
                self._emit(segment)
        else:
            self._emit(WHITESPACE_RE.sub(" ", data))

    def _start(self, tag: str, attrs: list[tuple[str, str | None]], *, push: bool) -> None:
        if tag == "body" and self.open_tags.get("head"):
            # An unclosed <head> must not hide the whole body.
            for index, element in enumerate(self.stack):
                if element.tag == "head":
                    while len(self.stack) > index:
                        self._pop()
                    break
        values: dict[str, str] = {}
        for name, value in attrs:
            values.setdefault(name.lower(), value or "")
        style = WHITESPACE_RE.sub("", values.get("style", "")).lower()
        hidden = tag in SKIPPED_ELEMENTS or "hidden" in values or HIDDEN_STYLE_RE.search(style) is not None
        quote = tag == "blockquote" or "gmail_quote" in values.get("class", "").lower()
        visible = not hidden and not self.hidden
        block = tag in BLOCK_ELEMENTS
        if visible:
            if block:
                self._break(2 if tag in PARAGRAPH_ELEMENTS else 1)
            if tag == "li":
                self._emit("- ")
            elif tag == "img" and values.get("alt", "").strip():
                self._emit(WHITESPACE_RE.sub(" ", values["alt"]))
            elif tag in {"td", "th"}:
                self._emit(" ")
        if not push:
            return
        href = values.get("href", "").strip() if tag == "a" else ""
        element = _OpenElement(tag=tag, hidden=hidden, quote=quote, pre=tag == "pre", block=block, href=href)
        self.stack.append(element)
        self.open_tags[tag] = self.open_tags.get(tag, 0) + 1
        self.hidden += hidden
        self.quote += quote
        self.pre += element.pre
        if tag == "a":
            if self.links:
                self.links[-1].nested = True
            self.links.append(element)

    def _pop(self) -> None:
        element = self.stack.pop()
        self.open_tags[element.tag] -= 1
        self.hidden -= element.hidden
        self.quote -= element.quote
        self.pre -= element.pre
        if element.tag == "a":
            # Links are popped in stack order, so this is the innermost one.
            self.links.pop()
            self._finish_link(element)
        if element.block and not element.hidden and not self.hidden:
            self._break(2 if element.tag in PARAGRAPH_ELEMENTS else 1)

    def _finish_link(self, element: _OpenElement) -> None:
        if element.hidden or self.hidden or not element.href.lower().startswith(LINK_SCHEMES):
            return
        text = "" if element.nested else "".join(element.text).strip()
        href = element.href
        target = href[len("mailto:") :] if href.lower().startswith("mailto:") else href
        if text and text in {href, target}:
            return
        self._emit(f" <{href}>")

    def _break(self, count: int) -> None:
        if self.current:
            self._flush()
        self.pending = max(self.pending, count)

    def _emit(self, text: str) -> None:
        if not text or self.hidden:
            return
        if not self.current:
            if not self.pre:
                text = text.lstrip(" ")
                if not text:
                    return
            if self.pending >= 2 and self.lines:
                self.lines.append(quote_prefix(self.quote).rstrip())
            self.pending = 0
            self.current_level = self.quote
        elif not self.pre and text.startswith(" ") and self.current[-1].endswith(" "):
            text = text.lstrip(" ")
            if not text:
                return
        self.current.append(text)
        if self.links:
            self.links[-1].text.append(text)

    def _flush(self) -> None:
        line = "".join(self.current).rstrip()
        prefix = quote_prefix(self.current_level)
        self.lines.append(prefix + line if line else prefix.rstrip())
        self.current = []

    def text(self) -> str:
        if self.current:
            self._flush()
        return "\n".join(self.lines)


def quote_prefix(level: int) -> str:
    """``> `` per quote level, capped so deeply nested quotes cannot blow up the output."""
    return "> " * min(level, MAX_HTML_QUOTE_DEPTH)


def html_to_text(markup: str) -> str:
    """Convert an HTML body to plain text, dropping hidden and non-content elements."""
    parser = _HtmlText()
    try:
        parser.feed(markup)
        parser.close()
    except Exception:
        pass
    text = "\n".join(line.rstrip() for line in parser.text().split("\n"))
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip("\n")


# Quote and signature collapsing ---------------------------------------------------

OUTLOOK_SEPARATOR_RE = re.compile(r"-{2,}\s*Original Message\s*-{2,}", re.IGNORECASE)
OUTLOOK_FROM_RE = re.compile(r"From:", re.IGNORECASE)
OUTLOOK_SENT_RE = re.compile(r"(?:Sent|Date):", re.IGNORECASE)
SIGNATURE_RE = re.compile(r"-- ?")


def is_quoted_line(line: str) -> bool:
    return line.lstrip(" \t")[:1] == ">"


def is_attribution(line: str) -> bool:
    return line.rstrip().lower().endswith("wrote:")


def outlook_block_start(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if OUTLOOK_SEPARATOR_RE.fullmatch(line.strip()):
            return index
        if OUTLOOK_FROM_RE.match(line) and any(
            OUTLOOK_SENT_RE.match(following) for following in lines[index + 1 : index + 5]
        ):
            return index
    return None


def collapse_quotes(text: str) -> str:
    """Collapse Outlook blocks, ``>`` quote runs, and an RFC 3676 signature.

    Each becomes ``[quoted text: N lines omitted]`` or ``[signature: N lines
    omitted]`` with N the removed line count. Text without any of them is
    returned unchanged.
    """
    lines = text.split("\n")
    while lines and not lines[-1].strip():
        lines.pop()
    tail: str | None = None
    cut = outlook_block_start(lines)
    if cut is not None:
        tail = f"[quoted text: {len(lines) - cut} lines omitted]"
        lines = lines[:cut]
    items: list[tuple[str, str | int]] = []
    index = 0
    while index < len(lines):
        if not is_quoted_line(lines[index]):
            items.append(("line", lines[index]))
            index += 1
            continue
        end = index
        while end < len(lines) and is_quoted_line(lines[end]):
            end += 1
        count = end - index
        if items and items[-1][0] == "line" and is_attribution(str(items[-1][1])):
            items.pop()
            count += 1
        elif (
            len(items) >= 2
            and items[-1][0] == "line"
            and not str(items[-1][1]).strip()
            and items[-2][0] == "line"
            and is_attribution(str(items[-2][1]))
        ):
            del items[-2:]
            count += 2
        items.append(("quote", count))
        index = end
    signature = None
    for position in range(len(items) - 1, -1, -1):
        kind, value = items[position]
        if kind == "line" and SIGNATURE_RE.fullmatch(str(value)):
            signature = position
            break
    if signature is not None:
        removed = sum(1 for kind, _value in items[signature:] if kind == "line")
        markers = [item for item in items[signature + 1 :] if item[0] != "line"]
        items = [*items[:signature], ("signature", removed), *markers]
    if tail is None and all(kind == "line" for kind, _value in items):
        return text
    output: list[str] = []
    for kind, value in items:
        if kind == "line":
            output.append(str(value))
        elif kind == "quote":
            output.append(f"[quoted text: {value} lines omitted]")
        else:
            output.append(f"[signature: {value} lines omitted]")
    if tail is not None:
        output.append(tail)
    return "\n".join(output)
