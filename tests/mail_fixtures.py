"""Synthetic mailbox fixtures for the mail source tests.

Every name, address, and domain here is invented (example.com, example.org,
and ``.test`` hosts). Builders return raw RFC 5322 bytes so tests control
exact header shapes, including malformed ones.
"""

from __future__ import annotations

import base64
import quopri
from pathlib import Path
from typing import Iterable, Sequence

AVERY = "Avery Example"
AVERY_ADDRESS = "avery@example.com"
JORDAN = "Jordan Sample"
JORDAN_ADDRESS = "jordan@example.org"
CASEY = "Casey Placeholder"
CASEY_ADDRESS = "casey@mail.example.test"

# Header values that must never reach a returned record.
DROPPED_HEADER_VALUES = {
    "Received": "from relay-zq81.example.test (relay-zq81 [192.0.2.71]) by mx-kw44.example.test",
    "Return-Path": "<bounce-hv93@bounce.example.test>",
    "DKIM-Signature": "v=1; a=rsa-sha256; d=example.test; s=sel-qp27; b=dkimsig4471",
    "ARC-Seal": "i=1; a=rsa-sha256; cv=none; d=example.test; b=arcseal8823",
    "Authentication-Results": "mx-kw44.example.test; spf=pass smtp.mailfrom=authres5510@example.test",
    "Delivered-To": "delivered-ux62@example.test",
    "List-Unsubscribe": "<https://lists.example.test/unsub?token=listtok7781>",
    "List-Id": "<team-yy18.lists.example.test>",
    "X-Mailer": "MailerSentinel 9.31",
    "X-Originating-IP": "[198.51.100.239]",
}


def message(
    *,
    message_id: str | None = "<m1@example.test>",
    sender: str | None = f"{AVERY} <{AVERY_ADDRESS}>",
    to: str | None = f"{JORDAN} <{JORDAN_ADDRESS}>",
    subject: str | None = "Quarterly planning",
    date: str | None = "Thu, 01 Oct 2026 10:15:00 +0200",
    body: str = "Hello team,\nThe plan is ready.\n",
    headers: Sequence[tuple[str, str]] = (),
    content_type: str | None = "text/plain; charset=utf-8",
    newline: str = "\n",
) -> bytes:
    """One single-part message. ``None`` omits a header."""
    lines: list[str] = []
    if message_id is not None:
        lines.append(f"Message-ID: {message_id}")
    if date is not None:
        lines.append(f"Date: {date}")
    if sender is not None:
        lines.append(f"From: {sender}")
    if to is not None:
        lines.append(f"To: {to}")
    if subject is not None:
        lines.append(f"Subject: {subject}")
    lines.extend(f"{name}: {value}" for name, value in headers)
    if content_type is not None:
        lines.append("MIME-Version: 1.0")
        lines.append(f"Content-Type: {content_type}")
    text = "\n".join(lines) + "\n\n" + body
    return text.replace("\n", newline).encode("utf-8")


def multipart(
    parts: Sequence[str],
    *,
    subtype: str = "mixed",
    boundary: str = "b-outer-0001",
    message_id: str = "<multi@example.test>",
    subject: str = "Multipart",
    date: str = "Fri, 02 Oct 2026 09:00:00 +0000",
    headers: Sequence[tuple[str, str]] = (),
) -> bytes:
    """A multipart message whose ``parts`` are raw MIME part texts (headers, blank line, body)."""
    head = [
        f"Message-ID: {message_id}",
        f"Date: {date}",
        f"From: {AVERY} <{AVERY_ADDRESS}>",
        f"To: {JORDAN} <{JORDAN_ADDRESS}>",
        f"Subject: {subject}",
        *(f"{name}: {value}" for name, value in headers),
        "MIME-Version: 1.0",
        f'Content-Type: multipart/{subtype}; boundary="{boundary}"',
    ]
    body = "".join(f"--{boundary}\n{part.rstrip(chr(10))}\n" for part in parts) + f"--{boundary}--\n"
    return ("\n".join(head) + "\n\n" + body).encode("utf-8")


def text_part(text: str, *, subtype: str = "plain", charset: str = "utf-8", extra: str = "") -> str:
    return f"Content-Type: text/{subtype}; charset={charset}\n{extra}\n{text}"


def attachment_part(filename: str, content_type: str, data: bytes) -> str:
    encoded = base64.b64encode(data).decode("ascii")
    return (
        f'Content-Type: {content_type}; name="{filename}"\n'
        f'Content-Disposition: attachment; filename="{filename}"\n'
        "Content-Transfer-Encoding: base64\n\n"
        f"{encoded}"
    )


def alternative_message() -> bytes:
    inner = multipart_part(
        [text_part("Plain body for the alternative.\n"), text_part("<p>HTML body for the alternative.</p>", subtype="html")],
        subtype="alternative",
        boundary="b-alt-0002",
    )
    return multipart([inner], subtype="mixed", message_id="<alt@example.test>", subject="Alternative")


def multipart_part(parts: Sequence[str], *, subtype: str, boundary: str) -> str:
    body = "".join(f"--{boundary}\n{part.rstrip(chr(10))}\n" for part in parts) + f"--{boundary}--"
    return f'Content-Type: multipart/{subtype}; boundary="{boundary}"\n\n{body}'


def html_message(markup: str, *, message_id: str = "<html@example.test>") -> bytes:
    return message(
        message_id=message_id,
        subject="HTML only",
        body=markup,
        content_type="text/html; charset=utf-8",
    )


def attachments_message() -> bytes:
    return multipart(
        [
            text_part("See the attached files.\n"),
            attachment_part("notes.txt", "text/plain", "Attachment notes from Jordan Sample.\nLine two.\n".encode()),
            attachment_part("report.pdf", "application/pdf", b"%PDF-1.4 fake pdf bytes"),
            attachment_part("archive.bin", "application/x-made-up", b"\x00\x01\x02binary"),
            attachment_part("weird.dat", "Not A Type", b"opaque"),
        ],
        message_id="<attach@example.test>",
        subject="Files attached",
    )


# Identities that appear only inside forwarded messages, one per nesting
# level (QUINN at depth 1 down to REESE at depth 4).
QUINN = "Quinn Relayford"
QUINN_ADDRESS = "quinn.relay@relaydesk.example.net"
MORGAN = "Morgan Deepwell"
MORGAN_ADDRESS = "morgan.deep@wellspring.example.org"
TAYLOR = "Taylor Innermost"
TAYLOR_ADDRESS = "taylor.inner@coreline.example.test"
REESE = "Reese Bottomley"
REESE_ADDRESS = "reese.bottom@floorplan.example.com"
CHAIN_IDENTITIES = ((QUINN, QUINN_ADDRESS), (MORGAN, MORGAN_ADDRESS), (TAYLOR, TAYLOR_ADDRESS), (REESE, REESE_ADDRESS))

# Header values of forwarded messages that must never reach a returned record.
NESTED_DROPPED_HEADER_VALUES = {
    "Received": "from fwdrelay-tq52.example.test (fwdrelay-tq52 [192.0.2.143]) by mx-fw17.example.test",
    "Return-Path": "<fwdbounce-ka28@bounce.example.test>",
    "DKIM-Signature": "v=1; a=rsa-sha256; d=example.test; s=sel-fw61; b=fwddkim3390",
    "Authentication-Results": "mx-fw17.example.test; spf=pass smtp.mailfrom=fwdauth6604@example.test",
    "Delivered-To": "fwddelivered-pp19@example.test",
    "List-Unsubscribe": "<https://lists.example.test/unsub?token=fwdlisttok2258>",
    "X-Mailer": "FwdMailerGadget 4.72",
    "X-Originating-IP": "[198.51.100.187]",
}


def forwarded_message(
    *,
    message_id: str | None = "<fwd-inner-priv5521@example.test>",
    sender: str | None = f"{QUINN} <{QUINN_ADDRESS}>",
    to: str | None = f"{MORGAN} <{MORGAN_ADDRESS}>",
    subject: str | None = "Ledger review",
    date: str | None = "Wed, 30 Sep 2026 10:00:00 +0200",
    body: str = "Status update for the review.\n",
    headers: Sequence[tuple[str, str]] = (),
    content_type: str = "text/plain; charset=utf-8",
    attachments: Sequence[str] = (),
    boundary: str = "b-fwd-0001",
) -> bytes:
    """A message to forward: single-part, or multipart/mixed when ``attachments`` (raw MIME parts) are given.

    Nested multiparts need distinct ``boundary`` values per level.
    """
    lines: list[str] = []
    if message_id is not None:
        lines.append(f"Message-ID: {message_id}")
    if date is not None:
        lines.append(f"Date: {date}")
    if sender is not None:
        lines.append(f"From: {sender}")
    if to is not None:
        lines.append(f"To: {to}")
    if subject is not None:
        lines.append(f"Subject: {subject}")
    lines.extend(f"{name}: {value}" for name, value in headers)
    lines.append("MIME-Version: 1.0")
    if attachments:
        lines.append(f'Content-Type: multipart/mixed; boundary="{boundary}"')
        parts = [f"Content-Type: {content_type}\n\n{body}", *attachments]
        payload = "".join(f"--{boundary}\n{part.rstrip(chr(10))}\n" for part in parts) + f"--{boundary}--\n"
    else:
        lines.append(f"Content-Type: {content_type}")
        payload = body
    return ("\n".join(lines) + "\n\n" + payload).encode("utf-8")


def forwarded_part(
    raw: bytes,
    *,
    content_type: str = "message/rfc822",
    filename: str | None = "forwarded.eml",
    encoding: str | None = None,
) -> str:
    """A MIME part forwarding ``raw`` as an attachment, optionally base64- or quoted-printable-encoded."""
    if encoding == "base64":
        payload = base64.encodebytes(raw).decode("ascii")
    elif encoding == "quoted-printable":
        payload = quopri.encodestring(raw).decode("ascii")
    else:
        payload = raw.decode("utf-8")
    disposition = f'attachment; filename="{filename}"' if filename is not None else "attachment"
    lines = [f"Content-Type: {content_type}", f"Content-Disposition: {disposition}"]
    if encoding is not None:
        lines.append(f"Content-Transfer-Encoding: {encoding}")
    return "\n".join(lines) + "\n\n" + payload


def forward_message(
    inner: bytes | None = None,
    *,
    message_id: str = "<fwd-outer@example.test>",
    encoding: str | None = None,
    content_type: str = "message/rfc822",
    extra_parts: Sequence[str] = (),
) -> bytes:
    """A top-level message whose attachment 1 is a text part and attachment 2 forwards ``inner``.

    ``inner`` defaults to ``forwarded_message`` with an inner text attachment.
    """
    if inner is None:
        inner = forwarded_message(
            headers=(
                ("In-Reply-To", "<fwd-parent-priv8812@example.test>"),
                ("References", "<fwd-root-priv1176@example.test> <fwd-parent-priv8812@example.test>"),
                *NESTED_DROPPED_HEADER_VALUES.items(),
            ),
            body=(
                f"Status update from {QUINN}.\n"
                "\n"
                f"On Tue, {MORGAN} wrote:\n"
                "> earlier nested question\n"
                "-- \n"
                f"{QUINN}\n"
                "Relay desk\n"
            ),
            attachments=[attachment_part("zephyrnotes.txt", "text/plain", f"Inner notes for {MORGAN}.\n".encode())],
        )
    return multipart(
        [
            text_part("Forwarding the note below.\n"),
            attachment_part("cover.txt", "text/plain", b"Cover text.\n"),
            forwarded_part(inner, encoding=encoding, content_type=content_type),
            *extra_parts,
        ],
        message_id=message_id,
        subject="Fwd: Ledger review",
    )


def nested_chain(depth: int, *, message_id: str = "<chain-outer@example.test>") -> bytes:
    """A top-level message whose attachment 1 forwards a chain ``depth`` messages deep.

    Level ``n`` is sent by ``CHAIN_IDENTITIES[n - 1]``, names its sender in
    its body, and forwards level ``n + 1`` as its attachment 1; the deepest
    level has a text attachment naming its sender instead. So ``/1`` is
    depth 1, ``/1/1`` depth 2, and ``/1/1/1/1`` is level 4 or, for
    ``depth`` 3, the deepest level's text attachment.
    """
    name, address = CHAIN_IDENTITIES[depth - 1]
    raw = forwarded_message(
        message_id=f"<chain-level{depth}-priv@example.test>",
        sender=f"{name} <{address}>",
        to=None,
        subject=f"Level {depth}",
        body=f"Level {depth} from {name}.\n",
        attachments=[attachment_part("obsidianleaf.txt", "text/plain", f"Leaf notes by {name}.\n".encode())],
        boundary=f"b-chain-{depth}",
    )
    for level in range(depth - 1, 0, -1):
        name, address = CHAIN_IDENTITIES[level - 1]
        raw = forwarded_message(
            message_id=f"<chain-level{level}-priv@example.test>",
            sender=f"{name} <{address}>",
            to=None,
            subject=f"Level {level}",
            body=f"Level {level} from {name}.\n",
            attachments=[forwarded_part(raw)],
            boundary=f"b-chain-{level}",
        )
    return multipart([text_part("Chain below.\n"), forwarded_part(raw)], message_id=message_id, subject="Chain")


def mbox_bytes(messages: Iterable[bytes], *, newline: str = "\n", leading_blank: bool = False) -> bytes:
    """An mboxrd file: ``From `` separators and ``>From`` escaping of body lines."""
    nl = newline.encode("ascii")
    chunks: list[bytes] = [nl] if leading_blank else []
    for number, raw in enumerate(messages, start=1):
        lines = raw.replace(b"\r\n", b"\n").split(b"\n")
        escaped = [b">" + line if line.lstrip(b">").startswith(b"From ") else line for line in lines]
        content = nl.join(escaped)
        if not content.endswith(nl):
            content += nl
        chunks.append(f"From sender{number}@example.test Thu Oct  1 10:15:00 2026".encode("ascii") + nl)
        chunks.append(content)
        chunks.append(nl)
    return b"".join(chunks)


def write_mbox(path: Path, messages: Iterable[bytes], *, newline: str = "\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(mbox_bytes(messages, newline=newline))
    return path


def write_maildir(
    path: Path,
    *,
    cur: dict[str, bytes] | None = None,
    new: dict[str, bytes] | None = None,
    tmp: dict[str, bytes] | None = None,
) -> Path:
    for folder, files in (("cur", cur), ("new", new), ("tmp", tmp)):
        (path / folder).mkdir(parents=True, exist_ok=True)
        for name, raw in (files or {}).items():
            (path / folder / name).write_bytes(raw)
    return path


def write_eml_tree(path: Path, files: dict[str, bytes]) -> Path:
    for rel, raw in files.items():
        target = path / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    return path


def thread_messages() -> list[bytes]:
    """A thread whose root is missing from the mailbox, plus an unrelated message.

    ``<root@example.test>`` is never stored. ``reply-a`` answers it,
    ``reply-b`` answers ``reply-a`` through a References chain, and
    ``reply-c`` names only the root in In-Reply-To.
    """
    return [
        message(
            message_id="<reply-a@example.test>",
            subject="Re: Launch",
            date="Mon, 05 Oct 2026 08:00:00 +0000",
            headers=(("In-Reply-To", "<root@example.test>"), ("References", "<root@example.test>")),
            body="First reply.\n",
        ),
        message(
            message_id="<reply-b@example.test>",
            subject="Re: Launch",
            date="Tue, 06 Oct 2026 08:00:00 +0000",
            headers=(
                ("In-Reply-To", "<reply-a@example.test>"),
                ("References", "<root@example.test> <reply-a@example.test>"),
            ),
            body="Second reply.\n",
        ),
        message(
            message_id="<reply-c@example.test>",
            subject="Re: Launch",
            date="Wed, 07 Oct 2026 08:00:00 +0000",
            headers=(("In-Reply-To", "<root@example.test> (message from Avery)"),),
            body="Third reply.\n",
        ),
        message(
            message_id="<unrelated@example.test>",
            subject="Lunch",
            date="Thu, 08 Oct 2026 08:00:00 +0000",
            body="Unrelated.\n",
        ),
    ]


def standard_messages() -> list[bytes]:
    """A mixed corpus used by most tests (storage order matters)."""
    return [
        message(
            message_id="<m1@example.test>",
            headers=tuple(DROPPED_HEADER_VALUES.items()),
            body="Hello team,\nFrom the desk of Avery.\n>From here on, escaped.\n",
        ),
        message(
            message_id="<m2@example.test>",
            sender=f"=?utf-8?q?J=C3=B6rdan_Sample?= <{JORDAN_ADDRESS}>",
            to=f"Planning Team: {AVERY} <{AVERY_ADDRESS}>, {CASEY_ADDRESS};",
            subject="=?utf-8?b?UmU6IHBsYW5uaW5nIOKAkyBkcmFmdA==?=",
            date="Sat, 03 Oct 2026 12:00:00 -0700",
            headers=(("Cc", f'"Sample, Jordan" <{JORDAN_ADDRESS}>'),),
            body="Reply text.\n",
        ),
        message(message_id=None, subject="No identifier", date="garbage date", body="No Message-ID here.\n"),
        alternative_message(),
        attachments_message(),
    ]
