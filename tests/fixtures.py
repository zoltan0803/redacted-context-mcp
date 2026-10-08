from __future__ import annotations

import fnmatch
import hashlib
import hmac
import re
from pathlib import Path
from typing import Iterator, Sequence

from redacted_context_mcp.limits import OperationBudget
from redacted_context_mcp.models import (
    UNKNOWN_REFERENCE_MESSAGE,
    SourceCapabilities,
    SourceDocument,
)


CLIENT_NAME = "Client Alpha"
CLIENT_ALIAS = "CA"
ORGANIZATION_NAME = "Riverton Partners"
PERSON_ONE = "Taylor Reed"
PERSON_TWO = "Jordan Vale"
PROJECT_TERM = "Project Meridian"
PUBLIC_TECH = "PostgreSQL"
PRIVATE_EMAIL_PREFIX = "taylor.reed"
PRIVATE_URL = "https://example.invalid/private"
CONTEXT_REL_PATH = "context/Client Alpha - Taylor Reed notes.md"

RAW_PRIVATE_VALUES = (
    CLIENT_NAME,
    "Taylor",
    "Reed",
    "Jordan",
    "Vale",
    ORGANIZATION_NAME,
    PRIVATE_EMAIL_PREFIX,
    "https://example.invalid",
    PROJECT_TERM,
)


def write_redaction_config(root: Path, *, github: bool = False) -> None:
    github_config = ""
    if github:
        github_config = """
[github.repos.context]
owner = "client-alpha"
repo = "private-context"
token_env = "REDCTX_TEST_GITHUB_TOKEN"
"""
    (root / ".agent-context-redactor.toml").write_text(
        f"""
[redaction]
clients = ["{CLIENT_NAME}", "{CLIENT_ALIAS}"]
organizations = ["{ORGANIZATION_NAME}"]
people = ["{PERSON_ONE}", "{PERSON_TWO}"]
terms = ["{PROJECT_TERM}"]
allow = ["Azure", "{PUBLIC_TECH}"]
{github_config}""",
        encoding="utf-8",
    )


def write_knowledgebase(root: Path) -> None:
    write_redaction_config(root)
    (root / "context").mkdir()
    (root / CONTEXT_REL_PATH).write_text(
        f"""# {CLIENT_NAME} notes

{PERSON_ONE} met {PERSON_TWO} from {ORGANIZATION_NAME}.
Email {PRIVATE_EMAIL_PREFIX}@example.invalid and visit {PRIVATE_URL}.
{PROJECT_TERM} depends on Azure and {PUBLIC_TECH} policy controls.
""",
        encoding="utf-8",
    )
    (root / "personal").mkdir()
    (root / "personal" / "secret.md").write_text("Raw secret", encoding="utf-8")


class InMemorySource:
    """Tiny non-filesystem context source used to prove adapters are pluggable.

    Documents are keyed by a raw locator (think "folder/message subject");
    references are salted ``@m_<12 hex>`` ids, like a future mailbox source.
    """

    name = "memory"
    untrusted_content = True
    capabilities = SourceCapabilities(listing=False, reading=False, searching=False, documents=True)
    REFERENCE_RE = re.compile(r"@m_[0-9a-f]{12}")

    def __init__(self, documents: dict[str, str], *, salt: str = "memory-test-salt") -> None:
        self.documents = dict(documents)
        self.salt = salt

    def reference_for(self, locator: str) -> str:
        digest = hmac.new(self.salt.encode("utf-8"), locator.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
        return f"@m_{digest}"

    def owns_reference(self, ref: str) -> bool:
        return isinstance(ref, str) and self.REFERENCE_RE.fullmatch(ref) is not None

    def resolve_reference(self, ref: str) -> str:
        if not self.owns_reference(ref):
            raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)
        for locator in self.documents:
            if self.reference_for(locator) == ref:
                return locator
        raise SystemExit(UNKNOWN_REFERENCE_MESSAGE)

    def iter_documents(
        self,
        budget: OperationBudget,
        *,
        scope: Sequence[str] = (),
        patterns: Sequence[str] = (),
    ) -> Iterator[SourceDocument]:
        wanted = {self.resolve_reference(ref) for ref in scope}
        for locator in sorted(self.documents):
            if wanted and locator not in wanted:
                continue
            if patterns and not any(fnmatch.fnmatch(locator, pattern) for pattern in patterns):
                continue
            text = self.documents[locator]
            budget.consume_document(len(text.encode("utf-8")))
            yield SourceDocument(ref=self.reference_for(locator), locator=locator, text=text)

