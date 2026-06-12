from __future__ import annotations

from pathlib import Path


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
