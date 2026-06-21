"""Default constants and compiled patterns for redacted context access."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path.cwd()
LOCAL_CONFIG = ".agent-context-redactor.toml"
STATE_DIR_ENV = "REDACTED_CONTEXT_STATE_DIR"
SALT_ENV = "REDACTED_CONTEXT_SALT"
TERMS_ENV = "REDACTED_CONTEXT_TERMS"
DETECTOR_PROFILE_ENV = "REDACTED_CONTEXT_DETECTOR_PROFILE"

DEFAULT_MAX_CHARS = 120_000
DEFAULT_MAX_FILES = 80
DEFAULT_MAX_SEARCH_RESULTS = 200
DEFAULT_MAX_RAW_BYTES_PER_FILE = 5_000_000
DEFAULT_MAX_TOTAL_RAW_BYTES = 50_000_000
DEFAULT_MAX_TRAVERSAL_ENTRIES = 10_000
DEFAULT_MAX_RESOURCE_BYTES = 1_000_000
DEFAULT_DISCOVERY_MODEL = "gemma4:e4b"
DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434"
DEFAULT_DISCOVERY_MAX_FILES = 80
DEFAULT_DISCOVERY_MAX_CHARS = 12_000
DISCOVERY_KEYS = ("clients", "organizations", "people", "terms", "allow")
DISCOVERY_SENSITIVE_KEYS = ("clients", "organizations", "people", "terms")
SYSTEM_CA_CANDIDATES = (
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
    "/usr/local/etc/openssl@3/cert.pem",
)

DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".claude",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".redacted-context-mcp",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "personal",
}

DEFAULT_EXCLUDE_GLOBS = {
    LOCAL_CONFIG,
    ".env",
    ".env.*",
    "*.crt",
    "*.docx",
    "*.key",
    "*.pem",
    "*.pptx",
    "*.xlsx",
    "*.xls",
    "*.pdf",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.mp4",
    "*.mov",
    "*.zip",
    "*.tar",
    "*.gz",
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".csv",
    ".css",
    ".env",
    ".gitignore",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsonl",
    ".jsx",
    ".log",
    ".md",
    ".mjs",
    ".py",
    ".rst",
    ".sh",
    ".sql",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}

DEFAULT_ALLOW_TERMS = {
    "ABAC",
    "ACL",
    "AD",
    "ADF",
    "ADLS",
    "AI",
    "API",
    "APIs",
    "ASCII",
    "AWS",
    "Azure",
    "BI",
    "CSV",
    "CI",
    "CD",
    "CI/CD",
    "CLI",
    "CMK",
    "DNS",
    "DOCX",
    "DPIA",
    "DSAR",
    "DevOps",
    "Entra",
    "GDPR",
    "Git",
    "GitHub",
    "HTML",
    "HTTP",
    "HTTPS",
    "JSON",
    "Key Vault",
    "Kubernetes",
    "Markdown",
    "Microsoft",
    "NSG",
    "PDF",
    "PII",
    "PPTX",
    "Power BI",
    "PostgreSQL",
    "Python",
    "RBAC",
    "README",
    "REST",
    "SCIM",
    "SQL",
    "SSL",
    "SSO",
    "TLS",
    "Terraform",
    "UAT",
    "VNet",
    "YAML",
    "XML",
    "Access",
    "Architecture",
    "Assessment",
    "Audit",
    "Classification",
    "Client",
    "Compliance",
    "Confidential",
    "Context",
    "Current",
    "Data",
    "Decision",
    "Decisions",
    "Delivery",
    "Design",
    "Development",
    "Governance",
    "Identity",
    "Internal",
    "Logging",
    "Meeting",
    "Monitoring",
    "Network",
    "Overview",
    "Phase",
    "Platform",
    "Planning",
    "Privacy",
    "Production",
    "Progress",
    "Public",
    "Purpose",
    "Recommendation",
    "Recommendations",
    "Restricted",
    "Risks",
    "Scope",
    "Security",
    "Storage",
    "Summary",
    "Target",
    "Workshop",
}

COMMON_CAPITALIZED_WORDS = {
    "A",
    "An",
    "And",
    "As",
    "At",
    "By",
    "For",
    "From",
    "If",
    "In",
    "Into",
    "It",
    "No",
    "Not",
    "Of",
    "On",
    "Or",
    "The",
    "Then",
    "This",
    "To",
    "With",
    "Without",
}

PATH_ALLOW_TERMS = {
    "archive",
    "assessment",
    "audit",
    "body",
    "brainstorm",
    "build",
    "changelog",
    "classification",
    "comms",
    "consolidated",
    "content",
    "context",
    "current",
    "deliverable",
    "deliverables",
    "delivery",
    "design",
    "doc",
    "docs",
    "draft",
    "extracted",
    "federated",
    "generated",
    "governance",
    "handoff",
    "identity",
    "infrastructure",
    "internal",
    "kickoff",
    "knowledge",
    "manual",
    "meeting",
    "meetings",
    "model",
    "network",
    "notes",
    "operating",
    "operational",
    "outputs",
    "phase",
    "planning",
    "platform",
    "policy",
    "presales",
    "progress",
    "proposal",
    "raw",
    "readiness",
    "received",
    "recommendations",
    "recording",
    "reference",
    "repo",
    "research",
    "review",
    "roadmap",
    "security",
    "sections",
    "structure",
    "subscription",
    "support",
    "target",
    "technical",
    "tool",
    "tools",
    "transcript",
    "transcripts",
    "workload",
    "workshop",
    "workshops",
}

MONTHS_AND_DAYS = {
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
}

URL_RE = re.compile(r"\b(?:https?://|www\.)[^\s<>)\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
GENERIC_SECRET_RE = re.compile(
    r"(?ix)"
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b|"
    r"\bgh[opsu]_[A-Za-z0-9_]{20,}\b|"
    r"\bsk-[A-Za-z0-9_-]{20,}\b|"
    r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|"
    r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}\b|"
    r"\b(?:api[_-]?key|secret|token|password|passwd|pwd|private[_-]?key)"
    r"\b\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=@:-]{8,}[\"']?"
)
PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
CREDIT_CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(
    r"(?ix)(?<![0-9A-F:])(?:"
    r"(?:[0-9A-F]{1,4}:){7}[0-9A-F]{1,4}|"
    r"(?:[0-9A-F]{1,4}:){1,7}:|"
    r"(?:[0-9A-F]{1,4}:){1,6}:[0-9A-F]{1,4}|"
    r"(?:[0-9A-F]{1,4}:){1,5}(?::[0-9A-F]{1,4}){1,2}|"
    r"(?:[0-9A-F]{1,4}:){1,4}(?::[0-9A-F]{1,4}){1,3}|"
    r"(?:[0-9A-F]{1,4}:){1,3}(?::[0-9A-F]{1,4}){1,4}|"
    r"(?:[0-9A-F]{1,4}:){1,2}(?::[0-9A-F]{1,4}){1,5}|"
    r"[0-9A-F]{1,4}:(?:(?::[0-9A-F]{1,4}){1,6})|"
    r":(?:(?::[0-9A-F]{1,4}){1,7}|:)"
    r")(?![0-9A-F:])"
)
MAC_RE = re.compile(r"\b[0-9A-F]{2}(?:[:-][0-9A-F]{2}){5}\b", re.IGNORECASE)
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b")
DOB_RE = re.compile(
    r"(?ix)\b(?:date\s+of\s+birth|dob|birthdate)\s*[:=]\s*"
    r"(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"
)
PASSPORT_RE = re.compile(r"(?ix)\bpassport(?:\s+(?:no|number))?\s*[:=]\s*[A-Z0-9]{6,12}\b")
DRIVER_ID_RE = re.compile(
    r"(?ix)\b(?:driver'?s?\s+licen[cs]e|driving\s+licen[cs]e|driver[_-]?id)"
    r"\s*[:=]\s*[A-Z0-9-]{6,20}\b"
)
CONNECTION_STRING_RE = re.compile(
    r"(?ix)\b(?:"
    r"(?:server|host|data\s+source|uid|user\s+id|password|pwd|accountkey|sharedaccesskey)"
    r"\s*=\s*[^;\s]+;){2,}[^ \n\r]*"
)
UNICODE_CONTROL_RE = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060-\u206F]")
PROMPT_INJECTION_RE = re.compile(
    r"(?ix)\b(?:ignore\s+(?:all\s+)?previous\s+instructions|"
    r"disregard\s+(?:all\s+)?(?:prior|previous)\s+instructions|"
    r"system\s+prompt|developer\s+message|tool\s+call)\b"
)
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
DOMAIN_RE = re.compile(
    r"(?<![@/\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|dev|io|net|org|app|cloud|local|internal|invalid|example)(?![\w.-])",
    re.IGNORECASE,
)
PHONE_RE = re.compile(
    r"(?<!\w)(?:\+\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?){2,4}\d{2,4}(?!\w)"
)
HANDLE_RE = re.compile(r"(?<![\w/])@[A-Za-z0-9_][A-Za-z0-9_.-]{1,}")
ORG_SUFFIX_RE = re.compile(
    r"\b(?:[A-Z][A-Za-z0-9&'.-]+(?:\s+|[-_])){0,5}"
    r"[A-Z][A-Za-z0-9&'.-]+\s+"
    r"(?:AG|BV|Corp(?:oration)?|GmbH|Holdings|Inc|Limited|LLC|Ltd|NV|PLC|SA|SAS)\b"
)
MULTI_PROPER_RE = re.compile(
    r"\b(?:[A-Z][A-Za-z'.-]{2,}|[A-Z]\.)"
    r"(?:\s+(?:[A-Z][A-Za-z'.-]{2,}|[A-Z]\.)){1,4}\b"
)
SPEAKER_LABEL_RE = re.compile(r"(?m)^([A-Z][A-Za-z'.-]{2,})(?=[ \t]*:)")
IDENTITY_LINE_RE = re.compile(
    r"(?im)\b(attendees?|participants?|stakeholders?|owners?|contacts?|authors?|"
    r"reviewers?|approvers?|speakers?|presenters?)\b([ \t]*):([ \t]*)([^\r\n]*)"
)
TITLECASE_TOKEN_RE = re.compile(r"\b[A-Z][a-z][A-Za-z'.-]{2,}\b")
ACRONYM_RE = re.compile(r"\b[A-Z][A-Z0-9]{2,}\b")
PATH_TOKEN_RE = re.compile(r"(?<!\[)\b[A-Za-z][A-Za-z0-9]{2,}\b(?!_\d{2}\])")
PLACEHOLDER_CATEGORIES = frozenset(
    {
        "CLIENT",
        "ORG",
        "PERSON",
        "SENSITIVE",
        "ENTITY",
        "EMAIL",
        "PHONE",
        "URL",
        "HANDLE",
        "SECRET",
        "SSN",
        "CARD",
        "IP",
        "ID",
        "DOMAIN",
        "IBAN",
        "MAC",
        "DOB",
        "PASSPORT",
        "DRIVER_ID",
        "CONNECTION",
        "UNICODE_CONTROL",
        "PROMPT_INJECTION",
    }
)
PLACEHOLDER_CATEGORY_PATTERN = "|".join(sorted(PLACEHOLDER_CATEGORIES, key=len, reverse=True))
PLACEHOLDER_RE = re.compile(
    rf"\[(?:{PLACEHOLDER_CATEGORY_PATTERN})_(?:\d{{2}}|[0-9a-f]{{8}}|[0-9a-f]{{32}})\]"
)
RESERVED_PLACEHOLDER_WORDS = {
    "client",
    "org",
    "organization",
    "person",
    "sensitive",
    "entity",
    "email",
    "phone",
    "url",
    "handle",
}
COUNTRY_OR_REGION_ONLY = {
    "australia",
    "austria",
    "brazil",
    "canada",
    "china",
    "denmark",
    "england",
    "europe",
    "france",
    "germany",
    "hungary",
    "iberia",
    "india",
    "ireland",
    "new zealand",
    "norway",
    "scotland",
    "spain",
    "sweden",
    "switzerland",
    "uk",
    "united kingdom",
    "united states",
    "us",
    "usa"
}
GENERIC_ORG_WORDS = {
    "business",
    "client",
    "company",
    "customer",
    "data platform",
    "department",
    "division",
    "internal",
    "platform",
    "project",
    "team",
    "unit",
}
ROLE_WORDS = {
    "account admin",
    "architect",
    "business partner",
    "clinical director",
    "compliance officer",
    "data engineer",
    "director",
    "head of",
    "lead",
    "manager",
    "owner",
    "practice manager",
    "privacy manager",
    "regional director",
    "role",
    "stakeholder",
    "vp ",
}
NON_PERSON_NAME_WORDS = {
    "account",
    "application",
    "client",
    "company",
    "corp",
    "corporation",
    "customer",
    "data",
    "domain",
    "engineering",
    "finance",
    "infrastructure",
    "lakehouse",
    "master",
    "metadata",
    "migration",
    "operations",
    "partner",
    "partners",
    "platform",
    "policy",
    "program",
    "programme",
    "project",
    "regional",
    "spreadsheet",
    "support",
    "system",
    "team",
    "tenant",
    "vendor",
    "workflow",
}
GENERIC_TERM_PATTERNS = (
    r"\bfindings?\b",
    r"\bworkflow[s]?\b",
    r"\bdocumentation\b",
    r"\bconfiguration\b",
    r"\bresources?\b",
    r"\bdeployment\b",
    r"\bdesign\b",
    r"\bimplementation\b",
    r"\bassessment\b",
    r"\breview\b",
    r"\btesting\b",
    r"\bvalidation\b",
    r"\breview gates?\b",
    r"\bbranching\b",
    r"\brollback\b",
    r"\bversioning\b",
    r"\bcleanup\b",
    r"\brepo(?:sitory|s)?\b",
    r"\bbundle definition\b",
)
FILENAME_OR_EXTENSION_RE = re.compile(
    r"(?:^|[/\\])[^/\\]+\.(?:md|txt|toml|json|yaml|yml|py|sql|csv|ts|tsx|js|jsx|html|xml)$",
    re.IGNORECASE,
)
REFERENCE_ID_RE = re.compile(
    r"^(?:[MRQD]\d{1,3}(?:\.\d+)?|Q\d{1,3}|BL-D\d+(?:\.\d+|\.x)?|A\.\d+|D\d+(?:\.\d+)?)"
    r"(?:\b|[:\s(])",
    re.IGNORECASE,
)
