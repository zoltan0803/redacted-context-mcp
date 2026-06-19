"""Path normalization and opaque path references."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path


def path_id(rel_path: str, salt: str = "") -> str:
    key = (salt or "redacted-context-mcp-v1").encode("utf-8")
    digest = hmac.new(key, rel_path.encode("utf-8"), hashlib.sha256).hexdigest()[:12]
    return f"p_{digest}"


def display_ref(rel_path: str, salt: str = "") -> str:
    return f"@{path_id(rel_path, salt)}"


def rel_posix(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix() or "."


def resolve_under_root(root: Path, value: str, *, allow_missing: bool = False) -> Path:
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        candidate = root / candidate
    candidate = candidate.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError:
        raise SystemExit("Refusing path outside root.")
    if not allow_missing and not candidate.exists():
        raise SystemExit("Path does not exist.")
    return candidate
