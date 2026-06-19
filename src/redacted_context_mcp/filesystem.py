"""Read-only filesystem access constrained to a configured root."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Iterable

from .defaults import DEFAULT_EXCLUDE_DIRS, DEFAULT_EXCLUDE_GLOBS, TEXT_EXTENSIONS
from .models import RedactionConfig
from .paths import path_id, rel_posix, resolve_under_root

class RedactedContext:
    def __init__(self, root: Path, config: RedactionConfig, *, include_private: bool = False):
        self.root = root.resolve()
        self.config = config
        self.include_private = include_private
        self.exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(config.exclude_dirs)
        self.exclude_globs = set(DEFAULT_EXCLUDE_GLOBS) | set(config.exclude_globs)

    def resolve_ref(self, value: str) -> Path:
        if value.startswith("@"):
            return self.resolve_id(value[1:])
        if re.fullmatch(r"p_[0-9a-f]{12}", value):
            return self.resolve_id(value)
        return resolve_under_root(self.root, value)

    def path_id(self, rel_path: str) -> str:
        return path_id(rel_path, self.config.salt)

    def display_ref(self, rel_path: str) -> str:
        return f"@{self.path_id(rel_path)}"

    def resolve_id(self, ref_id: str) -> Path:
        for path in self.walk(include_dirs=True):
            rel = rel_posix(path, self.root)
            if self.path_id(rel) == ref_id:
                return path
        raise SystemExit(f"Unknown path id: @{ref_id}")

    def is_excluded(self, path: Path) -> bool:
        if self.include_private:
            return False
        rel = rel_posix(path, self.root)
        if any(part in self.exclude_dirs for part in path.relative_to(self.root).parts):
            return True
        return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in self.exclude_globs)

    def walk(self, start: Path | None = None, *, include_dirs: bool = False) -> Iterable[Path]:
        start = start or self.root
        if self.is_excluded(start):
            return
        if start.is_file():
            yield start
            return
        if include_dirs:
            yield start
        for child in sorted(start.iterdir(), key=lambda p: (p.is_file(), p.name.casefold())):
            if self.is_excluded(child):
                continue
            if child.is_dir():
                yield from self.walk(child, include_dirs=include_dirs)
            else:
                yield child

    def child_entries(self, path: Path) -> list[Path]:
        if path.is_file():
            return [path]
        return [
            child
            for child in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.casefold()))
            if not self.is_excluded(child)
        ]


def is_probably_text(path: Path) -> bool:
    if path.suffix.casefold() in TEXT_EXTENSIONS or path.name in {".gitignore"}:
        return True
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return False
    if b"\x00" in chunk:
        return False
    if not chunk:
        return True
    textish = sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in chunk)
    return textish / len(chunk) > 0.85


def read_text_file(path: Path) -> str:
    if not path.is_file():
        raise SystemExit("Not a file.")
    if not is_probably_text(path):
        raise SystemExit("Refusing to print non-text file. Use stat/list to inspect metadata.")
    return path.read_text(encoding="utf-8-sig", errors="replace")


def iter_target_files(ctx: RedactedContext, refs: list[str], globs: list[str]) -> Iterable[Path]:
    starts = [ctx.resolve_ref(ref) for ref in refs] if refs else [ctx.root]
    seen: set[Path] = set()
    for start in starts:
        if ctx.is_excluded(start):
            raise SystemExit("Path is excluded by policy.")
        paths = [start] if start.is_file() else ctx.walk(start)
        for path in paths:
            if path in seen or not path.is_file() or not is_probably_text(path):
                continue
            rel = rel_posix(path, ctx.root)
            if globs and not any(fnmatch.fnmatch(rel, pattern) for pattern in globs):
                continue
            seen.add(path)
            yield path
