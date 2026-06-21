"""Read-only filesystem access constrained to a configured root."""

from __future__ import annotations

import fnmatch
import os
import re
import stat
from pathlib import Path
from typing import Iterable

from .defaults import DEFAULT_EXCLUDE_DIRS, DEFAULT_EXCLUDE_GLOBS, TEXT_EXTENSIONS
from .limits import OperationBudget
from .models import RedactionConfig
from .paths import path_id, rel_posix


class RedactedContext:
    def __init__(self, root: Path, config: RedactionConfig, *, include_private: bool = False):
        self.root = root.resolve()
        self.config = config
        self.include_private = include_private
        self.exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(config.exclude_dirs)
        self.exclude_globs = set(DEFAULT_EXCLUDE_GLOBS) | set(config.exclude_globs)
        self._path_index: dict[str, str] | None = None

    def resolve_ref(self, value: str, *, expected: str | None = None) -> Path:
        if value.startswith("@"):
            return self.resolve_id(value[1:], expected=expected)
        if re.fullmatch(r"p_[0-9a-f]{12}", value):
            return self.resolve_id(value, expected=expected)
        return self.validate_user_path(value, expected=expected)

    def validate_user_path(
        self,
        value: str | Path,
        *,
        expected: str | None = None,
        allow_missing: bool = False,
    ) -> Path:
        candidate = Path(value).expanduser()
        if candidate.is_absolute():
            raw = candidate
        else:
            if any(part == ".." for part in candidate.parts):
                raise SystemExit("Refusing path outside root.")
            raw = self.root / candidate
        return self.validate_path(raw, expected=expected, allow_missing=allow_missing)

    def validate_path(
        self,
        path: Path,
        *,
        expected: str | None = None,
        allow_missing: bool = False,
    ) -> Path:
        raw = path.expanduser()
        if not raw.is_absolute():
            raw = self.root / raw
        try:
            rel = raw.relative_to(self.root)
        except ValueError as exc:
            raise SystemExit("Refusing path outside root.") from exc
        if any(part in {"..", ""} for part in rel.parts):
            raise SystemExit("Refusing path outside root.")

        current = self.root
        parts = rel.parts
        for index, part in enumerate(parts):
            current = current / part
            is_last = index == len(parts) - 1
            if current.is_symlink() or is_reparse_point(current):
                raise SystemExit("Refusing unsafe path.")
            if not current.exists():
                if allow_missing and is_last:
                    return current
                raise SystemExit("Path does not exist.")

        try:
            resolved = current.resolve(strict=not allow_missing)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise SystemExit("Refusing path outside root.") from exc

        if expected == "file" and not resolved.is_file():
            raise SystemExit("Not a file.")
        if expected == "directory" and not resolved.is_dir():
            raise SystemExit("Not a directory.")
        if expected == "text":
            if not resolved.is_file():
                raise SystemExit("Not a file.")
            if not is_probably_text(resolved):
                raise SystemExit("Refusing to print non-text file. Use stat/list to inspect metadata.")
        return resolved

    def path_id(self, rel_path: str) -> str:
        return path_id(rel_path, self.config.salt)

    def display_ref(self, rel_path: str) -> str:
        return f"@{self.path_id(rel_path)}"

    def resolve_id(self, ref_id: str, *, expected: str | None = None) -> Path:
        index = self.path_index()
        rel = index.get(ref_id)
        if rel is None:
            raise SystemExit(f"Unknown path id: @{ref_id}")
        try:
            path = self.validate_user_path(rel, expected=expected)
            if self.is_excluded(path):
                raise SystemExit("Path is excluded by policy.")
            return path
        except SystemExit as exc:
            self.invalidate_path_index()
            self.refresh_path_index()
            if ref_id not in (self._path_index or {}):
                raise SystemExit(f"Unknown path id: @{ref_id}") from exc
            raise

    def invalidate_path_index(self) -> None:
        self._path_index = None

    def refresh_index(self) -> None:
        self.invalidate_path_index()
        self.path_index()

    def refresh_path_index(self) -> None:
        self.refresh_index()

    def path_index(self) -> dict[str, str]:
        if self._path_index is not None:
            return self._path_index
        index: dict[str, str] = {}
        for path in self.walk(include_dirs=True):
            rel = rel_posix(path, self.root)
            ref_id = self.path_id(rel)
            existing = index.get(ref_id)
            if existing is not None and existing != rel:
                raise SystemExit("Opaque path id collision detected.")
            index[ref_id] = rel
        self._path_index = index
        return index

    def is_excluded(self, path: Path) -> bool:
        if self.include_private:
            return False
        rel = rel_posix(path, self.root)
        try:
            parts = path.relative_to(self.root).parts
        except ValueError:
            return True
        if any(part in self.exclude_dirs for part in parts):
            return True
        return any(fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in self.exclude_globs)

    def walk(
        self,
        start: Path | None = None,
        *,
        include_dirs: bool = False,
        max_depth: int | None = None,
        max_entries: int | None = None,
        budget: OperationBudget | None = None,
    ) -> Iterable[Path]:
        start = self.validate_path(start or self.root)
        if self.is_excluded(start):
            return
        walk_budget = budget or OperationBudget(max_entries=max_entries)
        seen: set[tuple[int, int]] = set()
        yield from self._walk(start, include_dirs=include_dirs, max_depth=max_depth, depth=0, seen=seen, budget=walk_budget)

    def _walk(
        self,
        path: Path,
        *,
        include_dirs: bool,
        max_depth: int | None,
        depth: int,
        seen: set[tuple[int, int]],
        budget: OperationBudget,
    ) -> Iterable[Path]:
        budget.consume_entry()
        if path.is_symlink() or is_reparse_point(path):
            return
        try:
            mode = path.lstat().st_mode
        except OSError:
            return
        identity = file_identity(path)
        if identity is not None:
            if identity in seen:
                return
            seen.add(identity)
        if stat.S_ISREG(mode):
            yield path
            return
        if not stat.S_ISDIR(mode):
            yield path
            return
        if include_dirs:
            yield path
        if max_depth is not None and depth >= max_depth:
            return
        for child in self._safe_child_entries(path):
            if self.is_excluded(child):
                continue
            try:
                child_mode = child.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISDIR(child_mode):
                yield from self._walk(
                    child,
                    include_dirs=include_dirs,
                    max_depth=max_depth,
                    depth=depth + 1,
                    seen=seen,
                    budget=budget,
                )
            else:
                budget.consume_entry()
                yield child

    def child_entries(self, path: Path, *, budget: OperationBudget | None = None) -> list[Path]:
        path = self.validate_path(path)
        if path.is_file():
            return [path]
        entries = [child for child in self._safe_child_entries(path) if not self.is_excluded(child)]
        if budget is not None:
            for _entry in entries:
                budget.consume_entry()
        return entries

    def _safe_child_entries(self, path: Path) -> list[Path]:
        children: list[tuple[tuple[int, str], Path]] = []
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    try:
                        if entry.is_symlink() or is_reparse_point(child):
                            continue
                        mode = entry.stat(follow_symlinks=False).st_mode
                    except OSError:
                        continue
                    is_file = not stat.S_ISDIR(mode)
                    children.append(((1 if is_file else 0, entry.name.casefold()), child))
        except OSError:
            return [child for _key, child in children]
        return [child for _key, child in sorted(children, key=lambda item: item[0])]

    def scan_link_entries(
        self,
        start: Path | None = None,
        *,
        budget: OperationBudget | None = None,
    ) -> tuple[list[Path], int]:
        scan_budget = budget or OperationBudget()
        root = self.validate_path(start or self.root, expected="directory")
        links: list[Path] = []
        broken = 0

        def visit(path: Path) -> None:
            nonlocal broken
            scan_budget.consume_entry()
            try:
                with os.scandir(path) as entries:
                    for entry in entries:
                        child = Path(entry.path)
                        if self.is_excluded(child):
                            continue
                        if entry.is_symlink() or is_reparse_point(child):
                            links.append(child)
                            try:
                                child.resolve(strict=True)
                            except (OSError, RuntimeError):
                                broken += 1
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            visit(child)
            except OSError:
                return

        visit(root)
        return links, broken


def is_probably_text(path: Path) -> bool:
    if path.suffix.casefold() in TEXT_EXTENSIONS or path.name in {".gitignore"}:
        return True
    try:
        chunk = path.read_bytes()[:4096]
    except OSError:
        return False
    return is_probably_text_bytes(chunk)


def is_probably_text_bytes(chunk: bytes) -> bool:
    if b"\x00" in chunk:
        return False
    if not chunk:
        return True
    textish = sum(byte in b"\n\r\t" or 32 <= byte <= 126 for byte in chunk)
    return textish / len(chunk) > 0.85


def entry_sort_key(path: Path) -> tuple[int, str]:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return (1, path.name.casefold())
    is_file = not stat.S_ISDIR(mode)
    return (1 if is_file else 0, path.name.casefold())


def is_reparse_point(path: Path) -> bool:
    if os.name != "nt":
        return False
    try:
        attrs = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def file_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    return (int(getattr(info, "st_dev", 0)), int(getattr(info, "st_ino", 0)))


def read_text_file(path: Path, *, budget: OperationBudget | None = None) -> str:
    if path.is_symlink() or is_reparse_point(path):
        raise SystemExit("Refusing unsafe path.")
    if not path.is_file():
        raise SystemExit("Not a file.")
    if budget is not None:
        budget.consume_file(path)
    if not is_probably_text(path):
        raise SystemExit("Refusing to print non-text file. Use stat/list to inspect metadata.")
    return path.read_text(encoding="utf-8-sig", errors="replace")


def iter_target_files(
    ctx: RedactedContext,
    refs: list[str],
    globs: list[str],
    *,
    budget: OperationBudget | None = None,
    text_only: bool = True,
) -> Iterable[Path]:
    starts = [ctx.resolve_ref(ref) for ref in refs] if refs else [ctx.root]
    seen: set[Path] = set()
    for start in starts:
        start = ctx.validate_path(start)
        if ctx.is_excluded(start):
            raise SystemExit("Path is excluded by policy.")
        paths = [start] if start.is_file() else ctx.walk(start, budget=budget)
        for path in paths:
            if path in seen:
                continue
            if path.is_symlink() or is_reparse_point(path):
                continue
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if not stat.S_ISREG(mode):
                continue
            if text_only and not is_probably_text(path):
                continue
            rel = rel_posix(path, ctx.root)
            if globs and not any(fnmatch.fnmatch(rel, pattern) for pattern in globs):
                continue
            seen.add(path)
            yield path
