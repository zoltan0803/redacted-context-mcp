#!/usr/bin/env python3
"""MCP stdio server exposing redacted local-context tools.

This deliberately avoids external MCP SDK dependencies so the server can run in
minimal Python environments. It implements the stdio JSON-RPC lifecycle and the
tools/list + tools/call surface used by MCP clients.
"""

from __future__ import annotations

import argparse
import hashlib
import copy
import contextlib
import io
import json
import re
import sys
from argparse import Namespace
from collections import OrderedDict
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

try:
    from . import __version__
    from . import core as rc
except ImportError:  # pragma: no cover - direct script fallback
    __version__ = "0.8.0"
    package_root = Path(__file__).resolve().parents[1]
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))
    from redacted_context_mcp import core as rc

from redacted_context_mcp.config_reload import ConfigReloadError, LiveConfig
from redacted_context_mcp.documents import SAFE_ERROR_MESSAGES as DOCUMENT_ERROR_MESSAGES


SERVER_NAME = "redacted-context"
SERVER_TITLE = "Redacted Context"
SERVER_VERSION = __version__
MODERN_PROTOCOL_VERSION = "2026-07-28"
LATEST_LEGACY_PROTOCOL_VERSION = "2025-11-25"
LEGACY_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
MODERN_PROTOCOL_VERSIONS = (MODERN_PROTOCOL_VERSION,)
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"
SERVER_INFO_META_KEY = "io.modelcontextprotocol/serverInfo"
DISCOVERY_TTL_MS = 300_000
PUBLIC_LIST_TTL_MS = 300_000
RESOURCE_PAGE_SIZE = 200
RESOURCE_URI_PREFIX = "redctx://"
READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
TEXT_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "text": {"type": "string"},
        "receipt": {
            "type": "object",
            "properties": {
                "detector_profile": {"type": "string"},
                "counts_by_category": {"type": "object"},
            },
        },
    },
    "required": ["text", "receipt"],
    "additionalProperties": False,
}


class ProtocolError(Exception):
    def __init__(self, code: int, message: str, *, data: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


class ToolExecutionError(Exception):
    pass


class RedactedContentCache:
    def __init__(self, max_bytes: int) -> None:
        self.max_bytes = max(0, max_bytes)
        self.current_bytes = 0
        self.entries: OrderedDict[tuple[object, ...], str] = OrderedDict()

    def get(self, key: tuple[object, ...]) -> str | None:
        value = self.entries.get(key)
        if value is None:
            return None
        self.entries.move_to_end(key)
        return value

    def put(self, key: tuple[object, ...], value: str) -> None:
        if self.max_bytes <= 0:
            return
        size = len(value.encode("utf-8"))
        if size > self.max_bytes:
            return
        old = self.entries.pop(key, None)
        if old is not None:
            self.current_bytes -= len(old.encode("utf-8"))
        self.entries[key] = value
        self.current_bytes += size
        self.entries.move_to_end(key)
        while self.current_bytes > self.max_bytes and self.entries:
            _old_key, old_value = self.entries.popitem(last=False)
            self.current_bytes -= len(old_value.encode("utf-8"))

    def clear(self) -> None:
        self.entries.clear()
        self.current_bytes = 0

    def stats(self) -> dict[str, int]:
        return {"entries": len(self.entries), "bytes": self.current_bytes, "max_bytes": self.max_bytes}


class RedactedContextMcp:
    def __init__(
        self,
        *,
        root: Path,
        config_path: Path | None,
        mode: str,
        include_private: bool,
        documents: bool = False,
        enable_writes: bool = False,
        write_subdir: str = "incoming",
        max_resource_bytes: int = rc.DEFAULT_MAX_RESOURCE_BYTES,
        max_traversal_entries: int = rc.DEFAULT_MAX_TRAVERSAL_ENTRIES,
        max_submit_files: int = rc.DEFAULT_MAX_FILES,
        max_raw_bytes_per_file: int = rc.DEFAULT_MAX_RAW_BYTES_PER_FILE,
        max_total_raw_bytes: int = rc.DEFAULT_MAX_TOTAL_RAW_BYTES,
        cache_bytes: int = 2_000_000,
    ) -> None:
        self.root = root.expanduser().resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise SystemExit("Root must be an existing directory.")
        self.config_path = config_path.expanduser().resolve() if config_path is not None else None
        self.live_config = LiveConfig(
            self.root,
            self.config_path,
        )
        try:
            config = self.live_config.load()
        except ConfigReloadError as exc:
            raise SystemExit(str(exc)) from exc
        self.include_private = include_private
        self.documents = documents
        # Every source enabled by the policy; rebuilt with the redactor on reload.
        self.sources = self.build_sources(config)
        self.redactor = rc.Redactor(config, mode=mode)
        self.config_fingerprint = redaction_config_fingerprint(config)
        self.mode = mode
        self.enable_writes = enable_writes
        self.write_root = resolve_write_root(self.root, write_subdir)
        self.max_resource_bytes = max_resource_bytes
        self.max_traversal_entries = max_traversal_entries
        self.max_submit_files = max_submit_files
        self.max_raw_bytes_per_file = max_raw_bytes_per_file
        self.max_total_raw_bytes = max_total_raw_bytes
        self.cache = RedactedContentCache(cache_bytes)

    @property
    def ctx(self) -> rc.RedactedContext:
        """The filesystem source rooted at ``--root`` (always registered)."""
        return self.sources.filesystem

    def build_sources(self, config: rc.RedactionConfig) -> rc.SourceRegistry:
        return rc.build_sources(
            self.root,
            config,
            include_private=self.include_private,
            documents=self.documents,
        )

    def ensure_current_config(self) -> None:
        try:
            config = self.live_config.load()
            if config == self.ctx.config:
                return
            # Build the replacement completely before publishing it. This also
            # discards old raw rehydration mappings, the opaque path index,
            # and sources the new policy no longer enables.
            sources = self.build_sources(config)
            redactor = rc.Redactor(config, mode=self.mode)
            fingerprint = redaction_config_fingerprint(config)
        except (Exception, SystemExit) as exc:
            self.cache.clear()
            message = str(exc) if isinstance(exc, ConfigReloadError) else (
                "Redaction configuration could not be applied safely. Repair the local "
                "config, then retry. Context access is blocked."
            )
            raise ToolExecutionError(message) from exc
        self.sources = sources
        self.redactor = redactor
        self.config_fingerprint = fingerprint
        self.cache.clear()

    def ensure_resource_config(self) -> None:
        try:
            self.ensure_current_config()
        except ToolExecutionError as exc:
            raise ProtocolError(-32002, str(exc)) from exc

    def traversal_budget(self) -> rc.OperationBudget:
        return rc.OperationBudget(max_entries=self.max_traversal_entries)

    def submit_budget(self) -> rc.OperationBudget:
        return rc.OperationBudget(
            max_files=self.max_submit_files,
            max_raw_bytes_per_file=self.max_raw_bytes_per_file,
            max_total_raw_bytes=self.max_total_raw_bytes,
            max_entries=self.max_traversal_entries,
        )

    def initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("protocolVersion") or "")
        protocol_version = (
            requested
            if requested in LEGACY_PROTOCOL_VERSIONS
            else LATEST_LEGACY_PROTOCOL_VERSION
        )
        return {
            "protocolVersion": protocol_version,
            "capabilities": self.server_capabilities(),
            "serverInfo": server_info(),
            "instructions": self.instructions(),
        }

    def discover(self) -> dict[str, Any]:
        return {
            # server/discover negotiates only the stateless modern era.
            # Legacy revisions remain available through initialize and must
            # not be offered for per-request metadata negotiation.
            "supportedVersions": list(MODERN_PROTOCOL_VERSIONS),
            "capabilities": self.server_capabilities(),
            "instructions": self.instructions(),
        }

    def server_capabilities(self) -> dict[str, Any]:
        return {
            "tools": {"listChanged": False},
            "resources": {"listChanged": False},
        }

    def instructions(self) -> str:
        return (
            "Use redctx_tree, redctx_list, redctx_read, redctx_search, "
            "redctx_retrieve, redctx_stat, redctx_bundle, redctx_doctor, redctx_audit, "
            "redctx_refresh_index, and redctx_github_* "
            "tools for confidential local context. Redacted files are also "
            "available as redctx://p_<id> MCP resources. Results are redacted "
            "and file tools use opaque @p_<id> path references."
            " Local redaction config and term-file changes apply before the next "
            "context request. If a policy reload fails, ask the operator to repair "
            "the local configuration before retrying."
            " Use redctx_retrieve for ranked multi-word passage lookup with line citations."
            + (" Document extraction is enabled; document line citations refer to extracted Markdown." if self.documents else "")
            + (
                " redctx_submit_doc is enabled for controlled writes into "
                "the configured private-root write subdirectory."
                if self.enable_writes
                else ""
            )
        )

    def list_tools(self) -> dict[str, Any]:
        return {
            "tools": [
                public_tool_definition(tool)
                for tool in TOOL_DEFINITIONS
                if self.enable_writes or tool.get("name") != "redctx_submit_doc"
            ]
        }

    def list_resources(self, params: dict[str, Any]) -> dict[str, Any]:
        self.ensure_resource_config()
        offset = parse_cursor(params.get("cursor"))
        page: list[Path] = []
        next_cursor: str | None = None
        seen = 0
        try:
            for path in self.ctx.walk(budget=self.traversal_budget()):
                if not path.is_file() or not self.ctx.is_readable(path):
                    continue
                if seen < offset:
                    seen += 1
                    continue
                if len(page) >= RESOURCE_PAGE_SIZE:
                    next_cursor = str(offset + RESOURCE_PAGE_SIZE)
                    break
                page.append(path)
                seen += 1
        except rc.OperationLimitError as exc:
            raise ProtocolError(-32002, "Resource listing limit exceeded.") from exc
        resources = [self.resource_for_path(path) for path in page]
        result: dict[str, Any] = {"resources": resources}
        if next_cursor is not None:
            result["nextCursor"] = next_cursor
        return result

    def read_resource(self, params: dict[str, Any]) -> dict[str, Any]:
        self.ensure_resource_config()
        uri = params.get("uri")
        if not isinstance(uri, str):
            raise ProtocolError(-32602, "resources/read requires string uri.")
        path = self.path_for_resource_uri(uri)
        if self.ctx.is_excluded(path):
            raise ProtocolError(-32002, "Resource not found.")
        try:
            text = self.redacted_file_text(path)
        except (SystemExit, ToolExecutionError) as exc:
            raise ProtocolError(-32002, str(exc) or "Resource not found.") from exc
        rel = rc.rel_posix(path, self.ctx.root)
        return {
            "contents": [
                {
                    "uri": resource_uri(self.ctx.path_id(rel)),
                    "mimeType": mime_type_for_path(path),
                    "text": text,
                }
            ]
        }

    def list_resource_templates(self) -> dict[str, Any]:
        return {
            "resourceTemplates": [
                {
                    "uriTemplate": f"{RESOURCE_URI_PREFIX}{{path_id}}",
                    "name": "redacted_context_file",
                    "title": "Redacted Context File",
                    "description": "Read a redacted text file by opaque p_<id> path id.",
                    "mimeType": "text/plain",
                }
            ]
        }

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            raise ProtocolError(-32602, f"Unknown tool: {name}")
        before = self.redactor.stats_snapshot()
        try:
            self.ensure_current_config()
            before = self.redactor.stats_snapshot()
            validate_tool_arguments(name, arguments)
            text = handler(self, arguments)
        except ToolExecutionError as exc:
            text = str(exc) or "Tool execution failed."
            return {
                "content": [{"type": "text", "text": text}],
                "structuredContent": {"text": text, "receipt": self.redactor.receipt(before)},
                "isError": True,
            }
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": {"text": text, "receipt": self.redactor.receipt(before)},
            "isError": False,
        }

    def run_cli_command(self, command: Callable[[Namespace, rc.RedactedContext, rc.Redactor], int], args: Namespace) -> str:
        stdout = io.StringIO()
        try:
            with contextlib.redirect_stdout(stdout):
                status = command(args, self.ctx, self.redactor)
        except SystemExit as exc:
            raise ToolExecutionError(safe_error_message(exc, self.redactor)) from exc
        except Exception as exc:
            raise ToolExecutionError("Tool execution failed.") from exc

        output = stdout.getvalue()
        if status == 1 and output.strip():
            raise ToolExecutionError(output)
        if status == 1 and not output.strip():
            return "No matches.\n"
        return output or "OK\n"

    def run_source_operation(self, operation: Callable[[], str], *, empty: str) -> str:
        """Run a source-backed operation that returns already-redacted text.

        Errors are sanitized exactly like CLI-command errors: only known safe
        messages pass through, so raw identifiers and upstream response text
        never reach the client.
        """
        try:
            output = operation()
        except SystemExit as exc:
            raise ToolExecutionError(safe_error_message(exc, self.redactor)) from exc
        except Exception as exc:
            raise ToolExecutionError("Tool execution failed.") from exc
        return output or empty

    def resource_for_path(self, path: Path) -> dict[str, Any]:
        rel = rc.rel_posix(path, self.ctx.root)
        redacted_path = self.redactor.redact_path(rel)
        return {
            "uri": resource_uri(self.ctx.path_id(rel)),
            "name": self.ctx.display_ref(rel),
            "title": redacted_path,
            "description": "Redacted text file from the configured context root.",
            "mimeType": mime_type_for_path(path),
            "size": path.stat().st_size,
            "annotations": {"audience": ["assistant"], "priority": 0.5},
        }

    def path_for_resource_uri(self, uri: str) -> Path:
        if not uri.startswith(RESOURCE_URI_PREFIX):
            raise ProtocolError(-32002, "Resource not found.")
        try:
            # The filesystem source is the single resolver for opaque refs.
            return self.ctx.resolve_reference(uri, budget=self.traversal_budget())
        except SystemExit as exc:
            raise ProtocolError(-32002, "Resource not found.") from exc

    def redacted_file_text(self, path: Path, *, preserve_line_count: bool = False) -> str:
        path = self.ctx.validate_path(path, expected="text")
        try:
            info = path.stat()
        except OSError as exc:
            raise ToolExecutionError("Resource not found.") from exc
        if info.st_size > self.max_resource_bytes:
            raise ToolExecutionError("Resource exceeds the server resource byte limit. Use redctx_read with a narrower range.")
        rel = rc.rel_posix(path, self.ctx.root)
        key = (
            rel,
            int(getattr(info, "st_dev", 0)),
            int(getattr(info, "st_ino", 0)),
            int(info.st_mtime_ns),
            int(info.st_size),
            self.mode,
            self.redactor.config.detector_profile,
            self.config_fingerprint,
            preserve_line_count,
        )
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        text = self.ctx.read_text(path)
        redacted = self.redactor.redact(text, preserve_line_count=preserve_line_count)
        if self.ctx.is_document(path) and len(redacted.encode("utf-8")) > self.max_resource_bytes:
            raise ToolExecutionError("Extracted resource exceeds the server resource byte limit. Use redctx_read with a narrower range.")
        self.cache.put(key, redacted)
        return redacted

    def submit_doc(self, *, target_path: str, text: str, overwrite: bool) -> str:
        if not self.enable_writes:
            raise ToolExecutionError("Writes are disabled. Start the server with --enable-writes.")
        try:
            replacements = rc.build_rehydration_map(
                self.ctx,
                self.redactor,
                budget=self.submit_budget(),
                exclude_roots=(self.write_root,),
            )
        except rc.OperationLimitError as exc:
            raise ToolExecutionError(str(exc) or "Rehydration map limit exceeded.") from exc
        restored_target, target_replacements = rc.rehydrate_text_with_count(target_path, replacements)
        unresolved_target = rc.unresolved_rehydration_tokens(restored_target)
        if unresolved_target:
            raise ToolExecutionError(format_unresolved_tokens("target_path", unresolved_target))
        output_path = resolve_submit_target(self.write_root, restored_target)

        restored_text, text_replacements = rc.rehydrate_text_with_count(text, replacements)
        unresolved_text = rc.unresolved_rehydration_tokens(restored_text)
        if unresolved_text:
            raise ToolExecutionError(format_unresolved_tokens("text", unresolved_text))
        text_placeholder_values, text_path_values = rc.applied_rehydration_values(text, replacements)
        target_placeholder_values, target_path_values = rc.applied_rehydration_values(target_path, replacements)
        self.verify_round_trip_redaction(
            restored_target,
            restored_text,
            text_placeholder_values + target_placeholder_values,
            text_path_values + target_path_values,
        )
        if output_path.exists():
            if output_path.is_dir():
                raise ToolExecutionError("Target already exists as a directory.")
            if not overwrite:
                raise ToolExecutionError("Target already exists. Pass overwrite=true to replace it.")

        try:
            rc.atomic_write_text(output_path, restored_text, overwrite=overwrite)
        except SystemExit as exc:
            raise ToolExecutionError(str(exc) or "Write failed.") from exc
        # The output ref is derived directly from its relative path and salt,
        # so an eager full-tree refresh is unnecessary. Invalidate lazily to
        # avoid traversing an arbitrarily large write subtree after publish.
        self.ctx.invalidate_path_index()
        self.cache.clear()
        rel = rc.rel_posix(output_path, self.root)
        total_replacements = target_replacements + text_replacements
        return (
            "Wrote rehydrated document.\n"
            f"id: {self.ctx.display_ref(rel)}\n"
            f"path: {self.redactor.redact_path(rel)}\n"
            f"bytes: {len(restored_text.encode('utf-8'))}\n"
            f"replacements: {total_replacements}\n"
        )

    def verify_round_trip_redaction(
        self,
        restored_target: str,
        restored_text: str,
        placeholder_values: list[str],
        path_values: list[str],
    ) -> None:
        """Reject writes that would not redact consistently when read back.

        A restored value glued into a surrounding token (for example
        ``foo[PERSON_x]bar`` or two adjacent placeholders) can defeat redaction
        word boundaries on read-back. Verification runs against both the
        server's strict mode and the weaker balanced mode, because the written
        document may later be served by a server started with ``--mode
        balanced``. Every applied value must vanish from the re-redacted
        result, and each distinctive word token of a sensitive value must not
        survive either. Relative-path values are only checked whole because
        their generic path tokens are expected to remain visible.
        """
        redactors = [self.redactor]
        if self.mode != "balanced":
            redactors.append(rc.Redactor(self.redactor.config, mode="balanced"))
        haystacks: list[str] = []
        for redactor in redactors:
            haystacks.append(rc.PLACEHOLDER_RE.sub("", redactor.redact(restored_text)).casefold())
            haystacks.append(rc.PLACEHOLDER_RE.sub("", redactor.redact_path(restored_target)).casefold())
        allow = self.redactor.allow_lookup
        for value in path_values:
            probe = value.casefold()
            if probe and any(probe in haystack for haystack in haystacks):
                raise ToolExecutionError(self.round_trip_error_message)
        for value in placeholder_values:
            # Values made entirely of generic vocabulary (for example an
            # ENTITY captured from a common word like "Email") are only
            # sensitive under strict-mode over-redaction; balanced read-back
            # legitimately shows them. Distinctive values are probed whole
            # and token-wise in both modes.
            tokens = [
                token.casefold()
                for token in re.split(r"[^A-Za-z0-9]+", value)
                if len(token) >= 3
            ]
            distinctive = [
                token
                for token in tokens
                if token not in allow and token not in rc.GENERIC_PROBE_STOPWORDS
            ]
            probes = [value.casefold()] + distinctive if distinctive else []
            for probe in probes:
                if any(probe in haystack for haystack in haystacks):
                    raise ToolExecutionError(self.round_trip_error_message)
        for value in placeholder_values:
            for token in re.split(r"[^A-Za-z0-9]+", value):
                folded = token.casefold()
                if len(folded) < 3 or folded in allow or folded in rc.GENERIC_PROBE_STOPWORDS:
                    continue
                if any(folded in haystack for haystack in haystacks):
                    raise ToolExecutionError(self.round_trip_error_message)

    round_trip_error_message = (
        "Rehydrated document would not redact consistently on read-back. "
        "Keep placeholder references separated by spaces or punctuation "
        "so restored values redact cleanly."
    )


def resolve_write_root(root: Path, write_subdir: str) -> Path:
    value = write_subdir.strip()
    if not value:
        raise SystemExit("--write-subdir must not be empty.")
    path = Path(value)
    if path.is_absolute() or any(part in {"..", ""} for part in path.parts) or path == Path("."):
        raise SystemExit("--write-subdir must be a relative subdirectory under root.")
    raw_write_root = root / path
    for current in [raw_write_root, *raw_write_root.parents]:
        if current == root.parent:
            break
        if current.is_symlink() or rc.is_reparse_point(current):
            raise SystemExit("--write-subdir must not contain symlinks or reparse points.")
    write_root = raw_write_root.resolve(strict=False)
    try:
        write_root.relative_to(root)
    except ValueError as exc:
        raise SystemExit("--write-subdir must stay under root.") from exc
    if write_root == root:
        raise SystemExit("--write-subdir must be a subdirectory under root.")
    return write_root


def resolve_submit_target(write_root: Path, target_path: str) -> Path:
    value = target_path.strip()
    if not value:
        raise ToolExecutionError("target_path must not be empty.")
    path = Path(value)
    if path.is_absolute() or any(part in {"..", ""} for part in path.parts) or path == Path("."):
        raise ToolExecutionError("target_path must be a relative file path inside the write subdirectory.")
    raw_output_path = write_root / path
    for current in [raw_output_path, *raw_output_path.parents]:
        if current == write_root.parent:
            break
        if current.is_symlink() or rc.is_reparse_point(current):
            raise ToolExecutionError("target_path must not contain symlinks.")
    output_path = raw_output_path.resolve(strict=False)
    try:
        output_path.relative_to(write_root)
    except ValueError as exc:
        raise ToolExecutionError("target_path must stay inside the write subdirectory.") from exc
    return output_path


def format_unresolved_tokens(field: str, tokens: list[str]) -> str:
    preview = ", ".join(tokens[:10])
    suffix = "" if len(tokens) <= 10 else f", and {len(tokens) - 10} more"
    return f"Unresolved redaction token(s) in {field}: {preview}{suffix}."


def redaction_config_fingerprint(config: rc.RedactionConfig) -> str:
    payload = {
        "clients": config.clients,
        "organizations": config.organizations,
        "people": config.people,
        "terms": config.terms,
        "allow": config.allow,
        "exclude_dirs": config.exclude_dirs,
        "exclude_globs": config.exclude_globs,
        "detector_profile": config.detector_profile,
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def safe_error_message(exc: SystemExit, redactor: rc.Redactor) -> str:
    value = str(exc)
    if not value:
        return "Tool execution failed."
    safe_messages = {
        "Path is excluded by policy.",
        "Path does not exist.",
        "Refusing path outside root.",
        "Not a file.",
        "Refusing to print non-text file. Use stat/list to inspect metadata.",
        "--end-line must be greater than or equal to --start-line.",
        "Unknown GitHub repo alias.",
        "GitHub issue was not found.",
        "Could not reach GitHub API.",
        "GitHub response too large.",
        "GitHub state must be open, closed, or all.",
        "Invalid regex.",
        rc.UNSAFE_REGEX_MESSAGE,
        "Refusing unsafe path.",
        "Traversal entry limit exceeded.",
        "File limit exceeded.",
        "Raw file byte limit exceeded.",
        "Total raw byte limit exceeded.",
        "Operation deadline exceeded.",
        "Discovery total byte limit exceeded.",
        "Output already exists.",
        "Could not publish output atomically.",
        "Retrieval requires max_results between 1 and 50 and max_chars between 256 and 100000.",
        "Retrieval query exceeds the 2000 character limit.",
        "Retrieval requires 1 to 64 searchable query terms.",
        "Retrieval passage limit exceeded. Narrow the paths or glob.",
        rc.UNKNOWN_REFERENCE_MESSAGE,
        rc.DOCUMENTS_UNSUPPORTED_MESSAGE,
        *DOCUMENT_ERROR_MESSAGES,
    }
    if (
        value in safe_messages
        or value.startswith("Unknown path id: @")
        or value.startswith("GitHub request failed for repo alias")
        or value.startswith("Could not verify GitHub's TLS certificate.")
        or value.startswith("--limit must be at least")
        or value.startswith("--max-comments must be at least")
        or value.startswith("--max-body-chars must be at least")
    ):
        return value
    return "Tool execution failed."


def parse_cursor(value: object) -> int:
    if value is None:
        return 0
    if not isinstance(value, str) or not value.isdigit():
        raise ProtocolError(-32602, "cursor must be a string offset.")
    return int(value)


def resource_uri(ref_id: str) -> str:
    return f"{RESOURCE_URI_PREFIX}{ref_id}"


def mime_type_for_path(path: Path) -> str:
    if path.suffix.casefold() in rc.DOCUMENT_EXTENSIONS:
        return "text/markdown"
    suffix = path.suffix.casefold()
    if suffix == ".md":
        return "text/markdown"
    if suffix in {".json", ".jsonl"}:
        return "application/json"
    if suffix in {".yaml", ".yml"}:
        return "application/yaml"
    if suffix == ".toml":
        return "application/toml"
    if suffix in {".py", ".sh", ".js", ".ts", ".tsx", ".jsx", ".sql", ".css", ".html", ".xml"}:
        return "text/plain"
    return "text/plain"


def public_tool_definition(tool: dict[str, Any]) -> dict[str, Any]:
    formatted = copy.deepcopy(tool)
    formatted.setdefault("title", title_from_tool_name(str(formatted.get("name", ""))))
    formatted.setdefault("annotations", dict(READ_ONLY_ANNOTATIONS))
    schema = formatted.setdefault("inputSchema", {"type": "object", "properties": {}})
    if isinstance(schema, dict):
        schema.setdefault("type", "object")
        schema.setdefault("properties", {})
        schema.setdefault("additionalProperties", False)
    formatted.setdefault("outputSchema", copy.deepcopy(TEXT_OUTPUT_SCHEMA))
    return formatted


def title_from_tool_name(name: str) -> str:
    name = name.removeprefix("redctx_")
    return " ".join(part.capitalize() for part in name.split("_") if part)


def validate_tool_arguments(name: str, arguments: dict[str, Any]) -> None:
    tool = TOOL_DEFINITION_BY_NAME.get(name)
    if tool is None:
        return
    schema = tool.get("inputSchema", {})
    properties = schema.get("properties", {}) if isinstance(schema, dict) else {}
    allowed = set(properties) if isinstance(properties, dict) else set()
    unexpected = sorted(set(arguments) - allowed)
    if unexpected:
        raise ToolExecutionError(f"Unexpected argument(s): {', '.join(unexpected)}.")
    required = schema.get("required", []) if isinstance(schema, dict) else []
    if isinstance(required, list):
        missing = [item for item in required if isinstance(item, str) and item not in arguments]
        if missing:
            raise ToolExecutionError(f"Missing required argument(s): {', '.join(missing)}.")
    for argument_name, value in arguments.items():
        argument_schema = properties.get(argument_name) if isinstance(properties, dict) else None
        if isinstance(argument_schema, dict):
            validate_schema_value(argument_name, value, argument_schema)


def validate_schema_value(name: str, value: Any, schema: dict[str, Any]) -> None:
    expected_type = schema.get("type")
    if expected_type == "string":
        if not isinstance(value, str):
            raise ToolExecutionError(f"{name} must be a string.")
    elif expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise ToolExecutionError(f"{name} must be an integer.")
        minimum = schema.get("minimum")
        if isinstance(minimum, int) and value < minimum:
            raise ToolExecutionError(f"{name} must be at least {minimum}.")
    elif expected_type == "boolean":
        if not isinstance(value, bool):
            raise ToolExecutionError(f"{name} must be a boolean.")
    elif expected_type == "array":
        if not isinstance(value, list):
            raise ToolExecutionError(f"{name} must be an array.")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_schema_value(f"{name}[{index}]", item, item_schema)

    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        allowed = ", ".join(str(item) for item in enum)
        raise ToolExecutionError(f"{name} must be one of: {allowed}.")


def string_arg(arguments: dict[str, Any], name: str, default: str) -> str:
    value = arguments.get(name, default)
    if not isinstance(value, str):
        raise ToolExecutionError(f"{name} must be a string.")
    return value


def int_arg(arguments: dict[str, Any], name: str, default: int | None) -> int | None:
    value = arguments.get(name, default)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ToolExecutionError(f"{name} must be an integer.")
    return value


def bool_arg(arguments: dict[str, Any], name: str, default: bool) -> bool:
    value = arguments.get(name, default)
    if not isinstance(value, bool):
        raise ToolExecutionError(f"{name} must be a boolean.")
    return value


def string_list_arg(arguments: dict[str, Any], name: str, default: list[str] | None = None) -> list[str]:
    value = arguments.get(name, default or [])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ToolExecutionError(f"{name} must be an array of strings.")
    return value


def redctx_tree(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_tree,
        Namespace(
            path=string_arg(arguments, "path", "."),
            max_depth=int_arg(arguments, "max_depth", 3),
        ),
    )


def redctx_list(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_ls,
        Namespace(
            path=string_arg(arguments, "path", "."),
            recursive=bool_arg(arguments, "recursive", False),
            max_depth=int_arg(arguments, "max_depth", None),
        ),
    )


def redctx_read(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_cat,
        Namespace(
            path=string_arg(arguments, "path", "."),
            start_line=int_arg(arguments, "start_line", None),
            end_line=int_arg(arguments, "end_line", None),
            max_chars=int_arg(arguments, "max_chars", rc.DEFAULT_MAX_CHARS) or rc.DEFAULT_MAX_CHARS,
            line_numbers=bool_arg(arguments, "line_numbers", False),
        ),
    )


def redctx_search(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_grep,
        Namespace(
            query=string_arg(arguments, "query", ""),
            paths=string_list_arg(arguments, "paths"),
            ignore_case=bool_arg(arguments, "ignore_case", True),
            regex=bool_arg(arguments, "regex", False),
            context=int_arg(arguments, "context", 0) or 0,
            glob=string_list_arg(arguments, "glob"),
            max_results=int_arg(arguments, "max_results", rc.DEFAULT_MAX_SEARCH_RESULTS)
            or rc.DEFAULT_MAX_SEARCH_RESULTS,
            max_seconds=rc.DEFAULT_MCP_SEARCH_SECONDS,
        ),
    )


def redctx_stat(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_stat,
        Namespace(path=string_arg(arguments, "path", ".")),
    )

def redctx_retrieve(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_retrieve,
        Namespace(
            query=string_arg(arguments, "query", ""),
            paths=string_list_arg(arguments, "paths"), glob=string_list_arg(arguments, "glob"),
            max_results=int_arg(arguments, "max_results", 8), max_chars=int_arg(arguments, "max_chars", 12_000),
            max_files=rc.DEFAULT_MAX_FILES, max_entries=server.max_traversal_entries,
            max_raw_bytes_per_file=server.max_raw_bytes_per_file,
            max_total_raw_bytes=server.max_total_raw_bytes, max_seconds=rc.DEFAULT_MCP_SEARCH_SECONDS,
        ),
    )


def redctx_bundle(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_bundle,
        Namespace(
            paths=string_list_arg(arguments, "paths"),
            glob=string_list_arg(arguments, "glob"),
            max_files=int_arg(arguments, "max_files", rc.DEFAULT_MAX_FILES) or rc.DEFAULT_MAX_FILES,
            max_chars_per_file=int_arg(arguments, "max_chars_per_file", 30_000) or 30_000,
            max_total_chars=int_arg(arguments, "max_total_chars", 300_000) or 300_000,
        ),
    )


def redctx_submit_doc(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.submit_doc(
        target_path=string_arg(arguments, "target_path", ""),
        text=string_arg(arguments, "text", ""),
        overwrite=bool_arg(arguments, "overwrite", False),
    )


def redctx_doctor(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_doctor,
        Namespace(root=server.root, config=server.config_path),
    )


def redctx_audit(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_audit,
        Namespace(
            format=string_arg(arguments, "format", "text"),
            writes_enabled=server.enable_writes,
            write_subdir_confined=True,
            max_raw_bytes_per_file=rc.DEFAULT_MAX_RAW_BYTES_PER_FILE,
            max_total_raw_bytes=rc.DEFAULT_MAX_TOTAL_RAW_BYTES,
            max_entries=server.max_traversal_entries,
            max_seconds=None,
        ),
    )


def redctx_refresh_index(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    try:
        server.ctx.refresh_index(budget=server.traversal_budget())
    except rc.OperationLimitError as exc:
        raise ToolExecutionError(str(exc) or "Path index limit exceeded.") from exc
    server.cache.clear()
    return "Refreshed path index.\n"


def redctx_github_repos(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_source_operation(
        lambda: rc.github_repos_text(server.sources.github),
        empty="OK\n",
    )


def redctx_github_list_issues(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    repo_alias = string_arg(arguments, "repo_alias", "context")
    state = string_arg(arguments, "state", "open")
    labels = string_list_arg(arguments, "labels")
    limit = int_arg(arguments, "limit", 30) or 30
    return server.run_source_operation(
        lambda: rc.github_issue_list_text(
            server.sources.github,
            server.redactor,
            repo_alias=repo_alias,
            state=state,
            labels=labels,
            limit=limit,
        ),
        empty="No matches.\n",
    )


def redctx_github_read_issue(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    number = int_arg(arguments, "number", None)
    if number is None:
        raise ToolExecutionError("number must be an integer.")
    repo_alias = string_arg(arguments, "repo_alias", "context")
    comments = bool_arg(arguments, "comments", False)
    max_comments = int_arg(arguments, "max_comments", 20)
    max_body_chars = int_arg(arguments, "max_body_chars", 30_000)
    return server.run_source_operation(
        lambda: rc.github_issue_detail_text(
            server.sources.github,
            server.redactor,
            repo_alias=repo_alias,
            number=number,
            comments=comments,
            max_comments=max_comments,
            max_body_chars=max_body_chars,
        ),
        empty="OK\n",
    )


def redctx_github_search_issues(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    repo_alias = string_arg(arguments, "repo_alias", "context")
    query = string_arg(arguments, "query", "")
    state = string_arg(arguments, "state", "open")
    limit = int_arg(arguments, "limit", 30) or 30
    return server.run_source_operation(
        lambda: rc.github_issue_search_text(
            server.sources.github,
            server.redactor,
            repo_alias=repo_alias,
            query=query,
            state=state,
            limit=limit,
        ),
        empty="No matches.\n",
    )


TOOL_HANDLERS: dict[str, Callable[[RedactedContextMcp, dict[str, Any]], str]] = {
    "redctx_tree": redctx_tree,
    "redctx_list": redctx_list,
    "redctx_read": redctx_read,
    "redctx_search": redctx_search,
    "redctx_retrieve": redctx_retrieve,
    "redctx_stat": redctx_stat,
    "redctx_bundle": redctx_bundle,
    "redctx_submit_doc": redctx_submit_doc,
    "redctx_doctor": redctx_doctor,
    "redctx_audit": redctx_audit,
    "redctx_refresh_index": redctx_refresh_index,
    "redctx_github_repos": redctx_github_repos,
    "redctx_github_list_issues": redctx_github_list_issues,
    "redctx_github_read_issue": redctx_github_read_issue,
    "redctx_github_search_issues": redctx_github_search_issues,
}


TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "redctx_tree",
        "description": "Show a redacted file tree with opaque @p_<id> path references.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "default": ".", "description": "Path or @p_<id> reference."},
                "max_depth": {"type": "integer", "default": 3, "minimum": 0},
            },
        },
    },
    {
        "name": "redctx_list",
        "description": "List redacted files/directories with opaque @p_<id> path references.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "default": ".", "description": "Path or @p_<id> reference."},
                "recursive": {"type": "boolean", "default": False},
                "max_depth": {"type": "integer", "minimum": 0},
            },
        },
    },
    {
        "name": "redctx_read",
        "description": "Read a redacted text file by path or opaque @p_<id> reference.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path or @p_<id> reference."},
                "start_line": {"type": "integer", "minimum": 1},
                "end_line": {"type": "integer", "minimum": 1},
                "max_chars": {"type": "integer", "default": rc.DEFAULT_MAX_CHARS, "minimum": 1},
                "line_numbers": {"type": "boolean", "default": False},
            },
            "required": ["path"],
        },
    },
    {
        "name": "redctx_search",
        "description": "Search redacted text. The query is evaluated against redacted output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": [],
                    "description": "Paths or @p_<id> references to search. Empty searches the root.",
                },
                "ignore_case": {"type": "boolean", "default": True},
                "regex": {"type": "boolean", "default": False},
                "context": {"type": "integer", "default": 0, "minimum": 0},
                "glob": {"type": "array", "items": {"type": "string"}, "default": []},
                "max_results": {"type": "integer", "default": rc.DEFAULT_MAX_SEARCH_RESULTS, "minimum": 1},
            },
            "required": ["query"],
        },
    },
    {
        "name": "redctx_retrieve",
        "description": "Rank redacted passages by multi-word keyword relevance. Returns opaque references and line citations (extracted Markdown lines for documents). No embeddings or persistent index.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "maxLength": 2000},
                "paths": {"type": "array", "items": {"type": "string"}, "default": []},
                "glob": {"type": "array", "items": {"type": "string"}, "default": []},
                "max_results": {"type": "integer", "default": 8, "minimum": 1, "maximum": 50},
                "max_chars": {"type": "integer", "default": 12000, "minimum": 256, "maximum": 100000},
            },
            "required": ["query"],
        },
    },
    {
        "name": "redctx_stat",
        "description": "Show redacted metadata for a path or opaque @p_<id> reference.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "redctx_bundle",
        "description": "Concatenate redacted text files for compact agent context.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "paths": {"type": "array", "items": {"type": "string"}, "default": []},
                "glob": {"type": "array", "items": {"type": "string"}, "default": []},
                "max_files": {"type": "integer", "default": rc.DEFAULT_MAX_FILES, "minimum": 1},
                "max_chars_per_file": {"type": "integer", "default": 30_000, "minimum": 1},
                "max_total_chars": {"type": "integer", "default": 300_000, "minimum": 1},
            },
        },
    },
    {
        "name": "redctx_submit_doc",
        "description": (
            "Submit a generated redacted document for controlled local rehydration "
            "and writing under the configured private-root write subdirectory."
        ),
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
            "openWorldHint": False,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Relative file path under the configured write subdirectory.",
                },
                "text": {
                    "type": "string",
                    "description": "Generated document text containing only redacted placeholders.",
                },
                "overwrite": {
                    "type": "boolean",
                    "default": False,
                    "description": "Replace an existing file at target_path.",
                },
            },
            "required": ["target_path", "text"],
        },
    },
    {
        "name": "redctx_doctor",
        "description": "Show redaction setup counts without printing sensitive terms.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "redctx_audit",
        "description": "Run safe local redaction and containment checks without printing sensitive terms.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "format": {"type": "string", "enum": ["text", "json"], "default": "text"},
            },
        },
    },
    {
        "name": "redctx_refresh_index",
        "description": "Refresh the in-memory opaque path index for the configured local root.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "redctx_github_repos",
        "description": "List configured GitHub repo aliases. Aliases should be neutral names such as context.",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "redctx_github_list_issues",
        "description": "List redacted GitHub issues from a configured repo alias.",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_alias": {
                    "type": "string",
                    "default": "context",
                    "description": "Configured neutral repo alias, not owner/repo.",
                },
                "state": {"type": "string", "enum": ["open", "closed", "all"], "default": "open"},
                "labels": {"type": "array", "items": {"type": "string"}, "default": []},
                "limit": {"type": "integer", "default": 30, "minimum": 1},
            },
        },
    },
    {
        "name": "redctx_github_read_issue",
        "description": "Read one redacted GitHub issue by configured repo alias and issue number.",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_alias": {
                    "type": "string",
                    "default": "context",
                    "description": "Configured neutral repo alias, not owner/repo.",
                },
                "number": {"type": "integer", "minimum": 1},
                "comments": {"type": "boolean", "default": False},
                "max_comments": {"type": "integer", "default": 20, "minimum": 0},
                "max_body_chars": {"type": "integer", "default": 30000, "minimum": 1},
            },
            "required": ["number"],
        },
    },
    {
        "name": "redctx_github_search_issues",
        "description": "Search GitHub issues in a configured repo alias and return redacted summaries.",
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": True,
        },
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_alias": {
                    "type": "string",
                    "default": "context",
                    "description": "Configured neutral repo alias, not owner/repo.",
                },
                "query": {"type": "string"},
                "state": {"type": "string", "enum": ["open", "closed", "all"], "default": "open"},
                "limit": {"type": "integer", "default": 30, "minimum": 1},
            },
            "required": ["query"],
        },
    },
]

TOOL_DEFINITION_BY_NAME: dict[str, dict[str, Any]] = {
    str(tool["name"]): tool for tool in TOOL_DEFINITIONS
}


def handle_request(server: RedactedContextMcp, message: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ProtocolError(-32602, "params must be an object.")

    if request_id is None:
        return None

    if method == "initialize":
        return server.initialize(params)
    modern = validate_modern_request_metadata(params, required=method == "server/discover")

    try:
        if method == "server/discover":
            return modern_result(method, server.discover())
        if method == "ping":
            if modern:
                raise ProtocolError(-32601, "Method not found: ping")
            return {}
        if method == "tools/list":
            result = server.list_tools()
            return modern_result(method, result) if modern else result
        if method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments")
            if arguments is None:
                arguments = {}
            if not isinstance(name, str) or not isinstance(arguments, dict):
                raise ProtocolError(-32602, "tools/call requires string name and object arguments.")
            result = server.call_tool(name, arguments)
            return modern_result(method, result) if modern else result
        if method == "resources/list":
            result = server.list_resources(params)
            return modern_result(method, result) if modern else result
        if method == "resources/read":
            result = server.read_resource(params)
            return modern_result(method, result) if modern else result
        if method == "resources/templates/list":
            result = server.list_resource_templates()
            return modern_result(method, result) if modern else result

        raise ProtocolError(-32601, f"Method not found: {method}")
    except ProtocolError as exc:
        if modern and exc.code == -32002:
            raise ProtocolError(-32602, exc.message, data=exc.data) from exc
        raise


def validate_modern_request_metadata(params: dict[str, Any], *, required: bool) -> bool:
    meta = params.get("_meta")
    if meta is None:
        if required:
            raise ProtocolError(-32602, "Modern MCP requests require params._meta.")
        return False
    if not isinstance(meta, dict):
        raise ProtocolError(-32602, "params._meta must be an object.")

    requested = meta.get(PROTOCOL_VERSION_META_KEY)
    if requested is None:
        if required:
            raise ProtocolError(
                -32602,
                f"params._meta.{PROTOCOL_VERSION_META_KEY} is required.",
            )
        return False
    if not isinstance(requested, str):
        raise ProtocolError(
            -32602,
            f"params._meta.{PROTOCOL_VERSION_META_KEY} must be a string.",
        )
    if requested != MODERN_PROTOCOL_VERSION:
        raise ProtocolError(
            -32022,
            "Unsupported protocol version",
            data={
                "supported": list(MODERN_PROTOCOL_VERSIONS),
                "requested": requested,
            },
        )

    client_capabilities = meta.get(CLIENT_CAPABILITIES_META_KEY)
    if not isinstance(client_capabilities, dict):
        raise ProtocolError(
            -32602,
            f"params._meta.{CLIENT_CAPABILITIES_META_KEY} must be an object.",
        )

    client_info = meta.get(CLIENT_INFO_META_KEY)
    if client_info is not None:
        if not isinstance(client_info, dict):
            raise ProtocolError(
                -32602,
                f"params._meta.{CLIENT_INFO_META_KEY} must be an object.",
            )
        if not isinstance(client_info.get("name"), str) or not isinstance(
            client_info.get("version"), str
        ):
            raise ProtocolError(
                -32602,
                f"params._meta.{CLIENT_INFO_META_KEY} requires string name and version.",
            )
    return True


def modern_result(method: str, result: dict[str, Any]) -> dict[str, Any]:
    modern = dict(result)
    modern["resultType"] = "complete"
    result_meta = modern.get("_meta")
    if result_meta is None:
        result_meta = {}
    elif not isinstance(result_meta, dict):
        raise ProtocolError(-32603, "Internal error.")
    else:
        result_meta = dict(result_meta)
    result_meta[SERVER_INFO_META_KEY] = server_info()
    modern["_meta"] = result_meta

    if method == "server/discover":
        modern["ttlMs"] = DISCOVERY_TTL_MS
        modern["cacheScope"] = "public"
    elif method in {"tools/list", "resources/templates/list"}:
        modern["ttlMs"] = PUBLIC_LIST_TTL_MS
        modern["cacheScope"] = "public"
    elif method in {"resources/list", "resources/read"}:
        modern["ttlMs"] = 0
        modern["cacheScope"] = "private"
    return modern


def server_info() -> dict[str, str]:
    return {
        "name": SERVER_NAME,
        "title": SERVER_TITLE,
        "version": SERVER_VERSION,
    }


def write_response(request_id: Any, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> None:
    response: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result if result is not None else {}
    payload = (json.dumps(response, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if hasattr(sys.stdout, "buffer"):
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
    else:  # pragma: no cover - nonstandard stream
        sys.stdout.write(payload.decode("utf-8"))
        sys.stdout.flush()


MAX_REQUEST_LINE_BYTES = 10 * 1024 * 1024
REQUEST_CHUNK_BYTES = 65536


def _read_request_chunk(stream: Any) -> bytes:
    """Read one available chunk without waiting for a full buffer."""
    reader = getattr(stream, "read1", None)
    if callable(reader):
        return reader(REQUEST_CHUNK_BYTES)
    # Nonstandard text stream fallback: readline keeps line semantics.
    data = stream.readline()
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return data


def iter_request_lines(stream: Any, max_bytes: int) -> Iterator[bytes | None]:
    """Yield newline-delimited request lines, capped at max_bytes each.

    Oversized lines are reported as None so the server can answer with a
    protocol error without buffering unbounded input in memory.
    """
    buffer = bytearray()
    overflow = False
    while True:
        chunk = _read_request_chunk(stream)
        if not chunk:
            if overflow:
                yield None
            elif buffer:
                yield bytes(buffer)
            return
        buffer.extend(chunk)
        while True:
            newline = buffer.find(b"\n")
            if newline < 0:
                break
            line = bytes(buffer[:newline])
            del buffer[: newline + 1]
            if overflow or len(line) > max_bytes:
                overflow = False
                yield None
            else:
                yield line
        if len(buffer) > max_bytes:
            overflow = True
            del buffer[:]


def serve(server: RedactedContextMcp, stream: Any | None = None) -> int:
    input_stream = stream if stream is not None else getattr(sys.stdin, "buffer", sys.stdin)
    for raw_line in iter_request_lines(input_stream, MAX_REQUEST_LINE_BYTES):
        if raw_line is None:
            write_response(
                None,
                error={"code": -32600, "message": "Request line exceeds maximum size."},
            )
            continue
        raw = raw_line.decode("utf-8", errors="replace").strip()
        if not raw:
            continue
        request_id: Any = None
        try:
            message = json.loads(raw)
            if not isinstance(message, dict):
                raise ProtocolError(-32600, "Invalid request.")
            request_id = message.get("id")
            result = handle_request(server, message)
            if request_id is not None:
                write_response(request_id, result=result)
        except json.JSONDecodeError as exc:
            write_response(None, error={"code": -32700, "message": f"Parse error: {exc.msg}"})
        except ProtocolError as exc:
            error: dict[str, Any] = {"code": exc.code, "message": exc.message}
            if exc.data is not None:
                error["data"] = exc.data
            write_response(request_id, error=error)
        except Exception:
            write_response(request_id, error={"code": -32603, "message": "Internal error."})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the redacted context MCP stdio server.")
    parser.add_argument("--root", type=Path, default=rc.REPO_ROOT, help="knowledgebase/context root")
    parser.add_argument("--config", type=Path, help=f"TOML config path, defaults to {rc.LOCAL_CONFIG}")
    parser.add_argument("--mode", choices=("balanced", "strict"), default="strict")
    parser.add_argument("--include-private", action="store_true")
    parser.add_argument("--documents", action="store_true", help="enable local document extraction; requires the documents extra")
    parser.add_argument(
        "--enable-writes",
        action="store_true",
        help="enable redctx_submit_doc controlled writes into --write-subdir",
    )
    parser.add_argument(
        "--write-subdir",
        default="incoming",
        help="relative private-root subdirectory used by redctx_submit_doc",
    )
    parser.add_argument(
        "--max-resource-bytes",
        type=int,
        default=rc.DEFAULT_MAX_RESOURCE_BYTES,
        help="maximum raw bytes allowed for MCP resources/read",
    )
    parser.add_argument(
        "--max-traversal-entries",
        type=int,
        default=rc.DEFAULT_MAX_TRAVERSAL_ENTRIES,
        help="maximum entries inspected for MCP resource/index traversal",
    )
    parser.add_argument(
        "--max-submit-files",
        type=int,
        default=rc.DEFAULT_MAX_FILES,
        help="maximum files scanned while building redctx_submit_doc rehydration maps",
    )
    parser.add_argument(
        "--max-raw-bytes-per-file",
        type=int,
        default=rc.DEFAULT_MAX_RAW_BYTES_PER_FILE,
        help="maximum raw bytes per file for MCP submit-doc rehydration scans",
    )
    parser.add_argument(
        "--max-total-raw-bytes",
        type=int,
        default=rc.DEFAULT_MAX_TOTAL_RAW_BYTES,
        help="maximum total raw bytes for MCP submit-doc rehydration scans",
    )
    parser.add_argument(
        "--cache-bytes",
        type=int,
        default=2_000_000,
        help="maximum in-memory bytes for redacted MCP content cache",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    rc.configure_stdio_utf8()
    args = build_parser().parse_args(argv)
    server = RedactedContextMcp(
        root=args.root,
        config_path=args.config,
        mode=args.mode,
        include_private=args.include_private,
        documents=args.documents,
        enable_writes=args.enable_writes,
        write_subdir=args.write_subdir,
        max_resource_bytes=args.max_resource_bytes,
        max_traversal_entries=args.max_traversal_entries,
        max_submit_files=args.max_submit_files,
        max_raw_bytes_per_file=args.max_raw_bytes_per_file,
        max_total_raw_bytes=args.max_total_raw_bytes,
        cache_bytes=args.cache_bytes,
    )
    return serve(server)


if __name__ == "__main__":
    raise SystemExit(main())
