#!/usr/bin/env python3
"""MCP stdio server exposing redacted local-context tools.

This deliberately avoids external MCP SDK dependencies so the server can run in
minimal Python environments. It implements the stdio JSON-RPC lifecycle and the
tools/list + tools/call surface used by MCP clients.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
from argparse import Namespace
from collections.abc import Callable
from pathlib import Path
from typing import Any

try:
    from . import __version__
    from . import core as rc
except ImportError:  # pragma: no cover - direct script fallback
    __version__ = "0.1.0"
    package_root = Path(__file__).resolve().parents[1]
    if str(package_root) not in sys.path:
        sys.path.insert(0, str(package_root))
    from redacted_context_mcp import core as rc


SERVER_NAME = "redacted-context"
SERVER_TITLE = "Redacted Context"
SERVER_VERSION = __version__
LATEST_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"}


class ProtocolError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class ToolExecutionError(Exception):
    pass


class RedactedContextMcp:
    def __init__(
        self,
        *,
        root: Path,
        config_path: Path | None,
        mode: str,
        include_private: bool,
    ) -> None:
        self.root = root.expanduser().resolve()
        if not self.root.exists() or not self.root.is_dir():
            raise SystemExit("Root must be an existing directory.")
        config = rc.load_config(
            self.root,
            config_path.expanduser().resolve() if config_path is not None else None,
        )
        self.ctx = rc.RedactedContext(self.root, config, include_private=include_private)
        self.redactor = rc.Redactor(config, mode=mode)
        self.config_path = config_path
        self.mode = mode

    def initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        requested = str(params.get("protocolVersion") or "")
        protocol_version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else LATEST_PROTOCOL_VERSION
        return {
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {
                "name": SERVER_NAME,
                "title": SERVER_TITLE,
                "version": SERVER_VERSION,
            },
            "instructions": (
                "Use redctx_tree, redctx_list, redctx_read, redctx_search, "
                "redctx_stat, redctx_bundle, redctx_doctor, and redctx_github_* "
                "tools for confidential local context. Results are redacted "
                "and file tools use opaque @p_<id> path references."
            ),
        }

    def list_tools(self) -> dict[str, Any]:
        return {"tools": TOOL_DEFINITIONS}

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        handler = TOOL_HANDLERS.get(name)
        if handler is None:
            raise ProtocolError(-32602, f"Unknown tool: {name}")
        try:
            text = handler(self, arguments)
        except ToolExecutionError as exc:
            text = str(exc) or "Tool execution failed."
            return {"content": [{"type": "text", "text": text}], "isError": True}
        return {"content": [{"type": "text", "text": text}], "isError": False}

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
        if status == 1 and not output.strip():
            return "No matches.\n"
        return output or "OK\n"


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
        "GitHub state must be open, closed, or all.",
    }
    if (
        value in safe_messages
        or value.startswith("Unknown path id: @")
        or value.startswith("GitHub request failed for repo alias")
        or value.startswith("Could not reach GitHub API:")
        or value.startswith("Could not verify GitHub's TLS certificate.")
        or value.startswith("--limit must be at least")
        or value.startswith("--max-comments must be at least")
        or value.startswith("--max-body-chars must be at least")
    ):
        return value
    return redactor.redact_path(value)


def string_arg(arguments: dict[str, Any], name: str, default: str) -> str:
    value = arguments.get(name, default)
    if not isinstance(value, str):
        raise ToolExecutionError(f"{name} must be a string.")
    return value


def int_arg(arguments: dict[str, Any], name: str, default: int | None) -> int | None:
    value = arguments.get(name, default)
    if value is None:
        return None
    if not isinstance(value, int):
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
        ),
    )


def redctx_stat(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_stat,
        Namespace(path=string_arg(arguments, "path", ".")),
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


def redctx_doctor(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_doctor,
        Namespace(root=server.root, config=server.config_path),
    )


def redctx_github_repos(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_github_repos,
        Namespace(),
    )


def redctx_github_list_issues(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_github_issues,
        Namespace(
            repo_alias=string_arg(arguments, "repo_alias", "context"),
            state=string_arg(arguments, "state", "open"),
            label=string_list_arg(arguments, "labels"),
            limit=int_arg(arguments, "limit", 30) or 30,
        ),
    )


def redctx_github_read_issue(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    number = int_arg(arguments, "number", None)
    if number is None:
        raise ToolExecutionError("number must be an integer.")
    return server.run_cli_command(
        rc.command_github_issue,
        Namespace(
            repo_alias=string_arg(arguments, "repo_alias", "context"),
            number=number,
            comments=bool_arg(arguments, "comments", False),
            max_comments=int_arg(arguments, "max_comments", 20) or 20,
            max_body_chars=int_arg(arguments, "max_body_chars", 30_000) or 30_000,
        ),
    )


def redctx_github_search_issues(server: RedactedContextMcp, arguments: dict[str, Any]) -> str:
    return server.run_cli_command(
        rc.command_github_search,
        Namespace(
            repo_alias=string_arg(arguments, "repo_alias", "context"),
            query=string_arg(arguments, "query", ""),
            state=string_arg(arguments, "state", "open"),
            limit=int_arg(arguments, "limit", 30) or 30,
        ),
    )


TOOL_HANDLERS: dict[str, Callable[[RedactedContextMcp, dict[str, Any]], str]] = {
    "redctx_tree": redctx_tree,
    "redctx_list": redctx_list,
    "redctx_read": redctx_read,
    "redctx_search": redctx_search,
    "redctx_stat": redctx_stat,
    "redctx_bundle": redctx_bundle,
    "redctx_doctor": redctx_doctor,
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
        "name": "redctx_doctor",
        "description": "Show redaction setup counts without printing sensitive terms.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "redctx_github_repos",
        "description": "List configured GitHub repo aliases. Aliases should be neutral names such as context.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "redctx_github_list_issues",
        "description": "List redacted GitHub issues from a configured repo alias.",
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


def handle_request(server: RedactedContextMcp, message: dict[str, Any]) -> dict[str, Any] | None:
    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}
    if not isinstance(params, dict):
        raise ProtocolError(-32602, "params must be an object.")

    if request_id is None:
        return None

    if method == "initialize":
        return server.initialize(params)
    if method == "ping":
        return {}
    if method == "tools/list":
        return server.list_tools()
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise ProtocolError(-32602, "tools/call requires string name and object arguments.")
        return server.call_tool(name, arguments)

    raise ProtocolError(-32601, f"Method not found: {method}")


def write_response(request_id: Any, *, result: dict[str, Any] | None = None, error: dict[str, Any] | None = None) -> None:
    response: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id}
    if error is not None:
        response["error"] = error
    else:
        response["result"] = result if result is not None else {}
    sys.stdout.write(json.dumps(response, separators=(",", ":"), ensure_ascii=False) + "\n")
    sys.stdout.flush()


def serve(server: RedactedContextMcp) -> int:
    for line in sys.stdin:
        raw = line.strip()
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
            write_response(request_id, error={"code": exc.code, "message": exc.message})
        except Exception:
            write_response(request_id, error={"code": -32603, "message": "Internal error."})
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the redacted context MCP stdio server.")
    parser.add_argument("--root", type=Path, default=rc.REPO_ROOT, help="knowledgebase/context root")
    parser.add_argument("--config", type=Path, help=f"TOML config path, defaults to {rc.LOCAL_CONFIG}")
    parser.add_argument("--mode", choices=("balanced", "strict"), default="strict")
    parser.add_argument("--include-private", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    server = RedactedContextMcp(
        root=args.root,
        config_path=args.config,
        mode=args.mode,
        include_private=args.include_private,
    )
    return serve(server)


if __name__ == "__main__":
    raise SystemExit(main())
