"""Optional local document extraction. Only explicitly supported converters run."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import zipfile

DOCUMENT_EXTENSIONS = frozenset({".docx", ".pptx", ".pdf", ".xlsx", ".xls"})
LEGACY_OFFICE_EXTENSIONS = frozenset({".doc", ".ppt"})
MAX_DOCUMENT_BYTES = 5_000_000
MAX_EXTRACTED_CHARS = 1_000_000
MAX_EXPANDED_BYTES = 50_000_000
MAX_ARCHIVE_MEMBERS = 2_000
EXTRACTION_SECONDS = 15.0
INSTALL_MESSAGE = 'Document extraction requires the optional extra: pip install "redacted-context-mcp[documents]".'
FAILURE_MESSAGE = "Document extraction failed. The document may be malformed, encrypted, or unsupported."
DISABLED_MESSAGE = "Document extraction is disabled. Install the documents extra and start with --documents."
LEGACY_MESSAGE = "Legacy .doc and .ppt files are unsupported. Export them as .docx, .pptx, or PDF first."
LIMIT_MESSAGE = "Document expanded-size or extracted-text limit exceeded."
EMPTY_MESSAGE = "Document contains no extractable text. Scanned documents require OCR outside this MCP."
SAFE_ERROR_MESSAGES = frozenset({
    INSTALL_MESSAGE, FAILURE_MESSAGE, DISABLED_MESSAGE, LEGACY_MESSAGE, LIMIT_MESSAGE, EMPTY_MESSAGE,
    "Unsupported document format.", "Document input byte limit exceeded.", "Document extraction deadline exceeded.",
})


def require_document_support() -> None:
    if importlib.util.find_spec("markitdown") is None:
        raise SystemExit(INSTALL_MESSAGE)


def extract_document(data: bytes, extension: str, *, timeout: float = EXTRACTION_SECONDS) -> str:
    require_document_support()
    if extension not in DOCUMENT_EXTENSIONS:
        raise SystemExit("Unsupported document format.")
    if len(data) > MAX_DOCUMENT_BYTES:
        raise SystemExit("Document input byte limit exceeded.")
    try:
        # Only bytes cross the worker boundary: no private filename, URL, raw
        # temporary file, plugin, cloud service, or auto-detected ZIP converter.
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), extension],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=max(0.001, min(timeout, EXTRACTION_SECONDS)),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise SystemExit("Document extraction deadline exceeded.") from exc
    except OSError as exc:
        raise SystemExit(FAILURE_MESSAGE) from exc
    messages = {
        2: INSTALL_MESSAGE,
        3: LIMIT_MESSAGE,
        4: EMPTY_MESSAGE,
    }
    if result.returncode:
        raise SystemExit(messages.get(result.returncode, FAILURE_MESSAGE))
    if len(result.stdout) > MAX_EXTRACTED_CHARS * 4:
        raise SystemExit(messages[3])
    try:
        return result.stdout.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SystemExit(FAILURE_MESSAGE) from exc


def convert_bytes(data: bytes, extension: str) -> str:
    # OOXML is a ZIP container. Bound declared expansion before parsing it.
    if extension in {".docx", ".pptx", ".xlsx"}:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if (len(members) > MAX_ARCHIVE_MEMBERS
                    or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES):
                raise SystemExit(3)
    from markitdown import StreamInfo, MissingDependencyException
    from markitdown.converters import DocxConverter, PdfConverter, PptxConverter, XlsxConverter, XlsConverter

    converter = {
        ".docx": DocxConverter, ".pdf": PdfConverter, ".pptx": PptxConverter,
        ".xlsx": XlsxConverter, ".xls": XlsConverter,
    }[extension]()
    try:
        result = converter.convert(io.BytesIO(data), StreamInfo(extension=extension))
    except MissingDependencyException as exc:
        raise SystemExit(2) from exc
    text = result.markdown
    if len(text) > MAX_EXTRACTED_CHARS:
        raise SystemExit(3)
    if not text.strip():
        raise SystemExit(4)
    return text


def worker() -> int:
    output_fd = os.dup(sys.stdout.fileno())
    try:
        # Suppress parser diagnostics at the OS stream level too: native
        # libraries must not pollute the result or MCP protocol with raw text.
        with open(os.devnull, "w") as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            os.dup2(sink.fileno(), 1)
            data = sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1)
            if len(data) > MAX_DOCUMENT_BYTES:
                return 3
            text = convert_bytes(data, sys.argv[1])
        with os.fdopen(os.dup(output_fd), "wb") as output:
            output.write(text.encode("utf-8"))
        return 0
    except ImportError:
        return 2
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    except Exception:
        return 1
    finally:
        os.close(output_fd)


if __name__ == "__main__":
    raise SystemExit(worker())
