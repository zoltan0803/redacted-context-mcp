"""Request-boundary reloads of local redaction policy, without a watcher thread."""

from __future__ import annotations

import stat
from pathlib import Path

from .config import load_config
from .defaults import LOCAL_CONFIG
from .models import RedactionConfig


class ConfigReloadError(Exception):
    """A deliberately non-sensitive error suitable for MCP responses."""


Stamp = tuple[int, int, int, int, int] | None


def file_stamp(path: Path) -> Stamp:
    try:
        info = path.stat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("Policy input must be a regular file.")
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class LiveConfig:
    """Keep one validated policy; never fall back to it after a failed reload.

    Metadata probes are cheap on unchanged requests. A changed policy is loaded
    twice around dependency snapshots, so newly referenced term files are also
    checked for concurrent edits before the candidate is accepted. Like the
    filesystem layer, this is not an adversarial concurrent-mutation sandbox.
    """

    def __init__(self, root: Path, config_path: Path | None) -> None:
        self.root = root
        self.path = config_path if config_path is not None else root / LOCAL_CONFIG
        self.config: RedactionConfig | None = None
        self.stamps: dict[Path, Stamp] = {}

    def snapshot(self, config: RedactionConfig | None) -> dict[Path, Stamp]:
        paths = {self.path}
        if config is not None:
            paths.update(self.root / name for name in config.term_files)
        return {path: file_stamp(path) for path in paths}

    def load(self) -> RedactionConfig:
        try:
            before = self.snapshot(self.config)
            if self.config is not None and before == self.stamps:
                return self.config
            # Removing a previously loaded config must not silently revert to
            # built-in detectors or create a new vault salt.
            if self.stamps.get(self.path) is not None and before[self.path] is None:
                raise ValueError("Loaded config disappeared.")
            candidate = load_config(self.root, self.path)
            middle = self.snapshot(candidate)
            if any(middle[path] != stamp for path, stamp in before.items() if path in middle):
                raise ValueError("Policy changed while loading.")
            # Missing files at startup remain optional for compatibility, but
            # once loaded they cannot disappear while still referenced.
            if any(
                stamp is not None and middle[path] is None
                for path, stamp in self.stamps.items() if path in middle
            ):
                raise ValueError("Loaded term file disappeared.")
            verified = load_config(self.root, self.path)
            after = self.snapshot(verified)
            if candidate != verified or middle != after:
                raise ValueError("Policy changed while loading.")
            if self.config is not None and candidate.salt != self.config.salt:
                raise ConfigReloadError(
                    "Redaction salt changed. Restore the previous salt or restart the MCP server "
                    "and obtain new opaque references. Context access is blocked."
                )
        except ConfigReloadError:
            raise
        except (Exception, SystemExit) as exc:
            # Parser and OS exceptions can contain private terms and paths.
            raise ConfigReloadError(
                "Redaction configuration could not be reloaded safely. Repair the local "
                "config and referenced term files, then retry. Context access is blocked."
            ) from exc
        self.config = candidate
        self.stamps = after
        return candidate
