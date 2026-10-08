"""Source adapter contract and registry.

Layering rule: **sources own identity and reference opaqueness; the redaction
boundary owns content redaction.**

A source adapter turns one kind of private data (a filesystem root, GitHub
issues, later a mailbox) into raw text plus opaque references. It decides how
private identifiers become neutral references (``@p_<id>`` path ids,
``<alias>#<number>`` issue refs, ``user_<hex>`` author aliases) and it enforces
its own containment and exclusion policy. It never redacts content: everything
a source yields is raw and must pass through the CLI/MCP redaction boundary
(``Redactor`` plus ``rendering``) before it leaves the process.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Iterator, Protocol, Sequence, runtime_checkable

from .filesystem import RedactedContext
from .github import GitHubSource
from .limits import OperationBudget
from .models import RedactionConfig, SourceCapabilities, SourceDocument


@runtime_checkable
class ContextSource(Protocol):
    """Minimal contract every context source implements.

    - ``name``: stable registry key such as ``"filesystem"`` or ``"github"``.
    - ``untrusted_content``: true when text comes from outside the operator's
      control (for example upstream issue bodies); outputs must label it.
    - ``capabilities``: which tool families the source backs and whether
      ``iter_documents`` is supported.
    - ``owns_reference(ref)``: whether ``ref`` is in this source's opaque
      reference namespace. Purely syntactic plus configuration; no I/O.
    - ``resolve_reference(ref)``: map an owned opaque reference to the
      source-native handle (a validated ``Path``, an ``(alias, number)``
      pair, ...). Raises ``SystemExit`` with a message that never echoes
      raw identifiers for foreign, malformed, unknown, or excluded refs.
    - ``iter_documents(budget, scope=..., patterns=...)``: yield raw
      ``SourceDocument`` items under ``budget``. Exceeding a limit raises
      ``OperationLimitError`` rather than truncating silently. Sources that
      do not declare ``capabilities.documents`` raise ``SystemExit`` before
      any I/O or budget consumption.
    """

    name: str
    untrusted_content: bool
    capabilities: SourceCapabilities

    def owns_reference(self, ref: str) -> bool: ...

    def resolve_reference(self, ref: str) -> object: ...

    def iter_documents(
        self,
        budget: OperationBudget,
        *,
        scope: Sequence[str] = (),
        patterns: Sequence[str] = (),
    ) -> Iterator[SourceDocument]: ...


class SourceRegistry:
    """The set of sources one server or CLI invocation exposes, keyed by name."""

    def __init__(self, sources: Iterable[ContextSource]) -> None:
        self._sources: dict[str, ContextSource] = {}
        for source in sources:
            if source.name in self._sources:
                raise ValueError("Duplicate context source name.")
            self._sources[source.name] = source
        if not isinstance(self._sources.get("filesystem"), RedactedContext):
            raise ValueError("A filesystem context source is required.")

    def __iter__(self) -> Iterator[ContextSource]:
        return iter(self._sources.values())

    def __contains__(self, name: object) -> bool:
        return name in self._sources

    def names(self) -> tuple[str, ...]:
        return tuple(self._sources)

    def get(self, name: str) -> ContextSource | None:
        return self._sources.get(name)

    @property
    def filesystem(self) -> RedactedContext:
        source = self._sources["filesystem"]
        assert isinstance(source, RedactedContext)
        return source

    @property
    def github(self) -> GitHubSource | None:
        source = self._sources.get("github")
        return source if isinstance(source, GitHubSource) else None

    def owner_of(self, ref: str) -> ContextSource | None:
        """Return the single source whose namespace contains ``ref``, if any."""
        owners = [source for source in self._sources.values() if source.owns_reference(ref)]
        return owners[0] if len(owners) == 1 else None


def build_sources(
    root: Path,
    config: RedactionConfig,
    *,
    include_private: bool = False,
    documents: bool = False,
) -> SourceRegistry:
    """Build every source enabled by ``config``.

    The filesystem source is always present. GitHub is present only when the
    config defines ``[github.repos.<alias>]`` tables. Callers rebuild the whole
    registry together with the ``Redactor`` whenever the policy changes.
    """
    sources: list[ContextSource] = [
        RedactedContext(root, config, include_private=include_private, documents=documents)
    ]
    github = GitHubSource.from_config(config)
    if github is not None:
        sources.append(github)
    return SourceRegistry(sources)
