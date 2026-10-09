"""Optional GLiNER zero-shot NER detector adapter.

Enable with ``--detector gliner`` or ``--detector gliner=OPTIONS`` after
``pip install "redacted-context-mcp[gliner]"``. ``OPTIONS`` is a
comma-separated ``key=value`` list:

- ``model``: Hugging Face model id (default ``urchade/gliner_small-v2.1``) or
  an absolute path to a local model directory. A value that looks like a path
  (it contains a backslash, starts with ``.``, ``~``, ``/``, or a drive
  letter, or names an existing directory) must be absolute and exist; any
  other value must be a ``namespace/name`` Hub id. Invalid values fail at
  startup without contacting the Hub.
- ``revision``: Hub revision (branch, tag, or commit) to load. Pinning a
  commit keeps detections reproducible across restarts.
- ``threshold``: minimum GLiNER score from 0 to 1 (default ``0.5``).
- ``labels``: ``|``-separated ``label:CATEGORY`` pairs replacing the default
  ``person:PERSON|organization:ORG``. Labels are passed to the model exactly
  as written; categories must be canonical placeholder categories.
- ``offline``: ``true`` loads only from the local Hugging Face cache
  (``local_files_only=True``). With the default ``false`` the Hub is contacted
  at every startup (to download the weights or check for a newer revision),
  even when the cache is warm; nothing is ever fetched at request time.
- ``window`` and ``overlap``: window size and overlap in GLiNER words (default
  300 and 50; the overlap must be smaller than half the window). GLiNER
  silently truncates input beyond its ``max_len`` (384 words for the default
  model).
- ``max_tokens``: subword-token budget per window, including the label prompt
  (default 512, at most the encoder's maximum sequence length).

Long text is analyzed in overlapping windows taken directly from the original
string. A window ends when it reaches ``window`` words *or* ``max_tokens``
subword tokens, counted with the model's own tokenizer, so token-heavy text
(long identifiers, base64, hex) cannot push a later name past what the model
attends to. For windowing only, a GLiNER word longer than 64 characters is
split into 64-character pieces; windows remain character ranges of the
original string, so offsets map back exactly. GLiNER labels whole words, so it
cannot find a name inside such a run of letters and digits; windows made only
of these pieces are skipped.

The library is imported only inside ``factory``, so importing this module (or
``detectors``) never imports GLiNER or torch. The model loads once at startup
and stays on the CPU, where inference is deterministic for identical input;
GPU inference may not be bit-for-bit deterministic and is not used. Calls are
serialized with a lock because neither GLiNER nor its tokenizer documents
thread safety.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .defaults import PLACEHOLDER_CATEGORIES
from .detectors import (
    Span,
    collect_window_spans,
    installed_version as distribution_version,
    parse_bool_option,
    parse_category_pairs,
    parse_detector_options,
    parse_float_option,
    parse_int_option,
)


DETECTOR_NAME = "gliner"
DISTRIBUTION = "gliner"
INSTALL_MESSAGE = (
    "The gliner detector requires GLiNER. Install it with: "
    'pip install "redacted-context-mcp[gliner]"'
)
DEFAULT_MODEL = "urchade/gliner_small-v2.1"
DEFAULT_THRESHOLD = 0.5
DEFAULT_WINDOW_WORDS = 300
DEFAULT_OVERLAP_WORDS = 50
MAX_WINDOW_WORDS = 4096
# Subword tokens per window, including the label prompt and special tokens.
# 512 is the sequence length the default model's DeBERTa encoder was trained on.
DEFAULT_MAX_TOKENS = 512
MIN_MAX_TOKENS = 64
MAX_MAX_TOKENS = 8192
# Words longer than this are split into pieces of this many characters for
# windowing, so one unbroken run cannot form an unbounded window.
LONG_WORD_CHARS = 64
DEFAULT_LABEL_CATEGORIES: Mapping[str, str] = {"person": "PERSON", "organization": "ORG"}
OPTION_KEYS = frozenset({"model", "revision", "threshold", "labels", "offline", "window", "overlap", "max_tokens"})
# GLiNER's own word splitter (gliner.data_processing.tokenizer.WhitespaceTokenSplitter);
# its max_len is counted in these words, so windows are counted the same way.
GLINER_WORD_RE = re.compile(r"\w+(?:[-_]\w+)*|\S")
SUPPORTED_WORD_SPLITTERS = frozenset({"whitespace"})
LABEL_RE = re.compile(r"[^|,:=\x00-\x1f]{1,64}")
HUB_MODEL_ID_RE = re.compile(r"[A-Za-z0-9][\w.-]*/[\w.-]+", re.ASCII)
REVISION_RE = re.compile(r"[A-Za-z0-9][\w./-]{0,127}", re.ASCII)
DRIVE_PREFIX_RE = re.compile(r"[A-Za-z]:")
WARM_UP_TEXT = "Warm-up check: Avery Lindqvist joined Lantern Labs."

TokenCounter = Callable[[Sequence[str]], Sequence[int]]


class GlinerConfigurationError(ValueError):
    """Invalid detector configuration; the message is operator-facing and input-free."""


def installed_version() -> str:
    return distribution_version(DISTRIBUTION)


# Windowing ------------------------------------------------------------------


def window_units(text: str) -> list[tuple[int, int, bool]]:
    """Return ``(start, end, is_piece)`` units: GLiNER words, long ones split.

    A word longer than ``LONG_WORD_CHARS`` becomes consecutive pieces of at
    most that many characters, flagged ``is_piece``.
    """

    units: list[tuple[int, int, bool]] = []
    for match in GLINER_WORD_RE.finditer(text):
        start, end = match.span()
        if end - start <= LONG_WORD_CHARS:
            units.append((start, end, False))
            continue
        for piece_start in range(start, end, LONG_WORD_CHARS):
            units.append((piece_start, min(piece_start + LONG_WORD_CHARS, end), True))
    return units


def word_windows(
    text: str,
    window_words: int,
    overlap_words: int,
    *,
    token_budget: int | None = None,
    count_tokens: TokenCounter | None = None,
) -> list[tuple[int, int]]:
    """Return ``[start, end)`` character windows over ``text``.

    Windows are built from ``window_units`` over the original string. Each
    window holds at most ``window_words`` units and, when ``count_tokens`` is
    given, at most ``token_budget`` subword tokens (a single unit that alone
    exceeds the budget still forms a window). A piece of an over-long word is
    charged one extra token, because the tokenizer may need one more token for
    a whole word than for its pieces. Each window runs from the first
    character of its first unit to the last character of its last unit, so
    offsets map back exactly. Consecutive windows share ``overlap_words``
    units, but never more than half of the earlier window, so token-limited
    windows still advance. Windows made only of pieces of over-long words are
    skipped.
    """

    units = window_units(text)
    if not units:
        return []
    costs: Sequence[int] | None = None
    if count_tokens is not None and token_budget is not None:
        counted = list(count_tokens([text[start:end] for start, end, _piece in units]))
        if len(counted) != len(units):
            raise ValueError("Token counter returned a wrong number of counts.")
        costs = [int(count) + (1 if piece else 0) for count, (_start, _end, piece) in zip(counted, units)]
    # natural[i] = number of non-piece units among units[:i]
    natural = [0]
    for _start, _end, piece in units:
        natural.append(natural[-1] + (0 if piece else 1))
    total = len(units)
    windows: list[tuple[int, int]] = []
    first = 0
    while True:
        last = first
        used = costs[first] if costs is not None else 0
        while last + 1 < total and last + 1 - first < window_words:
            if costs is not None and token_budget is not None:
                if used + costs[last + 1] > token_budget:
                    break
                used += costs[last + 1]
            last += 1
        if natural[last + 1] > natural[first]:
            windows.append((units[first][0], units[last][1]))
        if last == total - 1:
            return windows
        count = last - first + 1
        first = max(first + 1, last + 1 - min(overlap_words, count // 2))


# Model helpers --------------------------------------------------------------


def model_tokenizer(model: Any) -> Any | None:
    """Return the transformer tokenizer GLiNER uses, or ``None``."""

    tokenizer = getattr(getattr(model, "data_processor", None), "transformer_tokenizer", None)
    return tokenizer if callable(tokenizer) else None


def make_token_counter(tokenizer: Any) -> TokenCounter:
    """Count subword tokens per word the way GLiNER tokenizes its input.

    GLiNER passes pre-split words to the tokenizer (``is_split_into_words``),
    so each word's tokens are independent of its neighbours and window costs
    add up.
    """

    def count(words: Sequence[str]) -> list[int]:
        if not words:
            return []
        encoding = tokenizer(list(words), is_split_into_words=True, add_special_tokens=False)
        try:
            word_ids = encoding.word_ids()
        except (AttributeError, ValueError):  # slow tokenizers have no word_ids()
            word_ids = None
        if word_ids is None:
            return [len(ids) for ids in tokenizer(list(words), add_special_tokens=False)["input_ids"]]
        counts = [0] * len(words)
        for index in word_ids:
            if index is not None:
                counts[index] += 1
        return counts

    return count


def prompt_words(model: Any, labels: Sequence[str]) -> list[str]:
    """Return the label prompt GLiNER prepends to every window."""

    processor = getattr(model, "data_processor", None)
    prepare = getattr(processor, "prepare_inputs", None)
    if callable(prepare):
        try:
            input_texts, _lengths = prepare([[]], list(labels))
            return [str(word) for word in input_texts[0]]
        except Exception:
            pass
    config = getattr(model, "config", None)
    ent_token = getattr(processor, "ent_token", None) or getattr(config, "ent_token", None) or "<<ENT>>"
    sep_token = getattr(processor, "sep_token", None) or getattr(config, "sep_token", None) or "<<SEP>>"
    words: list[str] = []
    for label in labels:
        words.extend((str(ent_token), label))
    words.append(str(sep_token))
    return words


def prompt_token_count(model: Any, tokenizer: Any, labels: Sequence[str]) -> int:
    """Tokens taken by the label prompt plus the special tokens of a window."""

    return len(tokenizer(prompt_words(model, labels), is_split_into_words=True)["input_ids"])


def model_token_limit(model: Any) -> int:
    """The encoder's maximum sequence length, or ``DEFAULT_MAX_TOKENS``."""

    encoder = getattr(getattr(model, "config", None), "encoder_config", None)
    limit = getattr(encoder, "max_position_embeddings", None)
    if isinstance(limit, int) and not isinstance(limit, bool) and limit > 0:
        return limit
    return DEFAULT_MAX_TOKENS


class GlinerDetector:
    """Nominate spans found by a GLiNER model.

    ``model`` is any object with ``predict_entities(text, labels=[...],
    threshold=...)`` returning dicts with ``start``, ``end``, ``text``,
    ``label``, and ``score``, and with ``data_processor.transformer_tokenizer``
    (or pass ``tokenizer``); tests inject fakes. ``labels`` maps each label,
    exactly as passed to the model, to a canonical category. Results with an
    unknown label or a score below ``threshold`` are skipped; spans from
    overlapping windows are resolved with ``drop_contained_spans``, and span
    ends are extended over trailing combining marks.
    """

    name = DETECTOR_NAME

    def __init__(
        self,
        model: Any,
        *,
        version: str,
        labels: Mapping[str, str] | None = None,
        threshold: float = DEFAULT_THRESHOLD,
        window_words: int = DEFAULT_WINDOW_WORDS,
        overlap_words: int = DEFAULT_OVERLAP_WORDS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        tokenizer: Any | None = None,
    ) -> None:
        self.model = model
        self.version = version
        self.labels: dict[str, str] = dict(DEFAULT_LABEL_CATEGORIES if labels is None else labels)
        if not self.labels or any(category not in PLACEHOLDER_CATEGORIES for category in self.labels.values()):
            raise GlinerConfigurationError("GLiNER labels must map to canonical placeholder categories.")
        self.label_list = list(self.labels)
        self.threshold = float(threshold)
        if window_words < 2 or not 0 <= overlap_words * 2 < window_words:
            raise GlinerConfigurationError("The gliner detector option 'overlap' must be smaller than half of 'window'.")
        self.window_words = window_words
        self.overlap_words = overlap_words
        tokenizer = tokenizer if tokenizer is not None else model_tokenizer(model)
        if tokenizer is None:
            raise GlinerConfigurationError(
                "The gliner detector needs the model's transformer tokenizer to keep windows within the "
                "token budget, and this model does not expose one."
            )
        self.max_tokens = int(max_tokens)
        try:
            self.prompt_tokens = prompt_token_count(model, tokenizer, self.label_list)
        except Exception as exc:
            raise GlinerConfigurationError(
                f"The gliner detector could not measure its label prompt with the model's tokenizer ({type(exc).__name__})."
            ) from None
        if self.prompt_tokens > self.max_tokens // 2:
            raise GlinerConfigurationError(
                f"The gliner detector labels take {self.prompt_tokens} of the {self.max_tokens}-token window budget; "
                "use fewer or shorter labels."
            )
        self.token_budget = self.max_tokens - self.prompt_tokens
        self._count_tokens = make_token_counter(tokenizer)
        self._lock = threading.Lock()

    def windows(self, text: str) -> list[tuple[int, int]]:
        return word_windows(
            text,
            self.window_words,
            self.overlap_words,
            token_budget=self.token_budget,
            count_tokens=self._count_tokens,
        )

    def _predict(self, chunk: str) -> list[Any]:
        return list(self.model.predict_entities(chunk, labels=list(self.label_list), threshold=self.threshold))

    def detect(self, text: str) -> list[Span]:
        if not text:
            return []
        with self._lock:  # the tokenizer is not documented as thread-safe either
            return collect_window_spans(
                text,
                self.windows(text),
                self._predict,
                _read_entity,
                categories=self.labels,
                threshold=self.threshold,
                library="GLiNER",
            )


def _read_entity(entity: Any) -> tuple[object, object, object, object]:
    return entity["label"], entity["start"], entity["end"], entity["score"]


# Option parsing -------------------------------------------------------------


@dataclass(frozen=True)
class GlinerOptions:
    model: str = DEFAULT_MODEL
    threshold: float = DEFAULT_THRESHOLD
    labels: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_LABEL_CATEGORIES))
    offline: bool = False
    window_words: int = DEFAULT_WINDOW_WORDS
    overlap_words: int = DEFAULT_OVERLAP_WORDS
    revision: str | None = None
    max_tokens: int = DEFAULT_MAX_TOKENS
    local_model: bool = False


def _is_existing_directory(value: str) -> bool:
    try:
        return Path(value).is_dir()
    except (OSError, ValueError):
        return False


def resolve_model(value: str) -> tuple[str, bool]:
    """Return ``(model, is_local)`` or fail with a path-free startup error.

    A value that looks like a local path must be an absolute path to an
    existing directory; anything else must be a ``namespace/name`` Hub id, so
    a relative or mistyped path is never sent to the Hub as a repository id.
    """

    looks_local = (
        "\\" in value
        or value.startswith((".", "~", "/"))
        or DRIVE_PREFIX_RE.match(value) is not None
        or _is_existing_directory(value)
    )
    if looks_local:
        try:
            path = Path(value).expanduser()
            valid = path.is_absolute() and path.is_dir()
        except (OSError, RuntimeError, ValueError):
            valid = False
        if not valid:
            raise SystemExit(
                "The gliner detector option 'model' looks like a local path, but it is not an absolute path "
                "to an existing model directory."
            )
        return str(path), True
    if not HUB_MODEL_ID_RE.fullmatch(value) or any(part in {".", ".."} for part in value.split("/")):
        raise SystemExit(
            "The gliner detector option 'model' must be a Hugging Face model id such as "
            f"{DEFAULT_MODEL} or an absolute path to a local model directory."
        )
    return value, False


def _normalize_label(value: str) -> str | None:
    return value if LABEL_RE.fullmatch(value) else None


def parse_gliner_options(argument: str | None) -> GlinerOptions:
    """Validate the ``--detector gliner=...`` argument without importing GLiNER."""

    raw = parse_detector_options(argument, detector=DETECTOR_NAME, allowed=OPTION_KEYS)
    model = raw.get("model", DEFAULT_MODEL)
    if not model:
        raise SystemExit("The gliner detector option 'model' must not be empty.")
    model, local_model = resolve_model(model)
    revision: str | None = None
    if "revision" in raw:
        revision = raw["revision"]
        if not REVISION_RE.fullmatch(revision) or ".." in revision:
            raise SystemExit("The gliner detector option 'revision' must be a Hub branch, tag, or commit id.")
        if local_model:
            raise SystemExit("The gliner detector option 'revision' applies only to Hugging Face model ids.")
    threshold = DEFAULT_THRESHOLD
    if "threshold" in raw:
        threshold = parse_float_option(raw["threshold"], detector=DETECTOR_NAME, key="threshold", minimum=0.0, maximum=1.0)
    offline = False
    if "offline" in raw:
        offline = parse_bool_option(raw["offline"], detector=DETECTOR_NAME, key="offline")
    window_words = DEFAULT_WINDOW_WORDS
    if "window" in raw:
        window_words = parse_int_option(raw["window"], detector=DETECTOR_NAME, key="window", minimum=2, maximum=MAX_WINDOW_WORDS)
    overlap_words = DEFAULT_OVERLAP_WORDS
    if "overlap" in raw:
        overlap_words = parse_int_option(
            raw["overlap"], detector=DETECTOR_NAME, key="overlap", minimum=0, maximum=MAX_WINDOW_WORDS
        )
    if overlap_words * 2 >= window_words:
        raise SystemExit("The gliner detector option 'overlap' must be smaller than half of 'window'.")
    max_tokens = DEFAULT_MAX_TOKENS
    if "max_tokens" in raw:
        max_tokens = parse_int_option(
            raw["max_tokens"], detector=DETECTOR_NAME, key="max_tokens", minimum=MIN_MAX_TOKENS, maximum=MAX_MAX_TOKENS
        )
    labels = dict(DEFAULT_LABEL_CATEGORIES)
    if "labels" in raw:
        labels = parse_category_pairs(
            raw["labels"], detector=DETECTOR_NAME, key="labels", left_name="label", normalize=_normalize_label
        )
    return GlinerOptions(
        model=model,
        threshold=threshold,
        labels=labels,
        offline=offline,
        window_words=window_words,
        overlap_words=overlap_words,
        revision=revision,
        max_tokens=max_tokens,
        local_model=local_model,
    )


def model_label(model: str) -> str:
    """Return the model as recorded in ``version``: the default id, else ``custom``.

    Receipts and ``redctx doctor`` are agent-visible, so any other value (a
    private Hub id such as ``org/client-name-model`` or a local directory) is
    never echoed.
    """

    return model if model == DEFAULT_MODEL else "custom"


# Factory --------------------------------------------------------------------


def _import_gliner() -> tuple[Any, str]:
    """Import the optional library; isolated so tests can simulate absence."""

    try:
        import gliner
        from gliner import GLiNER
    except ImportError:
        raise SystemExit(INSTALL_MESSAGE) from None
    return GLiNER, str(getattr(gliner, "__version__", "") or installed_version())


def factory(argument: str | None) -> GlinerDetector:
    """Load the GLiNER model once at startup from ``--detector gliner[=OPTIONS]``."""

    options = parse_gliner_options(argument)
    gliner_cls, library_version = _import_gliner()
    label = model_label(options.model)
    load_options: dict[str, Any] = {"local_files_only": options.offline}
    if options.revision is not None:
        load_options["revision"] = options.revision
    try:
        model = gliner_cls.from_pretrained(options.model, **load_options)
    except Exception as exc:
        if options.offline:
            raise SystemExit(
                "The gliner detector could not load its model from the local Hugging Face cache "
                f"(offline=true, {type(exc).__name__}). Download it once before going offline, for example "
                "start once without offline=true or run `hf download MODEL_ID`, and keep HF_HOME pointing at "
                "the same cache."
            ) from None
        raise SystemExit(
            f"The gliner detector could not load its model ({type(exc).__name__}). Check the model option "
            "and network access to the Hugging Face Hub, which is contacted at every startup without "
            "offline=true, or pre-download the model and use offline=true."
        ) from None
    if hasattr(model, "eval"):
        model.eval()
    config = getattr(model, "config", None)
    splitter = getattr(config, "words_splitter_type", None)
    if splitter is not None and splitter not in SUPPORTED_WORD_SPLITTERS:
        raise SystemExit(
            "The gliner detector supports only models that split words on whitespace "
            "(words_splitter_type 'whitespace'). This model uses another splitter, which counts words "
            "differently from the adapter's windows and may download resources at request time."
        )
    max_len = getattr(config, "max_len", None)
    if isinstance(max_len, int) and not isinstance(max_len, bool) and options.window_words > max_len:
        raise SystemExit(
            f"The gliner detector option 'window' ({options.window_words}) exceeds the model's maximum of "
            f"{max_len} words."
        )
    token_limit = model_token_limit(model)
    if options.max_tokens > token_limit:
        raise SystemExit(
            f"The gliner detector option 'max_tokens' ({options.max_tokens}) exceeds the model's maximum "
            f"sequence length of {token_limit} tokens."
        )
    try:
        detector = GlinerDetector(
            model,
            version=f"{library_version}/{label}",
            labels=options.labels,
            threshold=options.threshold,
            window_words=options.window_words,
            overlap_words=options.overlap_words,
            max_tokens=options.max_tokens,
        )
    except GlinerConfigurationError as exc:
        raise SystemExit(str(exc)) from None
    try:
        detector.detect(WARM_UP_TEXT)
    except Exception as exc:
        raise SystemExit(f"The gliner detector failed its start-up check ({type(exc).__name__}).") from None
    return detector


__all__: Sequence[str] = (
    "DEFAULT_LABEL_CATEGORIES",
    "GlinerDetector",
    "GlinerOptions",
    "factory",
    "make_token_counter",
    "parse_gliner_options",
    "resolve_model",
    "window_units",
    "word_windows",
)
