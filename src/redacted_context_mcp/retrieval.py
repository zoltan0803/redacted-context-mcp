"""Small, dependency-free passage retrieval over redacted text only."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import re

from .defaults import PLACEHOLDER_RE
from .filesystem import RedactedContext, iter_target_files
from .limits import OperationBudget, OperationLimitError
from .paths import rel_posix
from .redaction import Redactor

TOKEN_RE = re.compile(rf"{PLACEHOLDER_RE.pattern}|[^\W_]+(?:[-'][^\W_]+)*", re.UNICODE)
STOP_WORDS = frozenset("a an and are as at be by for from how in is it of on or that the this to was what when where which who with".split())
PASSAGE_CHARS = 1600
PASSAGE_LINES = 24
MAX_PASSAGES = 20_000


@dataclass
class Passage:
    ref: str
    path: str
    start_line: int
    end_line: int
    text: str
    score: float = 0.0


def tokens(text: str) -> list[str]:
    # Whole opaque placeholders are searchable; their category/hash fragments
    # must not become incidental matches for ordinary query words.
    return [match.group().casefold() for match in TOKEN_RE.finditer(text)]


def passages(text: str):
    block: list[str] = []
    size = 0
    start = end = 1
    for number, line in enumerate(text.splitlines(), 1):
        if block and (size + len(line) + 1 > PASSAGE_CHARS or number - start >= PASSAGE_LINES):
            yield start, end, "\n".join(block)
            block, size = [], 0
        # Also bound a single exceptionally long line, keeping tokens intact
        # where possible and never cutting a redaction placeholder in half.
        while len(line) > PASSAGE_CHARS:
            cut = PASSAGE_CHARS
            space = line.rfind(" ", 0, cut)
            if space > 0:
                cut = space + 1
            for match in PLACEHOLDER_RE.finditer(line):
                if match.start() < cut < match.end():
                    cut = match.start()
                    break
                if match.start() >= cut:
                    break
            yield number, number, line[:cut]
            line = line[cut:]
        if not block:
            start = number
        block.append(line)
        size += len(line) + 1
        end = number
    if block:
        yield start, end, "\n".join(block)


def retrieve(
    ctx: RedactedContext, redactor: Redactor, query: str, *,
    paths: list[str], globs: list[str], budget: OperationBudget,
    max_results: int = 8, max_chars: int = 12_000,
) -> str:
    if not 1 <= max_results <= 50 or not 256 <= max_chars <= 100_000:
        raise SystemExit("Retrieval requires max_results between 1 and 50 and max_chars between 256 and 100000.")
    if len(query) > 2000:
        raise SystemExit("Retrieval query exceeds the 2000 character limit.")
    terms = set(tokens(query)) - STOP_WORDS
    if not terms or len(terms) > 64:
        raise SystemExit("Retrieval requires 1 to 64 searchable query terms.")
    candidates: list[tuple[Passage, Counter[str], int]] = []
    frequency: Counter[str] = Counter()
    count = total_length = 0
    for path in iter_target_files(ctx, paths, globs, budget=budget):
        raw = ctx.read_text(path, budget=budget)
        redacted = redactor.redact(raw, preserve_line_count=True)
        rel = rel_posix(path, ctx.root)
        ref, safe_path = ctx.display_ref(rel), redactor.redact_path(rel)
        for start, end, text in passages(redacted):
            budget.check_deadline()
            count += 1
            if count > MAX_PASSAGES:
                raise OperationLimitError("Retrieval passage limit exceeded. Narrow the paths or glob.")
            words = tokens(text)
            total_length += len(words)
            matches = Counter(word for word in words if word in terms)
            frequency.update(matches.keys())
            if matches:
                candidates.append((Passage(ref, safe_path, start, end, text), matches, len(words)))
    if not candidates:
        return "No matches.\n"
    average_length = max(1.0, total_length / max(1, count))
    for passage, matches, length in candidates:
        budget.check_deadline()
        # BM25, with query coverage as the primary ordering key below. A
        # passage addressing several terms beats one repeating only one term.
        passage.score = sum(
            math.log(1 + (count - frequency[word] + 0.5) / (frequency[word] + 0.5))
            * (hits * 2.2) / (hits + 1.2 * (0.25 + 0.75 * length / average_length))
            for word, hits in matches.items()
        )
    candidates.sort(key=lambda item: (-len(item[1]), -item[0].score, item[0].ref, item[0].start_line))
    output = ""
    selected = 0
    marker = "[TRUNCATED: more matching passages; narrow the query or increase limits]\n"
    for passage, _matches, _length in candidates[:max_results]:
        entry = (
            f"--- {passage.ref} {passage.path} lines {passage.start_line}-{passage.end_line} "
            f"score={passage.score:.3f} ---\n{passage.text}\n\n"
        )
        if len(output) + len(entry) + len(marker) > max_chars:
            # Return complete cited passages; do not mislabel truncated text
            # as a complete source range or split its placeholders.
            break
        output += entry
        selected += 1
    if selected < len(candidates):
        output += marker if selected else "Matching passages exceed max_chars. Increase max_chars to return a cited passage.\n"
    return output
