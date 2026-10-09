"""Catastrophic-backtracking defences for regular expressions.

Two layers live here: a static screen that rejects obviously explosive
patterns, and a killable worker process that runs a regex under a wall-clock
bound. This leaf module has no package imports so that the CLI, the MCP
server, and plugged detectors (for example the built-in ``patterns``
detector) can share both without import cycles. ``core`` re-exports every
name here for compatibility.
"""

from __future__ import annotations

import math
import multiprocessing
import re
from typing import Any, Callable, Sequence, TypeVar


UNSAFE_REGEX_MESSAGE = "Unsafe regex: potentially catastrophic backtracking pattern."

# A quantified group whose repetition upper bound exceeds this is treated as
# effectively unbounded; below it, bounded backtracking is cheap enough.
QUANTIFIER_REPETITION_FLOOR = 8


def _regex_quantifier_at(pattern: str, index: int) -> tuple[str, int, float]:
    """Classify the quantifier starting at pattern[index].

    Returns ("none"|"bounded"|"unbounded", token_length, max_repetitions)
    where max_repetitions is inf for unbounded quantifiers.
    """
    n = len(pattern)
    if index >= n:
        return "none", 0, 0.0
    char = pattern[index]
    if char in "*+":
        if index + 1 < n and pattern[index + 1] == "+":
            return "unbounded", 2, math.inf
        return "unbounded", 1, math.inf
    if char == "?":
        if index + 1 < n and pattern[index + 1] in {"?", "+"}:
            return "bounded", 2, 1
        return "bounded", 1, 1
    if char == "{":
        end = pattern.find("}", index + 1)
        if end == -1 or end - index > 12:
            return "none", 0, 0.0
        body = pattern[index + 1 : end]
        if not re.fullmatch(r"\d*,\d*|\d+", body):
            return "none", 0, 0.0
        if "," in body and body.partition(",")[2] == "":
            return "unbounded", end - index + 1, math.inf
        parts = body.split(",")
        maximum = max(int(part) for part in parts if part)
        return "bounded", end - index + 1, float(maximum)
    return "none", 0, 0.0


def _split_top_level_alternation(body: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    index = 0
    n = len(body)
    while index < n:
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            close = index + 1
            if close < n and body[close] == "^":
                close += 1
            if close < n and body[close] == "]":
                close += 1
            while close < n and body[close] != "]":
                if body[close] == "\\":
                    close += 1
                close += 1
            index = close + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth = max(0, depth - 1)
        elif char == "|" and depth == 0:
            parts.append(body[start:index])
            start = index + 1
        index += 1
    parts.append(body[start:])
    return parts


def _branch_first_chars(branch: str) -> frozenset[str] | None:
    """Approximate set of literal first characters a branch can start with.

    Returns None when the estimate is unknown (escapes, dot, any class with
    negation or ranges, groups); callers must treat unknown as potentially
    overlapping.
    """
    branch = branch.lstrip("^")
    if not branch:
        return None
    if branch[0] == "\\":
        return None
    if branch[0] == ".":
        return None
    if branch[0] == "[":
        end = branch.find("]")
        if end == -1:
            return None
        inner = branch[1:end]
        if inner.startswith("^"):
            # Negated classes match almost anything; they cannot be narrowed
            # to the literal characters written inside the brackets.
            return None
        if inner.startswith("]"):
            inner = inner[1:]
        if "-" in inner or "\\" in inner:
            return None
        return frozenset(inner)
    if branch[0] == "(":
        close = branch.find(")")
        if close == -1:
            return None
        inner = branch[1:close]
        if inner.startswith("?"):
            return None
        branch_sets = [_branch_first_chars(part) for part in _split_top_level_alternation(inner)]
        if any(value is None for value in branch_sets):
            return None
        combined: set[str] = set()
        for value in branch_sets:
            combined.update(value)
        return frozenset(combined)
    return frozenset(branch[0])


def _alternation_overlap(body: str) -> bool:
    branches = _split_top_level_alternation(body)
    if len(branches) < 2:
        return False
    first_sets = [_branch_first_chars(branch) for branch in branches]
    for index in range(len(first_sets)):
        for other in range(index + 1, len(first_sets)):
            left, right = first_sets[index], first_sets[other]
            if left is None or right is None or left & right:
                return True
    return False


def regex_backtracking_violation(pattern: str) -> str | None:
    """Return a violating snippet when a pattern can backtrack explosively.

    Conservative screen over user-supplied regexes. A group is hazardous when
    its body contains any quantifier or an ambiguous top-level alternation;
    hazards propagate outward through nesting. A hazardous group quantified
    beyond QUANTIFIER_REPETITION_FLOOR repetitions (or unbounded) is rejected.
    Unknown shapes fail closed. The screen is a fast-fail layer; process-level
    match isolation enforces the actual wall-clock bound.
    """
    n = len(pattern)
    index = 0
    # Each stack entry: [group_open_position, has_quantifier_inside, hazard]
    groups: list[list[object]] = []

    while index < n:
        char = pattern[index]
        if char == "\\":
            index += 2
            kind, length, _maximum = _regex_quantifier_at(pattern, index)
            if kind != "none":
                index += length
                if groups:
                    groups[-1][1] = True
            continue
        if char == "[":
            close = index + 1
            if close < n and pattern[close] == "^":
                close += 1
            if close < n and pattern[close] == "]":
                close += 1
            while close < n and pattern[close] != "]":
                if pattern[close] == "\\":
                    close += 1
                close += 1
            index = close + 1
            kind, length, _maximum = _regex_quantifier_at(pattern, index)
            if kind != "none":
                index += length
                if groups:
                    groups[-1][1] = True
            continue
        if char == "(":
            groups.append([index, False, False])
            index += 1
            if index < n and pattern[index] == "?":
                index += 1
                if index < n and pattern[index] == "P":
                    index += 1
                    if index < n and pattern[index] == "<":
                        gt = pattern.find(">", index)
                        index = gt + 1 if gt != -1 else n
            continue
        if char == ")":
            if not groups:
                index += 1
                continue
            open_position, has_quantifier, inner_hazard = groups.pop()
            close_position = index
            index += 1
            kind, length, maximum = _regex_quantifier_at(pattern, index)
            if kind != "none":
                index += length
            body = pattern[open_position + 1 : close_position]
            if body.startswith("?P") or body.startswith("?<"):
                gt = body.find(">")
                body = body[gt + 1 :] if gt != -1 else ""
            elif body.startswith("?"):
                body = body[2:]
            group_hazard = has_quantifier or inner_hazard or _alternation_overlap(body)
            if kind != "none" and maximum > QUANTIFIER_REPETITION_FLOOR and group_hazard:
                return pattern[max(0, open_position - 12) : min(n, index + 4)]
            if groups and (kind != "none" or group_hazard):
                groups[-1][1] = groups[-1][1] or kind != "none"
                groups[-1][2] = True if group_hazard else groups[-1][2]
            continue
        # Plain atom.
        index += 1
        kind, length, _maximum = _regex_quantifier_at(pattern, index)
        if kind != "none":
            index += length
            if groups:
                groups[-1][1] = True
    return None


# Killable worker processes ---------------------------------------------------

_T = TypeVar("_T")


def run_in_killable_process(
    target: Callable[..., None],
    args: tuple[Any, ...],
    collect: Callable[[Any, Any], _T],
) -> _T:
    """Run ``target(sender, *args)`` in a child process that never outlives the call.

    ``collect(receiver, process)`` reads the child's messages and returns the
    result, applying its own timeouts. The child is terminated as soon as
    ``collect`` returns or raises, so a runaway regex cannot hang the caller.
    """
    methods = multiprocessing.get_all_start_methods()
    context = multiprocessing.get_context("fork" if "fork" in methods else None)
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=target, args=(sender, *args), daemon=True)
    process.start()
    sender.close()
    try:
        return collect(receiver, process)
    finally:
        process.terminate()
        process.join(1)


def _regex_match_worker(connection: object, pattern: str, flags: int, job: list[list[str]], seconds: float) -> None:
    """Apply a compiled pattern to redacted lines in an isolated process.

    Runs only redacted text and cannot outlive the parent's kill timeout, so
    catastrophic-backtracking patterns cannot hang the serving process.
    """
    import time as time_module

    try:
        compiled = re.compile(pattern, flags)
    except re.error:
        connection.send(("error", None))
        return
    deadline = time_module.monotonic() + seconds if seconds > 0 else None
    matched: list[list[int]] = []
    for lines in job:
        indices: list[int] = []
        for index, line in enumerate(lines):
            if deadline is not None and time_module.monotonic() > deadline:
                connection.send(("deadline", None))
                return
            if compiled.search(line):
                indices.append(index)
        matched.append(indices)
    connection.send(("ok", matched))


def match_regex_lines(
    pattern: str,
    flags: int,
    job: list[list[str]],
    timeout_seconds: float,
) -> list[list[int]]:
    """Match redacted lines with a user regex in a killable child process."""
    if not job:
        return []

    def collect(receiver: Any, process: Any) -> list[list[int]]:
        if not receiver.poll(timeout_seconds + 5):
            process.terminate()
            process.join(2)
            raise SystemExit("Operation deadline exceeded.")
        try:
            status, payload = receiver.recv()
        except (EOFError, OSError):
            process.terminate()
            process.join(2)
            raise SystemExit("Operation deadline exceeded.")
        if status == "deadline":
            raise SystemExit("Operation deadline exceeded.")
        if status == "error":
            raise SystemExit("Invalid regex.")
        return payload

    return run_in_killable_process(_regex_match_worker, (pattern, flags, job, timeout_seconds), collect)


# Launch-time stress test for operator-supplied regexes -------------------------

# Every rule runs over each of its stress inputs at two sizes. A rule is
# rejected as "too slow" when one run exceeds REGEX_STRESS_SECONDS, and as
# "superlinear" when the larger input takes more than REGEX_STRESS_GROWTH_LIMIT
# times as long as the smaller one (linear growth is 4x; quadratic is 16x).
# Growth is judged only when the larger run takes at least
# REGEX_STRESS_MIN_SECONDS, and a suspicious pair is re-timed and the fastest
# of REGEX_STRESS_REPEATS runs kept, so timer noise and a loaded machine do
# not reject linear rules.
REGEX_STRESS_SMALL_CHARS = 10_000
REGEX_STRESS_INPUT_CHARS = 40_000
REGEX_STRESS_SECONDS = 2.0
REGEX_STRESS_GROWTH_LIMIT = 6.0
REGEX_STRESS_MIN_SECONDS = 0.02
REGEX_STRESS_REPEATS = 3
REGEX_STRESS_STARTUP_SECONDS = 60.0
REGEX_STRESS_FAILED_MESSAGE = "Regex stress test could not run."
REGEX_STRESS_TOO_SLOW = "too slow"
REGEX_STRESS_SUPERLINEAR = "superlinear"
# Distinct characters taken from repeated atoms (each becomes a run input).
REGEX_STRESS_MAX_RUN_CHARS = 8
# Word and non-word characters (at most this many of each) taken from repeated
# atoms are paired; each pair becomes an alternating input, so a word boundary
# holds at every position.
REGEX_STRESS_MAX_PAIR_CHARS = 4
_STRESS_MIXED_UNIT = "word Text x1_9, a-b.c; (q) "
_STRESS_ESCAPES = {"d": "0", "w": "a", "s": " "}
_STRESS_METACHARACTERS = frozenset("()[]{}?*+|^$")
# Candidates tried for negated classes and categories, in order.
_STRESS_CANDIDATES = "aA0z9 _-.x@/"
_WORD_CHAR_RE = re.compile(r"\w")


def _cycled(unit: str, size: int) -> str:
    return (unit * (size // len(unit) + 1))[:size]


def _category_matches(category: object, char: str) -> bool:
    name = str(category)
    if name.endswith("_DIGIT"):
        matched = char.isdigit()
    elif name.endswith("_WORD"):
        matched = char.isalnum() or char == "_"
    elif name.endswith("_SPACE"):
        matched = char.isspace()
    elif name.endswith("_LINEBREAK"):
        matched = char == "\n"
    else:
        return False
    return not matched if "_NOT_" in name else matched


def _class_matches(items: Sequence[tuple[Any, Any]], char: str) -> bool:
    negate = False
    matched = False
    for op, av in items:
        name = str(op)
        if name == "NEGATE":
            negate = True
        elif name == "LITERAL" and chr(av) == char:
            matched = True
        elif name == "RANGE" and av[0] <= ord(char) <= av[1]:
            matched = True
        elif name == "CATEGORY" and _category_matches(av, char):
            matched = True
    return matched != negate


def _class_representatives(items: Sequence[tuple[Any, Any]]) -> list[str]:
    """A few characters that a parsed character class matches."""
    chars: list[str] = []
    if not any(str(op) == "NEGATE" for op, _av in items):
        for op, av in items:
            name = str(op)
            if name == "LITERAL":
                chars.append(chr(av))
            elif name == "RANGE":
                chars.extend((chr(av[0]), chr(av[1])))
            elif name == "CATEGORY":
                chars.extend(char for char in _STRESS_CANDIDATES if _category_matches(av, char))
    else:
        chars.extend(char for char in _STRESS_CANDIDATES if _class_matches(items, char))
    return list(dict.fromkeys(chars))


class _StressShape:
    """Characters and literals gathered from a parsed regex."""

    def __init__(self) -> None:
        self.skeleton: list[str] = []
        self.run_chars: list[str] = []
        self.prefix: list[str] = []
        self.prefix_open = True
        self.after_prefix: list[str] = []

    def atom(self, chars: list[str], *, repeated: bool, literal: bool) -> None:
        if not chars:
            return
        self.skeleton.append(chars[0])
        if repeated:
            self.run_chars.extend(chars)
        if self.prefix_open and literal and not repeated:
            self.prefix.append(chars[0])
            return
        if self.prefix_open:
            self.prefix_open = False
            self.after_prefix = chars

    def walk(self, parsed: Any, *, repeated: bool = False) -> None:
        for op, av in parsed:
            name = str(op)
            if name == "LITERAL":
                self.atom([chr(av)], repeated=repeated, literal=True)
            elif name == "NOT_LITERAL":
                self.atom([char for char in _STRESS_CANDIDATES if char != chr(av)], repeated=repeated, literal=False)
            elif name == "ANY":
                self.atom(["a", " ", "0"], repeated=repeated, literal=False)
            elif name == "IN":
                self.atom(_class_representatives(av), repeated=repeated, literal=False)
            elif name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}:
                low, high, body = av
                self.walk(body, repeated=repeated or high > 1)
                if low == 0:
                    self.prefix_open = False
            elif name == "SUBPATTERN":
                self.walk(av[-1], repeated=repeated)
            elif name == "ATOMIC_GROUP":
                self.walk(av, repeated=repeated)
            elif name == "BRANCH":
                branches = av[1]
                self.walk(branches[0], repeated=repeated)
                for branch in branches[1:]:
                    shape = _StressShape()
                    shape.prefix_open = False
                    shape.walk(branch, repeated=repeated)
                    self.run_chars.extend(shape.run_chars)
                self.prefix_open = False
            elif name == "AT":
                continue
            else:
                # Assertions, group references, and conditionals add no
                # characters; anything after them is not a literal prefix.
                self.prefix_open = False


def _stress_shape(pattern: str, flags: int) -> _StressShape | None:
    try:
        from re import _parser  # type: ignore[attr-defined]

        parsed = _parser.parse(pattern, flags)
    except Exception:
        return None
    shape = _StressShape()
    try:
        shape.walk(parsed)
    except Exception:
        return None
    return shape


def _legacy_skeleton(pattern: str) -> tuple[str, str]:
    """Literal prefix and skeleton from a lexical scan (used if parsing fails)."""
    skeleton: list[str] = []
    prefix: str | None = None
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\" and index + 1 < len(pattern):
            escaped = pattern[index + 1]
            if escaped in _STRESS_ESCAPES:
                prefix = "".join(skeleton) if prefix is None else prefix
                skeleton.append(_STRESS_ESCAPES[escaped])
            elif escaped in "bBAZ":  # zero-width assertions match no characters
                pass
            elif escaped.isalnum():
                prefix = "".join(skeleton) if prefix is None else prefix
            else:
                skeleton.append(escaped)
            index += 2
            continue
        if char in _STRESS_METACHARACTERS or char == ".":
            if prefix is None and not (char == "^" and index == 0):
                prefix = "".join(skeleton)
        if char not in _STRESS_METACHARACTERS:
            skeleton.append("a" if char == "." else char)
        index += 1
    return ("".join(skeleton) if prefix is None else prefix), "".join(skeleton)


def regex_stress_inputs(pattern: str, size: int = REGEX_STRESS_INPUT_CHARS, flags: int = 0) -> tuple[str, ...]:
    """Synthetic worst-case inputs for ``pattern``, each ``size`` characters long.

    Derived from the rule itself: a run of each character that a repeated
    atom (a class, category, dot, or literal under ``+``, ``*``, or a large
    ``{m,n}``) matches, including both ends of every range; each pair of a
    word and a non-word character drawn from those repeated atoms cycled,
    alone and after the literal prefix (``a.`` or ``eyJa-``: a word boundary
    at every position starts a new attempt, which catches word-boundary-anchored
    rules over classes that mix ``.`` or ``-`` with word characters); the
    literal prefix in its own, upper, and lower case followed by a run of
    the next atom's character; the rule's skeleton (one character per atom)
    cycled, and the skeleton without its last character (a near miss for
    rules that need a terminator) cycled. Generic inputs (a run of ``a``
    ending in a different character, mixed words and punctuation, runs of
    ``a`` and ``0``) are always included. Duplicates are removed; the order is stable.
    """
    shape = _stress_shape(pattern, flags)
    inputs: list[str] = ["a" * (size - 1) + "b", _cycled(_STRESS_MIXED_UNIT, size), "a" * size, "0" * size]
    if shape is None:
        prefix, skeleton = _legacy_skeleton(pattern)
        prefix = prefix[: size // 2]
        inputs.append(prefix + "a" * (size - len(prefix)))
        inputs.append(_cycled(skeleton[:-1] or _STRESS_MIXED_UNIT, size))
        return tuple(dict.fromkeys(inputs))
    all_run_chars = list(dict.fromkeys(shape.run_chars))
    run_chars = all_run_chars[:REGEX_STRESS_MAX_RUN_CHARS]
    inputs.extend(char * size for char in run_chars)
    prefix = "".join(shape.prefix)[: size // 2]
    word_chars = [char for char in all_run_chars if _WORD_CHAR_RE.match(char)][:REGEX_STRESS_MAX_PAIR_CHARS]
    other_chars = [char for char in all_run_chars if not _WORD_CHAR_RE.match(char)][:REGEX_STRESS_MAX_PAIR_CHARS]
    for word_char in word_chars:
        for other_char in other_chars:
            inputs.append(_cycled(word_char + other_char, size))
            if prefix:
                inputs.append(_cycled(prefix + word_char + other_char, size))
    if prefix:
        tail = (shape.after_prefix or ["a"])[0]
        for variant in dict.fromkeys((prefix, prefix.upper(), prefix.lower())):
            inputs.append(variant + tail * (size - len(variant)))
    skeleton = "".join(shape.skeleton)
    if skeleton:
        inputs.append(_cycled(skeleton, size))
    inputs.append(_cycled(skeleton[:-1] or _STRESS_MIXED_UNIT, size))
    return tuple(dict.fromkeys(inputs))


def _timed_scan(compiled: re.Pattern[str], text: str) -> float:
    import time as time_module

    started = time_module.perf_counter()
    for _match in compiled.finditer(text):
        pass
    return time_module.perf_counter() - started


def _regex_stress_worker(connection: Any, rules: list[tuple[str, int]]) -> None:
    """Time every rule over its stress inputs at both sizes, reporting after each run.

    Messages: ``("rule", index)`` before a rule, ``("step", index)`` after
    every timed run (the parent kills the child when one does not arrive in
    time), ``("superlinear", index)`` when a rule's time grows too fast,
    ``("error", index)`` for a rule that does not compile, and
    ``("ok", None)`` at the end.
    """
    connection.send(("ready", None))
    for index, (pattern, flags) in enumerate(rules):
        connection.send(("rule", index))
        try:
            compiled = re.compile(pattern, flags)
        except re.error:
            connection.send(("error", index))
            return
        small_inputs = regex_stress_inputs(pattern, REGEX_STRESS_SMALL_CHARS, flags)
        large_inputs = regex_stress_inputs(pattern, REGEX_STRESS_INPUT_CHARS, flags)
        for small_text, large_text in zip(small_inputs, large_inputs):
            small = _timed_scan(compiled, small_text)
            connection.send(("step", index))
            large = _timed_scan(compiled, large_text)
            connection.send(("step", index))
            for _repeat in range(REGEX_STRESS_REPEATS - 1):
                if not _superlinear(small, large):
                    break
                small = min(small, _timed_scan(compiled, small_text))
                connection.send(("step", index))
                large = min(large, _timed_scan(compiled, large_text))
                connection.send(("step", index))
            if _superlinear(small, large):
                connection.send(("superlinear", index))
                return
    connection.send(("ok", None))


def _superlinear(small: float, large: float) -> bool:
    return large >= REGEX_STRESS_MIN_SECONDS and large > REGEX_STRESS_GROWTH_LIMIT * small


def regex_stress_report(
    rules: Sequence[tuple[str, int]],
    *,
    seconds: float = REGEX_STRESS_SECONDS,
) -> tuple[int, str] | None:
    """Return ``(index, reason)`` for the first rule that fails the stress test.

    Every rule runs over each of its ``regex_stress_inputs`` at
    ``REGEX_STRESS_SMALL_CHARS`` and ``REGEX_STRESS_INPUT_CHARS`` characters
    in a single killable child process. ``reason`` is
    ``REGEX_STRESS_TOO_SLOW`` when one run needs more than ``seconds`` (the
    child is killed at the first overrun) and ``REGEX_STRESS_SUPERLINEAR``
    when the larger input takes more than ``REGEX_STRESS_GROWTH_LIMIT`` times
    as long as the smaller one. Returns ``None`` when every rule passes.
    Meant for launch-time checks of operator-trusted rules; raises
    ``SystemExit`` with an input-free message if the check itself cannot run.
    """
    job = [(str(pattern), int(flags)) for pattern, flags in rules]
    if not job:
        return None

    def collect(receiver: Any, process: Any) -> tuple[int, str] | None:
        del process
        try:
            if not receiver.poll(REGEX_STRESS_STARTUP_SECONDS) or receiver.recv()[0] != "ready":
                raise SystemExit(REGEX_STRESS_FAILED_MESSAGE)
            current = 0
            while True:
                if not receiver.poll(seconds):
                    return current, REGEX_STRESS_TOO_SLOW
                status, payload = receiver.recv()
                if status == "rule":
                    current = int(payload)
                elif status == "superlinear":
                    return int(payload), REGEX_STRESS_SUPERLINEAR
                elif status == "ok":
                    return None
                elif status != "step":
                    raise SystemExit(REGEX_STRESS_FAILED_MESSAGE)
        except (EOFError, OSError):
            raise SystemExit(REGEX_STRESS_FAILED_MESSAGE) from None

    return run_in_killable_process(_regex_stress_worker, (job,), collect)


def regex_stress_violation(
    rules: Sequence[tuple[str, int]],
    *,
    seconds: float = REGEX_STRESS_SECONDS,
) -> int | None:
    """Index of the first rule that fails ``regex_stress_report``, or ``None``."""
    report = regex_stress_report(rules, seconds=seconds)
    return None if report is None else report[0]
