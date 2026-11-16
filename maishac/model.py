"""Core shared data model for Maisha.

Every analyzer, the memory store, the loop engine and the MCP layer speak
one language: the Finding. A Finding carries a *stable fingerprint* so the
harness can recognize the same defect across edits (line numbers move,
content mostly doesn't) - this is what makes verification and memory work.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path


class Severity(str, Enum):
    # Unified severity across standards.
    # MISRA: mandatory/required/advisory. CERT: L1-L3. BARR-C: rule/guideline.
    BLOCKER = "blocker"      # MISRA mandatory, CERT L1
    CRITICAL = "critical"    # MISRA required,  CERT L2
    MAJOR = "major"          # CERT L3, BARR-C rules
    MINOR = "minor"          # MISRA advisory, BARR-C style guidance
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"blocker": 0, "critical": 1, "major": 2, "minor": 3, "info": 4}[self.value]


class Standard(str, Enum):
    MISRA = "MISRA-C:2012"
    BARR = "BARR-C:2018"
    CERT = "CERT-C"


_WS = re.compile(r"\s+")
_IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


def _normalize_line(line: str) -> str:
    """Whitespace-insensitive normalization so trivial reformatting does not
    change a finding's identity."""
    return _WS.sub(" ", line.strip())


def compute_fingerprint(rule_id: str, rel_path: str, line_content: str,
                        context_symbol: str = "", occurrence: int = 0) -> str:
    """Stable identity of a defect: rule + file + normalized offending line +
    enclosing symbol. Deliberately excludes the line *number*.

    ``occurrence`` tells apart the nth identical violating line in the same
    function. Occurrence 0 hashes exactly as it did before the argument
    existed, so every fingerprint already on record stays valid.
    """
    fields = [rule_id, rel_path, _normalize_line(line_content), context_symbol]
    if occurrence:
        fields.append(str(int(occurrence)))
    payload = "\x1f".join(fields)
    return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class Finding:
    rule_id: str                 # e.g. "MISRA-C:2012 Rule 21.3", "CERT STR31-C", "BARR-C 1.3a"
    standard: str                # Standard enum value
    severity: str                # Severity enum value
    file: str                    # path relative to project root
    line: int
    column: int = 0
    message: str = ""
    analyzer: str = "native"     # which evidence source produced it
    line_content: str = ""       # the offending source line (for fingerprint + agent context)
    context_symbol: str = ""     # enclosing function, if known
    fingerprint: str = ""
    cross_refs: list[str] = field(default_factory=list)  # equivalent rules in other standards
    fix_hint: str = ""           # short remediation guidance for the agent
    code_flow: list = field(default_factory=list)  # data-flow steps [{file,line,message}] from a qualified engine's SARIF codeFlows
    suppression: dict = field(default_factory=dict)  # {justification, kind} if an imported SARIF result was already suppressed/baselined

    def __post_init__(self) -> None:
        # Identity must not depend on the OS: always forward slashes.
        self.file = self.file.replace("\\", "/")
        if not self.fingerprint:
            self.fingerprint = compute_fingerprint(
                self.rule_id, self.file, self.line_content, self.context_symbol
            )

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        known = {f for f in Finding.__dataclass_fields__}  # type: ignore[attr-defined]
        return Finding(**{k: v for k, v in d.items() if k in known})


def _base_fingerprint(f: "Finding") -> str:
    return compute_fingerprint(f.rule_id, f.file, f.line_content, f.context_symbol)


def occurrence_alignment(runs: list[list["Finding"]]) -> dict[str, dict[int, int]]:
    """Occurrence numbers that let several analyzers number identical violations alike.

    ``assign_occurrences`` numbers repeats within one analyzer's run. If tool A
    reports both of two identical lines and tool B only the second, B's lone
    finding would be occurrence 0 and merge into A's finding for the FIRST line.
    For each group of identical violations (same rule, file, function and
    normalized source line) this returns a map ``line -> occurrence`` shared by
    all analyzers.

    * Analyzers that report the same lines (or a subset of them): occurrence =
      position of the line in the union of all reported lines.
    * Analyzers that disagree on where a violation is (multi-line statements,
      a tool pointing at the next line): reports from different analyzers within
      one line of each other are treated as the same violation and share one
      occurrence number. A line reported twice by the same analyzer, or a line
      that could belong to two different violations, makes the group truly
      ambiguous; it then keeps per-analyzer numbering (and is omitted here).
    """
    per_run: list[dict[str, set[int]]] = []
    for run in runs:
        per: dict[str, set[int]] = {}
        for f in run:
            if f.fingerprint == _base_fingerprint(f):
                per.setdefault(f.fingerprint, set()).add(f.line)
        per_run.append(per)
    out: dict[str, dict[int, int]] = {}
    for base in {b for per in per_run for b in per}:
        reports = [(idx, per[base]) for idx, per in enumerate(per_run) if base in per]
        union = sorted(set().union(*(lines for _, lines in reports)))
        if len(union) == max(len(lines) for _, lines in reports):
            out[base] = {line: i for i, line in enumerate(union)}
            continue
        clusters = _cluster_reports(reports)
        if clusters is not None:
            out[base] = {line: i for i, cluster in enumerate(clusters) for line in cluster}
    return out


def _cluster_reports(reports: list[tuple[int, set[int]]]) -> list[list[int]] | None:
    """Group lines reported by different analyzers (within one line of each other)
    into violations. None when the grouping would be a guess."""
    who: dict[int, set[int]] = {}
    for idx, lines in reports:
        for line in lines:
            who.setdefault(line, set()).add(idx)
    clusters: list[tuple[list[int], set[int]]] = []     # (lines, analyzers)
    for line in sorted(who):
        if clusters and line - clusters[-1][0][-1] <= 1:
            lines, owners = clusters[-1]
            if owners & who[line]:
                return None     # one tool reports two neighbouring lines: ambiguous
            lines.append(line)
            owners |= who[line]
        else:
            clusters.append(([line], set(who[line])))
    return [lines for lines, _ in clusters]


def assign_occurrences(findings: list["Finding"],
                       aligned: dict[str, dict[int, int]] | None = None) -> list["Finding"]:
    """Give identical violations their own identity.

    Two findings of the same rule on identical (whitespace-normalized) lines in
    the same function of one file hash to the same fingerprint, so fixing one
    would look like fixing both. Within one analyzer run, the nth such finding
    (in line order) gets occurrence n folded into its fingerprint. Occurrence 0
    keeps the legacy fingerprint. Repeats on the very same line are one
    finding, as before. Only fingerprints Maisha computed itself are touched;
    ones supplied by an external tool are kept verbatim.

    ``aligned`` (from :func:`occurrence_alignment`) numbers a finding by the
    occurrence its line maps to across all analyzers, instead of by the order
    within this run alone.

    Returns the findings with exact repeats removed, in their original order.
    """
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        base = compute_fingerprint(f.rule_id, f.file, f.line_content, f.context_symbol)
        if f.fingerprint == base:
            groups.setdefault(base, []).append(f)
    drop: set[int] = set()
    for base, members in groups.items():
        order = sorted(members, key=lambda f: (f.line, f.column))
        places: list[int] = []
        for f in order:
            place = f.line
            if place in places:
                drop.add(id(f))
                continue
            places.append(place)
            n = len(places) - 1
            if aligned and place in aligned.get(base, ()):
                n = aligned[base][place]
            if n:
                f.fingerprint = compute_fingerprint(f.rule_id, f.file, f.line_content,
                                                    f.context_symbol, n)
    return [f for f in findings if id(f) not in drop]


_CTRL_LEAD_RE = re.compile(r"^\s*(if|for|while|switch|else|do)\b")
_SIG_TAIL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*$")


def _reconstruct_header(lines: list[str], brace_line_idx: int) -> str:
    """A block's opening '{' identifies *that* brace's owner, but the header
    itself may live on earlier lines — either sharing the brace's line
    ("void f(void) {") or, for long parameter lists, spread across several
    lines with the brace alone on its own line (common Allman-style embedded
    C). Reconstruct the header text by pulling in lines until the parens
    balance, so it can be told apart from a control statement's header."""
    head = lines[brace_line_idx].split("{", 1)[0].strip()
    collected: list[str] = [head] if head else []
    j = brace_line_idx - 1
    if not head:
        while j >= 0 and not lines[j].strip():
            j -= 1
        if j < 0:
            return ""
        collected = [lines[j].strip()]
        j -= 1
    balance = collected[0].count(")") - collected[0].count("(")
    while balance > 0 and j >= 0:
        s = lines[j].strip()
        if not s:
            j -= 1
            continue
        if s.endswith((";", "{", "}")):
            break
        collected.insert(0, s)
        balance += s.count(")") - s.count("(")
        j -= 1
    return " ".join(collected).strip()


def enclosing_function(lines: list[str], idx: int) -> str:
    """Heuristic: walk upward tracking brace nesting to find the *innermost*
    block that actually encloses idx, skipping over control-flow blocks
    (if/for/while/switch/do) rather than matching the first line anywhere
    above that merely looks like a function header. Also reconstructs headers
    split across multiple lines. Good enough for fingerprint context."""
    balance = 0
    i = idx
    while i >= 0:
        balance += lines[i].count("}") - lines[i].count("{")
        if balance < 0:
            header = _reconstruct_header(lines, i)
            if header and not _CTRL_LEAD_RE.match(header):
                m = _SIG_TAIL_RE.search(header)
                if m:
                    return m.group(1)
            # not a function header (a control block, or unrecognized) —
            # treat this level as matched and keep looking for the next one up.
            balance = 0
        i -= 1
    return ""


def relpath(path: str | Path, root: str | Path) -> str:
    """Project-relative path with forward slashes on every OS, so a fingerprint
    computed on Windows equals the one computed on Linux."""
    try:
        return Path(path).resolve().relative_to(Path(root).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def jdump(obj) -> str:
    return json.dumps(obj, indent=2, default=str)
