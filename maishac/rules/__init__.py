"""Unified rule registry across MISRA C:2012, BARR-C:2018 and CERT C.

Responsibilities:
  * load + index all rule metadata shipped with the package
  * resolve fuzzy rule identifiers ("21.3", "misra 21.3", "STR31-C", "barr 1.3a")
  * expose the cross-standard equivalence graph so one fix can be credited
    against every standard it satisfies
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Optional

_FILES = {
    "MISRA-C:2012": "misra_c_2012.json",
    "BARR-C:2018": "barr_c_2018.json",
    "CERT-C": "cert_c.json",
}

_SEV_DEFAULT = {"mandatory": "blocker", "required": "critical", "advisory": "minor"}


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, dict] = {}   # canonical_id -> metadata
        self._by_standard: dict[str, list[str]] = {}
        for standard, fname in _FILES.items():
            data = json.loads(
                resources.files("maishac.rules").joinpath(fname).read_text("utf-8")
            )
            ids = []
            for rid, meta in data["rules"].items():
                canonical = self._canonical(standard, rid)
                meta = dict(meta)
                meta["id"] = canonical
                meta["standard"] = standard
                meta.setdefault("severity", "major")
                self._rules[canonical] = meta
                ids.append(canonical)
            self._by_standard[standard] = ids

    @staticmethod
    def _canonical(standard: str, rid: str) -> str:
        if standard == "MISRA-C:2012":
            return f"MISRA-C:2012 {rid}"
        if standard == "BARR-C:2018":
            return f"BARR-C {rid}"
        return f"CERT {rid}"

    # ------------------------------------------------------------------ lookup
    _PREFIX_RE = re.compile(
        r"^(?P<std>misra(?:[- ]?c)?(?:[: ]*2012)?|barr(?:[- ]?c)?(?:[: ]*2018)?|cert(?:[- ]?c)?)"
        r"(?![a-z0-9])[\s:]*")
    _NUM_RE = re.compile(r"(?:(?P<kind>rule|dir|directive)\s*)?(?P<num>\d+\.\d+)(?P<sfx>[a-z]?)")

    def candidates(self, query: str) -> list[dict]:
        """Every rule an authoritative reference could mean. Exact matches only:
        there is no substring fallback, because a typo or a partial id silently
        binding to some other rule would let a deviation/suppression/GRP entry
        land on the wrong guideline. Use search() for fuzzy lookup."""
        q = (query or "").strip()
        if q in self._rules:
            return [self._rules[q]]
        qn = q.lower()
        hint = None
        m = self._PREFIX_RE.match(qn)
        if m:
            hint = m.group("std")[:2]          # mi | ba | ce
            qn = qn[m.end():].strip()
        # CERT style: STR31-C
        m = re.fullmatch(r"[a-z]{3}\d{2}-c", qn)
        if m:
            if hint in (None, "ce"):
                r = self._rules.get(f"CERT {qn.upper()}")
                return [r] if r else []
            return []
        m = self._NUM_RE.fullmatch(qn)
        if not m:
            return []
        kind, num, sfx = m.group("kind"), m.group("num"), m.group("sfx")
        out: list[dict] = []
        if hint == "ce":
            return out
        if hint in (None, "mi") and not sfx:
            names = {"rule": ("Rule",), "dir": ("Dir",), "directive": ("Dir",),
                     None: ("Rule", "Dir")}[kind]
            out = [self._rules[c] for n in names
                   if (c := f"MISRA-C:2012 {n} {num}") in self._rules]
        if not out and hint in (None, "ba") and kind is None:
            r = self._rules.get(f"BARR-C {num}{sfx}")
            if r:
                out = [r]
        return out

    def resolve(self, query: str) -> Optional[dict]:
        """Resolve a rule reference to metadata, or None when it is unknown or
        ambiguous (a bare "4.1" that is both a Rule and a Directive). Accepts
        canonical ids and informal forms ("21.3", "MISRA 21.3", "MISRA Dir 4.6",
        "STR31-C", "barr 1.3a")."""
        c = self.candidates(query)
        return c[0] if len(c) == 1 else None

    def resolve_loose(self, query: str) -> Optional[dict]:
        """resolve(), then the first substring match over ids. ONLY for the
        knowledge base's own cross-reference lists (e.g. "BARR-C 5.6" meaning
        5.6a), never for deviations, suppressions, GRP or SARIF mapping."""
        r = self.resolve(query)
        if r or not (query or "").strip():
            return r
        q = query.strip().lower()
        for rid in self._rules:
            if q in rid.lower():
                return self._rules[rid]
        return None

    def resolve_error(self, query: str) -> str:
        """Human-readable reason why resolve(query) returned None."""
        c = self.candidates(query)
        if len(c) > 1:
            return (f"'{query}' is ambiguous ({', '.join(m['id'] for m in c)}); "
                    "write 'Rule' or 'Dir' explicitly, e.g. 'MISRA Rule 4.1'.")
        near = [h["id"] for h in self.search(query, 5)]
        hint = f" Closest: {', '.join(near)}." if near else ""
        return (f"Unknown rule '{query}'. Use a full reference such as 'MISRA 21.3', "
                f"'MISRA Dir 4.6', 'CERT STR31-C' or 'BARR 1.3a'.{hint}")

    def cross_refs(self, rule_id: str) -> list[str]:
        meta = self._rules.get(rule_id) or self.resolve(rule_id)
        if not meta:
            return []
        out = []
        for ref in meta.get("cross", []):
            r = self.resolve_loose(ref)
            if r:
                out.append(r["id"])
        return out

    def search(self, text: str, limit: int = 10) -> list[dict]:
        t = text.lower()
        hits = [m for m in self._rules.values()
                if t in m["id"].lower() or t in m.get("summary", "").lower()
                or t in m.get("fix", "").lower()]
        return hits[:limit]

    def all_ids(self, standard: str | None = None) -> list[str]:
        if standard:
            return list(self._by_standard.get(standard, []))
        return list(self._rules)

    def get(self, rule_id: str) -> Optional[dict]:
        return self._rules.get(rule_id)


REGISTRY = RuleRegistry()
