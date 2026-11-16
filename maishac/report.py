"""Compliance reporting.

Generates an auditable snapshot from memory: per-standard compliance matrix,
open findings by severity, deviation register, and SARIF export for CI and
IDE problem panes.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import posixpath
import re
import time
from pathlib import Path
from urllib.parse import unquote

from . import __version__
from .analyzers.cppcheck import CPPCHECK_TO_CERT
from .memory import MemoryStore
from .model import Finding, assign_occurrences, compute_fingerprint
from .rules import REGISTRY

_STANDARDS = ["MISRA-C:2012", "BARR-C:2018", "CERT-C"]

# SARIF result.level -> unified severity (used only when the rule isn't one we
# recognize; recognized rules take severity from the knowledge base).
_LEVEL_SEV = {"error": "critical", "warning": "major", "note": "minor", "none": "info"}
_SARIF_MISRA = re.compile(r"misra[_-]c?[-_]?20\d\d[-_ ]?(?:rule[-_ ]?|dir(?:ective)?[-_ ]?)?(\d+\.\d+)", re.I)
_SARIF_MISRA_WORD = re.compile(r"\b(?:rule|dir(?:ective)?)\s*(\d+\.\d+)\b", re.I)
_SARIF_BARE_NUM = re.compile(r"^\s*(\d+\.\d+)\s*$")
_SARIF_CERT = re.compile(r"\b([A-Z]{3}\d{2}-C)\b", re.I)
# Results whose kind is not a genuine defect must not be imported as violations.
_NON_DEFECT_KINDS = {"pass", "notApplicable", "informational", "open", "review"}


def _resolve_sarif_rule(rule_id: str) -> dict | None:
    """Best-effort map of a foreign SARIF ruleId / taxon id onto a Maisha rule.
    Handles Maisha's own ids, MISRA in many forms (``misra-c2012-21.3``,
    ``MISRA C 2012 Rule 21.3``, ``Rule 21.3``, bare ``21.3``), CERT
    (``cert-err34-c``, ``ERR34-C``) and cppcheck semantic ids
    (``nullPointer`` -> EXP34-C)."""
    if not rule_id:
        return None
    meta = REGISTRY.get(rule_id) or REGISTRY.resolve(rule_id)
    if meta:
        return meta
    for pat in (_SARIF_MISRA, _SARIF_MISRA_WORD, _SARIF_BARE_NUM):
        m = pat.search(rule_id)
        if m and (r := REGISTRY.resolve(f"MISRA {m.group(1)}")):
            return r
    m = _SARIF_CERT.search(rule_id)
    if m and (r := REGISTRY.resolve(f"CERT {m.group(1).upper()}")):
        return r
    if rule_id in CPPCHECK_TO_CERT:
        return REGISTRY.resolve(f"CERT {CPPCHECK_TO_CERT[rule_id]}")
    return None


def _norm_uri(uri: str, root: Path | None = None) -> str:
    """Normalize a SARIF artifactLocation URI to a project-relative POSIX path:
    strip ``file://``, percent-decode, turn backslashes into slashes, drop a
    leading ``./``, and make an absolute path inside ``root`` relative to it.
    The result is the one value used for both a finding's ``file`` and its
    fingerprint, so it is identical whatever form the engine emitted."""
    if not uri:
        return ""
    if uri.startswith("file:"):
        uri = uri[5:]
        if uri.startswith("//"):
            uri = uri[2:]
            if not uri.startswith("/"):      # file://host/path -> drop the authority
                uri = "/" + uri.split("/", 1)[1] if "/" in uri else ""
    uri = unquote(uri).replace("\\", "/")
    if len(uri) > 2 and uri[0] == "/" and uri[2] == ":":  # /C:/... from file:///C:/...
        uri = uri[1:]
    if root is not None and (uri.startswith("/") or (len(uri) > 1 and uri[1] == ":")):
        try:
            return Path(uri).resolve().relative_to(Path(root).resolve()).as_posix()
        except (ValueError, OSError):
            pass
    uri = posixpath.normpath(uri) if uri else ""
    while uri.startswith("./"):
        uri = uri[2:]
    return "" if uri == "." else uri


def _run_indexes(run: dict) -> tuple[list[dict], list[list[dict]]]:
    """Return (driver rule descriptors, taxonomy taxa lists) for a run, so
    results can be resolved by ruleIndex and rules can be mapped to standard
    guidelines via their relationships into a taxonomy."""
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = driver.get("rules") or []
    taxonomies = [(t.get("taxa") or []) for t in (run.get("taxonomies") or [])]
    return rules, taxonomies


def _result_descriptor(res: dict, rules: list[dict]) -> dict:
    """Locate a result's reportingDescriptor via result.rule (index/id),
    result.ruleIndex, or result.ruleId — whichever the tool used."""
    ref = res.get("rule") or {}
    idx = ref.get("index")
    if idx is None:
        idx = res.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    rid = ref.get("id") or res.get("ruleId")
    if rid:
        for r in rules:
            if r.get("id") == rid:
                return r
    return {}


def _guideline_candidates(res: dict, desc: dict, taxonomies: list[list[dict]]) -> list[str]:
    """Ordered candidate ids to map onto the registry. Taxonomy guideline ids
    (reached via the rule's relationships — how Helix QAC / Coverity attach the
    MISRA/CERT number to a checker-specific ruleId like ``ABV.GENERAL``) come
    first, then the ruleId / descriptor id / name strings."""
    cands: list[str] = []
    for rel in desc.get("relationships") or []:
        tgt = rel.get("target") or {}
        if tgt.get("id"):
            cands.append(tgt["id"])
        tc = (tgt.get("toolComponent") or {}).get("index")
        ti = tgt.get("index")
        if isinstance(tc, int) and isinstance(ti, int) and 0 <= tc < len(taxonomies):
            taxa = taxonomies[tc]
            if 0 <= ti < len(taxa):
                tax = taxa[ti]
                cands += [tax.get("id", ""), tax.get("name", "")]
    for taxon in res.get("taxa") or []:            # some tools attach taxa to the result
        cands.append(taxon.get("id", ""))
    cands += [res.get("ruleId") or "", desc.get("id") or "", desc.get("name") or ""]
    seen, out = set(), []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _primary_location(res: dict) -> dict:
    for loc in res.get("locations") or []:
        if loc.get("physicalLocation"):
            return loc["physicalLocation"]
    return {}


def parse_sarif(data: dict, root: Path) -> list[Finding]:
    """Parse SARIF 2.1.0 results from any tool into Findings, robustly across
    real qualified-engine dialects. Handles ruleId / ruleIndex / result.rule,
    taxonomy+relationship guideline mapping, defaultConfiguration levels,
    result.kind / baselineState filtering, multi-location results, missing
    regions, scheme-prefixed URIs, and reuses Maisha's partialFingerprints so
    its own export round-trips."""
    findings: list[Finding] = []
    for run in data.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = (driver.get("name") or "sarif").lower()
        rules, taxonomies = _run_indexes(run)
        for res in run.get("results", []):
            # Only genuine defects. kind defaults to "fail"; skip pass/etc.,
            # and skip findings a baseline marks as no longer present.
            if (res.get("kind") or "fail") in _NON_DEFECT_KINDS:
                continue
            if res.get("baselineState") == "absent":
                continue

            desc = _result_descriptor(res, rules)
            phys = _primary_location(res)
            uri = _norm_uri((phys.get("artifactLocation") or {}).get("uri") or "", root)
            region = phys.get("region") or {}
            line = int(region.get("startLine") or 0)
            col = int(region.get("startColumn") or 0)
            snippet = (region.get("snippet") or {}).get("text") or ""
            msg = (res.get("message") or {}).get("text") or ""
            level = (res.get("level")
                     or (desc.get("defaultConfiguration") or {}).get("level")
                     or "warning")

            candidates = _guideline_candidates(res, desc, taxonomies)
            meta = next((m for c in candidates if (m := _resolve_sarif_rule(c))), None)
            if meta:
                rid, standard = meta["id"], meta["standard"]
                severity = meta.get("severity", _LEVEL_SEV.get(level, "major"))
                fix = meta.get("fix", "")
            else:
                raw = next((c for c in candidates if c), "unknown")
                rid, standard = f"sarif:{raw}", "generic"
                severity, fix = _LEVEL_SEV.get(level, "major"), ""

            line_content = snippet.strip()
            if not line_content and uri and line:
                line_content = _read_line(root / uri, line)

            fp = (res.get("partialFingerprints") or {}).get("maishac/v1")
            if not fp:
                if line_content:
                    fp = compute_fingerprint(rid, uri, line_content)
                else:
                    # ponytail: no source line to anchor to — fall back to a
                    # location+message hash. Not line-stable, but external SARIF
                    # is re-imported wholesale, so identity only needs to be
                    # unique within one import. Upgrade: fetch the source line.
                    fp = hashlib.sha1(
                        f"{rid}\x1f{uri}\x1f{line}\x1f{col}\x1f{msg}".encode("utf-8", "replace")
                    ).hexdigest()[:16]

            findings.append(Finding(
                rule_id=rid, standard=standard, severity=severity, file=uri, line=line,
                column=col, message=msg, analyzer=f"sarif:{tool}",
                line_content=line_content, fix_hint=fix, fingerprint=fp,
                code_flow=_parse_code_flows(res), suppression=_parse_suppression(res)))
    return assign_occurrences(findings)


def sarif_scope(data: dict, root: Path) -> dict[str, set[str]]:
    """tool name (``sarif:<driver>``) -> project-relative files its run covers:
    every artifact it lists and every file any of its results (even one a
    baseline marks absent) points at. A re-import may only resolve findings in
    these files; a file the run never mentions was simply not analyzed."""
    out: dict[str, set[str]] = {}
    for run in data.get("runs", []):
        driver = (run.get("tool") or {}).get("driver") or {}
        files = out.setdefault(f"sarif:{(driver.get('name') or 'sarif').lower()}", set())
        for art in run.get("artifacts") or []:
            uri = _norm_uri(((art.get("location") or {}).get("uri")) or "", root)
            if uri:
                files.add(uri)
        for res in run.get("results", []):
            uri = _norm_uri((_primary_location(res).get("artifactLocation") or {})
                            .get("uri") or "", root)
            if uri:
                files.add(uri)
    return out


def _parse_suppression(res: dict) -> dict:
    """Read SARIF result.suppressions. A result is suppressed unless every
    entry is explicitly rejected (SARIF 2.1.0 §3.27.23). Returns {justification,
    kind} for a carried-over suppression, or {} if the result is live."""
    supps = res.get("suppressions")
    if not supps:
        return {}
    active = [s for s in supps if (s.get("status") or "accepted") != "rejected"]
    if not active:
        return {}
    just = "; ".join(s["justification"] for s in active
                     if s.get("justification")) or "suppressed in imported SARIF"
    return {"justification": just, "kind": active[0].get("kind", "")}


def _parse_code_flows(res: dict) -> list[dict]:
    """Flatten SARIF codeFlows -> threadFlows -> locations into an ordered list
    of {file, line, message} steps. This is a qualified engine's core value-add
    (the data-flow path to the defect); Maisha carries it through to the agent
    briefing instead of dropping it. Only the first codeFlow is kept — engines
    emit alternates but the primary path is what a fixer needs."""
    steps: list[dict] = []
    for cf in (res.get("codeFlows") or [])[:1]:
        for tf in cf.get("threadFlows") or []:
            for loc in tf.get("locations") or []:
                inner = loc.get("location") or {}
                pl = inner.get("physicalLocation") or {}
                uri = (pl.get("artifactLocation") or {}).get("uri") or ""
                region = pl.get("region") or {}
                steps.append({
                    "file": uri,
                    "line": int(region.get("startLine") or 0),
                    "message": (inner.get("message") or {}).get("text") or "",
                })
    return steps


def _read_line(path: Path, line: int) -> str:
    try:
        lines = path.read_text("utf-8", errors="replace").splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""
    except OSError:
        return ""


def last_scan_info(mem: MemoryStore) -> dict:
    """What the most recent analysis run did, for every report that draws a
    conclusion. `recorded` False means no scan/verify was ever logged, so
    nothing in memory has been checked by this harness. `checked_analyzers` are
    the analyzers whose clean output counts as evidence: they ran, did not fail
    (or partly fail), and the run covered at least one file."""
    last = mem.last_scan()
    imp = mem.last_scan(("import",))
    info = {"recorded": last is not None, "degraded": None, "ts": None, "kind": None,
            "paths": [], "files_scanned": 0, "analyzers_used": [],
            "analyzers_failed": [], "checked_analyzers": [], "versions": {},
            "maishac_version": None,
            "last_import": ({"ts": imp["ts"], "sources": imp["paths"], "tools": imp["analyzers_used"]}
                            if imp else None)}
    if last:
        failed = sorted({e.get("analyzer", "") for e in last["analyzers_failed"]})
        used = list(last["analyzers_used"])
        info.update(
            degraded=last["degraded"], ts=last["ts"], kind=last["kind"],
            paths=last["paths"], files_scanned=last["files_scanned"],
            analyzers_used=used, analyzers_failed=failed,
            errors=last["analyzers_failed"],
            checked_analyzers=([] if not last["files_scanned"]
                               else sorted(set(used) - set(failed))),
            versions=(last["toolchain"] or {}).get("versions", {}),
            maishac_version=last["maishac_version"])
    return info


def _fmt_ts(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)) if ts else "never"


def _last_scan_lines(info: dict) -> list[str]:
    """Markdown bullet lines stating what the last scan covered."""
    if not info["recorded"]:
        return ["- **No scan recorded.** Nothing in this report was produced by a "
                "Maisha analysis run; run `maishac scan` first."]
    L = [f"- Last {info['kind']}: {_fmt_ts(info['ts'])} · {info['files_scanned']} file(s) · "
         f"paths: {', '.join(info['paths']) or '—'} · Maisha {info['maishac_version']}",
         "- Analyzers used: " + (", ".join(
             f"{a} ({info['versions'][a]})" if a in info["versions"] else a
             for a in info["analyzers_used"]) or "none")]
    if info["analyzers_failed"]:
        L.append("- **Analyzers that failed or partly failed: "
                 + ", ".join(info["analyzers_failed"])
                 + ".** Their guidelines are reported as not checked.")
    if info["degraded"]:
        L.append("- **The last scan ran with a degraded toolchain** (missing or "
                 "deselected analyzers, or an analyzer failure).")
    if info["last_import"]:
        L.append(f"- Last SARIF import: {_fmt_ts(info['last_import']['ts'])} "
                 f"({', '.join(info['last_import']['tools']) or 'no results'})")
    return L


def compliance_matrix(mem: MemoryStore) -> dict:
    from .coverage import enforced_ids
    rows = [dict(r) for r in mem.db.execute("SELECT * FROM findings")]
    last = last_scan_info(mem)
    enforced = enforced_ids()
    matrix = {}
    for std in _STANDARDS:
        in_kb = set(REGISTRY.all_ids(std))
        detectable = in_kb & enforced
        violated = {r["rule_id"] for r in rows
                    if r["standard"] == std and r["status"] in ("open", "regressed")}
        deviated = {d["rule_id"] for d in mem.deviations() if d["rule_id"] in in_kb}
        n_pending = sum(1 for r in rows if r["standard"] == std
                        and r["status"] == "pending_verification")
        clean_among_checked = not violated and not n_pending
        matrix[std] = {
            # Legacy key. It always meant "rules in the knowledge base", not
            # "rules a scan examined"; kept for consumers, see the two below.
            "rules_checked": len(in_kb),
            "rules_in_kb": len(in_kb),
            "rules_detectable": len(detectable),
            "rules_violated": sorted(violated),
            "rules_deviated": sorted(deviated),
            "open_findings": sum(1 for r in rows if r["standard"] == std
                                 and r["status"] in ("open", "regressed")),
            "pending_verification": n_pending,
            "resolved_findings": sum(1 for r in rows if r["standard"] == std
                                     and r["status"] == "resolved"),
            # No open violation and no unconfirmed fix, among what was checked.
            "clean_among_checked": clean_among_checked,
            # Strict: also nothing unchecked, a scan on record, and that scan
            # neither degraded nor failed. Almost never true, on purpose.
            "clean": (clean_among_checked and len(detectable) == len(in_kb)
                      and last["recorded"] and not last["degraded"]),
            "analysis_recorded": last["recorded"],
            "analysis_degraded": bool(last["degraded"]),
        }
    return matrix


def _expired(d: dict, now: float | None = None) -> bool:
    return bool(d.get("expires")) and d["expires"] < (time.time() if now is None else now)


def _mark(row: dict) -> str:
    """Flag a sign-off that did not come from a person at the CLI."""
    src = (row.get("source") or row.get("approval_source") or "cli")
    if src == "mcp":
        return " **[AGENT-ORIGINATED via MCP]**"
    if src == "import":
        return " *[from SARIF import]*"
    return ""


def agent_signoffs(mem: MemoryStore) -> dict:
    """Every approval, deviation, suppression and re-categorization an MCP agent
    applied directly (only possible with MAISHAC_ALLOW_AGENT_APPROVALS=1)."""
    db = mem.db
    return {
        "approvals": [dict(r) for r in db.execute(
            "SELECT fingerprint, rule_id, approved_by FROM findings"
            " WHERE approval_source='mcp'")],
        "deviations": [dict(r) for r in db.execute(
            "SELECT id, rule_id, scope FROM deviations WHERE source='mcp' AND revoked_at IS NULL")],
        "suppressions": [dict(r) for r in db.execute(
            "SELECT fingerprint, reason FROM suppressions WHERE source='mcp'")],
        "recategorizations": [dict(r) for r in db.execute(
            "SELECT rule_id, to_category FROM recategorizations WHERE source='mcp'")],
    }


def _audit_lines(mem: MemoryStore, limit: int = 15) -> list[str]:
    rows = mem.audit_entries(limit)
    pending = mem.proposals()
    L = ["", "## Audit trail", ""]
    ag = agent_signoffs(mem)
    n_agent = sum(len(v) for v in ag.values())
    if n_agent:
        L += [f"> **WARNING: {n_agent} sign-off(s) were applied directly by an MCP agent** "
              "(MAISHAC_ALLOW_AGENT_APPROVALS was enabled), not by a person. They are "
              "marked below; review them before relying on this report.", ""]
    if pending:
        L += [f"{len(pending)} agent proposal(s) are awaiting a human decision "
              "(`maishac proposals list`).", ""]
    if not rows:
        return L + ["No sign-offs recorded."]
    L += ["| Time | Source | Action | Actor | Target |", "|---|---|---|---|---|"]
    for r in rows:
        flag = " **[AGENT]**" if r["source"] == "mcp" else ""
        L.append(f"| {_fmt_ts(r['ts'])} | {r['source']}{flag} | {r['action']} | "
                 f"{r['actor'] or '—'} | `{r['target']}` |")
    L += ["", f"Showing the latest {len(rows)} entries; the full append-only log is "
              "`maishac audit`."]
    return L


def markdown_report(mem: MemoryStore, project_name: str = "") -> str:
    stats = mem.stats()
    matrix = compliance_matrix(mem)
    lines = [
        f"# Maisha Compliance Report{(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary",
        "",
        f"Findings by status: {json.dumps(stats['findings_by_status'])}",
        f"Deviations on record: {stats['deviations']} · Suppressions: {stats['suppressions']}"
        f" · Fix attempts logged: {stats['fix_attempts']}",
        "",
        "## Last scan",
        "",
        *_last_scan_lines(last_scan_info(mem)),
        "",
        "## Standards matrix",
        "",
        "*Clean among checked* = no open violation and no unconfirmed fix. *Clean* "
        "additionally requires every rule in the knowledge base to be detectable, "
        "and a recorded, non-degraded scan; a rule no analyzer checks is not clean.",
        "",
        "| Standard | Rules in KB | Detectable | Open | Pending | Resolved | Violated rules | Deviated rules | Clean among checked | Clean |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for std, m in matrix.items():
        lines.append(
            f"| {std} | {m['rules_in_kb']} | {m['rules_detectable']} | {m['open_findings']} | "
            f"{m['pending_verification']} | {m['resolved_findings']} | "
            f"{', '.join(m['rules_violated']) or '—'} | {', '.join(m['rules_deviated']) or '—'} | "
            f"{'yes' if m['clean_among_checked'] else 'no'} | "
            f"{'yes' if m['clean'] else 'no'} |")
    lines += ["", "## Open findings", ""]
    opens = mem.open_findings(limit=500)
    if not opens:
        lines.append("None.")
    for f in opens:
        lines.append(f"- **{f['rule_id']}** ({f['severity']}, {f['status']}) "
                     f"`{f['file']}:{f['line']}` — {f['message']}")
    devs = mem.deviations()
    if devs:
        lines += ["", "## Deviation register", ""]
        for d in devs:
            lines.append(f"- **{d['rule_id']}** scope `{d['scope']}` — {d['justification']}"
                         f"{(' (approved by ' + d['approver'] + ')') if d['approver'] else ''}"
                         f"{_mark(d)}"
                         f"{' **[EXPIRED ' + _fmt_ts(d['expires'])[:10] + ']**' if _expired(d) else ''}")
    supps = mem.suppressions()
    if supps:
        lines += ["", "## Suppressions", ""]
        for sp in supps:
            exp = (" **[EXPIRED]**" if sp.get("expires") and sp["expires"] < time.time() else "")
            lines.append(f"- `{sp['fingerprint']}` — {sp['reason']}"
                         f"{(' (by ' + sp['approver'] + ')') if sp.get('approver') else ''}"
                         f"{_mark(sp)}{exp}")
    lines += _audit_lines(mem)
    return "\n".join(lines) + "\n"


def _rule_descriptor(rid: str, fallback_msg: str = "") -> dict:
    meta = REGISTRY.get(rid) or {}
    return {
        "id": rid,
        "shortDescription": {"text": (meta.get("summary") or fallback_msg or rid)[:200]},
        "help": {"text": meta.get("fix", "")},
    }


def _code_flows_to_sarif(steps: list[dict]) -> list[dict]:
    return [{"threadFlows": [{"locations": [
        {"location": {
            "physicalLocation": {
                "artifactLocation": {"uri": s.get("file", "")},
                "region": {"startLine": max(1, int(s.get("line") or 1))},
            },
            "message": {"text": s.get("message", "")},
        }} for s in steps]}]}]


_SARIF_LEVEL = {"blocker": "error", "critical": "error", "major": "warning",
                "minor": "note", "info": "note"}


def _sarif_suppression(mem: MemoryStore, f: dict) -> dict | None:
    """SARIF `suppressions` entry for a suppressed/deviated finding, or None if
    the finding has no live justification (e.g. its deviation permit expired,
    so it must be reported as the violation it again is).

    kind is "external": both the suppression and the deviation register live in
    Maisha's memory, not in an in-source comment (SARIF kind "inSource")."""
    if f["status"] == "suppressed":
        r = mem.db.execute("SELECT reason, ts, approver, source FROM suppressions"
                           " WHERE fingerprint=?", (f["fingerprint"],)).fetchone()
        return {"kind": "external", "status": "accepted",
                "justification": r["reason"] if r else "suppressed in Maisha memory",
                "properties": {"maishac/origin": "suppression",
                               "maishac/source": (r["source"] if r else "cli"),
                               "maishac/approver": (r["approver"] if r else "") or ""}}
    if f["status"] == "deviated":
        d = mem.matching_deviation(f["rule_id"], f["file"])
        if not d:
            return None
        return {"kind": "external", "status": "accepted",
                "justification": d["justification"],
                "properties": {"maishac/origin": "deviation", "maishac/deviationId": d["id"],
                               "maishac/source": d.get("source") or "cli",
                               "maishac/approver": d.get("approver") or ""}}
    return None


def sarif(mem: MemoryStore) -> dict:
    """SARIF 2.1.0 export. Open/regressed findings are live results. Suppressed
    findings and findings covered by a live deviation permit are exported too,
    carrying a SARIF `suppressions` entry, so a consumer sees the whole triage
    state instead of a list that quietly omits everything waived. Findings
    pending verification are not results (the analyzer no longer flags them);
    their count is on the run's `properties`."""
    rows = mem.open_findings(limit=100000)
    rows += [dict(r) for r in mem.db.execute(
        "SELECT * FROM findings WHERE status IN ('suppressed','deviated')"
        " ORDER BY file, line")]
    rules_seen, results = {}, []
    for f in rows:
        supp = None
        if f["status"] in ("suppressed", "deviated"):
            supp = _sarif_suppression(mem, f)
            if supp is None and f["status"] == "suppressed":
                continue
        rid = f["rule_id"]
        rules_seen.setdefault(rid, _rule_descriptor(rid, f["message"]))
        meta = REGISTRY.get(rid) or {}
        result = {
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["message"] or meta.get("summary", "")},
            "partialFingerprints": {"maishac/v1": f["fingerprint"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, f["line"]),
                               **({"startColumn": f["column"]} if f.get("column") else {})},
                }}],
        }
        if supp:
            result["suppressions"] = [supp]
        # Carry an imported qualified-engine data-flow path back out, so an
        # import -> export round-trip preserves it.
        flow = f.get("code_flow")
        if flow:
            steps = json.loads(flow) if isinstance(flow, str) else flow
            if steps:
                result["codeFlows"] = _code_flows_to_sarif(steps)
        results.append(result)

    # Cross-standard equivalences as SARIF reportingDescriptor.relationships
    # (e.g. MISRA 21.3 <-> its CERT equivalent). Referenced rules are added as
    # descriptors so a consumer/re-import can resolve each relationship target.
    for rid in list(rules_seen):
        refs = REGISTRY.cross_refs(rid)
        if not refs:
            continue
        rels = []
        for ref in refs:
            rules_seen.setdefault(ref, _rule_descriptor(ref))
            rels.append({"target": {"id": ref}, "kinds": ["relevant"]})
        rules_seen[rid]["relationships"] = rels

    last = last_scan_info(mem)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Maisha", "version": __version__,
                                  "rules": list(rules_seen.values())}},
            "results": results,
            "properties": {
                "maishac/pendingVerification": mem.count_pending(),
                "maishac/analysisRecorded": last["recorded"],
                "maishac/analysisDegraded": bool(last["degraded"]),
                "maishac/analyzersFailed": last["analyzers_failed"],
            },
        }],
    }


# --------------------------------------------------------------------------
# MISRA Compliance:2020 Guideline Compliance Summary (GCS)
# --------------------------------------------------------------------------
# The artifact a functional-safety assessor actually asks for: every enforced
# guideline classified Compliant / Deviations / Violations, tied to deviation
# permits, with the legality checks MISRA Compliance:2020 mandates (a Mandatory
# guideline may NOT be deviated or disapplied; Required may be deviated;
# Advisory may be deviated or disapplied). This is a *summary of recorded
# evidence*, not a certification — see the disclaimer in the rendered report.

_MISRA_STD = "MISRA-C:2012"
# APPROXIMATE size of the full MISRA C:2012 guideline set: 143 rules + 16
# directives = 159 in the base standard, plus the rules added by Amendments 1-4
# and the Technical Corrigenda, rounded to a documented working figure. The exact
# count depends on which amendments an organisation adopts, so every report that
# shows it says "~". It is used only to state honest coverage ("catalogued N of
# roughly 175"), never to score compliance. README/COVERAGE.md quote the same
# figure; change it here and in tools/gen_coverage.py together.
MISRA_C_2012_APPROX_GUIDELINES = 175
_MISRA_UNIVERSE = MISRA_C_2012_APPROX_GUIDELINES


def _coverage_breakdown() -> dict:
    """Two denominators, because one of them always misleads.

    "Coverage" collapses two different questions that move independently, and
    reporting a single percentage lets a reader answer the one they were not
    asking:

      * detectable / carried   -- of the guidelines Maisha catalogues, how many
                                  can any analyzer actually find?
      * carried / universe     -- how much of MISRA is catalogued at all?

    Growing the knowledge base with reference-only entries raises the second
    ratio and *lowers* the first, which looks like a regression if only one
    number is published. Keeping them apart is what makes a bulk import of the
    remaining standard readable as a denominator change rather than a loss.

    Reference-only guidelines are not failures and not passes: nothing examined
    them. They are carried so they can be cross-referenced, deviated against,
    listed in a Guideline Enforcement Plan, and matched when an external
    engine's SARIF is imported.
    """
    from .coverage import analyzers_for, enforced_ids, native_ids, toolchain_status
    carried = set(REGISTRY.all_ids(_MISRA_STD))
    # `enforced_ids` means "some analyzer Maisha ships maps a check onto this",
    # which is not the same as "a tool present on this machine will check it".
    # A compliance document must report the second, so the installed toolchain
    # is intersected in as `detectable_here` -- the number that actually
    # governs what a scan on this machine examined.
    detectable = carried & enforced_ids()
    usable = set(toolchain_status()["installed"])
    native = native_ids()
    here = {rid for rid in detectable
            if any(m.split(" ")[0] in usable for m in analyzers_for(rid, native))}
    return {
        "detectable": len(detectable),
        "detectable_here": len(here),
        "unavailable_here": len(detectable) - len(here),
        "carried": len(carried),
        "reference_only": len(carried) - len(detectable),
        "not_carried": max(0, _MISRA_UNIVERSE - len(carried)),
        "universe": _MISRA_UNIVERSE,
        "pct_carried_detectable": round(100 * len(detectable) / len(carried), 1)
        if carried else 0.0,
        "pct_standard_carried": round(100 * len(carried) / _MISRA_UNIVERSE, 1),
    }

_STATUS_KEY = {"Compliant": "compliant", "Deviations": "deviations",
               "Violations": "violations", "Pending verification": "pending",
               "Disapplied": "disapplied", "Not checked": "not_checked"}


def _checkers(gid: str, native: set[str]) -> list[str]:
    """Analyzer names (no '(partial)' suffix) that map a check onto `gid`."""
    from .coverage import analyzers_for
    return [m.split(" ")[0] for m in analyzers_for(gid, native)]


def misra_compliance_summary(mem: MemoryStore) -> dict:
    """Per-guideline status from recorded evidence.

    "Compliant" means a recorded scan ran an analyzer that checks the guideline
    and found nothing. A guideline no analyzer checked (reference-only, or its
    analyzer was not installed, not selected, failed or partly failed in the
    last scan, or no scan was ever recorded) is "Not checked": unexamined, not
    compliant. Findings from any source (including imported SARIF) still make a
    guideline Violations/Pending/Deviations regardless of the scan log.
    """
    from .coverage import analyzers_for, native_ids
    now = time.time()
    rows = [dict(r) for r in mem.db.execute(
        "SELECT rule_id, status, file FROM findings WHERE standard=?", (_MISRA_STD,))]
    dev_by_rule: dict[str, list] = {}
    for d in mem.deviations():
        dev_by_rule.setdefault(d["rule_id"], []).append(d)
    recats = mem.recategorizations()  # GRP: rule_id -> {to_category, ...}
    last = last_scan_info(mem)
    ran = set(last["checked_analyzers"])
    native = native_ids()

    def live_permit(rule, file):
        return any(not _expired(d, now) and fnmatch.fnmatch(file, d["scope"])
                   for d in dev_by_rule.get(rule, []))

    enforced = REGISTRY.all_ids(_MISRA_STD)
    guidelines, blocking = [], []
    counts = {"compliant": 0, "deviations": 0, "violations": 0, "pending": 0,
              "disapplied": 0, "not_checked": 0}
    for gid in enforced:
        meta = REGISTRY.get(gid) or {}
        base_cat = meta.get("category", "required")
        recat = recats.get(gid)
        cat = recat["to_category"] if recat else base_cat  # effective category (post-GRP)
        gr = [r for r in rows if r["rule_id"] == gid]
        open_v = sum(1 for r in gr if r["status"] in ("open", "regressed"))
        pending = sum(1 for r in gr if r["status"] == "pending_verification")
        # A 'deviated' row only counts while a live permit still covers it; one
        # whose permit expired is a violation again even before the next rescan.
        deviated = 0
        for r in gr:
            if r["status"] == "deviated":
                if live_permit(gid, r["file"]):
                    deviated += 1
                else:
                    open_v += 1
        permits_all = dev_by_rule.get(gid, [])
        permits = [d for d in permits_all if not _expired(d, now)]
        expired = len(permits_all) - len(permits)

        mapped = _checkers(gid, native)
        checked_by = sorted(set(mapped) & ran)
        checked = bool(checked_by)

        if cat == "disapplied":
            # Removed from the compliance argument by an agreed GRP entry;
            # violations are neither counted nor blocking.
            status = "Disapplied"
        elif open_v:
            status = "Violations"
        elif pending:
            status = "Pending verification"
        elif deviated or (permits and checked):
            status = "Deviations"
        elif not checked:
            status = "Not checked"
        else:
            status = "Compliant"

        # A Mandatory guideline (post-GRP) can be neither deviated nor left in
        # violation. Not-checked is unexamined, not a violation, so not blocking.
        is_blocking = cat == "mandatory" and status in (
            "Violations", "Deviations", "Pending verification")
        if is_blocking:
            blocking.append(gid)
        counts[_STATUS_KEY[status]] += 1
        if not mapped:
            why = "reference-only: no analyzer checks it"
        elif checked:
            why = ""
        elif not last["recorded"]:
            why = "no scan recorded"
        else:
            why = ("its analyzer (" + ", ".join(mapped) + ") was not installed, not "
                   "selected, or failed in the last scan")
        guidelines.append({
            "guideline": gid, "category": cat, "base_category": base_cat,
            "recategorized": bool(recat), "status": status,
            "open": open_v, "pending": pending, "deviated": deviated,
            "permits": len(permits), "expired_permits": expired,
            "blocking": is_blocking,
            "checked": checked, "checked_by": checked_by,
            "partial_check": checked and any(
                m.endswith("(partial)") for m in analyzers_for(gid, native)),
            "not_checked_reason": why,
            "summary": meta.get("summary", ""),
        })

    coverage = _coverage_breakdown()
    unchecked = counts["not_checked"] + coverage["not_carried"]
    scan_bad = bool(last["degraded"] or last["analyzers_failed"])
    if blocking:
        verdict = "NON-COMPLIANT — a Mandatory guideline is violated or deviated"
    elif counts["violations"]:
        verdict = "NON-COMPLIANT — open violations without a deviation permit"
    elif counts["pending"]:
        verdict = "PENDING — fixes recorded but not yet verified"
    elif not last["recorded"]:
        verdict = "NOT ASSESSED — no scan recorded"
    elif unchecked or scan_bad:
        verdict = (f"NO VIOLATIONS FOUND IN CHECKED GUIDELINES ({unchecked} unchecked"
                   + ("; last scan degraded or incomplete" if scan_bad else "") + ")"
                   + (" WITH DEVIATIONS" if counts["deviations"] else ""))
    elif counts["deviations"]:
        verdict = "COMPLIANT WITH DEVIATIONS"
    else:
        verdict = "COMPLIANT"

    return {
        "standard": _MISRA_STD,
        "verdict": verdict,
        # `enforced` historically meant "carried in the knowledge base", which
        # conflated cataloguing a guideline with being able to check it. Both
        # numbers are now published separately under `coverage`; these keys are
        # kept so existing consumers do not break, with `enforced` corrected to
        # mean what its name says.
        "enforced": coverage["detectable"],
        "carried": coverage["carried"],
        "not_checked": coverage["reference_only"] + coverage["not_carried"],
        "unchecked_guidelines": unchecked,
        "universe": _MISRA_UNIVERSE,
        "coverage": coverage,
        "last_scan": last,
        "counts": counts,
        "guidelines": guidelines,
        "deviation_permits": [{**d, "expired": _expired(d, now)} for d in mem.deviations()],
        "recategorizations": list(recats.values()),
        "blocking_guidelines": blocking,
    }


def misra_compliance_markdown(mem: MemoryStore, project_name: str = "") -> str:
    s = misra_compliance_summary(mem)
    cv = s["coverage"]
    c = s["counts"]
    L = [
        f"# MISRA C:2012 Guideline Compliance Summary{(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} · Standard: {s['standard']}"
        " · Framework: MISRA Compliance:2020",
        "",
        f"## Verdict: **{s['verdict']}**",
        "",
        f"- **Checked on this machine: {cv['detectable_here']} of the "
        f"{cv['carried']} guidelines catalogued.** "
        + (f"{cv['unavailable_here']} more could be checked, but the analyzer "
           "that covers them is not installed here. " if cv["unavailable_here"] else "")
        + (f"The remaining {cv['reference_only']} "
           f"{'is' if cv['reference_only'] == 1 else 'are'} carried for "
           "cross-referencing and deviation records; no analyzer Maisha ships "
           "checks them at all." if cv["reference_only"] else ""),
        f"- **Catalogued: {cv['carried']} of ~{cv['universe']}** MISRA C:2012 "
        f"guidelines ({cv['pct_standard_carried']}%, Amendments included). The "
        f"remaining {cv['not_carried']} are outside Maisha's knowledge base "
        "entirely.",
        "- Neither figure is a compliance score. A guideline that was never "
        "checked is not compliant and not in violation — it is unexamined, and "
        "must be assigned an enforcement method of its own.",
        f"- Compliant: **{c['compliant']}** · With deviations: **{c['deviations']}** · "
        f"Pending verification: **{c['pending']}** · In violation: **{c['violations']}** · "
        f"Disapplied (GRP): **{c['disapplied']}** · "
        f"Not checked: **{c['not_checked']}**",
        "",
        "### Last scan",
        "",
        *_last_scan_lines(s["last_scan"]),
    ]
    if s["blocking_guidelines"]:
        L += ["", "> ⚠ **Audit-blocking:** Mandatory guideline(s) not compliant — "
              f"{', '.join(s['blocking_guidelines'])}. MISRA Compliance:2020 permits "
              "no deviation or disapplication of a Mandatory guideline."]

    L += ["", "## Guideline compliance",
          "", "| Guideline | Category | Status | Open | Pending | Deviated | Permits |",
          "|---|---|---|---|---|---|---|"]
    order = {"Violations": 0, "Pending verification": 1, "Deviations": 2,
             "Disapplied": 3, "Compliant": 4, "Not checked": 5}
    for g in sorted(s["guidelines"], key=lambda g: (order[g["status"]], g["guideline"])):
        mark = "🚫 " if g["blocking"] else ""
        cat = g["category"] + (" *(re-cat)*" if g["recategorized"] else "")
        status = g["status"] + (" *(partial check)*" if g["status"] == "Compliant"
                                and g["partial_check"] else "")
        permits_cell = str(g["permits"]) + (f" (+{g['expired_permits']} expired)"
                                            if g["expired_permits"] else "")
        L.append(f"| {g['guideline']} | {cat} | {mark}{status} | "
                 f"{g['open']} | {g['pending']} | {g['deviated']} | {permits_cell} |")

    permits = s["deviation_permits"]
    L += ["", "## Deviation permits", ""]
    if not permits:
        L.append("None on record.")
    else:
        L += ["| Guideline | Scope | Justification | Approver | Expires |",
              "|---|---|---|---|---|"]
        for d in permits:
            exp = time.strftime("%Y-%m-%d", time.localtime(d["expires"])) if d.get("expires") else "—"
            if d.get("expired"):
                exp += " **EXPIRED (not counted)**"
            appr = (d.get("approver") or "**UNAPPROVED**") + _mark(d)
            L.append(f"| {d['rule_id']} | `{d['scope']}` | {d['justification']} | {appr} | {exp} |")

    L += ["", "---", "",
          "*Coverage caveat:* Maisha enforces a curated subset of MISRA C:2012. "
          "Guidelines it does not check are reported as \"not checked\", **not** as "
          "compliant — for the remaining guidelines, layer a qualified engine's "
          "findings via `maishac import` and re-run this report.",
          "",
          "*Disclaimer:* This is a summary of the evidence recorded in Maisha's "
          "memory (findings, fixes, deviations, approvals). It is **not** a formal "
          "compliance certification and Maisha is not a qualified/proven-in-use "
          "analysis tool. Rule summaries are original paraphrases; consult the "
          "official MISRA C:2012 and MISRA Compliance:2020 documents for normative wording."]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# Guideline Enforcement Plan (GEP) — MISRA Compliance:2020 §3.3
# --------------------------------------------------------------------------
# "A GEP listing each guideline ... shall indicate how compliance is to be
# checked" and, for each tool, record its version, config, options, and evidence
# it can detect the guidelines it checks. Maisha generates this over the
# guidelines it enforces, records the live tool inventory, and honestly flags
# the remainder of the standard as requiring a separately-assigned method.

def enforcement_tools(mem: MemoryStore) -> list[dict]:
    """The tool inventory for the GEP: every static-analysis tool that could be
    enforcing guidelines here — Maisha's active analyzers (with live versions +
    options) plus any external engine whose SARIF was imported into memory."""
    from .analyzers import ALL_ANALYZERS
    tools = []
    for cls in ALL_ANALYZERS:
        a = cls()
        if a.available():
            tools.append({
                "tool": a.name, "version": a.version(), "options": a.options,
                "kind": "native" if a.requires is None else "external analyzer",
                "status": "available",
            })
        else:
            # An absent analyzer is a disclosure, not an omission. MISRA
            # Compliance:2020 requires the GEP to record how each guideline is
            # enforced *including* where no tool covers it — a plan that lists
            # only the tools that happen to be installed reads as though the
            # rest of the standard were checked and passed.
            tools.append({
                "tool": a.name, "version": "not installed",
                "options": a.options,
                # `requires` is None for the compiler adapter because it resolves
                # gcc/clang/cc dynamically — it is still an external dependency,
                # so don't let it inherit the "native" (always-present) label.
                "kind": "native" if a.name == "native" else "external analyzer",
                "status": "NOT INSTALLED - guidelines it would enforce were not checked",
                "requires": a.requires or "gcc, clang or cc",
            })
    # engines whose findings arrived via `maishac import` (analyzer = "sarif:<tool>")
    imported = sorted({r["analyzer"] for r in mem.db.execute(
        "SELECT DISTINCT analyzer FROM findings WHERE analyzer LIKE 'sarif:%'")})
    for a in imported:
        tools.append({"tool": a.split("sarif:", 1)[1], "version": "(from imported SARIF)",
                      "options": "imported via SARIF 2.1.0", "kind": "imported qualified engine"})
    return tools


_NO_TOOLING = "Not enforced by tooling - requires separate method"


def guideline_enforcement_plan(mem: MemoryStore) -> dict:
    from .coverage import analyzers_for, native_ids
    summary = misra_compliance_summary(mem)
    tools = enforcement_tools(mem)
    installed = {t["tool"] for t in tools if t.get("version") != "not installed"}
    native = native_ids()
    # which guidelines have an observed detection in this project (strong
    # evidence), and which tool produced it (covers imported SARIF engines)
    observed: dict[str, set[str]] = {}
    for r in mem.db.execute("SELECT DISTINCT rule_id, analyzer FROM findings WHERE standard=?",
                            (_MISRA_STD,)):
        observed.setdefault(r["rule_id"], set()).add(r["analyzer"] or "")
    rows = []
    for g in summary["guidelines"]:
        gid = g["guideline"]
        # Only tools that actually map a check onto this guideline, each marked
        # when it is not installed (so the check cannot have run here).
        mapped = [m.split(" ")[0] for m in analyzers_for(gid, native)]
        checked_by = [m if m in installed else f"{m} (not installed)" for m in mapped]
        imported = sorted(a for a in observed.get(gid, ()) if a.startswith("sarif:"))
        checked_by += imported
        if mapped and any(m in installed for m in mapped):
            method = "Static analysis"
        elif mapped:
            method = "Static analysis (tool not installed here - not checked)"
        elif imported:
            method = "Imported qualified engine (SARIF)"
        else:
            method = _NO_TOOLING
        if gid in observed:
            evidence = "observed in project"
        elif mapped and any(m in installed for m in mapped):
            evidence = "check mapped; no violation observed in this project"
        else:
            evidence = "none"
        rows.append({
            "guideline": gid, "category": g["category"],
            "method": method, "checked_by": checked_by, "evidence": evidence,
        })
    return {"standard": _MISRA_STD, "tools": tools, "guidelines": rows,
            "enforced": summary["enforced"], "not_checked": summary["not_checked"],
            "universe": summary["universe"], "coverage": summary["coverage"],
            "last_scan": summary["last_scan"]}


def guideline_enforcement_markdown(mem: MemoryStore, project_name: str = "") -> str:
    gep = guideline_enforcement_plan(mem)
    gc = gep["coverage"]
    L = [
        f"# MISRA C:2012 Guideline Enforcement Plan (GEP){(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} · Standard: {gep['standard']}"
        " · Framework: MISRA Compliance:2020 §3.3",
        "",
        "## Enforcement tools",
        "",
        "| Tool | Version | Options | Role | Status |",
        "|---|---|---|---|---|",
    ]
    for t in gep["tools"]:
        mark = "**NOT INSTALLED**" if t.get("version") == "not installed" else "available"
        L.append(f"| {t['tool']} | {t['version']} | {t['options']} | {t['kind']} | {mark} |")
    if not gep["tools"]:
        L.append("| _(none active)_ | | | | |")

    absent = [t for t in gep["tools"] if t.get("version") == "not installed"]
    if absent:
        L += ["",
              "> **Toolchain incomplete on the machine that generated this plan.** "
              + ", ".join(f"`{t['tool']}` (needs {t.get('requires', '?')})" for t in absent)
              + (" was" if len(absent) == 1 else " were")
              + " not installed, so the guidelines they would enforce were **not "
                "checked at all** — they are neither compliant nor in violation, they "
                "are unexamined. Install the missing analyzers and regenerate before "
                "presenting this plan as evidence."]

    L += ["", "## Last scan", "", *_last_scan_lines(gep["last_scan"])]

    L += ["", "## Per-guideline enforcement", "",
          f"This plan covers the **{gc['detectable_here']}** guidelines the "
          f"tools installed on this machine actually check, out of "
          f"**{gc['detectable']}** Maisha can check with a full toolchain, "
          f"**{gc['carried']}** catalogued, and ~{gc['universe']} in the standard.",
          "",
          f"Three separate gaps must each be closed by other means. "
          f"**{gc['unavailable_here']}** are covered by an analyzer that is not "
          f"installed here, **{gc['reference_only']}** catalogued guideline(s) "
          f"have no analyzer behind them at all, and **{gc['not_carried']}** are "
          "not in the knowledge base. Each requires an enforcement method of "
          "its own — a "
          "compiler, an additional or qualified tool, or documented manual review. "
          "Layer a qualified engine's SARIF via `maishac import` to extend "
          "coverage, then regenerate.",
          "",
          "| Guideline | Category | Method | Checked by | Detection evidence |",
          "|---|---|---|---|---|"]
    for r in sorted(gep["guidelines"], key=lambda r: r["guideline"]):
        L.append(f"| {r['guideline']} | {r['category']} | {r['method']} | "
                 f"{', '.join(r['checked_by']) or '—'} | {r['evidence']} |")

    L += ["", "---", "",
          "*Detection evidence:* \"observed in project\" means at least one violation "
          "of that guideline was produced by the tooling on this codebase. \"check "
          "mapped\" means an installed analyzer has a check for it that has not fired "
          "here; Maisha's own regression tests and `examples/bad.c` are the standing "
          "evidence the native analyzer detects the guidelines it claims. \"none\" "
          "means no evidence the guideline is examined at all.",
          "",
          "*Disclaimer:* Maisha is a workflow/orchestration layer, not a "
          "qualified/proven-in-use analysis tool. For tool-qualification evidence "
          "(ISO 26262, DO-330, IEC 61508), the qualified engine you layer via SARIF "
          "is the qualified component; record its qualification artifacts alongside "
          "this plan."]
    return "\n".join(L) + "\n"


# --------------------------------------------------------------------------
# Guideline Re-categorization Plan (GRP) — MISRA Compliance:2020 §5.4
# --------------------------------------------------------------------------

def guideline_recategorization_markdown(mem: MemoryStore, project_name: str = "") -> str:
    recats = mem.recategorizations()
    L = [
        f"# MISRA C:2012 Guideline Re-categorization Plan (GRP){(' — ' + project_name) if project_name else ''}",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')} · Standard: {_MISRA_STD}"
        " · Framework: MISRA Compliance:2020 §5.4",
        "",
        "Agreed re-categorizations for this project. MISRA permits: Advisory → "
        "Mandatory/Required/Disapplied; Required → Mandatory only; a **Mandatory "
        "guideline may not be re-categorized in any way**. Maisha enforces these "
        "rules when a re-categorization is recorded (`maishac recategorize`).",
        "",
    ]
    if not recats:
        L.append("No re-categorizations on record — every guideline retains its "
                 "default MISRA category.")
        return "\n".join(L) + "\n"
    L += ["| Guideline | Original category | Re-categorized to | Rationale | Approver |",
          "|---|---|---|---|---|"]
    for gid, r in recats.items():
        meta = REGISTRY.get(gid) or {}
        base = meta.get("category", "—")
        appr = (r.get("approver") or "**UNAPPROVED**") + _mark(r)
        L.append(f"| {gid} | {base} | {r['to_category']} | {r['rationale']} | {appr} |")
    return "\n".join(L) + "\n"
