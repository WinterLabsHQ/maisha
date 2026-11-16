"""Subcommands and flags quoted in fenced code blocks of the docs must exist in the CLI."""

import argparse
import re
import shlex
from pathlib import Path

import pytest

from maishac.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
DOCS = ["README.md", "INSTALL.md", "AGENT_PLAYBOOK.md"]


def _subparsers(parser):
    for a in parser._actions:
        if isinstance(a, argparse._SubParsersAction):
            return a.choices
    return {}


def _flags(parser):
    return {s for a in parser._actions for s in a.option_strings}


def _invocations(name):
    text = (ROOT / name).read_text()
    for block in re.findall(r"```(?:bash|sh|console|shell)?\n(.*?)```", text, re.S):
        for line in block.splitlines():
            m = re.match(r"^\s*(?:[$>]\s*)?(?:python -m )?maishac\s+(.*)$", line)
            if not m:
                continue
            if re.match(r"\d+\.\d+", m.group(1)):
                continue  # sample output such as "maishac 0.5.0 at ..."
            try:
                yield shlex.split(re.split(r"\s[|>#]", m.group(1))[0])
            except ValueError:
                continue


@pytest.mark.parametrize("doc", DOCS)
def test_documented_commands_and_flags_exist(doc):
    top = build_parser()
    problems = []
    for toks in _invocations(doc):
        parser, i = top, 0
        while i < len(toks):
            t = toks[i]
            if t == "--project":
                i += 2
                continue
            if t.startswith("-"):
                if t.split("=")[0] not in _flags(parser):
                    problems.append((toks, t))
                i += 1
                continue
            subs = _subparsers(parser)
            if subs and t in subs:
                parser = subs[t]
            elif subs:
                problems.append((toks, t))
                break
            i += 1
    assert not problems
