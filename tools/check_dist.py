"""Verify built distributions: the wheel must ship the rule knowledge base.

Usage: python tools/check_dist.py [dist-dir]   (default: dist)

Also, when MAISHAC_TAG is set (e.g. "v0.5.0"), require it to equal
"v" + the version of the built wheel, so a release cannot be published from a
tag that disagrees with maishac.__version__.
"""

from __future__ import annotations

import os
import sys
import zipfile
from pathlib import Path

REQUIRED = ("maishac/rules/misra_c_2012.json", "maishac/rules/cert_c.json",
            "maishac/rules/barr_c_2018.json")


def main(argv: list[str]) -> int:
    dist = Path(argv[1] if len(argv) > 1 else "dist")
    wheels = sorted(dist.glob("*.whl"))
    if len(wheels) != 1:
        print(f"expected exactly one wheel in {dist}, found {len(wheels)}", file=sys.stderr)
        return 1
    names = set(zipfile.ZipFile(wheels[0]).namelist())
    missing = [n for n in REQUIRED if n not in names]
    if missing:
        print(f"wheel {wheels[0].name} is missing: {', '.join(missing)}", file=sys.stderr)
        return 1
    version = wheels[0].name.split("-")[1]
    tag = os.environ.get("MAISHAC_TAG")
    if tag and tag != f"v{version}":
        print(f"tag {tag} does not match package version v{version}", file=sys.stderr)
        return 1
    print(f"ok: {wheels[0].name} contains {len(REQUIRED)} rule files"
          + (f"; tag {tag} matches" if tag else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
