#!/usr/bin/env python3
"""sync_rules.py — copy rules.json into js/rules.js as the offline fallback.

rules.json is the single source of truth for detection rules. When the page is
served over http(s) the browser fetches it directly; when index.html is opened
from disk (file://) browsers block that fetch, so js/rules.js carries an
embedded copy between the BEGIN/END markers. This script rewrites that copy.

    python3 scripts/sync_rules.py          # rewrite js/rules.js
    python3 scripts/sync_rules.py --check  # exit 1 if they differ (CI / tests)

Standard library only, so it runs without the backend's virtualenv.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RULES_JSON = ROOT / "rules.json"
RULES_JS = ROOT / "js" / "rules.js"

BEGIN, END = "/* BEGIN rules.json */", "/* END rules.json */"
BLOCK = re.compile(re.escape(BEGIN) + r".*?" + re.escape(END), re.S)

SEVERITIES = {"high", "medium", "low", "informational"}
ALLOWED_FLAGS = set("imsu")  # no g / y: they make RegExp.test() stateful


def validate(rules: list[dict]) -> list[str]:
    """Return human-readable problems; mirrors compileRules() in js/rules.js."""
    problems = []
    for i, r in enumerate(rules):
        where = f"rule #{i} ({r.get('id', '?')})"
        for field in ("id", "sev", "rule", "pattern"):
            if not isinstance(r.get(field), str) or not r[field]:
                problems.append(f"{where}: missing '{field}'")
        if r.get("sev") not in SEVERITIES:
            problems.append(f"{where}: sev must be one of {sorted(SEVERITIES)}")
        if not set(r.get("flags", "")) <= ALLOWED_FLAGS:
            problems.append(f"{where}: flags may only contain {''.join(sorted(ALLOWED_FLAGS))}")
        try:  # Python's re is close enough to JS regex to catch typos
            re.compile(r.get("pattern", ""))
        except re.error as exc:
            problems.append(f"{where}: pattern does not compile: {exc}")
    return problems


def render_block(rules: list[dict]) -> str:
    return f"{BEGIN}\n{json.dumps(rules, indent=2, ensure_ascii=False)}\n{END}"


def main() -> int:
    rules = json.loads(RULES_JSON.read_text(encoding="utf-8"))["rules"]
    problems = validate(rules)
    if problems:
        print("rules.json has problems:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 1

    js = RULES_JS.read_text(encoding="utf-8")
    if not BLOCK.search(js):
        print(f"{RULES_JS}: BEGIN/END markers not found", file=sys.stderr)
        return 1
    updated = BLOCK.sub(lambda _: render_block(rules), js, count=1)

    if "--check" in sys.argv:
        if updated != js:
            print("js/rules.js is out of date — run: python3 scripts/sync_rules.py", file=sys.stderr)
            return 1
        print(f"OK — js/rules.js matches rules.json ({len(rules)} rules)")
        return 0

    RULES_JS.write_text(updated, encoding="utf-8")
    print(f"Wrote {len(rules)} rules into {RULES_JS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
