"""rules.json must be valid, and js/rules.js's offline copy must match it."""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import sync_rules  # noqa: E402


def test_rules_json_is_valid():
    rules = json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]
    assert sync_rules.validate(rules) == []


def test_requested_techniques_are_present():
    ids = {r["id"] for r in json.loads((ROOT / "rules.json").read_text(encoding="utf-8"))["rules"]}
    assert {"T1003", "T1105", "T1055", "T1562.001", "T1136"} <= ids


def test_offline_copy_in_rules_js_matches_rules_json():
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "sync_rules.py"), "--check"],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
