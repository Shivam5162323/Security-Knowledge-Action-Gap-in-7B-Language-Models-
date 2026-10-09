"""
detect.py — static detection with Semgrep, batched.

All answers for one weakness class are written to a directory and scanned with
that class's rule file in a single Semgrep process. Scanning 18,000 answers
takes seven Semgrep start-ups instead of 18,000.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .config import RULES_DIR

RULE_FILES = {
    "CWE-89": "cwe89_sql_injection.yaml",
    "CWE-79": "cwe79_xss.yaml",
    "CWE-22": "cwe22_path_traversal.yaml",
    "CWE-78": "cwe78_command_injection.yaml",
    "CWE-502": "cwe502_deserialization.yaml",
    "CWE-798": "cwe798_hardcoded_credentials.yaml",
    "CWE-120": "cwe120_buffer_overflow.yaml",
}
EXT = {"python": ".py", "c": ".c"}
CHUNK = 1500


def semgrep_path() -> str | None:
    return shutil.which("semgrep")


def semgrep_version() -> str | None:
    exe = semgrep_path()
    if not exe:
        return None
    try:
        return subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=120).stdout.strip() or None
    except Exception:
        return None


def rules_hash() -> str:
    h = hashlib.sha256()
    for name in sorted(RULE_FILES.values()):
        h.update(name.encode())
        h.update((RULES_DIR / name).read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def scan_batch(items: list[tuple[str, str, str, str]]) -> dict[str, dict]:
    """
    items: (key, cwe, lang, code). Returns key -> {"flag": bool | None, "rules": [...], "note": str}.
    flag is None when Semgrep is unavailable or failed for that batch.
    """
    exe = semgrep_path()
    results: dict[str, dict] = {k: {"flag": None, "rules": [], "note": "not scanned"} for k, *_ in items}
    if not exe:
        for r in results.values():
            r["note"] = "semgrep not installed"
        return results

    by_cwe: dict[str, list] = {}
    for it in items:
        by_cwe.setdefault(it[1], []).append(it)

    for cwe, group in by_cwe.items():
        rule = RULES_DIR / RULE_FILES[cwe]
        for start in range(0, len(group), CHUNK):
            chunk = group[start:start + CHUNK]
            tmp = tempfile.mkdtemp(prefix="skgap_scan_")
            try:
                names: dict[str, str] = {}
                for i, (key, _, lang, code) in enumerate(chunk):
                    name = f"s{i:05d}{EXT[lang]}"
                    names[name] = key
                    Path(tmp, name).write_text(code if code.strip() else "\n", encoding="utf-8")
                cmd = [exe, "scan", "--config", str(rule), "--json", "--quiet", "--metrics=off",
                       "--disable-version-check", "--no-git-ignore", "--timeout", "30", "."]
                env = dict(os.environ, SEMGREP_SEND_METRICS="off", PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
                proc = subprocess.run(cmd, cwd=tmp, capture_output=True, timeout=1800, env=env)
                try:
                    data = json.loads(proc.stdout.decode("utf-8", "replace"))
                except json.JSONDecodeError:
                    note = "semgrep failed: " + proc.stderr.decode("utf-8", "replace")[-200:]
                    for key in names.values():
                        results[key] = {"flag": None, "rules": [], "note": note}
                    continue
                for key in names.values():
                    results[key] = {"flag": False, "rules": [], "note": ""}
                for hit in data.get("results", []):
                    key = names.get(os.path.basename(hit.get("path", "")))
                    if key:
                        results[key]["flag"] = True
                        rid = hit.get("check_id", "").split(".")[-1]
                        if rid not in results[key]["rules"]:
                            results[key]["rules"].append(rid)
                for err in data.get("errors", []):
                    key = names.get(os.path.basename(str(err.get("path", ""))))
                    if key and not results[key]["note"]:
                        results[key]["note"] = "parse: " + str(err.get("type", ""))[:60]
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
    return results
