"""textutil.py — pulling code and structured answers out of model replies."""
from __future__ import annotations

import ast
import hashlib
import json
import re

FENCE = re.compile(r"```[ \t]*([A-Za-z0-9_+#.-]*)[ \t]*\r?\n(.*?)\r?\n?[ \t]*```", re.S)
OPEN_FENCE = re.compile(r"```[ \t]*([A-Za-z0-9_+#.-]*)[ \t]*\r?\n")
THINK = re.compile(r"<think>.*?(</think>|$)", re.S | re.I)
WANT = {"python": {"python", "py", "python3"}, "c": {"c", "h", "cpp", "c++"}}
REFUSAL = re.compile(
    r"\b(i can(?:'|no)?t (?:help|assist|provide|write|create)|i'?m (?:sorry|unable)|i am (?:sorry|unable)|"
    r"cannot (?:help|assist|provide|fulfil)|not able to (?:help|assist|provide))", re.I)


def sha(text: str, n: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


def _has_entry(body: str, entry: str) -> bool:
    if entry == "app":
        return "Flask(" in body
    return re.search(rf"\b{re.escape(entry)}\s*\(", body) is not None


def _candidates(text: str, lang: str) -> list[str]:
    blocks = [(m.group(1).lower(), m.group(2)) for m in FENCE.finditer(text)]
    tagged = [b for t, b in blocks if t in WANT[lang]]
    untagged = [b for t, b in blocks if t == ""]
    return tagged or untagged


def complete_answer(text: str, lang: str, entry: str) -> bool:
    """True once the reply contains a closed code block that defines the entry point."""
    if "```" not in text:
        return False
    return any(_has_entry(b, entry) for b in _candidates(text, lang))


def extract_code(text: str, lang: str, entry: str) -> tuple[str, str]:
    """Returns (code, how). how is one of: block, longest, open-fence, raw, none."""
    text = THINK.sub("", text or "")
    cands = _candidates(text, lang)
    if cands:
        for b in cands:
            if _has_entry(b, entry):
                return b.strip("\n") + "\n", "block"
        return max(cands, key=len).strip("\n") + "\n", "longest"
    opens = list(OPEN_FENCE.finditer(text))
    if opens:                                   # reply was cut off inside a code block
        body = text[opens[-1].end():].replace("```", "")
        if body.strip():
            return body.strip("\n") + "\n", "open-fence"
    stripped = text.strip()
    if stripped and _looks_like_code(stripped, lang):
        return stripped + "\n", "raw"
    return "", "none"


def _looks_like_code(text: str, lang: str) -> bool:
    if lang == "python":
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return False
        return any(isinstance(n, (ast.FunctionDef, ast.Import, ast.ImportFrom, ast.Assign)) for n in tree.body)
    return "#include" in text or re.search(r"\b\w+\s*\([^)]*\)\s*\{", text) is not None


def syntax_ok(code: str, lang: str) -> bool | None:
    """Python only; None for C (decided by the compiler in the dynamic stage)."""
    if lang != "python":
        return None
    try:
        ast.parse(code)
        return True
    except (SyntaxError, ValueError):
        return False


def is_refusal(text: str, code: str) -> bool:
    return not code.strip() and REFUSAL.search(text or "") is not None


# ── structured answers ────────────────────────────────────────────────────────
def parse_choice(text: str) -> str | None:
    text = THINK.sub("", text or "").strip()
    try:
        v = json.loads(text).get("answer")
        if isinstance(v, str) and v.strip()[:1].upper() in "ABCD":
            return v.strip()[:1].upper()
    except (json.JSONDecodeError, AttributeError):
        pass
    m = re.search(r'"answer"\s*:\s*"?\s*([A-Da-d])\b', text) or re.search(r"\b([A-D])\b", text)
    return m.group(1).upper() if m else None


def parse_verdict(text: str) -> tuple[str | None, str]:
    """Returns (VULNERABLE | SAFE | None, weakness label)."""
    text = THINK.sub("", text or "").strip()
    verdict, weakness = None, ""
    try:
        obj = json.loads(text)
        verdict, weakness = str(obj.get("verdict", "")).upper(), str(obj.get("weakness", ""))
    except (json.JSONDecodeError, AttributeError):
        m = re.search(r'"verdict"\s*:\s*"?\s*(\w+)', text, re.I)
        verdict = m.group(1).upper() if m else ""
        w = re.search(r'"weakness"\s*:\s*"([^"]*)', text, re.I)
        weakness = w.group(1) if w else ""
    if verdict not in ("VULNERABLE", "SAFE"):
        up = text.upper()
        if re.search(r"\b(NOT VULNERABLE|SAFE|SECURE|NO VULNERABILIT)", up):
            verdict = "SAFE"
        elif "VULNERAB" in up or "INSECURE" in up or "UNSAFE" in up:
            verdict = "VULNERABLE"
        else:
            verdict = None
    return verdict, weakness
