"""Reads the result tables of the run so every number in the manuscript's tables comes from the analysis output."""
from __future__ import annotations

import csv
import json
from pathlib import Path

MINUS = "−"

# order used in every per-model table: by parameter count
MODEL_ORDER = ["Qwen3.5-2B", "Qwen2.5-Coder-3B", "Llama-3.2-3B", "Phi-4-mini-3.8B", "Qwen3-4B", "Qwen3.5-4B",
               "OLMo-3-7B", "Mistral-7B-v0.3", "Qwen2.5-Coder-7B"]
MODEL_INFO = {  # family type and release year (from the model cards; see skgap/config.py)
    "Qwen3.5-2B": ("General", "2026"), "Qwen2.5-Coder-3B": ("Code", "2024"), "Llama-3.2-3B": ("General", "2024"),
    "Phi-4-mini-3.8B": ("General", "2025"), "Qwen3-4B": ("General", "2025"), "Qwen3.5-4B": ("General", "2026"),
    "OLMo-3-7B": ("General", "2025"), "Mistral-7B-v0.3": ("General", "2024"), "Qwen2.5-Coder-7B": ("Code", "2024"),
}
CWES = ["CWE-89", "CWE-79", "CWE-22", "CWE-78", "CWE-502", "CWE-798", "CWE-120"]
# names of the conditions and of the paired contrasts, as used in tables and figures
CONDITION_NAME = {"baseline": "Baseline", "reminder": "Reminder", "ctx_irrelevant": "Irrelevant notes",
                  "rag_dense": "Dense RAG", "rag_hybrid": "Hybrid RAG", "rag_oracle": "Oracle RAG"}
CONTRAST_NAME = {
    "reminder - baseline": "Reminder − baseline (H3a)",
    "ctx_irrelevant - baseline": "Irrelevant notes − baseline",
    "rag_dense - baseline": "Dense RAG − baseline (H4a)",
    "rag_hybrid - baseline": "Hybrid RAG − baseline (H4a)",
    "rag_oracle - baseline": "Oracle RAG − baseline",
    "rag_dense - reminder": "Dense RAG − reminder (H4b)",
    "rag_dense - ctx_irrelevant": "Dense RAG − irrelevant notes (H4c)",
    "rag_hybrid - ctx_irrelevant": "Hybrid RAG − irrelevant notes (H4c)",
    "rag_hybrid - rag_dense": "Hybrid − dense RAG (H5)",
}


class Data:
    def __init__(self, run: Path):
        self.run = run
        self.t = {p.stem.split("_")[0]: list(csv.DictReader(p.open(encoding="utf-8")))
                  for p in sorted((run / "analysis" / "tables").glob("T*.csv"))}

    def by(self, table: str, key: str) -> dict:
        return {r[key]: r for r in self.t[table]}

    def prompts(self) -> list[tuple[str, str]]:
        out = []
        for line in (self.run / "prompts.jsonl").open(encoding="utf-8"):
            r = json.loads(line)
            if r["condition"] == "baseline":
                out.append((r["task"], r["prompt"].split("\n\nReturn the complete code")[0].strip()))
        return out


def f2(x) -> str:
    """0.37 / −0.13 with a real minus sign."""
    v = float(x)
    s = f"{abs(v):.2f}"
    return (MINUS if v < 0 and float(s) != 0 else "") + s


def f3(x) -> str:
    v = float(x)
    s = f"{abs(v):.3f}"
    return (MINUS if v < 0 and float(s) != 0 else "") + s


def pp(x, digits=1) -> str:
    """Proportion as percentage points with sign: −13.3, +1.9."""
    v = float(x) * 100
    s = f"{abs(v):.{digits}f}"
    if float(s) == 0:
        return s
    return (MINUS if v < 0 else "+") + s


def pval(x) -> str:
    if isinstance(x, str) and x.strip().startswith("<"):
        return x.strip()
    v = float(x)
    return "<0.001" if v < 0.001 else f"{v:.3f}"
