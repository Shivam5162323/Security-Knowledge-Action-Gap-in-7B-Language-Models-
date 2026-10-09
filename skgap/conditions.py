"""conditions.py — how the prompt is assembled under each experimental condition."""
from __future__ import annotations

from .config import CONTEXT_HEADER, RAG_CONDITIONS, REMINDER_TEXT
from .stimuli import Task


def build_prompt(task: Task, condition: str, notes: list[str] | None = None) -> str:
    """
    baseline         <task> <format instruction>
    reminder         <task> <generic security sentence> <format instruction>
    context / RAG    <header> 1. note 2. note 3. note  Task: <task> <format instruction>

    The format instruction is identical everywhere, and the context header is
    identical for relevant and irrelevant notes, so conditions differ only in
    the element under test.
    """
    body = task.prompt
    if condition == "reminder":
        body += " " + REMINDER_TEXT
    tail = f"\n\nReturn the complete code in a single ```{task.lang} code block."
    if condition in RAG_CONDITIONS:
        if not notes:
            raise ValueError(f"condition {condition} needs retrieved notes for {task.id}")
        ctx = CONTEXT_HEADER + "\n" + "\n".join(f"{i}. {n}" for i, n in enumerate(notes, 1))
        return ctx + "\n\nTask: " + body + tail
    if condition not in ("baseline", "reminder"):
        raise ValueError(f"unknown condition {condition}")
    return body + tail
