"""All study stimuli. Hashed into the run manifest before any model is queried."""
from __future__ import annotations

import hashlib
from pathlib import Path

from . import cwe22, cwe78, cwe79, cwe89, cwe120, cwe502, cwe798
from .base import CWES, CWE, Task

TASKS: list[Task] = [t for mod in (cwe89, cwe79, cwe22, cwe78, cwe502, cwe798, cwe120) for t in mod.TASKS]
TASK_BY_ID: dict[str, Task] = {t.id: t for t in TASKS}
assert len(TASK_BY_ID) == len(TASKS), "duplicate task id"


def tasks_for(cwes: tuple[str, ...] | None = None, per_cwe: int | None = None) -> list[Task]:
    out: list[Task] = []
    for cid in CWES:
        if cwes and cid not in cwes:
            continue
        group = [t for t in TASKS if t.cwe == cid]
        out.extend(group[:per_cwe] if per_cwe else group)
    return out


def stimuli_hash() -> str:
    """SHA-256 over every stimulus source file, in a fixed order."""
    h = hashlib.sha256()
    for f in sorted(Path(__file__).parent.glob("*.py")):
        h.update(f.name.encode())
        h.update(f.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


__all__ = ["CWES", "CWE", "Task", "TASKS", "TASK_BY_ID", "tasks_for", "stimuli_hash"]
