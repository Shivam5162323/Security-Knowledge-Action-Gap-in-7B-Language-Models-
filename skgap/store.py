"""
store.py — append-only JSONL stores that make every stage resumable.

Each record carries a deterministic "key". A record is written and fsync'd the
moment it exists, so a crash, a disconnect or a session time-out loses at most
the requests that were in flight. On restart, keys already present are skipped.

Failed requests are stored too (with an "error" field) but do not count as done:
they are retried on the next run, up to MAX_ATTEMPTS, and are never silently
dropped from the denominator.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

MAX_ATTEMPTS = 3


class JsonlStore:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._latest: dict[str, dict] = {}
        self._attempts: dict[str, int] = {}
        self._fh = None
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue          # truncated final line after a hard kill
                self._index(rec)

    def _index(self, rec: dict) -> None:
        key = rec.get("key")
        if key is None:
            return
        if rec.get("error"):
            self._attempts[key] = self._attempts.get(key, 0) + 1
            if key in self._latest and not self._latest[key].get("error"):
                return                # never let a failure hide a success
        self._latest[key] = rec

    def done(self, key: str) -> bool:
        """True when no further work is needed for this key."""
        rec = self._latest.get(key)
        if rec is None:
            return False
        if rec.get("error"):
            return self._attempts.get(key, 0) >= MAX_ATTEMPTS
        return True

    def get(self, key: str) -> dict | None:
        return self._latest.get(key)

    def append(self, rec: dict) -> None:
        line = json.dumps(rec, ensure_ascii=False)
        with self._lock:
            if self._fh is None:
                torn = False
                if self.path.exists() and self.path.stat().st_size > 0:
                    with open(self.path, "rb") as fh:
                        fh.seek(-1, os.SEEK_END)
                        torn = fh.read(1) != b"\n"
                self._fh = open(self.path, "a", encoding="utf-8", newline="\n")
                if torn:                  # a killed process left half a line: do not glue onto it
                    self._fh.write("\n")
            self._fh.write(line + "\n")
            self._fh.flush()
            try:
                os.fsync(self._fh.fileno())
            except OSError:
                pass                  # some network filesystems refuse fsync
            self._index(rec)

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def records(self, include_errors: bool = False) -> list[dict]:
        return [r for r in self._latest.values() if include_errors or not r.get("error")]

    def __len__(self) -> int:
        return len(self.records())


def read_jsonl(path: Path | str) -> list[dict]:
    return JsonlStore(path).records() if Path(path).exists() else []


def merge_run_dirs(sources: list[Path], dest: Path) -> dict[str, int]:
    """
    Union the JSONL stores (and cached corpus/retrieval files) of earlier
    partial runs into `dest`. Used to resume from a previous Kaggle notebook
    output or a downloaded copy. Existing successful records in dest win.
    """
    added: dict[str, int] = {}
    for src in sources:
        src = Path(src)
        if not src.exists():
            continue
        for f in src.rglob("*.jsonl"):
            rel = f.relative_to(src)
            if rel.parts[0] == "analysis":
                continue
            if rel.name == "corpus.jsonl":
                if not (dest / rel).exists():
                    (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                    (dest / rel).write_bytes(f.read_bytes())
                continue
            target = JsonlStore(dest / rel)
            n = 0
            for rec in JsonlStore(f).records():
                if not target.done(rec["key"]) or target.get(rec["key"]).get("error"):
                    target.append(rec)
                    n += 1
            target.close()
            if n:
                added[str(rel)] = added.get(str(rel), 0) + n
        for name in ("retrieval.json", "corpus_embeddings.npy", "manifest.json"):
            if (src / name).exists() and not (dest / name).exists():
                dest.mkdir(parents=True, exist_ok=True)
                (dest / name).write_bytes((src / name).read_bytes())
    return added
