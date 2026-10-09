"""
sync.py — keeping a run alive across sessions.

Three ways to carry a partial run into the next session, in order of convenience:

  Colab   put SKGAP_RUNS_DIR on Google Drive; nothing else to do.
  Kaggle  save a version of the notebook; next time add that notebook's output
          as an input. `restore_from_inputs` finds it and merges it.
  Any     set HF_TOKEN and SKGAP_HF_REPO (a private Hugging Face dataset repo);
          the run folder is pushed every few minutes and pulled at start.
"""
from __future__ import annotations

import os
import shutil
import threading
import zipfile
from pathlib import Path

from .config import ROOT, RunPaths
from .store import merge_run_dirs

SKIP_DIRS = {"analysis", "logs", "__pycache__"}


def find_previous_runs(run_name: str, search_roots: list[Path] | None = None) -> list[Path]:
    """Earlier copies of this run under /kaggle/input (or the given roots), including inside zip files."""
    roots = search_roots or [Path("/kaggle/input")]
    found: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for man in root.rglob("manifest.json"):
            if man.parent.name == run_name and (man.parent / "gen").exists():
                found.append(man.parent)
        for z in root.rglob("*.zip"):
            try:
                with zipfile.ZipFile(z) as zf:
                    names = zf.namelist()
                    hit = [n for n in names if n.endswith(f"{run_name}/manifest.json")]
                    if hit:
                        target = Path(os.getenv("TMPDIR", "/tmp")) / f"skgap_restore_{z.stem}"
                        zf.extractall(target)
                        found.append(target / Path(hit[0]).parent)
            except (zipfile.BadZipFile, OSError):
                continue
    return found


def restore_from_inputs(paths: RunPaths, run_name: str, extra: list[str] | None = None, say=print) -> None:
    sources = find_previous_runs(run_name) + [Path(p) for p in (extra or [])]
    sources = [s for s in sources if s.resolve() != paths.run.resolve()]
    if not sources:
        return
    added = merge_run_dirs(sources, paths.run)
    total = sum(added.values())
    say(f"restored {total} records from {len(sources)} earlier copy/copies of run '{run_name}'")


# ── Hugging Face Hub ──────────────────────────────────────────────────────────
def _hf():
    repo, token = os.getenv("SKGAP_HF_REPO"), os.getenv("HF_TOKEN")
    if not repo or not token:
        return None
    try:
        from huggingface_hub import HfApi
    except ImportError:
        return None
    return HfApi(token=token), repo


def hf_pull(paths: RunPaths, run_name: str, say=print) -> bool:
    h = _hf()
    if not h:
        return False
    api, repo = h
    try:
        from huggingface_hub import snapshot_download
        api.create_repo(repo, repo_type="dataset", private=True, exist_ok=True)
        tmp = snapshot_download(repo, repo_type="dataset", token=api.token, allow_patterns=[f"{run_name}/*"])
        src = Path(tmp) / run_name
        if src.exists():
            added = merge_run_dirs([src], paths.run)
            say(f"hub: restored {sum(added.values())} records from {repo}")
        return True
    except Exception as exc:
        say(f"hub: pull failed ({type(exc).__name__}: {exc}); continuing with local data")
        return False


def hf_push(paths: RunPaths, run_name: str, say=print) -> bool:
    h = _hf()
    if not h:
        return False
    api, repo = h
    try:
        api.upload_folder(folder_path=str(paths.run), path_in_repo=run_name, repo_id=repo, repo_type="dataset",
                          ignore_patterns=["logs/*", "*.tmp"], commit_message=f"skgap sync {run_name}")
        return True
    except Exception as exc:
        say(f"hub: push failed ({type(exc).__name__}: {exc}); data is still safe locally")
        return False


class PeriodicPush:
    """Pushes the run folder to the Hub every `minutes` while a stage is running."""

    def __init__(self, paths: RunPaths, run_name: str, minutes: float = 10, say=print):
        self.paths, self.run_name, self.say = paths, run_name, say
        self.interval = minutes * 60
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self.enabled = _hf() is not None

    def _loop(self):
        while not self._stop.wait(self.interval):
            hf_push(self.paths, self.run_name, self.say)

    def __enter__(self):
        if self.enabled:
            self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        if self.enabled:
            hf_push(self.paths, self.run_name, self.say)


# ── archives ──────────────────────────────────────────────────────────────────
def export_run(paths: RunPaths, dest: Path | None = None) -> Path:
    """Zip a run folder (records, manifest, analysis) for download or as a Kaggle dataset."""
    dest = dest or paths.run.parent / f"{paths.run.name}.zip"
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in sorted(paths.run.rglob("*")):
            if f.is_file() and "logs" not in f.relative_to(paths.run).parts:
                zf.write(f, Path(paths.run.name) / f.relative_to(paths.run))
    return dest


def bundle_project(dest: Path | None = None) -> Path:
    """Zip the code and frozen data (no runs, no legacy) for upload to Kaggle or Colab."""
    dest = dest or ROOT / "skgap_bundle.zip"
    keep = ["skgap", "rules", "data", "docs", "notebooks", "tests", "requirements.txt", "README.md"]
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in keep:
            p = ROOT / name
            if p.is_file():
                zf.write(p, Path("security_gap_research") / name)
            elif p.is_dir():
                for f in sorted(p.rglob("*")):
                    if f.is_file() and "__pycache__" not in f.parts and f.suffix != ".pyc":
                        zf.write(f, Path("security_gap_research") / f.relative_to(ROOT))
    return dest


def copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "runs", "legacy"))
