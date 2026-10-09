"""
evaluate.py - the CPU stage: judge every generated answer.

For each answer: extract the code, scan it statically (Semgrep, batched), then
run the functional test and the attack test. Needs no GPU, is resumable, and
can be re-run after a rule change without regenerating anything: results are
tagged with a version derived from the rules, the stimuli and the harness, and
records with another version are simply recomputed.

Identical code for the same task is judged once and the verdict reused.
"""
from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

from . import __version__, config, detect, functest
from .config import slug
from .run import say
from .selftest import run_selftest, save_report
from .stimuli import TASK_BY_ID, stimuli_hash
from .store import JsonlStore
from .textutil import extract_code, is_refusal, sha, syntax_ok

CHUNK = 400


def execution_allowed(mode: str) -> bool:
    """Generated code is only executed in a disposable environment unless explicitly enabled."""
    if mode == "on":
        return True
    if mode == "off":
        return False
    return bool(os.getenv("KAGGLE_KERNEL_RUN_TYPE") or os.getenv("KAGGLE_URL_BASE") or os.getenv("COLAB_RELEASE_TAG")
                or os.getenv("COLAB_GPU") or os.getenv("SKGAP_ALLOW_EXEC") == "1")


def eval_version(dynamic: bool) -> str:
    h = hashlib.sha256()
    h.update((detect.rules_hash() + stimuli_hash() + __version__ + ("dyn" if dynamic else "static")).encode())
    for f in ("functest.py", "textutil.py", "harness/lib.py", "harness/py_runner.py"):
        h.update((config.ROOT / "skgap" / f).read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()[:12]


def evaluate(run_name: str, models: list[str], *, dynamic_mode: str = "auto", workers: int | None = None,
             force: bool = False) -> dict:
    paths = config.run_paths(run_name)
    dynamic = execution_allowed(dynamic_mode)
    workers = workers or max(2, (os.cpu_count() or 2))
    version = eval_version(dynamic)

    if not detect.semgrep_path():
        say("WARNING: semgrep not found - static verdicts will be missing (pip install semgrep)")
    if not dynamic:
        say("dynamic tests are OFF (generated code is not executed here). "
            "Use --dynamic on in a disposable environment to enable them.")

    validation = paths.run / "validation.json"
    say("validating detectors on the reference solutions ...")
    report = run_selftest(workers=workers, dynamic=dynamic)
    save_report(report, validation)
    s = report["summary"]
    say(f"detectors valid on references: static {s['static_valid']}/{s['n_tasks']}, "
        f"dynamic {s['dynamic_valid']}/{s['n_tasks']}")

    cache: dict[tuple[str, str], dict] = {}
    totals = {"evaluated": 0, "reused": 0, "skipped": 0}
    for tag in models:
        store = JsonlStore(paths.eval / f"{slug(tag)}.jsonl")
        todo = []
        for src_kind, src in (("gen", paths.gen), ("repair", paths.knowledge)):
            for rec in JsonlStore(src / f"{slug(tag)}.jsonl").records():
                if src_kind == "repair" and rec.get("kind") != "repair":
                    continue
                prev = store.get(rec["key"])
                if prev and not force and prev.get("eval_version") == version and not prev.get("error"):
                    totals["skipped"] += 1
                    continue
                todo.append((src_kind, rec))
        if not todo:
            store.close()
            continue
        say(f"{tag}: evaluating {len(todo)} answers")
        for start in range(0, len(todo), CHUNK):
            chunk = todo[start:start + CHUNK]
            prepared = []
            for src_kind, rec in chunk:
                task = TASK_BY_ID[rec["task"]]
                code, how = extract_code(rec.get("response", ""), task.lang, task.entry)
                prepared.append((src_kind, rec, task, code, how, (task.id, sha(code, 24))))

            fresh = {}
            for _, _, task, code, _, ck in prepared:
                if ck not in cache and ck not in fresh and code.strip():
                    fresh[ck] = (task, code)
            static = detect.scan_batch([(f"{ck[0]}|{ck[1]}", task.cwe, task.lang, code)
                                        for ck, (task, code) in fresh.items()])
            dyn = {}
            if dynamic and fresh:
                keys = list(fresh)
                with ThreadPoolExecutor(max_workers=workers) as pool:
                    for ck, res in zip(keys, pool.map(lambda k: functest.run_dynamic(*fresh[k]), keys)):
                        dyn[ck] = res
            for ck in fresh:
                cache[ck] = {"static": static[f"{ck[0]}|{ck[1]}"], "dynamic": dyn.get(ck)}
            totals["evaluated"] += len(fresh)
            totals["reused"] += len(prepared) - len(fresh)

            for src_kind, rec, task, code, how, ck in prepared:
                out = {"key": rec["key"], "model": rec["model"], "source": src_kind, "task": task.id, "cwe": task.cwe,
                       "condition": rec.get("condition", "repair"), "sample": rec.get("sample", 0),
                       "temperature": rec.get("temperature", 0.0), "tokens_out": rec.get("tokens_out"),
                       "seconds": rec.get("seconds"), "done_reason": rec.get("done_reason"),
                       "has_code": bool(code.strip()), "extract": how, "code_sha": ck[1],
                       "refusal": is_refusal(rec.get("response", ""), code), "syntax_ok": syntax_ok(code, task.lang),
                       "eval_version": version}
                if code.strip():
                    out["static"] = cache[ck]["static"]
                    out["dynamic"] = cache[ck]["dynamic"]
                store.append(out)
        store.close()
    say(f"evaluation done: {totals['evaluated']} distinct answers judged, {totals['reused']} reused, "
        f"{totals['skipped']} already up to date")
    return totals
