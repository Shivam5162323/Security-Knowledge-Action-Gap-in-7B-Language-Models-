"""
run.py - the GPU stage: knowledge battery + code generation for every model.

Design for interruption:
  * one JSONL file per model and stage; every reply is written and fsync'd at once
  * work is ordered sample-major, so a partial run is still a balanced (smaller) design
  * a time budget stops cleanly before a platform's session limit
  * models are processed one at a time per GPU and removed from disk afterwards
Re-running the same command continues where the previous session stopped.
"""
from __future__ import annotations

import json
import platform
import re
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone

from . import __version__, config, detect
from .conditions import build_prompt
from .config import MAX_TOKENS, MODEL_BY_TAG, RAG_CONDITIONS, RunPaths, slug
from .llm import LLMError, MockBackend, OllamaServer, gpu_count
from .retrieval import context_block, ensure_retrieval
from .stimuli import CWES, Task, stimuli_hash, tasks_for
from .stimuli import knowledge as K
from .store import JsonlStore
from .textutil import complete_answer, parse_choice, parse_verdict, sha

_print_lock = threading.Lock()


def say(msg: str) -> None:
    with _print_lock:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


# ── manifest ──────────────────────────────────────────────────────────────────
def load_manifest(paths: RunPaths) -> dict:
    return json.loads(paths.manifest.read_text(encoding="utf-8")) if paths.manifest.exists() else {}


_manifest_lock = threading.Lock()


def save_manifest(paths: RunPaths, manifest: dict) -> None:
    with _manifest_lock:
        tmp = paths.manifest.with_suffix(".tmp")
        tmp.write_text(json.dumps(manifest, indent=1), encoding="utf-8")
        tmp.replace(paths.manifest)


def design_fingerprint() -> dict:
    return {
        "stimuli_sha": stimuli_hash(),
        "rules_sha": detect.rules_hash(),
        "temperature": config.TEMPERATURE, "top_p": config.TOP_P, "num_ctx": config.NUM_CTX, "think": config.THINK,
        "max_tokens": config.MAX_TOKENS, "rag_top_k": config.RAG_TOP_K, "rag_doc_chars": config.RAG_DOC_CHARS,
        "rag_encoder": config.RAG_ENCODER, "rrf": [config.RRF_K, config.RRF_W_DENSE, config.RRF_W_BM25],
        "reminder_text": config.REMINDER_TEXT, "context_header": config.CONTEXT_HEADER,
        "analysis": {"alpha": config.ALPHA, "gap_margin": config.GAP_MARGIN, "knowledge_tau": config.KNOWLEDGE_TAU,
                     "bootstrap": config.BOOTSTRAP_B, "permutations": config.PERMUTATIONS, "seed": config.RNG_SEED},
    }


def init_manifest(paths: RunPaths, profile: config.Profile, backend: str, force: bool = False) -> dict:
    manifest = load_manifest(paths)
    fp = design_fingerprint()
    if manifest:
        if manifest.get("backend") != backend and not force:
            raise SystemExit(f"This run directory was created with backend '{manifest.get('backend')}', not '{backend}'. "
                             "Use another --run name.")
        old = manifest.get("design", {})
        changed = [k for k in ("stimuli_sha", "temperature", "top_p", "think", "max_tokens", "reminder_text",
                               "context_header", "rag_top_k", "rag_doc_chars") if old.get(k) != fp.get(k)]
        if changed and not force:
            raise SystemExit(
                "The study design differs from the one this run was started with (" + ", ".join(changed) + ").\n"
                "Mixing the two would invalidate the data. Start a new run with a different --run name, "
                "or pass --force if the change is intentional and documented.")
    else:
        manifest = {"skgap_version": __version__, "created_utc": datetime.now(timezone.utc).isoformat(),
                    "backend": backend, "design": fp, "models": {}, "sessions": []}
    manifest["profile"] = {"name": profile.name, "models": list(profile.models), "conditions": list(profile.conditions),
                           "n_samples": profile.n_samples, "tasks_per_cwe": profile.tasks_per_cwe,
                           "cwes": list(profile.cwes) if profile.cwes else None}
    save_manifest(paths, manifest)
    return manifest


# ── jobs ──────────────────────────────────────────────────────────────────────
def knowledge_jobs(model: str, tasks: list[Task]) -> list[dict]:
    cwes = {t.cwe for t in tasks}
    jobs = []
    for it in K.mcq_items():
        if it["cwe"] in cwes:
            jobs.append({"key": f"{model}|mcq|{it['id']}", "kind": "mcq", "id": it["id"], "cwe": it["cwe"],
                         "item": it["item"], "answer": it["answer"], "prompt": it["prompt"], "fmt": K.MCQ_SCHEMA})
    for t in tasks:
        for variant in ("insecure", "secure"):
            code = getattr(t, "ref_" + variant)
            jobs.append({"key": f"{model}|detect|{t.id}|{variant}", "kind": "detect", "id": f"{t.id}|{variant}",
                         "cwe": t.cwe, "task": t.id, "variant": variant, "prompt": K.detect_prompt(t.lang, code),
                         "fmt": K.DETECT_SCHEMA})
    for cwe in sorted(cwes, key=list(CWES).index):
        jobs.append({"key": f"{model}|explain|{cwe}", "kind": "explain", "id": cwe, "cwe": cwe,
                     "prompt": K.explain_prompt(cwe)})
    for t in tasks:
        jobs.append({"key": f"{model}|repair|{t.id}", "kind": "repair", "id": t.id, "cwe": t.cwe, "task": t.id,
                     "prompt": K.repair_prompt(t.lang, t.ref_insecure)})
    for j in jobs:
        j.update(model=model, temperature=0.0, seed=0, max_tokens=MAX_TOKENS[j["kind"]])
    return jobs


def generation_jobs(model: str, tasks: list[Task], conditions, n_samples: int, prompts: dict) -> list[dict]:
    jobs = []
    for s in range(n_samples):                      # sample-major: partial runs stay balanced
        for t in tasks:
            for c in conditions:
                jobs.append({"key": f"{model}|gen|{t.id}|{c}|{s}", "kind": "generate", "id": f"{t.id}|{c}|{s}",
                             "model": model, "task": t.id, "cwe": t.cwe, "condition": c, "sample": s, "seed": s,
                             "temperature": 0.0 if s == 0 else config.TEMPERATURE,
                             "max_tokens": MAX_TOKENS["generate"], "prompt": prompts[(t.id, c)]})
    return jobs


def build_prompts(paths: RunPaths, tasks: list[Task], conditions, encoder: str) -> dict:
    retr, doc_text = None, {}
    if any(c in RAG_CONDITIONS for c in conditions):
        retr, doc_text = ensure_retrieval(paths.corpus, paths.retrieval, tasks, encoder, say)
    prompts = {}
    for t in tasks:
        for c in conditions:
            notes = context_block(t.id, c, retr, doc_text) if c in RAG_CONDITIONS else None
            prompts[(t.id, c)] = build_prompt(t, c, notes)
    with open(paths.run / "prompts.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for (tid, c), p in prompts.items():
            fh.write(json.dumps({"task": tid, "condition": c, "prompt_sha": sha(p), "prompt": p}, ensure_ascii=False) + "\n")
    return prompts


# ── execution ─────────────────────────────────────────────────────────────────
def _score_knowledge(job: dict, text: str) -> dict:
    if job["kind"] == "mcq":
        choice = parse_choice(text)
        return {"item": job["item"], "choice": choice, "correct": choice == job["answer"]}
    if job["kind"] == "detect":
        verdict, weakness = parse_verdict(text)
        truth = "VULNERABLE" if job["variant"] == "insecure" else "SAFE"
        return {"task": job["task"], "variant": job["variant"], "verdict": verdict, "weakness": weakness[:120],
                "correct": verdict == truth,
                "names_cwe": bool(weakness) and re.search(CWES[job["cwe"]].recognise, weakness, re.I) is not None}
    if job["kind"] == "explain":
        hits = [name for name, rx in CWES[job["cwe"]].concepts if re.search(rx, text, re.I)]
        return {"score": len(hits) / len(CWES[job["cwe"]].concepts), "concepts": hits}
    return {"task": job["task"]}


def _do_job(backend, job: dict, state: dict) -> dict:
    task = None
    stop_when = None
    if job["kind"] in ("generate", "repair"):
        from .stimuli import TASK_BY_ID
        task = TASK_BY_ID[job["task"]]
        stop_when = lambda text: complete_answer(text, task.lang, task.entry)      # noqa: E731
    kwargs = dict(temperature=job["temperature"], seed=job["seed"], max_tokens=job["max_tokens"], stop_when=stop_when)
    if job.get("fmt") is not None and state["use_format"]:
        kwargs["fmt"] = job["fmt"]
    if backend.backend == "mock":
        kwargs["_job"] = job
    rec = {"key": job["key"], "model": job["model"], "kind": job["kind"], "cwe": job["cwe"]}
    try:
        try:
            res = backend.chat(job["model"], job["prompt"], **kwargs)
        except LLMError as exc:
            if "structured output rejected" not in str(exc):
                raise
            state["use_format"] = False            # old server: fall back to free-text parsing
            kwargs.pop("fmt", None)
            res = backend.chat(job["model"], job["prompt"], **kwargs)
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"[:300]
        return rec
    rec.update(response=res["text"], tokens_in=res["tokens_in"], tokens_out=res["tokens_out"],
               seconds=res["seconds"], done_reason=res["done_reason"])
    if job["kind"] == "generate":
        rec.update(task=job["task"], condition=job["condition"], sample=job["sample"], seed=job["seed"],
                   temperature=job["temperature"], prompt_sha=sha(job["prompt"]))
    else:
        rec.update(_score_knowledge(job, res["text"]))
    return rec


def run_model(backend, tag: str, jobs_k: list[dict], jobs_g: list[dict], paths: RunPaths, manifest: dict,
              deadline: float | None, parallel: int, keep_models: bool) -> dict:
    store_k = JsonlStore(paths.knowledge / f"{slug(tag)}.jsonl")
    store_g = JsonlStore(paths.gen / f"{slug(tag)}.jsonl")
    pending = [(store_k, j) for j in jobs_k if not store_k.done(j["key"])]
    pending += [(store_g, j) for j in jobs_g if not store_g.done(j["key"])]
    total = len(jobs_k) + len(jobs_g)
    status = {"model": tag, "total": total, "pending_at_start": len(pending), "done": 0, "errors": 0, "stopped": None}
    if not pending:
        say(f"{tag}: complete ({total} records)")
        return status

    say(f"{tag}: {total - len(pending)}/{total} already done, {len(pending)} to go")
    backend.ensure()
    backend.pull(tag, say)
    manifest["models"][tag] = backend.describe(tag)
    save_manifest(paths, manifest)

    state = {"use_format": True}
    t0, last_report, consecutive_errors, done_at_report = time.time(), time.time(), 0, 0
    it = iter(pending)
    futures: dict = {}
    with ThreadPoolExecutor(max_workers=parallel) as pool:
        while True:
            while len(futures) < parallel * 2 and status["stopped"] is None:
                if deadline is not None and time.time() > deadline:
                    status["stopped"] = "time budget"
                    break
                nxt = next(it, None)
                if nxt is None:
                    break
                store, job = nxt
                futures[pool.submit(_do_job, backend, job, state)] = store
            if not futures:
                break
            finished, _ = wait(list(futures), return_when=FIRST_COMPLETED)
            for f in finished:
                store = futures.pop(f)
                rec = f.result()
                store.append(rec)
                if rec.get("error"):
                    status["errors"] += 1
                    consecutive_errors += 1
                else:
                    status["done"] += 1
                    consecutive_errors = 0
            if consecutive_errors >= 25 and status["stopped"] is None:
                status["stopped"] = "25 consecutive request failures"
            if time.time() - last_report > 60:
                # rate over the last interval: the quick knowledge requests at the start
                # would otherwise make the estimate for the slower generations too optimistic
                rate = (status["done"] - done_at_report) / max(time.time() - last_report, 1e-9)
                last_report, done_at_report = time.time(), status["done"]
                left = len(pending) - status["done"] - status["errors"]
                say(f"{tag}: {status['done']}/{len(pending)} this session, {rate:.2f} req/s, "
                    f"~{left / max(rate, 1e-9) / 60:.0f} min left, {status['errors']} errors")
    store_k.close()
    store_g.close()
    if status["stopped"] is None and not keep_models:
        backend.remove(tag)
    mins = (time.time() - t0) / 60
    say(f"{tag}: {'STOPPED (' + status['stopped'] + ')' if status['stopped'] else 'finished'} "
        f"- {status['done']} records in {mins:.1f} min, {status['errors']} errors")
    return status


def run(run_name: str, profile: config.Profile, *, backend_name: str = "ollama", max_hours: float | None = None,
        parallel: int = 4, servers: int | None = None, keep_models: bool = False, encoder: str = config.RAG_ENCODER,
        force: bool = False, stages: tuple[str, ...] = ("knowledge", "generate")) -> list[dict]:
    paths = config.run_paths(run_name)
    tasks = tasks_for(profile.cwes, profile.tasks_per_cwe)
    manifest = init_manifest(paths, profile, backend_name, force)
    deadline = time.time() + max_hours * 3600 if max_hours else None

    prompts = build_prompts(paths, tasks, profile.conditions, encoder) if "generate" in stages else {}
    work = {}
    for tag in profile.models:
        jk = knowledge_jobs(tag, tasks) if "knowledge" in stages else []
        jg = generation_jobs(tag, tasks, profile.conditions, profile.n_samples, prompts) if "generate" in stages else []
        work[tag] = (jk, jg)

    if backend_name == "mock":
        backends = [MockBackend()]
    else:
        n_gpu = gpu_count()
        n = servers or max(1, n_gpu)
        backends = [OllamaServer(11434 + i, gpu=i if n > 1 else None, parallel=parallel, log_dir=paths.run / "logs")
                    for i in range(n)]
        manifest["sessions"].append({"started_utc": datetime.now(timezone.utc).isoformat(), "host": platform.node(),
                                     "platform": platform.platform(), "gpus": n_gpu, "servers": n, "parallel": parallel})
        save_manifest(paths, manifest)
    say(f"run '{run_name}': {len(profile.models)} models, {len(tasks)} tasks, {len(profile.conditions)} conditions, "
        f"{profile.n_samples} samples - {sum(len(a) + len(b) for a, b in work.values())} requests in the full design")

    # largest models first, each to the least-loaded server
    queues: list[list[str]] = [[] for _ in backends]
    load = [0.0] * len(backends)
    for tag in sorted(profile.models, key=lambda t: -(MODEL_BY_TAG[t].params_b if t in MODEL_BY_TAG else 1.0)):
        i = load.index(min(load))
        queues[i].append(tag)
        load[i] += MODEL_BY_TAG[tag].params_b if tag in MODEL_BY_TAG else 1.0

    results: list[dict] = []
    lock = threading.Lock()

    def serve(i: int) -> None:
        for tag in queues[i]:
            if deadline is not None and time.time() > deadline:
                with lock:
                    results.append({"model": tag, "stopped": "time budget", "done": 0, "errors": 0})
                continue
            try:
                st = run_model(backends[i], tag, *work[tag], paths, manifest, deadline, parallel, keep_models)
            except Exception as exc:          # one model failing must not take the others down
                say(f"{tag}: FAILED - {type(exc).__name__}: {exc}")
                st = {"model": tag, "stopped": f"error: {exc}", "done": 0, "errors": 1}
            with lock:
                results.append(st)

    threads = [threading.Thread(target=serve, args=(i,), daemon=True) for i in range(len(backends))]
    for t in threads:
        t.start()
    try:
        for t in threads:
            while t.is_alive():
                t.join(timeout=1)
    except KeyboardInterrupt:
        say("interrupted - everything written so far is saved; re-run the same command to continue")
        raise
    finally:
        for b in backends:
            b.stop()
    return results


def progress_table(run_name: str, profile: config.Profile) -> list[dict]:
    """How much of the design exists on disk, per model."""
    paths = config.run_paths(run_name)
    tasks = tasks_for(profile.cwes, profile.tasks_per_cwe)
    rows = []
    for tag in profile.models:
        sk = JsonlStore(paths.knowledge / f"{slug(tag)}.jsonl")
        sg = JsonlStore(paths.gen / f"{slug(tag)}.jsonl")
        se = JsonlStore(paths.eval / f"{slug(tag)}.jsonl")
        nk = len(knowledge_jobs(tag, tasks))
        ng = len(tasks) * len(profile.conditions) * profile.n_samples
        rows.append({"model": tag, "knowledge": f"{len(sk)}/{nk}", "generation": f"{len(sg)}/{ng}",
                     "evaluated": f"{len(se)}/{len(sg) + len([r for r in sk.records() if r.get('kind') == 'repair'])}",
                     "complete": len(sk) >= nk and len(sg) >= ng})
    return rows
