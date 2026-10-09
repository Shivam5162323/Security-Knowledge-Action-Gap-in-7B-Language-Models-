"""
selftest.py — validate the detectors on the reference solutions before any model runs.

For every task both reference solutions go through exactly the path a model
answer takes. A detector is "valid" for a task in this environment when it
separates the two references:

    static   Semgrep flags the insecure reference and not the secure one
    dynamic  the attack succeeds on the insecure reference, fails on the secure
             one, and neither reference fails its functional test

The result is saved as validation.json in the run directory. The evaluation
stage uses a task's dynamic verdicts only if the dynamic detector was valid for
that task here; otherwise it falls back to the static verdict.
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import detect, functest
from .stimuli import TASKS, Task


def run_selftest(tasks: list[Task] | None = None, workers: int = 4, dynamic: bool = True) -> dict:
    tasks = tasks or TASKS
    items = []
    for t in tasks:
        items.append((t.id + "|secure", t.cwe, t.lang, t.ref_secure))
        items.append((t.id + "|insecure", t.cwe, t.lang, t.ref_insecure))
    static = detect.scan_batch(items)

    dyn: dict[str, dict] = {}
    if dynamic:
        jobs = [(t, kind, getattr(t, "ref_" + kind)) for t in tasks for kind in ("secure", "insecure")]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for (t, kind, _), res in zip(jobs, pool.map(lambda j: functest.run_dynamic(j[0], j[2]), jobs)):
                dyn[f"{t.id}|{kind}"] = res

    report = {"semgrep": detect.semgrep_version(), "asan": functest.asan_available(),
              "c_compiler": functest.c_compiler(), "tasks": {}}
    for t in tasks:
        s_sec, s_ins = static[t.id + "|secure"]["flag"], static[t.id + "|insecure"]["flag"]
        d_sec, d_ins = dyn.get(t.id + "|secure", {}), dyn.get(t.id + "|insecure", {})
        static_valid = (s_ins is True and s_sec is False) if s_ins is not None else None
        if not dynamic:
            dynamic_valid = None
        else:
            dynamic_valid = (
                d_ins.get("exploit") is True and d_sec.get("exploit") is False
                and d_ins.get("functional") is not False and d_sec.get("functional") is not False
            )
        report["tasks"][t.id] = {
            "cwe": t.cwe,
            "static_valid": static_valid,
            "dynamic_valid": dynamic_valid,
            "functional_checked": d_sec.get("functional") is True and d_ins.get("functional") is True,
            "static": {"secure": s_sec, "insecure": s_ins,
                       "rules": static[t.id + "|insecure"]["rules"], "note": static[t.id + "|secure"]["note"]},
            "dynamic": {"secure": d_sec, "insecure": d_ins},
        }
    vals = report["tasks"].values()
    report["summary"] = {
        "n_tasks": len(report["tasks"]),
        "static_valid": sum(1 for v in vals if v["static_valid"] is True),
        "dynamic_valid": sum(1 for v in vals if v["dynamic_valid"] is True),
        "functional_checked": sum(1 for v in vals if v["functional_checked"]),
    }
    return report


def print_report(report: dict) -> None:
    def cell(v):
        return {True: "yes", False: "NO ", None: "n/a"}[v]

    print(f"semgrep: {report['semgrep'] or 'NOT FOUND'}   C compiler: {report['c_compiler'] or 'NOT FOUND'}"
          f"   AddressSanitizer: {'yes' if report['asan'] else 'no'}")
    print(f"{'task':<12} {'static':<7} {'dynamic':<8} {'functional':<10}  detail")
    for tid, v in report["tasks"].items():
        detail = ""
        if v["static_valid"] is False:
            detail += f" static(sec={v['static']['secure']},ins={v['static']['insecure']})"
        if v["dynamic_valid"] is False:
            d = v["dynamic"]
            detail += (f" dyn(sec: f={d['secure'].get('functional')} x={d['secure'].get('exploit')};"
                       f" ins: f={d['insecure'].get('functional')} x={d['insecure'].get('exploit')})")
            for kind in ("secure", "insecure"):
                for k in ("note", "import_error", "functional_error", "exploit_error", "harness_error", "stderr"):
                    if d[kind].get(k):
                        detail += f" [{kind} {k}: {str(d[kind][k])[:110]}]"
        print(f"{tid:<12} {cell(v['static_valid']):<7} {cell(v['dynamic_valid']):<8} "
              f"{cell(v['functional_checked'] or None):<10} {detail}")
    s = report["summary"]
    print(f"\nstatic valid {s['static_valid']}/{s['n_tasks']}   dynamic valid {s['dynamic_valid']}/{s['n_tasks']}"
          f"   functional verified {s['functional_checked']}/{s['n_tasks']}")


def save_report(report: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=1), encoding="utf-8")
