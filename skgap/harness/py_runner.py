"""
harness/py_runner.py — child process that judges one Python answer.

    python py_runner.py <task_id> <code_file>

Run with the sandbox directory as the working directory. Prints one line
"SKGAP_RESULT {json}" with:
    functional  True / False / None (not evaluated on this platform)
    exploit     True / False / None (could not be determined)
"""
import json
import os
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != _HERE]
sys.path.insert(0, _ROOT)

from skgap.harness.lib import H, MARKER_FILE, PLACEHOLDER, ENV_SENTINEL  # noqa: E402
from skgap.stimuli import TASK_BY_ID  # noqa: E402


def _clear_markers():
    for name in os.listdir("."):
        if name.startswith(MARKER_FILE):
            try:
                os.remove(name)
            except OSError:
                pass


def main() -> None:
    task = TASK_BY_ID[sys.argv[1]]
    with open(sys.argv[2], "r", encoding="utf-8") as fh:
        code = fh.read()

    out = {"functional": None, "exploit": None, "import_ok": False, "entry_ok": False}
    h = H(stubs=tuple(task.stubs) + (("decouple", "environ") if task.stubs else ()))

    if "flask" in code.lower():
        try:
            import flask
            flask.Flask.run = lambda *a, **k: None      # an unguarded app.run() must not block
        except ImportError:
            out["harness_error"] = "flask not installed"

    if task.setup:
        task.setup(h)

    mod = types.ModuleType("candidate")
    mod.__file__ = os.path.abspath("candidate.py")
    sys.modules["candidate"] = mod
    try:
        exec(compile(code, "candidate.py", "exec"), mod.__dict__)
        out["import_ok"] = True
    except BaseException as exc:       # keep whatever was defined before the failure
        out["import_error"] = f"{type(exc).__name__}: {exc}"[:300]

    if task.entry == "app":
        try:
            h.client(mod)
            out["entry_ok"] = True
        except Exception as exc:
            out["entry_error"] = str(exc)[:200]
    else:
        out["entry_ok"] = callable(getattr(mod, task.entry, None))

    if out["entry_ok"]:
        try:
            r = task.functional(mod, h)
            out["functional"] = None if r is None else bool(r)
        except BaseException as exc:
            out["functional"] = False
            out["functional_error"] = f"{type(exc).__name__}: {exc}"[:300]

        _clear_markers()
        try:
            if task.setup:
                task.setup(h)
            r = task.exploit(mod, h)
            out["exploit"] = None if r is None else bool(r)
        except BaseException as exc:
            out["exploit_error"] = f"{type(exc).__name__}: {exc}"[:300]
    else:
        out["functional"] = False

    if task.stubs and out["exploit"]:
        # was every literal credential an obvious placeholder ("your_password_here")?
        lits = [str(v) for c in _all_calls(h) for v in list(c.args) + list(c.kwargs.values())
                if isinstance(v, str) and ENV_SENTINEL not in v]
        out["placeholder"] = bool(lits) and any(PLACEHOLDER.search(v) for v in lits)

    sys.stdout.write("\nSKGAP_RESULT " + json.dumps(out) + "\n")
    sys.stdout.flush()
    os._exit(0)                        # do not wait for threads the answer may have started


def _all_calls(h):
    calls = []
    for stub in h._stubs.values():
        for c in stub.mock_calls:
            calls.append(c)
    return calls


if __name__ == "__main__":
    main()
