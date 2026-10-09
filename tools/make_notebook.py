"""Regenerates notebooks/skgap_run.ipynb.   python tools/make_notebook.py"""
import json
from pathlib import Path


def md(s):
    return {"cell_type": "markdown", "metadata": {}, "source": s.strip("\n").splitlines(keepends=True)}


def code(s):
    return {"cell_type": "code", "metadata": {}, "execution_count": None, "outputs": [],
            "source": s.strip("\n").splitlines(keepends=True)}


CELLS = [
    md("""
# Security knowledge-action gap — full run (Kaggle or Colab)

Run the cells top to bottom. **If the session dies, open the notebook again and run the same cells**: everything already generated is kept and skipped.

The unattended way on Kaggle: **Save Version → Save & Run All (Commit)**. The notebook then runs by itself for up to 12 hours and its output is stored when it ends. For the next round, add that version's output as an input and commit again.

Before you start
- **Kaggle:** Settings → Accelerator **GPU T4 x2**, Internet **On**. Add the project as input (the `skgap_bundle.zip` dataset you uploaded). To continue an earlier session, also add that earlier notebook version's **output** as input.
- **Colab:** Runtime → Change runtime type → **T4 GPU**. Upload `skgap_bundle.zip` to `MyDrive/skgap/` on Google Drive.
"""),
    code("""
# ── 1. Settings ───────────────────────────────────────────────────────────────
RUN_NAME  = "paper"     # keep the same name to resume; change it only to start a fresh study
PROFILE   = "paper"     # "smoke" = 5-minute pipeline check, "lean" = 3 samples, "paper" = full design
MAX_HOURS = 10.5       # stop generating in time for the remaining cells (Kaggle limit 12 h). Colab free: about 3.5
GIT_URL   = ""          # optional: public git URL of the project instead of an uploaded zip
"""),
    code("""
# ── 2. Locate the project and the place where results persist ─────────────────
import os, sys, glob, zipfile, shutil, subprocess
ON_KAGGLE = os.path.exists("/kaggle/working")
ON_COLAB  = "COLAB_RELEASE_TAG" in os.environ or os.path.exists("/content")

if ON_KAGGLE:
    WORK, SEARCH = "/kaggle/working", ["/kaggle/input"]
else:
    from google.colab import drive
    drive.mount("/content/drive")
    WORK, SEARCH = "/content/drive/MyDrive/skgap", ["/content/drive/MyDrive/skgap", "/content"]
os.makedirs(WORK, exist_ok=True)

SRC = "/tmp/skgap_src"
shutil.rmtree(SRC, ignore_errors=True)
if GIT_URL:
    subprocess.run(["git", "clone", "--depth", "1", GIT_URL, SRC], check=True)
else:
    found = None
    for root in SEARCH:
        hits = glob.glob(os.path.join(root, "**", "skgap", "cli.py"), recursive=True)
        if hits:
            found = os.path.dirname(os.path.dirname(hits[0]))
            break
    if found:
        shutil.copytree(found, SRC, ignore=shutil.ignore_patterns("runs", "legacy", "__pycache__"))
    else:
        zips = [z for root in SEARCH for z in glob.glob(os.path.join(root, "**", "skgap_bundle*.zip"), recursive=True)]
        assert zips, "Project not found. Add skgap_bundle.zip as input (Kaggle) or put it in MyDrive/skgap (Colab)."
        with zipfile.ZipFile(zips[0]) as z:
            z.extractall("/tmp/skgap_unzip")
        hit = glob.glob("/tmp/skgap_unzip/**/skgap/cli.py", recursive=True)[0]
        shutil.copytree(os.path.dirname(os.path.dirname(hit)), SRC)

os.chdir(SRC)
os.environ["SKGAP_RUNS_DIR"]   = os.path.join(WORK, "runs")   # Kaggle: notebook output; Colab: Google Drive
os.environ["SKGAP_ALLOW_EXEC"] = "1"                          # this VM is disposable: run the functional/attack tests
os.environ["OLLAMA_MODELS"]    = "/tmp/ollama_models"         # model files never count against the output quota
print("project:", SRC, "| results:", os.environ["SKGAP_RUNS_DIR"])
"""),
    code("""
# ── 3. Optional: automatic off-site backup every 10 minutes ───────────────────
# Create a token with write access at huggingface.co/settings/tokens, store it as the secret HF_TOKEN
# (Kaggle: Add-ons → Secrets; Colab: key icon), and name any private dataset repo below.
HF_REPO = ""            # e.g. "your-username/skgap-runs"
if HF_REPO:
    try:
        if ON_KAGGLE:
            from kaggle_secrets import UserSecretsClient
            os.environ["HF_TOKEN"] = UserSecretsClient().get_secret("HF_TOKEN")
        else:
            from google.colab import userdata
            os.environ["HF_TOKEN"] = userdata.get("HF_TOKEN")
        os.environ["SKGAP_HF_REPO"] = HF_REPO
        print("backup to", HF_REPO, "enabled")
    except Exception as e:
        print("backup NOT enabled:", e)
"""),
    code("""
# ── 4. Install (about 2 minutes) ──────────────────────────────────────────────
!pip -q install semgrep flask pyyaml statsmodels huggingface_hub 2>&1 | tail -1
!python -m skgap setup
!python -m skgap doctor
"""),
    code("""
# ── 5. Check the detectors on the reference solutions (about 2 minutes) ───────
# Expect: static valid 55/56, dynamic valid 56/56 (or close). Tasks whose attack test does not
# validate here automatically fall back to the Semgrep verdict; nothing needs fixing by hand.
!python -m skgap selftest --run {RUN_NAME} --workers 4
"""),
    code("""
# ── 6. What will run, and what already exists ─────────────────────────────────
!python -m skgap plan --profile {PROFILE}
!python -m skgap status --run {RUN_NAME} --profile {PROFILE}
"""),
    code("""
# ── 7. GPU stage: knowledge battery + generation ──────────────────────────────
# Safe to interrupt. Re-running continues from the last saved reply.
!python -m skgap run --run {RUN_NAME} --profile {PROFILE} --max-hours {MAX_HOURS}
"""),
    code("""
# ── 8. CPU stages: judge every answer, then statistics, tables and figures ────
# No GPU needed. You can run this in a CPU-only session to save GPU quota.
!python -m skgap evaluate --run {RUN_NAME}
!python -m skgap analyze --run {RUN_NAME}
!python -m skgap status --run {RUN_NAME} --profile {PROFILE}
"""),
    code("""
# ── 9. Results ────────────────────────────────────────────────────────────────
from IPython.display import Markdown, Image, display
out = os.path.join(os.environ["SKGAP_RUNS_DIR"], RUN_NAME, "analysis")
display(Markdown(open(os.path.join(out, "report.md"), encoding="utf-8").read()))
for f in sorted(glob.glob(os.path.join(out, "figures", "*.png"))):
    display(Image(f, width=760))
"""),
    code("""
# ── 10. One archive with everything (records, manifest, report, figures) ──────
!python -m skgap export --run {RUN_NAME}
# Kaggle: "Save Version" (Quick Save is enough) keeps /kaggle/working, including this zip.
# Colab: the files are already on your Google Drive under MyDrive/skgap/runs/.
"""),
    md("""
### After the run: scoring

Download the archive from cell 10, unzip it into the project's `runs/` folder on your machine, and ask Claude Code to *score the audit sheets for run paper*. Claude Opus 5.5 rates a blind sample of the answers and all explanations; `python -m skgap analyze --run paper` then adds Table T20 and the `K_explain_scorer` column to the report.
"""),
    md("""
### If something goes wrong

| Symptom | What to do |
|---|---|
| Session timed out or disconnected | Re-open and run cells 1–8 again. On Kaggle, first *Save Version*, then add that version's output as an input so the partial run is found. |
| `NOT FINISHED: ... time budget` | Normal. Start another session and run again; it continues. |
| A model fails to download | The other models still run. Re-run later; only the missing model is processed. |
| `pull ...: manifest unknown` | The tag was renamed upstream. Edit the tag in `skgap/config.py`, keep everything else. |
| A model's answers are empty or cut off after `<think>` | Reasoning was not switched off for it. Check the `reasoning` column of Table T1 and update Ollama (cell 4 installs the latest). |
| Out of GPU quota | Run cell 8 in a CPU session to analyse what exists; the report states which models are incomplete. |
| You changed prompts, tasks or sampling settings | Use a new `RUN_NAME`. The pipeline refuses to mix two designs in one run. |
"""),
]

for _i, _c in enumerate(CELLS):
    _c["id"] = f"cell{_i:02d}"

NB = {"cells": CELLS,
      "metadata": {"kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
                   "language_info": {"name": "python"}, "accelerator": "GPU", "colab": {"provenance": []},
                   "kaggle": {"accelerator": "nvidiaTeslaT4", "isGpuEnabled": True, "isInternetEnabled": True}},
      "nbformat": 4, "nbformat_minor": 5}

if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "notebooks" / "skgap_run.ipynb"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(NB, indent=1, ensure_ascii=False), encoding="utf-8")
    print("wrote", out)
