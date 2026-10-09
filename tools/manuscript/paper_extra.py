"""
paper_extra.py <run name>      (run from the project root)

Tables and figures that the manuscript uses in addition to those written by `skgap analyze`:

    tables/T22_composition.csv        the four outcome combinations by condition
    tables/T23_effect_by_model.csv    change in each outcome under the reminder and dense retrieval, by model
    tables/T24_retrieval_hit.csv      retrieval quality, and the effect of retrieval split by whether it found the class
    figures/figP_pipeline.png         study pipeline (manuscript wording)
    figures/figP_composition.png      outcome composition by condition
    figures/figP_tradeoff.png         change in vulnerable share against change in functional share, by model
    figures/figP_threshold.png        sensitivity of the high/low-knowledge split to the threshold
    figures/figP_heatmaps.png         knowledge and baseline introduction rate by model and class, models in table order
    figures/figP_forest.png           paired contrasts for the three outcomes, with the manuscript's condition names

It also prints the counts that the manuscript quotes in running text, so they can be checked against the data.
(T21_mixed_model.csv is written by glmm_exact.R.)
"""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from paper_data import CONTRAST_NAME, MODEL_ORDER  # noqa: E402
from skgap import analyze, config, figures, stats  # noqa: E402
from skgap.figures import BLUE, GRID, INK, INK2, ORANGE, AXIS, plt  # noqa: E402
from skgap.stimuli import CWES, TASKS  # noqa: E402

AQUA, NEUTRAL = "#1baf7a", "#c3c2b7"
COND_LABEL = {"baseline": "Baseline", "reminder": "Reminder", "ctx_irrelevant": "Irrelevant notes",
              "rag_dense": "Dense RAG", "rag_hybrid": "Hybrid RAG", "rag_oracle": "Oracle RAG"}


def main(run: str) -> None:
    d = analyze.load(run)
    df, models = d["df"], d["models"]
    gen = df[df.source == "gen"].copy()
    rep = df[df.source == "repair"].copy()
    cwes = [c for c in CWES if (gen.cwe == c).any()]
    tasks = [t.id for t in TASKS if (gen.task == t.id).any()]
    task_cwe = {t.id: t.cwe for t in TASKS}
    conds = [c for c in config.CONDITIONS if (gen.condition == c).any()]
    name = analyze.name
    out = d["paths"].analysis
    B, SEED = config.BOOTSTRAP_B, config.RNG_SEED
    K = analyze.knowledge_frames(d, cwes, tasks)
    rec = K["recog"]
    M = {o: {c: analyze.mat(gen[gen.condition == c], o, "model", "task", models, tasks) for c in conds}
         for o in ("vulnerable", "functional", "secure_pass")}

    # ── counts quoted in the text ────────────────────────────────────────────
    print("== checks ==")
    print("programs", len(gen), "| no code", int((~gen.has_code).sum()), "| truncated", int(gen.truncated.sum()),
          f"({100 * gen.truncated.mean():.1f}%)")
    print("truncated by model:", {name(m): int(v) for m, v in gen.groupby("model").truncated.sum().items()})
    print("truncated by class:", gen.groupby("cwe").truncated.sum().astype(int).to_dict())
    print("truncated by condition:", gen.groupby("condition").truncated.sum().astype(int).to_dict())
    print(f"functional among truncated: {100 * gen[gen.truncated].functional.mean():.1f}%")
    print("mean output tokens by condition:", gen.groupby("condition").tokens_out.mean().round(0).to_dict())
    kdf = d["kdf"]
    mcq, det = kdf[kdf.kind == "mcq"], kdf[kdf.kind == "detect"]
    print(f"MCQ: {len(mcq)} presentations, {100 * mcq.correct.astype(float).mean():.1f}% correct")
    ins, sec = det[det.variant == "insecure"], det[det.variant == "secure"]
    print(f"insecure references called vulnerable: {100 * ins.correct.astype(float).mean():.1f}% | secure references "
          f"called vulnerable: {100 * (1 - sec.correct.astype(float).mean()):.1f}%")
    flagged = ins[ins.correct.astype(float) == 1]
    print(f"weakness named matches the class, among flagged insecure references: {100 * flagged.names_cwe.astype(float).mean():.1f}%")
    for c in cwes:
        print(f"  {c}: insecure flagged {100 * ins[ins.cwe == c].correct.astype(float).mean():.0f}%, secure flagged "
              f"{100 * (1 - sec[sec.cwe == c].correct.astype(float).mean()):.0f}%")
    always = [name(m) for m in models if det[det.model == m].verdict.astype(str).str.lower().isin(["true", "vulnerable", "1", "yes"]).all()]
    print("recognising cells:", int(np.nansum(rec)), "of", int(np.isfinite(rec).sum()))
    low = K["K"] < config.KNOWLEDGE_TAU
    print("cells with K < tau:", int(low.sum()), "by class:", {c: int(low[:, j].sum()) for j, c in enumerate(cwes)})
    if not rep.empty:
        ok = ((rep.functional == 1) & (rep.vulnerable == 0)).astype(float)
        print(f"repair: {100 * ok.mean():.1f}% overall |", (100 * ok.groupby(rep.cwe).mean()).round(0).to_dict())
    kept = gen[~gen.truncated]
    for a in ("reminder", "rag_dense"):
        print(f"truncated programs excluded, {a} - baseline (pooled, points):",
              {o: round(100 * (kept[kept.condition == a][o].mean() - kept[kept.condition == 'baseline'][o].mean()), 1)
               for o in ("vulnerable", "functional", "secure_pass")})
    print(f"smallest Holm-adjusted sign-flip p with {len(models)} models and 9 contrasts: {9 * 2 / 2 ** len(models):.3f}")

    # ── T22: the four outcome combinations by condition ──────────────────────
    rows = []
    for c in conds:
        g = gen[gen.condition == c]
        v, f = g.vulnerable == 1, g.functional == 1
        rows.append({"condition": c, "n": len(g), "working_secure": float((f & ~v).mean()),
                     "working_vulnerable": float((f & v).mean()), "notworking_vulnerable": float((~f & v).mean()),
                     "notworking_notvulnerable": float((~f & ~v).mean()), "truncated": float(g.truncated.mean())})
    t22 = pd.DataFrame(rows)
    t22.to_csv(out / "tables" / "T22_composition.csv", index=False)
    print("\n== T22 ==\n", t22.round(3).to_string(index=False))

    # ── T23: change in each outcome by model ─────────────────────────────────
    rows = []
    for i, m in enumerate(models):
        row = {"model": name(m)}
        for o in ("vulnerable", "functional", "secure_pass"):
            row[f"baseline_{o}"] = stats.nanmean(M[o]["baseline"][i])
            for a in ("reminder", "rag_dense"):
                row[f"{a}_{o}"] = stats.nanmean(M[o][a][i] - M[o]["baseline"][i])
        rows.append(row)
    t23 = pd.DataFrame(rows)
    t23.to_csv(out / "tables" / "T23_effect_by_model.csv", index=False)
    print("\n== T23 ==\n", t23.round(3).to_string(index=False))

    # ── T24: retrieval quality and effect by whether the class was found ─────
    retr = d["retrieval"]["tasks"]
    rows = []
    for a in ("rag_dense", "rag_hybrid", "rag_oracle"):
        on = np.array([[n["on_target"] for n in retr[t][a]] for t in tasks], dtype=float)
        hit = on.any(axis=1)
        for label, sel in (("all tasks", np.ones(len(tasks), bool)), ("class found", hit), ("class not found", ~hit)):
            if not sel.any():
                continue
            row = {"condition": a, "tasks": label, "n_tasks": int(sel.sum()), "hit_at_3": float(hit.mean()),
                   "on_class_share": float(on.mean())}
            for o in ("vulnerable", "secure_pass"):
                for ref in ("baseline", "ctx_irrelevant"):
                    diff = (M[o][a] - M[o][ref])[:, sel]
                    ci = stats.boot2way([diff], lambda ms: stats.nanmean(ms[0]), B, SEED)
                    row[f"{o}_vs_{ref}"], row[f"{o}_vs_{ref}_lo"], row[f"{o}_vs_{ref}_hi"] = ci["est"], ci["lo"], ci["hi"]
            row["hits_by_class"] = "; ".join(f"{c} {int(hit[[task_cwe[t] == c for t in tasks]].sum())}" for c in cwes)
            rows.append(row)
    t24 = pd.DataFrame(rows)
    t24.to_csv(out / "tables" / "T24_retrieval_hit.csv", index=False)
    print("\n== T24 ==\n", t24.drop(columns="hits_by_class").round(3).to_string(index=False))
    print(t24[["condition", "hits_by_class"]].drop_duplicates().to_string(index=False))

    # ── figures ──────────────────────────────────────────────────────────────
    fdir = out / "figures"
    pipeline(fdir, len(models), len(tasks), len(cwes), d["manifest"].get("profile", {}).get("n_samples", 5), len(conds))
    composition(fdir, t22)
    tradeoff(fdir, t23)
    t11 = pd.read_csv(out / "tables" / "T11_threshold_sensitivity.csv")
    threshold(fdir, t11)
    names = [name(m) for m in models]
    idx = [names.index(m) for m in MODEL_ORDER]
    base = gen[gen.condition == "baseline"]
    IRc = analyze.mat(base, "vulnerable", "model", "cwe", models, cwes)
    heatmaps(fdir, K["K"][idx], IRc[idx], MODEL_ORDER, cwes)
    forest(fdir, pd.read_csv(out / "tables" / "T13_contrasts.csv"))
    print("\nfigures written to", fdir)


def _save(fig, fdir: Path, stem: str) -> None:
    figures._save(fig, fdir, stem, False)


def pipeline(fdir, n_models, n_tasks, n_cwes, n_samples, n_conds):
    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    boxes = [
        ("Stimuli",
         f"{n_tasks} tasks in {n_cwes} CWE classes; each task has a functional test,\nan attack test and a secure / insecure reference solution"),
        ("Detector validation",
         "Semgrep rules and attack tests must separate the two reference\nsolutions of a task before their verdicts are used"),
        ("Knowledge battery (scored automatically)",
         "multiple choice · recognition of insecure vs secure code (class not named)\n· explanation · repair (reported separately)"),
        ("Generation",
         f"{n_models} models × {n_tasks} tasks × {n_conds} conditions × {n_samples} samples\nbaseline · reminder · irrelevant notes · dense RAG · hybrid RAG · oracle RAG"),
        ("Automatic judgement of every program",
         "functional test · attack test (dynamic) · Semgrep (static)\nvulnerable = attack verdict where available, otherwise Semgrep verdict"),
        ("Blind audit",
         "stratified sample of 140 programs and all 63 explanations rated by a scorer\nmodel; ratings then checked informally by the authors"),
        ("Analysis",
         "H1 residual gap · H2 coupling (fixed effects, mixed model)\nH3–H5 paired condition contrasts, model as the unit"),
    ]
    fig, ax = plt.subplots(figsize=(5.6, 7.4))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, len(boxes))
    ax.axis("off")
    for i, (head, body) in enumerate(boxes):
        y = len(boxes) - 1 - i
        ax.add_patch(FancyBboxPatch((0.04, y + 0.14), 0.92, 0.72, boxstyle="round,pad=0.01,rounding_size=0.03",
                                    fc="#f3f7fd", ec=BLUE, lw=1))
        ax.text(0.07, y + 0.70, head, fontsize=8.5, weight="bold", color=INK, va="center")
        ax.text(0.07, y + 0.40, body, fontsize=7.2, color=INK2, va="center", linespacing=1.35)
        if i < len(boxes) - 1:
            ax.add_patch(FancyArrowPatch((0.5, y + 0.14), (0.5, y - 0.14), arrowstyle="-|>", mutation_scale=10,
                                         color=INK2, lw=1))
    _save(fig, fdir, "figP_pipeline")


def composition(fdir, t22):
    parts = [("working_secure", "Working and not vulnerable (secure-pass)", BLUE, "white", None),
             ("working_vulnerable", "Working, vulnerable", ORANGE, "white", None),
             ("notworking_vulnerable", "Not working, vulnerable", AQUA, INK, "////"),
             ("notworking_notvulnerable", "Not working, not vulnerable", NEUTRAL, INK, None)]
    fig, ax = plt.subplots(figsize=(7.0, 2.9))
    y = np.arange(len(t22))[::-1]
    left = np.zeros(len(t22))
    for col, label, color, ink, hatch in parts:
        vals = t22[col].to_numpy(dtype=float)
        ax.barh(y, vals, left=left, height=0.56, color=color, edgecolor="white", linewidth=2, label=label,
                hatch=hatch, zorder=2)
        for yi, v, l in zip(y, vals, left):
            if v >= 0.045:
                ax.text(l + v / 2, yi, f"{100 * v:.0f}", ha="center", va="center", fontsize=7, color=ink, zorder=3,
                        bbox=dict(fc=color, ec="none", pad=0.6) if hatch else None)
        left += vals
    ax.set_yticks(y, [COND_LABEL[c] for c in t22.condition])
    ax.set_xlim(0, 1)
    ax.set_xticks(np.arange(0, 1.01, 0.2), [f"{int(100 * v)}%" for v in np.arange(0, 1.01, 0.2)])
    ax.set_xlabel("Share of the 2,520 programs of each condition")
    ax.tick_params(axis="y", length=0)
    ax.spines["left"].set_visible(False)
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.0), ncol=2, fontsize=7, handlelength=1.4, columnspacing=1.6)
    fig.tight_layout()
    _save(fig, fdir, "figP_composition")


def tradeoff(fdir, t23):
    fig, ax = plt.subplots(figsize=(4.4, 3.9))
    lim = 100 * float(np.nanmin(t23[[c for c in t23.columns if c.startswith(("reminder_", "rag_dense_"))]].to_numpy())) - 3
    lim = min(lim, -24)
    ax.plot([lim, 6], [lim, 6], color=AXIS, lw=1, zorder=1)
    ax.text(lim + 1.2, lim + 2.6, "equal loss of vulnerable\nand of working programs", fontsize=6.5, color=INK2, va="bottom",
            rotation=45, rotation_mode="anchor")
    ax.axhline(0, color=GRID, lw=0.8, zorder=0)
    ax.axvline(0, color=GRID, lw=0.8, zorder=0)
    for a, color, marker, label in (("reminder", BLUE, "o", "Reminder"), ("rag_dense", ORANGE, "s", "Dense RAG")):
        x, yv = 100 * t23[f"{a}_functional"], 100 * t23[f"{a}_vulnerable"]
        ax.scatter(x, yv, s=42, c=color, marker=marker, edgecolors="white", linewidths=1.2, label=f"{label}, one model", zorder=3)
        ax.scatter([x.mean()], [yv.mean()], s=150, facecolors="none", edgecolors=color, marker=marker, linewidths=1.6,
                   label=f"{label}, mean of the nine models", zorder=4)
    ax.set_xlim(lim, 6)
    ax.set_ylim(lim, 6)
    ax.set_aspect("equal")
    ax.set_xlabel("Change in functional programs (percentage points)")
    ax.set_ylabel("Change in vulnerable programs (percentage points)")
    ax.grid(color=GRID, lw=0.5, zorder=0)
    ax.legend(loc="upper left", fontsize=6.5, handletextpad=0.3, borderaxespad=0.2)
    fig.tight_layout()
    _save(fig, fdir, "figP_tradeoff")


def heatmaps(fdir, K, IR, rows, cols):
    fig, axes = plt.subplots(1, 2, figsize=(7.4, 3.0), sharey=True)
    for ax, mat, title in zip(axes, (K, IR), ("(a) Knowledge K", "(b) Introduction rate without a cue")):
        mesh = ax.pcolormesh(np.ma.masked_invalid(mat), cmap=figures.SEQ, vmin=0, vmax=1, edgecolors="white", linewidth=2)
        for i in range(len(rows)):
            for j in range(len(cols)):
                v = mat[i, j]
                ax.text(j + 0.5, i + 0.5, f"{v:.2f}", ha="center", va="center", fontsize=6.5,
                        color="white" if v > 0.55 else INK)
        ax.set_xticks(np.arange(len(cols)) + 0.5, [c.replace("CWE-", "") for c in cols])
        ax.set_yticks(np.arange(len(rows)) + 0.5, rows)
        ax.set_xlabel("CWE class")
        ax.tick_params(length=0)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.set_title(title, loc="left")
    axes[0].invert_yaxis()
    fig.tight_layout()
    cb = fig.colorbar(mesh, ax=axes, fraction=0.02, pad=0.015)
    cb.outline.set_visible(False)
    _save(fig, fdir, "figP_heatmaps")


def forest(fdir, t13):
    outs = [("vulnerable", "Vulnerable"), ("functional", "Functional"), ("secure_pass", "Secure-pass")]
    n = int((t13.outcome == "vulnerable").sum())
    fig, axes = plt.subplots(1, 3, figsize=(7.4, 0.75 + 0.27 * n), sharey=True)
    for ax, (o, title) in zip(axes, outs):
        dd = t13[t13.outcome == o].reset_index(drop=True)
        y = np.arange(len(dd))[::-1]
        ax.axvline(0, color=AXIS, lw=1, zorder=1)
        ax.hlines(y, 100 * dd.ci_lo, 100 * dd.ci_hi, color=BLUE, lw=2, zorder=2)
        sig = (dd.p_holm < config.ALPHA).to_numpy()
        ax.scatter(100 * dd.risk_difference[sig], y[sig], s=34, c=BLUE, edgecolors="white", linewidths=0.8, zorder=3,
                   label="Holm-adjusted p < 0.05")
        ax.scatter(100 * dd.risk_difference[~sig], y[~sig], s=34, facecolors="white", edgecolors=BLUE, linewidths=1.4,
                   zorder=3, label="not significant")
        ax.set_yticks(y, [CONTRAST_NAME[c].replace("−", "–") for c in dd.contrast])
        ax.set_title(title, loc="left")
        ax.set_xlim(-22, 22)
        ax.set_xticks([-20, -10, 0, 10, 20])
        ax.grid(axis="x", color=GRID, lw=0.5, zorder=0)
        ax.tick_params(axis="y", length=0)
    axes[1].set_xlabel("Difference in percentage points (95% CI)")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="lower center", ncol=2, fontsize=7, bbox_to_anchor=(0.6, -0.07))
    fig.tight_layout()
    _save(fig, fdir, "figP_forest")


def threshold(fdir, t11):
    fig, ax = plt.subplots(figsize=(4.6, 2.6))
    ax.plot(t11.tau, t11.ir_low, color=ORANGE, lw=2, marker="s", ms=5, mec="white", mew=1, label="cells with K below τ", zorder=3)
    ax.plot(t11.tau, t11.ir_high, color=BLUE, lw=2, marker="o", ms=5, mec="white", mew=1, label="cells with K at or above τ", zorder=3)
    ax.axvline(config.KNOWLEDGE_TAU, color=INK2, lw=0.8, zorder=1)
    ax.text(config.KNOWLEDGE_TAU, 0.97, " τ = 0.5", fontsize=6.5, color=INK2, va="top")
    ax.set_ylim(0, 1)
    ax.set_xlabel("Knowledge threshold τ")
    ax.set_ylabel("Introduction rate without a cue")
    ax.grid(color=GRID, lw=0.5, zorder=0)
    ax.legend(loc="upper right", fontsize=7)
    fig.tight_layout()
    _save(fig, fdir, "figP_threshold")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "paper")
