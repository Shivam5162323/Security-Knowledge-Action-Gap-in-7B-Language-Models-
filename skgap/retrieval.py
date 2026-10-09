"""
retrieval.py — the security-note corpus and the retrieval conditions.

Corpus (mixed, several hundred weakness classes):
  * every weakness entry of the MITRE CWE catalogue (name, description, mitigations)
  * NVD CVE descriptions for ~40 common CWE classes from a fixed publication window

Retrievers, all run once on CPU and cached in retrieval.json:
  rag_dense       cosine similarity of sentence embeddings, whole corpus
  rag_hybrid      weighted reciprocal-rank fusion of dense and BM25 rankings:
                      score(d) = w_dense / (k + rank_dense(d)) + w_bm25 / (k + rank_bm25(d))
  rag_oracle      dense ranking restricted to notes of the task's own CWE family
  ctx_irrelevant  k notes drawn at random (fixed seed) from classes unrelated to
                  any studied CWE

The query is the task prompt, exactly what a deployed system would have.
"""
from __future__ import annotations

import hashlib
import io
import json
import math
import os
import random
import re
import time
import zipfile
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree as ET

import numpy as np
import requests

from .config import (NVD_PER_CWE, RAG_CONDITIONS, RAG_DOC_CHARS, RAG_ENCODER, RAG_TOP_K, RNG_SEED, ROOT,
                     RRF_K, RRF_W_BM25, RRF_W_DENSE)
from .stimuli import CWES, Task

DATA_DIR = ROOT / "data"
SHIPPED_CORPUS = DATA_DIR / "corpus.jsonl"
SHIPPED_RETRIEVAL = DATA_DIR / "retrieval.json"

CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_WINDOW = ("2024-01-01T00:00:00.000", "2024-04-29T23:59:59.999")     # 120 days, the API maximum
NVD_CWES = [
    "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-502", "CWE-798", "CWE-120", "CWE-787", "CWE-125", "CWE-416",
    "CWE-20", "CWE-352", "CWE-434", "CWE-862", "CWE-476", "CWE-287", "CWE-190", "CWE-77", "CWE-119", "CWE-918",
    "CWE-306", "CWE-362", "CWE-269", "CWE-94", "CWE-863", "CWE-276", "CWE-200", "CWE-400", "CWE-611", "CWE-732",
    "CWE-295", "CWE-601", "CWE-327", "CWE-330", "CWE-259", "CWE-312", "CWE-319", "CWE-384", "CWE-613", "CWE-770",
]
STUDIED_FAMILY = {c for cw in CWES.values() for c in cw.family}
STOP = set("a an and are as at be by for from has have in is it its of on or that the this to was were which with "
           "via can may allows allow could when where into not".split())


# ── corpus construction ───────────────────────────────────────────────────────
def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def fetch_cwe_catalogue(progress=print) -> list[dict]:
    progress("downloading the MITRE CWE catalogue ...")
    r = requests.get(CWE_XML_URL, timeout=120)
    r.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        xml = z.read(z.namelist()[0])
    root = ET.fromstring(xml)
    ns = {"c": root.tag.split("}")[0].strip("{")}
    docs = []
    for w in root.iterfind(".//c:Weaknesses/c:Weakness", ns):
        if w.get("Status") == "Deprecated":
            continue
        cid = "CWE-" + w.get("ID")
        desc = _clean("".join(w.find("c:Description", ns).itertext())) if w.find("c:Description", ns) is not None else ""
        mits = []
        for m in w.iterfind(".//c:Potential_Mitigations/c:Mitigation/c:Description", ns):
            mits.append(_clean("".join(m.itertext())))
        text = f"{cid} {w.get('Name')}: {desc}"
        if mits:
            text += " Mitigation: " + " ".join(mits)
        docs.append({"id": cid, "cwe": cid, "kind": "cwe", "text": text})
    progress(f"  {len(docs)} CWE entries")
    return docs


def fetch_nvd(progress=print) -> list[dict]:
    key = os.getenv("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    delay = 0.8 if key else 6.5              # NVD rate limit: 5 requests / 30 s without a key
    docs, seen = [], set()
    for cwe in NVD_CWES:
        params = {"cweId": cwe, "resultsPerPage": NVD_PER_CWE, "pubStartDate": NVD_WINDOW[0], "pubEndDate": NVD_WINDOW[1]}
        data = None
        for attempt in range(4):
            try:
                r = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
                if r.status_code == 200:
                    data = r.json()
                    break
            except requests.RequestException:
                pass
            time.sleep(delay * (attempt + 2))
        if data is None:
            progress(f"  NVD: {cwe} failed, skipped")
            continue
        n = 0
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
            if not desc or cve.get("id") in seen or cve.get("vulnStatus") == "Rejected":
                continue
            seen.add(cve["id"])
            docs.append({"id": cve["id"], "cwe": cwe, "kind": "cve", "text": f"{cve['id']} ({cwe}): {_clean(desc)}"})
            n += 1
        progress(f"  NVD: {cwe} {n} CVEs")
        time.sleep(delay)
    return docs


def build_corpus(path: Path, progress=print) -> list[dict]:
    docs = fetch_cwe_catalogue(progress) + fetch_nvd(progress)
    if len(docs) < 200:
        raise RuntimeError(f"corpus too small ({len(docs)} notes); check network access")
    save_corpus(docs, path)
    return docs


def save_corpus(docs: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for d in docs:
            fh.write(json.dumps(d, ensure_ascii=False) + "\n")


def load_corpus(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def corpus_sha(docs: list[dict]) -> str:
    h = hashlib.sha256()
    for d in docs:
        h.update(d["id"].encode() + b"\0" + d["text"].encode("utf-8") + b"\n")
    return h.hexdigest()


# ── retrieval ─────────────────────────────────────────────────────────────────
def tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9_]+", text.lower()) if t not in STOP and len(t) > 1]


class BM25:
    def __init__(self, docs: list[list[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.tf = [Counter(d) for d in docs]
        self.len = np.array([len(d) for d in docs], dtype=float)
        self.avg = float(self.len.mean()) if len(docs) else 0.0
        df = Counter(t for d in self.tf for t in d)
        n = len(docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def scores(self, query: list[str]) -> np.ndarray:
        s = np.zeros(len(self.tf))
        for t in set(query):
            idf = self.idf.get(t)
            if idf is None:
                continue
            f = np.array([d.get(t, 0) for d in self.tf], dtype=float)
            s += idf * f * (self.k1 + 1) / (f + self.k1 * (1 - self.b + self.b * self.len / self.avg))
        return s


def encode(texts: list[str], encoder: str = RAG_ENCODER, progress=print) -> np.ndarray:
    """L2-normalised embeddings. encoder="hash" is a dependency-free stand-in for tests only."""
    if encoder == "hash":
        dim = 512
        m = np.zeros((len(texts), dim), dtype=np.float32)
        for i, t in enumerate(texts):
            for tok in tokenize(t):
                m[i, int(hashlib.md5(tok.encode()).hexdigest(), 16) % dim] += 1.0
    else:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("sentence-transformers is required to rebuild the retrieval cache "
                               "(pip install sentence-transformers)") from exc
        progress(f"encoding {len(texts)} texts with {encoder} ...")
        m = SentenceTransformer(encoder).encode(texts, batch_size=64, show_progress_bar=False,
                                                convert_to_numpy=True).astype(np.float32)
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms


def _ranks(scores: np.ndarray) -> np.ndarray:
    """rank[i] = 1-based rank of document i (ties broken by index, deterministic)."""
    order = np.lexsort((np.arange(len(scores)), -scores))
    ranks = np.empty(len(scores), dtype=int)
    ranks[order] = np.arange(1, len(scores) + 1)
    return ranks


def build_retrieval(tasks: list[Task], docs: list[dict], encoder: str = RAG_ENCODER, progress=print) -> dict:
    doc_vecs = encode([d["text"] for d in docs], encoder, progress)
    q_vecs = encode([t.prompt for t in tasks], encoder, progress)
    bm25 = BM25([tokenize(d["text"]) for d in docs])
    cwes = [d["cwe"] for d in docs]
    unrelated = [i for i, c in enumerate(cwes) if c not in STUDIED_FAMILY]

    out: dict = {"encoder": encoder, "corpus_sha": corpus_sha(docs), "n_docs": len(docs), "top_k": RAG_TOP_K,
                 "rrf": {"k": RRF_K, "w_dense": RRF_W_DENSE, "w_bm25": RRF_W_BM25}, "tasks": {}}
    for t, q in zip(tasks, q_vecs):
        family = set(CWES[t.cwe].family)
        dense = doc_vecs @ q
        r_dense, r_bm25 = _ranks(dense), _ranks(bm25.scores(tokenize(t.prompt)))
        fused = RRF_W_DENSE / (RRF_K + r_dense) + RRF_W_BM25 / (RRF_K + r_bm25)
        in_family = np.array([c in family for c in cwes])
        rng = random.Random(f"{RNG_SEED}-{t.id}")
        picks = {
            "rag_dense": np.argsort(r_dense)[:RAG_TOP_K],
            "rag_hybrid": np.argsort(_ranks(fused))[:RAG_TOP_K],
            "rag_oracle": np.argsort(_ranks(np.where(in_family, dense, -np.inf)))[:RAG_TOP_K],
            "ctx_irrelevant": rng.sample(unrelated, RAG_TOP_K),
        }
        out["tasks"][t.id] = {
            cond: [{"id": docs[i]["id"], "cwe": cwes[i], "kind": docs[i]["kind"], "on_target": cwes[i] in family,
                    "dense_rank": int(r_dense[i]), "bm25_rank": int(r_bm25[i])} for i in map(int, idx)]
            for cond, idx in picks.items()
        }
    return out


def retrieval_quality(retr: dict) -> dict:
    """Share of tasks with at least one on-target note (hit@k) and mean share of on-target notes."""
    q = {}
    for cond in RAG_CONDITIONS:
        rows = [t[cond] for t in retr["tasks"].values() if cond in t]
        if rows:
            q[cond] = {"hit_at_k": round(float(np.mean([any(d["on_target"] for d in r) for r in rows])), 4),
                       "precision_at_k": round(float(np.mean([np.mean([d["on_target"] for d in r]) for r in rows])), 4)}
    return q


def context_block(task_id: str, condition: str, retr: dict, doc_text: dict[str, str]) -> list[str]:
    return [compact_note(doc_text[d["id"]]) for d in retr["tasks"][task_id][condition]]


def _cut(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n].rsplit(" ", 1)[0] + " ..."


def compact_note(text: str, limit: int = RAG_DOC_CHARS) -> str:
    """
    Fit a note into the context budget. CWE entries keep the start of the description and
    the start of the mitigation text, so the actionable part is not what gets cut off.
    """
    if len(text) <= limit:
        return text
    if " Mitigation: " in text:
        head, mit = text.split(" Mitigation: ", 1)
        head = _cut(head, limit // 2)
        return head + " Mitigation: " + _cut(mit, max(60, limit - len(head) - 13))
    return _cut(text, limit)


def ensure_retrieval(corpus_path: Path, retrieval_path: Path, tasks: list[Task], encoder: str = RAG_ENCODER,
                     progress=print) -> tuple[dict, dict[str, str]]:
    """
    Load the retrieval cache for this run, creating it if needed. Order of preference:
    the run's own files, then the snapshot shipped in data/, then a fresh build.
    """
    if not corpus_path.exists():
        if SHIPPED_CORPUS.exists():
            corpus_path.write_bytes(SHIPPED_CORPUS.read_bytes())
            progress(f"using the shipped corpus snapshot ({SHIPPED_CORPUS.name})")
        else:
            build_corpus(corpus_path, progress)
    docs = load_corpus(corpus_path)
    sha = corpus_sha(docs)
    need = {t.id for t in tasks}

    def usable(r: dict) -> bool:
        return r.get("corpus_sha") == sha and need <= set(r.get("tasks", {})) and r.get("top_k") == RAG_TOP_K

    retr = None
    if retrieval_path.exists():
        retr = json.loads(retrieval_path.read_text(encoding="utf-8"))
        retr = retr if usable(retr) else None
    if retr is None and SHIPPED_RETRIEVAL.exists():
        shipped = json.loads(SHIPPED_RETRIEVAL.read_text(encoding="utf-8"))
        if usable(shipped):
            retr = shipped
            progress(f"using the shipped retrieval cache ({SHIPPED_RETRIEVAL.name})")
    if retr is None:
        retr = build_retrieval(tasks, docs, encoder, progress)
    retrieval_path.write_text(json.dumps(retr, indent=1), encoding="utf-8")
    return retr, {d["id"]: d["text"] for d in docs}
