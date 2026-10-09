"""
llm.py — model backends.

OllamaServer  manages one `ollama serve` process (optionally pinned to one GPU)
              and talks to it over HTTP. Replies are streamed so generation can
              be cut off as soon as the answer is complete, which saves the
              tokens small models spend on trailing explanations.
MockBackend   deterministic fake models for testing the pipeline end to end
              without a GPU. Its output is synthetic and labelled as such.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable

import requests

from .config import NUM_CTX, THINK, TOP_P


class LLMError(RuntimeError):
    pass


def gpu_count() -> int:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return 0
    try:
        out = subprocess.run([exe, "--query-gpu=index", "--format=csv,noheader"],
                             capture_output=True, text=True, timeout=20).stdout
        return len([line for line in out.splitlines() if line.strip()])
    except Exception:
        return 0


class OllamaServer:
    backend = "ollama"

    def __init__(self, port: int = 11434, gpu: int | None = None, parallel: int = 4, log_dir: Path | None = None):
        self.port, self.gpu, self.parallel = port, gpu, parallel
        self.url = os.getenv("OLLAMA_BASE_URL", f"http://127.0.0.1:{port}") if port == 11434 else f"http://127.0.0.1:{port}"
        self.log_dir = log_dir
        self.proc: subprocess.Popen | None = None
        self.managed = False
        self._thinks: dict[str, bool] = {}       # tag -> the model offers a reasoning mode

    # ── lifecycle ────────────────────────────────────────────────────────────
    def alive(self) -> bool:
        try:
            return requests.get(self.url + "/api/version", timeout=5).status_code == 200
        except requests.RequestException:
            return False

    def version(self) -> str | None:
        try:
            return requests.get(self.url + "/api/version", timeout=5).json().get("version")
        except Exception:
            return None

    def start(self) -> None:
        exe = shutil.which("ollama")
        if not exe:
            raise LLMError("ollama is not installed. Run `python -m skgap setup` (Linux) or install it from ollama.com.")
        env = dict(os.environ)
        env["OLLAMA_HOST"] = f"127.0.0.1:{self.port}"
        env["OLLAMA_NUM_PARALLEL"] = str(self.parallel)
        env["OLLAMA_MAX_LOADED_MODELS"] = "1"
        env["OLLAMA_KEEP_ALIVE"] = "30m"
        env.setdefault("OLLAMA_NOPRUNE", "1")      # do not delete partial downloads on restart
        if self.gpu is not None:
            env["CUDA_VISIBLE_DEVICES"] = str(self.gpu)
        log = subprocess.DEVNULL
        if self.log_dir:
            self.log_dir.mkdir(parents=True, exist_ok=True)
            log = open(self.log_dir / f"ollama_{self.port}.log", "ab")
        self.proc = subprocess.Popen([exe, "serve"], env=env, stdout=log, stderr=log)
        self.managed = True

    def ensure(self, wait: int = 90) -> None:
        if self.alive():
            return
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
        self.start()
        t0 = time.time()
        while time.time() - t0 < wait:
            if self.alive():
                return
            time.sleep(1)
        raise LLMError(f"ollama server on port {self.port} did not come up within {wait}s")

    def stop(self) -> None:
        if self.managed and self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()

    # ── models ───────────────────────────────────────────────────────────────
    def has(self, tag: str) -> bool:
        try:
            tags = requests.get(self.url + "/api/tags", timeout=20).json().get("models", [])
            return any(m.get("name") == tag or m.get("model") == tag for m in tags)
        except Exception:
            return False

    def pull(self, tag: str, progress: Callable[[str], None] | None = None) -> None:
        if self.has(tag):
            return
        last = ""
        for attempt in range(3):
            try:
                with requests.post(self.url + "/api/pull", json={"model": tag, "name": tag, "stream": True},
                                   stream=True, timeout=(30, 1800)) as r:
                    r.raise_for_status()
                    for line in r.iter_lines():
                        if not line:
                            continue
                        msg = json.loads(line)
                        if msg.get("error"):
                            raise LLMError(f"pull {tag}: {msg['error']}")
                        status = msg.get("status", "")
                        if progress and status != last and "pulling" not in status:
                            progress(f"  pull {tag}: {status}")
                        last = status
                if self.has(tag):
                    return
            except (requests.RequestException, json.JSONDecodeError) as exc:
                if attempt == 2:
                    raise LLMError(f"pull {tag} failed: {exc}") from exc
                time.sleep(10 * (attempt + 1))
                self.ensure()
        raise LLMError(f"pull {tag} did not complete")

    def describe(self, tag: str) -> dict:
        """What Ollama actually serves under this tag: digest, quantisation, size."""
        info: dict = {"tag": tag}
        try:
            show = requests.post(self.url + "/api/show", json={"model": tag, "name": tag}, timeout=60).json()
            d = show.get("details", {})
            info.update(quantization=d.get("quantization_level"), parameter_size=d.get("parameter_size"),
                        family=d.get("family"), format=d.get("format"), capabilities=show.get("capabilities"))
            if "thinking" in (show.get("capabilities") or []):
                info["thinking"] = "on" if THINK else "disabled"
            for m in requests.get(self.url + "/api/tags", timeout=20).json().get("models", []):
                if m.get("name") == tag or m.get("model") == tag:
                    info.update(digest=m.get("digest"), size_bytes=m.get("size"))
        except Exception as exc:
            info["describe_error"] = str(exc)[:200]
        return info

    def remove(self, tag: str) -> None:
        try:
            requests.post(self.url + "/api/generate", json={"model": tag, "keep_alive": 0}, timeout=60)
            requests.delete(self.url + "/api/delete", json={"model": tag, "name": tag}, timeout=60)
        except requests.RequestException:
            pass

    # ── inference ────────────────────────────────────────────────────────────
    def thinks(self, tag: str) -> bool:
        """Does the model offer a reasoning mode? Asked once per model."""
        if tag not in self._thinks:
            try:
                show = requests.post(self.url + "/api/show", json={"model": tag, "name": tag}, timeout=60).json()
                self._thinks[tag] = "thinking" in (show.get("capabilities") or [])
            except Exception:
                return False                     # not cached: ask again on the next request
        return self._thinks[tag]

    def chat(self, model: str, prompt: str, *, temperature: float, seed: int, max_tokens: int,
             fmt: dict | None = None, stop_when: Callable[[str], bool] | None = None) -> dict:
        body = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True,
            "keep_alive": "30m",
            "options": {"temperature": temperature, "seed": seed, "num_predict": max_tokens,
                        "num_ctx": NUM_CTX, "top_p": TOP_P},
        }
        if fmt is not None:
            body["format"] = fmt
        if self.thinks(model):
            body["think"] = THINK
        last_exc: Exception | None = None
        for attempt in range(3):
            t0 = time.time()
            try:
                return self._stream(body, stop_when, t0)
            except LLMError as exc:
                if "think rejected" not in str(exc) or "think" not in body:
                    raise
                del body["think"]                # this build of the model cannot switch reasoning
                self._thinks[model] = False
                last_exc = exc
            except (requests.RequestException, json.JSONDecodeError, OSError) as exc:
                last_exc = exc
                time.sleep(3 * (attempt + 1))
                try:
                    self.ensure()
                except LLMError:
                    pass
        raise LLMError(f"request failed after 3 attempts: {last_exc}")

    def _stream(self, body: dict, stop_when, t0: float) -> dict:
        parts: list[str] = []
        meta: dict = {}
        early = False
        with requests.post(self.url + "/api/chat", json=body, stream=True, timeout=(30, 600)) as r:
            if r.status_code >= 400:
                detail = r.text[:300]
                if r.status_code == 400 and "format" in body and "format" in detail.lower():
                    raise LLMError("structured output rejected: " + detail)
                if r.status_code == 400 and "think" in body and "think" in detail.lower():
                    raise LLMError("think rejected: " + detail)
                if r.status_code == 404:
                    raise LLMError("model not found: " + detail)
                r.raise_for_status()
            for line in r.iter_lines():
                if not line:
                    continue
                msg = json.loads(line)
                if msg.get("error"):
                    raise requests.RequestException(msg["error"])
                piece = msg.get("message", {}).get("content", "")
                if piece:
                    parts.append(piece)
                    if stop_when is not None and "`" in piece and stop_when("".join(parts)):
                        early = True
                        break
                if msg.get("done"):
                    meta = msg
                    break
        return {
            "text": "".join(parts),
            "tokens_out": meta.get("eval_count", len(parts)),
            "tokens_in": meta.get("prompt_eval_count"),
            "seconds": round(time.time() - t0, 2),
            "done_reason": "early_stop" if early else meta.get("done_reason"),
        }


# ── mock backend (pipeline tests only) ────────────────────────────────────────
MOCK_MODELS = ["mock:weak-1b", "mock:mid-3b", "mock:good-7b", "mock:strong-7b"]


class MockBackend:
    """
    Synthetic models with a built-in, known relationship between "knowledge" and
    behaviour, used to check that the analysis recovers what was planted.
    NOT a source of results.
    """
    backend = "mock"
    url = "mock://"

    def __init__(self, *_, **__):
        self.skill = {m: s for m, s in zip(MOCK_MODELS, (0.25, 0.5, 0.7, 0.9))}

    def ensure(self, *a, **k): pass
    def stop(self): pass
    def pull(self, *a, **k): pass
    def remove(self, *a, **k): pass
    def alive(self): return True
    def version(self): return "mock"
    def has(self, tag): return tag in self.skill

    def describe(self, tag):
        return {"tag": tag, "quantization": "none", "parameter_size": "mock", "digest": "mock", "synthetic": True}

    @staticmethod
    def _u(*parts) -> float:
        h = hashlib.sha256("|".join(map(str, parts)).encode()).digest()
        return int.from_bytes(h[:8], "big") / 2**64

    def chat(self, model, prompt, *, temperature, seed, max_tokens, fmt=None, stop_when=None, _job=None) -> dict:
        from .stimuli import CWES, TASK_BY_ID
        job = _job or {}
        skill = self.skill.get(model, 0.5)
        cwe_ids = list(CWES)
        kind = job.get("kind")
        if kind == "mcq":
            cwe_bias = 0.15 * (cwe_ids.index(job["cwe"]) % 3 - 1)
            ok = self._u(model, job["item"]) < min(0.97, max(0.2, skill + 0.15 + cwe_bias))
            ans = job["answer"] if ok else random.Random(job["id"] + model).choice([x for x in "ABCD" if x != job["answer"]])
            text = json.dumps({"answer": ans})
        elif kind == "detect":
            knows = self._u(model, job["task"], "recog") < skill
            truth = "VULNERABLE" if job["variant"] == "insecure" else "SAFE"
            verdict = truth if knows else ("VULNERABLE" if self._u(model, job["id"]) < 0.6 else "SAFE")
            text = json.dumps({"verdict": verdict, "weakness": CWES[job["cwe"]].name if verdict == "VULNERABLE" else "none"})
        elif kind == "explain":
            c = CWES[job["cwe"]]
            text = (f"{c.name} happens when user input is used directly. Use parameterised, escaped, canonical, "
                    f"bounded or data-only handling, and environment variables for secrets." if skill > 0.4 else "It is a bug.")
        else:
            task = TASK_BY_ID[job["task"]]
            knows = self._u(model, job["task"], "recog") < skill
            p_vuln = 0.75 - 0.35 * skill - (0.25 if knows else 0.0)
            cond = job.get("condition", "baseline")
            p_vuln -= {"baseline": 0, "reminder": 0.10 + (0.12 if knows else 0), "ctx_irrelevant": 0.02,
                       "rag_dense": 0.12, "rag_hybrid": 0.15, "rag_oracle": 0.25}.get(cond, 0.2)
            u = self._u(model, job.get("id", prompt), seed)
            if self._u(model, job.get("id", prompt), seed, "broken") < 0.06 + 0.10 * (1 - skill):
                body = "def broken(:\n    pass\n" if task.lang == "python" else "int main( {\n"
            else:
                body = task.ref_insecure if u < max(0.03, p_vuln) else task.ref_secure
            text = f"Here is the code:\n\n```{task.lang}\n{body}```\n\nThis implements the request."
        return {"text": text, "tokens_out": len(text) // 4, "tokens_in": len(prompt) // 4, "seconds": 0.0,
                "done_reason": "stop"}


def install_ollama(progress=print) -> None:
    """Linux only: install the Ollama binary (used on Kaggle and Colab)."""
    if shutil.which("ollama"):
        progress("ollama already installed")
        return
    if os.name != "posix":
        raise LLMError("Automatic install is Linux-only. Install Ollama from https://ollama.com/download")
    subprocess.run("apt-get install -y -qq zstd pciutils >/dev/null 2>&1 || true", shell=True)
    r = subprocess.run("curl -fsSL https://ollama.com/install.sh | sh", shell=True, capture_output=True, text=True)
    if not shutil.which("ollama"):
        raise LLMError("ollama install failed:\n" + (r.stdout + r.stderr)[-800:])
    progress("ollama installed")
