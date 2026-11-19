"""
Option C: optional LLM polish on top of Option A.

Design rules:
  * The LLM NEVER sees the raw message (so a scammer can't prompt-inject it). It only
    receives the already-built template warning.
  * Verdict, type, score and facts stay decided by the pipeline. The LLM only rephrases.
  * Every output is validated; on ANY failure (timeout, bad style, new number/link,
    lost phone/site, wrong tone) we return the template text. Safe by construction.
  * Nothing is logged.

Works with a local Ollama server (default http://localhost:11434), e.g.:
    ollama pull qwen3:0.6b
"""
from __future__ import annotations

import json
import re
import urllib.request
from typing import Callable, Optional

from scam_warnings import Warning, style_problems

SYSTEM = (
    "Ești un asistent care rescrie avertismente anti-țepe pentru persoane în vârstă, în limba română. "
    "Reguli stricte: folosește forma de politețe (dumneavoastră); cel mult 3 propoziții scurte; "
    "fără cuvinte tehnice (spune „adresă de internet falsă”, nu „phishing” sau „link”); "
    "păstrează EXACT toate numerele, sumele, numele și adresele din text; nu adăuga numere de telefon, "
    "adrese sau fapte noi; o singură acțiune clară; ton calm, fără reproșuri. "
    "Răspunde DOAR cu avertismentul rescris, fără ghilimele sau explicații."
)
EXAMPLE_IN = ("Atenție, pare o țeapă! Mesajul se dă drept Banca Dunărea, dar folosește o adresă de internet falsă. "
              "Nu apăsați pe adresă; sunați la numărul de pe spatele cardului.")
EXAMPLE_OUT = ("Atenție, pare o țeapă! Mesajul spune că vine de la banca dumneavoastră, dar adresa de internet este falsă. "
               "Nu apăsați pe ea; sunați la numărul de pe spatele cardului.")

Generate = Callable[[list[dict]], str]

# The one model used by the whole rewriter unless a caller explicitly overrides it.
# writer.py and evaluate_set.py import this, so the default cannot drift again.
DEFAULT_MODEL = "qwen3:0.6b"


def check_ollama(model: str = DEFAULT_MODEL, host: str = "http://localhost:11434",
                 timeout: float = 3.0) -> dict:
    """Pre-flight check: is Ollama answering, and is `model` pulled?

    Never raises. A missing Ollama is not an error — the rewriter falls back to its
    template warnings — but the caller should tell the user how to install it.

    Returns {"ok", "running", "has_model", "models", "error", "message"}.
    """
    info = {"ok": False, "running": False, "has_model": False, "models": [], "error": None}
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=timeout) as r:
            payload = json.loads(r.read())
    except Exception as e:                        # not installed, not running, or wrong port
        info["error"] = f"{type(e).__name__}: {e}"
        info["message"] = (
            f"Ollama is NOT reachable at {host} ({info['error']}).\n"
            f"  1. Install Ollama:   https://ollama.com/download\n"
            f"  2. Start it:         ollama serve\n"
            f"  3. Download the model: ollama pull {model}\n"
            f"Continuing WITHOUT AI polish: warnings come from the built-in templates."
        )
        return info

    info["running"] = True
    info["models"] = [m.get("name", "") for m in payload.get("models", []) if m.get("name")]

    def _same(name: str) -> bool:                 # 'gemma3:4b' exact; 'gemma3' also matches 'gemma3:4b'
        return name == model or (":" not in model and name.split(":")[0] == model)

    info["has_model"] = any(_same(n) for n in info["models"])
    info["ok"] = info["has_model"]
    if info["ok"]:
        info["message"] = f"Ollama ready at {host} with model {model}."
    else:
        have = ("Models found: " + ", ".join(info["models"])) if info["models"] else "You have no models yet."
        info["message"] = (
            f"Ollama is running at {host}, but the model '{model}' is NOT downloaded.\n"
            f"  Run:  ollama pull {model}\n"
            f"  {have}\n"
            f"Continuing WITHOUT AI polish: warnings come from the built-in templates."
        )
    return info


def ollama_generate(model: str = DEFAULT_MODEL, host: str = "http://localhost:11434",
                    timeout: float = 20.0) -> Generate:
    def _gen(messages: list[dict]) -> str:
        body = json.dumps({"model": model, "messages": messages, "stream": False, "think": False,
                           "options": {"temperature": 0.3, "num_predict": 250}}).encode()
        req = urllib.request.Request(f"{host}/api/chat", body, {"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())["message"]["content"]
    return _gen


_NUM = re.compile(r"\d[\d.,\s]*\d|\d")
_SITE = re.compile(r"\b[\w-]+(?:\.[\w-]+)+\b")
_INFORMAL = re.compile(r"\b(tu|tău|ta|tale|ți|te)\b", re.I)


def _facts(text: str) -> set[str]:
    nums = {re.sub(r"\s+", " ", m.strip()) for m in _NUM.findall(text)}
    sites = set(_SITE.findall(text))
    return {x.rstrip(".,") for x in nums | sites}


def validate(candidate: str, original: Warning) -> list[str]:
    """Return a list of problems; empty list means the rewrite is acceptable."""
    problems = style_problems(candidate)
    if "\n" in candidate.strip():
        problems.append("multi-line")
    if _INFORMAL.search(candidate):
        problems.append("informal address")
    allowed = _facts(original.text)
    extra = _facts(candidate) - allowed
    if extra:
        problems.append(f"new facts: {sorted(extra)}")
    for k in original.keep:                       # phones, official sites, amounts, names
        if k not in candidate:
            problems.append(f"lost fact: {k}")
    low = candidate.lower()
    if original.verdict == "SCAM" and not ("țeap" in low or "înșel" in low or "teap" in low):
        problems.append("SCAM tone missing")
    if original.verdict == "SUSPICIOUS" and ("pare o țeapă" in low or "este o țeapă" in low):
        problems.append("over-alarming for SUSPICIOUS")
    return problems


_THINK = re.compile(r"<think>.*?</think>", re.S | re.I)


def clean(raw: str) -> str:
    """Strip reasoning blocks (Qwen3/DeepSeek-style), quotes and whitespace."""
    out = _THINK.sub("", raw or "")
    out = re.sub(r"</?think>", "", out, flags=re.I)
    return out.strip().strip('"„”')


def build_messages(warning: Warning) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": f"Rescrie:\n{EXAMPLE_IN}"},
        {"role": "assistant", "content": EXAMPLE_OUT},
        {"role": "user", "content": f"Rescrie:\n{warning.text}"},
    ]


def polish_verbose(warning: Warning, generate: Optional[Generate] = None, retries: int = 1) -> dict:
    """Like polish() but also reports WHY a rewrite was rejected.
    Returns {text, source, raw, problems, error}."""
    info = {"text": warning.text, "source": "template", "raw": None, "problems": [], "error": None}
    if generate is None:
        return info
    for _ in range(retries + 1):
        try:
            raw = generate(build_messages(warning))
        except Exception as e:                    # server down / timeout -> template
            info["error"] = f"{type(e).__name__}: {e}"
            break
        out = clean(raw)
        problems = validate(out, warning) if out else ["empty output"]
        info["raw"], info["problems"] = raw, problems
        if not problems:
            info.update(text=out, source="llm")
            return info
    return info


def polish(warning: Warning, generate: Optional[Generate] = None, retries: int = 1) -> tuple[str, str]:
    """Return (text, source) where source is 'llm' or 'template'."""
    r = polish_verbose(warning, generate, retries)
    return r["text"], r["source"]