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
    ollama pull qwen2.5:3b
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


def ollama_generate(model: str = "qwen2.5:3b", host: str = "http://localhost:11434",
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