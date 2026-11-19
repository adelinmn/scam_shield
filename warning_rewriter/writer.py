"""
Combined A + C entry point. This is the only file your app needs to call.

    from writer import ScamShieldWriter
    w = ScamShieldWriter(detector=my_detector, use_llm=True)   # use_llm=False -> pure Option A
    result = w.run("validation_set/V04.json")                   # path or already-loaded dict

With use_llm=True the constructor checks that Ollama is running and that the model is
pulled (check_ollama), prints how to install them if not, and then falls back to the
template warnings instead of failing. `w.llm_status` holds that check. Pass
verify_llm=False to skip the check (e.g. in tests).

`detector(conversation_prefix) -> (set_of_RF_codes, scam_type)` is YOUR classifier
(wrap your MiniLM model, optionally with scam_warnings.combine(model, rules)).

Result keys: verdict, scam_type, risk_score, red_flags, first_alert, ui_label,
             warning_text, warning_source ("llm" | "template"), timeline[]
Nothing is logged or stored.
"""
from __future__ import annotations

import sys
from typing import Optional

from scam_warnings import Conversation, Detector, analyze, load_conversation
from llm_rewrite import DEFAULT_MODEL, check_ollama, ollama_generate, polish


class ScamShieldWriter:
    def __init__(self, detector: Detector, use_llm: bool = True,
                 model: str = DEFAULT_MODEL, host: str = "http://localhost:11434", timeout: float = 20.0,
                 polish_all: bool = False, verify_llm: bool = True):
        # polish_all=False: only the FINAL warning goes through the LLM (fewer calls, faster).
        # polish_all=True : every step of the timeline is polished.
        self.detector = detector
        self.polish_all = polish_all
        self.llm_status = None
        self.generate = None
        if use_llm:
            self.llm_status = check_ollama(model, host) if verify_llm else {"ok": True, "message": ""}
            if self.llm_status["ok"]:
                self.generate = ollama_generate(model, host, timeout)
            else:
                print(self.llm_status["message"], file=sys.stderr)

    def run(self, conversation) -> dict:
        conv = conversation if isinstance(conversation, Conversation) else load_conversation(conversation)
        r = analyze(conv, self.detector)           # A: score, verdict, first_alert, template warnings

        timeline = []
        n = len(r["timeline"])
        for k, step in enumerate(r["timeline"]):   # C: polish; falls back to the template
            use = self.generate if (self.polish_all or k == n - 1) else None
            text, src = polish(step["warning"], use)
            timeline.append({"message": step["message"], "risk_score": step["risk_score"],
                             "verdict": step["verdict"], "text": text, "source": src})

        last = timeline[-1] if timeline else None
        return {
            "verdict": r["verdict"], "scam_type": r["scam_type"], "risk_score": r["risk_score"],
            "red_flags": r["red_flags"], "first_alert": r["first_alert"], "ui_label": r["ui_label"],
            "warning_text": last["text"] if last else None,
            "warning_source": last["source"] if last else None,
            "timeline": timeline,
        }


if __name__ == "__main__":
    # demo:  python writer.py V04 [--llm] [--stub]      (V04, V04.json or a full path)
    import sys, json
    from csv_detector import CsvDetector, resolve_conversation_path
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--stub" in sys.argv:
        from run_validation import stub_detector as detector
    else:
        detector = CsvDetector()                  # official answer-key CSV; swap for your model later
    out = ScamShieldWriter(detector, use_llm="--llm" in sys.argv).run(resolve_conversation_path(args[0]))
    print(json.dumps(out, ensure_ascii=False, indent=2))
