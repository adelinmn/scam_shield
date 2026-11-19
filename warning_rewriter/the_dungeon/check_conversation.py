"""
Check one or more conversation JSON files (same format as validation_set/Vxx.json).

    python check_conversation.py examples/E01.json
    python check_conversation.py examples/E01.json --llm --model gemma3:4b
    python check_conversation.py my.json --detector mypkg.mymodel:my_detector

What it does:
  1. validates the JSON format (required keys, message numbering, sender values)
  2. runs the full pipeline (detector -> score -> first_alert -> warnings [-> LLM polish])
  3. checks every warning against the brief's style rules (<=3 sentences, no jargon)
  4. if the JSON has an optional "expected" block (verdict / scam_type / first_alert /
     risk_score), compares the result against it. Exit code is 1 on any failure.

--detector  auto (default) | csv | stub | module:function
  auto: uses the official CSV when the id is in it (V01-V11), otherwise the regex stub.
  The regex stub is only a rough placeholder: for new messages, results are only as good
  as its few rules. Plug in your real detector with module:function.
"""
import argparse, importlib, json, sys
from pathlib import Path

from scam_warnings import style_problems
from writer import ScamShieldWriter

CHANNELS = {"sms", "whatsapp", "email", "chat", "call_transcript"}


def validate_format(d: dict) -> list[str]:
    p = []
    if not isinstance(d, dict):
        return ["top level must be an object"]
    if not d.get("id"):
        p.append('missing "id"')
    if d.get("channel") not in CHANNELS:
        p.append(f'"channel" should be one of {sorted(CHANNELS)} (got {d.get("channel")!r})')
    snd = d.get("sender")
    if not isinstance(snd, dict) or not {"name", "address", "known_contact"} <= set(snd):
        p.append('"sender" needs name, address, known_contact')
    msgs = d.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return p + ['"messages" must be a non-empty list']
    for i, m in enumerate(msgs, 1):
        if m.get("n") != i:
            p.append(f"message #{i}: n should be {i} (got {m.get('n')!r})")
        if m.get("from") not in ("sender", "reader"):
            p.append(f'message #{i}: "from" must be "sender" or "reader"')
        if not str(m.get("text", "")).strip():
            p.append(f"message #{i}: empty text")
    if msgs[0].get("from") == "reader":
        p.append("message 1 is from the reader (threads normally start with the sender)")
    return p


def pick_detector(spec: str, conv_id: str):
    if spec in ("auto", "csv"):
        try:
            from csv_detector import CsvDetector
            det = CsvDetector()
            if conv_id in det.rows:
                return det, "official CSV"
            if spec == "csv":
                sys.exit(f'id {conv_id!r} is not in the CSV (only V01-V11). Use --detector stub or your own.')
        except FileNotFoundError as e:
            if spec == "csv":
                sys.exit(str(e))
    if spec in ("auto", "stub"):
        from run_validation import stub_detector
        return stub_detector, "regex stub (rough placeholder)"
    mod, _, fn = spec.partition(":")
    return getattr(importlib.import_module(mod), fn), f"your detector {spec}"


def check(path: str, args) -> bool:
    print(f"\n=== {path}", flush=True)
    if not Path(path).is_file():
        print(f"  NOT FOUND: {path!r} (run from the scripts folder, one command at a time; "
              f"current folder: {Path.cwd()})")
        return False
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"  NOT VALID JSON: {e}")
        return False
    problems = validate_format(data)
    for q in problems:
        print("  FORMAT:", q)
    if problems:
        return False

    detector, dname = pick_detector(args.detector, str(data["id"]))
    print(f"  detector: {dname}")
    r = ScamShieldWriter(detector, use_llm=args.llm, model=args.model, polish_all=True).run(data)

    print(f"  verdict={r['verdict']}  type={r['scam_type']}  score={r['risk_score']}  first_alert={r['first_alert']}")
    print(f"  flags: {', '.join(r['red_flags']) or '-'}")
    ok = True
    for step in r["timeline"]:
        sp = style_problems(step["text"])
        ok &= not sp
        print(f"  [msg {step['message']}, score {step['risk_score']}, {step['source']}] {step['text']}" +
              (f"   !! STYLE: {sp}" if sp else ""))
    if not r["timeline"]:
        print("  (no warning: message judged safe)")

    exp = data.get("expected")
    if exp:
        for k in ("verdict", "scam_type", "first_alert", "risk_score"):
            if k in exp and exp[k] != r[k]:
                ok = False
                print(f"  EXPECTED {k}={exp[k]!r} but got {r[k]!r}")
        if ok:
            print("  matches the expected block")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--detector", default="auto")
    ap.add_argument("--llm", action="store_true", help="polish warnings with the local model")
    ap.add_argument("--model", default="gemma3:4b")
    a, extra = ap.parse_known_args()
    if extra:
        sys.exit(f"Unrecognised arguments: {extra}\nRun ONE command per line, e.g.\n"
                 f"  python check_conversation.py examples/E01.json")
    print(f"check_conversation: {len(a.files)} file(s), detector={a.detector}, llm={a.llm}", flush=True)
    results = [check(f, a) for f in a.files]
    print("\nALL CHECKS PASSED" if all(results) else "\nCHECKS FAILED")
    sys.exit(0 if all(results) else 1)