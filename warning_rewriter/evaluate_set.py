"""
Evaluate the pipeline on a labelled set (default: the 100-case testing set).

    python evaluate_set.py                                  # ../testing_set/input + ../testing_set/validation_expected_results_100.csv
    python evaluate_set.py --inputs D --csv F               # other locations
    python evaluate_set.py --detector mypkg.mymodel:my_fn   # YOUR detector (the real test)
    python evaluate_set.py --llm 10 --model gemma3:4b       # also polish 10 final warnings with the local model

--detector
  stub (default)   regex placeholder. Gives a rough, honest score; not your model.
  csv              reads the answer key itself -> always ~100%. Only checks the plumbing
                   (scoring, first_alert, warning text), NOT detection quality.
  module:function  your detector: fn(conversation_prefix) -> (set_of_RF_codes, scam_type)

Reports: verdict / type / first_alert / score accuracy, a verdict confusion matrix
(false alarms vs missed scams), red-flag precision/recall (which flags your detector gets
wrong), style problems in the warnings, and the mismatching cases. Predictions are written
to --out in the same CSV format as the answer key. Nothing else is stored.
"""
from __future__ import annotations

import argparse, csv, importlib, json, re, sys, time
from collections import Counter
from pathlib import Path

from scam_warnings import analyze, load_conversation, style_problems
from llm_rewrite import DEFAULT_MODEL

HERE = Path(__file__).resolve().parent
DEFAULT_INPUTS = HERE.parent / "testing_set" / "input"
DEFAULT_CSV = HERE.parent / "testing_set" / "validation_expected_results_100.csv"
VERDICTS = ["SAFE", "SUSPICIOUS", "SCAM"]


def parse_first_alert(s):
    s = (s or "").strip()
    if not s:
        return None
    m = re.match(r"^(\d+)\s*[-–:]\s*(\d+)$", s)          # tolerate an accepted window like "5-7"
    return (int(m.group(1)), int(m.group(2))) if m else (int(float(s)),) * 2


def load_expected(path: Path) -> dict:
    out = {}
    with open(path, encoding="utf-8-sig", newline="") as fh:
        for r in csv.DictReader(fh):
            r = {(k or "").strip().lower(): (v or "").strip() for k, v in r.items()}
            out[r["id"]] = {
                "verdict": r.get("verdict", ""), "scam_type": r.get("scam_type") or "NONE",
                "score": int(r["risk_score"]) if r.get("risk_score") else None,
                "first": parse_first_alert(r.get("first_alert")),
                "flags": set(filter(None, r.get("red_flags", "").split(";"))),
            }
    return out


def pick_detector(spec: str, csv_path: Path):
    if spec == "stub":
        from run_validation import stub_detector
        return stub_detector, "regex stub (placeholder, not your model)"
    if spec == "csv":
        from csv_detector import CsvDetector
        return CsvDetector(csv_path), "answer-key CSV (circular: plumbing test only)"
    mod, _, fn = spec.partition(":")
    return getattr(importlib.import_module(mod), fn), f"your detector {spec}"


def first_ok(pred, exp, window):
    if exp is None or pred is None:
        return exp is None and pred is None
    return exp[0] - window <= pred <= exp[1] + window


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", default=str(DEFAULT_INPUTS))
    ap.add_argument("--csv", default=str(DEFAULT_CSV))
    ap.add_argument("--detector", default="stub")
    ap.add_argument("--out", default="evaluation_results.csv")
    ap.add_argument("--window", type=int, default=1, help="extra tolerance (messages) for the 'within window' first_alert metric")
    ap.add_argument("--all", action="store_true", help="list every mismatching case (default: first 25)")
    ap.add_argument("--llm", type=int, default=0, metavar="N", help="polish the final warning of N cases with the local LLM")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    a = ap.parse_args()

    inputs, csv_path = Path(a.inputs), Path(a.csv)
    for p, what in ((inputs, "inputs folder"), (csv_path, "expected-results CSV")):
        if not p.exists():
            sys.exit(f"{what} not found: {p}\n(run from the scripts folder or pass --inputs / --csv)")
    expected = load_expected(csv_path)
    detector, dname = pick_detector(a.detector, csv_path)
    files = sorted(inputs.glob("*.json"))
    print(f"detector : {dname}\ninputs   : {inputs}  ({len(files)} json files)\nexpected : {csv_path}  ({len(expected)} rows)", flush=True)

    rows, errors, no_label = [], [], []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            conv = load_conversation(data)
            cid = conv.id or f.stem
            if cid not in expected:
                no_label.append(cid); continue
            r = analyze(conv, detector)
            rows.append((cid, expected[cid], r))
        except Exception as e:                                       # keep going; report at the end
            errors.append((f.name, f"{type(e).__name__}: {e}"))

    n = len(rows)
    if not n:
        sys.exit("No case could be evaluated.\n" + "\n".join(f"  {a_}: {b}" for a_, b in errors[:10]))

    v_ok = t_ok = s_ok = fa_ok = fa_win = 0
    conf, score_err, style_bad = Counter(), [], 0
    tp, fp, fn = Counter(), Counter(), Counter()
    bad_cases = []
    for cid, e, r in rows:
        pv, pt, ps, pf = r["verdict"], r["scam_type"], r["risk_score"], r["first_alert"]
        v_ok += pv == e["verdict"]; t_ok += pt == e["scam_type"]
        s_ok += ps == e["score"]
        if e["score"] is not None: score_err.append(abs(ps - e["score"]))
        fa_ok += first_ok(pf, e["first"], 0); fa_win += first_ok(pf, e["first"], a.window)
        conf[(e["verdict"], pv)] += 1
        for fl in r["red_flags"]: (tp if fl in e["flags"] else fp)[fl] += 1
        for fl in e["flags"] - set(r["red_flags"]): fn[fl] += 1
        style_bad += sum(bool(style_problems(s["warning"].text)) for s in r["timeline"])
        if pv != e["verdict"] or pt != e["scam_type"] or not first_ok(pf, e["first"], a.window):
            bad_cases.append((cid, e, r))

    pct = lambda k: f"{k}/{n} ({100 * k / n:.0f}%)"
    print(f"\n=== RESULTS on {n} labelled cases")
    print(f"verdict correct            : {pct(v_ok)}")
    print(f"scam type correct          : {pct(t_ok)}")
    print(f"first_alert exact          : {pct(fa_ok)}   (within ±{a.window}: {pct(fa_win)})")
    print(f"risk score exact           : {pct(s_ok)}   (mean abs error {sum(score_err) / max(1, len(score_err)):.1f} points)")
    over = sum(c for (ev, pv), c in conf.items() if ev == "SAFE" and pv != "SAFE")
    miss = sum(c for (ev, pv), c in conf.items() if ev != "SAFE" and pv == "SAFE")
    print(f"false alarms (SAFE -> flagged): {over}    missed scams (flagged -> SAFE): {miss}")
    print("\nverdict confusion (rows = expected, cols = predicted)")
    print("              " + "".join(f"{v:>12}" for v in VERDICTS))
    for ev in VERDICTS:
        print(f"{ev:<14}" + "".join(f"{conf[(ev, pv)]:>12}" for pv in VERDICTS))

    T, P, R = sum(tp.values()), sum(tp.values()) + sum(fp.values()), sum(tp.values()) + sum(fn.values())
    prec, rec = T / P if P else 0, T / R if R else 0
    print(f"\nred flags: precision {prec:.2f}  recall {rec:.2f}  F1 {2 * prec * rec / (prec + rec) if prec + rec else 0:.2f}")
    worst = sorted(set(tp) | set(fp) | set(fn), key=lambda k: -(fn[k] + fp[k]))[:8]
    print("  flag                    caught  missed  extra")
    for k in worst:
        print(f"  {k:<22}{tp[k]:>7}{fn[k]:>8}{fp[k]:>7}")
    print(f"\nwarnings breaking the style rules: {style_bad}")

    shown = bad_cases if a.all else bad_cases[:25]
    print(f"\n=== MISMATCHES (verdict / type / first_alert): {len(bad_cases)}" + ("" if a.all or len(bad_cases) <= 25 else "  (showing 25, use --all)"))
    for cid, e, r in shown:
        miss_f, extra_f = sorted(e["flags"] - set(r["red_flags"])), sorted(set(r["red_flags"]) - e["flags"])
        print(f"{cid}: expected {e['verdict']}/{e['scam_type']}/fa={e['first']}  got {r['verdict']}/{r['scam_type']}/fa={r['first_alert']}"
              f"\n      missed flags: {miss_f or '-'}   extra flags: {extra_f or '-'}")

    with open(a.out, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh); w.writerow(["id", "verdict", "scam_type", "risk_score", "first_alert", "red_flags"])
        for cid, _, r in rows:
            w.writerow([cid, r["verdict"], r["scam_type"], r["risk_score"], r["first_alert"] or "", ";".join(r["red_flags"])])
    print(f"\npredictions written to {a.out}")
    if no_label: print(f"{len(no_label)} json file(s) had no row in the CSV (skipped): {no_label[:5]}")
    if errors:
        print(f"{len(errors)} file(s) failed to process:")
        for name, err in errors[:5]: print(f"  {name}: {err}")

    if a.llm:
        from llm_rewrite import check_ollama, ollama_generate, polish_verbose
        status = check_ollama(a.model)
        print(f"\n=== Ollama pre-flight ({a.model})\n{status['message']}")
        if not status["ok"]:
            print("Skipping the LLM polish run.")
            return
        gen, done, acc, t0 = ollama_generate(a.model), 0, 0, time.time()
        print(f"\n=== LLM polish ({a.model}) on up to {a.llm} final warnings")
        for cid, _, r in rows:
            if r["warning"] is None: continue
            info = polish_verbose(r["warning"], gen, retries=0); done += 1; acc += info["source"] == "llm"
            if done <= 3 or info["source"] != "llm":
                print(f"[{cid}] ({info['source']}) {info['text']}" + (f"\n     rejected: {info['error'] or '; '.join(info['problems'])}" if info["source"] != "llm" else ""))
            if done >= a.llm: break
        print(f"accepted {acc}/{done}, avg {(time.time() - t0) / max(1, done):.1f}s per warning")


if __name__ == "__main__":
    main()
