"""
Bake-off: which local model rewrites best on YOUR machine?

    python compare_models.py qwen3:4b gemma3:4b qwen2.5:3b [--dir path/to/validation_set]

For each model it rewrites the final warning of every validation scenario and reports:
  accepted = rewrites that passed the validator (the rest fell back to the template)
  avg_s    = average seconds per warning
Then READ the printed Romanian yourself: the validator checks facts/format, not fluency.
Models must already be pulled (`ollama pull <tag>`).
"""
import glob, os, sys, time
from scam_warnings import analyze, load_conversation
from llm_rewrite import ollama_generate, polish_verbose
from csv_detector import CsvDetector, default_validation_dir


def bench(folder, models, make_gen=ollama_generate, detector=None, show=True):
    detector = detector or CsvDetector()      # official CSV; pass your own detector later
    warnings = []
    for path in sorted(glob.glob(os.path.join(folder, "V*.json"))):
        w = analyze(load_conversation(path), detector)["warning"]
        if w:
            warnings.append((os.path.basename(path)[:-5], w))
    rows = []
    for model in models:
        gen, ok, t0 = make_gen(model), 0, time.time()
        if show: print(f"\n##### {model}")
        for vid, w in warnings:
            r = polish_verbose(w, gen, retries=0)
            ok += r["source"] == "llm"
            if show:
                print(f"[{vid}] ({r['source']})\n   {r['text']}")
                if r["source"] == "template":
                    why = r["error"] or "; ".join(r["problems"])
                    print(f"   REJECTED because: {why}")
                    print(f"   raw model output: {(r['raw'] or '')[:300]!r}")
        rows.append((model, ok, len(warnings), (time.time() - t0) / len(warnings)))
    print("\nmodel".ljust(24), "accepted".ljust(10), "avg_s")
    for m, ok, n, avg in rows:
        print(m.ljust(23), f"{ok}/{n}".ljust(10), f"{avg:.1f}")
    return rows


if __name__ == "__main__":
    argv = sys.argv[1:]
    folder = default_validation_dir()
    if "--dir" in argv:
        i = argv.index("--dir"); folder = argv[i + 1]; del argv[i:i + 2]
    bench(folder, argv)