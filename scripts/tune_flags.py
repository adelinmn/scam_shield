"""Measure Romanian flag hypotheses and select thresholds using reviewed labels."""

import argparse
import csv
from collections.abc import Mapping, Sequence
from pathlib import Path

from scam_detector.cli import DEFAULT_OUTPUT, read_scenario_json, scenario_files, write_json
from scam_detector.conversation import Conversation, parse_scenario
from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.flag_profiles import FlagProfile, load_flag_profile
from scam_detector.model import FlagClassifier, ModelSetupError
from scam_detector.model_assets import PROJECT_ROOT


def read_labels(path: Path, split: str | None) -> tuple[dict[str, set[str]], str]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or ())
        reviewed = {"id", "split", "annotator_reviewed", "expected_red_flags"} <= fields
        if reviewed:
            split = split or "dev"
            flag_field = "expected_red_flags"
        elif {"id", "red_flags"} <= fields and "annotator_reviewed" not in fields:
            if split is not None:
                raise ValueError("The official labels have no split column.")
            split = "official"
            flag_field = "red_flags"
        else:
            raise ValueError("Use official red_flags or reviewed expected_red_flags labels.")

        labels = {}
        for row in reader:
            if reviewed:
                if row["split"] != split or (row["annotator_reviewed"] or "").strip().upper() != "YES":
                    continue
            case_id = (row["id"] or "").strip()
            if not case_id or case_id in labels or row[flag_field] is None:
                raise ValueError(f"Missing or duplicate label at CSV line {reader.line_num}.")
            flags = {flag.strip() for flag in row[flag_field].split(";") if flag.strip()}
            if unknown := flags - FLAG_DEFINITIONS.keys():
                raise ValueError(f"Unknown flags for {case_id}: {', '.join(sorted(unknown))}")
            labels[case_id] = flags
    if not labels:
        raise ValueError(f"No reviewed flag labels found for split {split!r}.")
    return labels, split


def load_labeled_cases(files: Sequence[Path], labels: Mapping[str, set[str]]) -> list[Conversation]:
    cases = {}
    for path in files:
        data = read_scenario_json(path)
        case_id = data.get("id") if isinstance(data, dict) else None
        if not isinstance(case_id, str) or case_id not in labels:
            continue
        if case_id in cases:
            raise ValueError(f"Duplicate scenario for {case_id}.")
        cases[case_id] = parse_scenario(data)
    if missing := labels.keys() - cases.keys():
        raise ValueError(f"Missing input for labeled scenarios: {', '.join(sorted(missing))}")
    return [cases[case_id] for case_id in sorted(cases)]


def collect_scores(
    cases: Sequence[Conversation], classifier: FlagClassifier, profile: FlagProfile
) -> dict[str, list[dict[str, float | None]]]:
    # A scenario's flag is present if any sender turn passes its threshold.
    by_flag = {flag: [{} for _ in phrases] for flag, phrases in profile.hypotheses.items()}
    for case in cases:
        turns = [
            classifier.score_flag_hypotheses([message.text])[0]
            for message in case.messages
            if message.role == "sender"
        ]
        for flag, columns in by_flag.items():
            for index, column in enumerate(columns):
                column[case.id] = max((turn[flag][index] for turn in turns), default=None)
    return by_flag


def f1_score(tp: int, fp: int, fn: int) -> float:
    denominator = 2 * tp + fp + fn
    return 2 * tp / denominator if denominator else 0.0


def measure(
    scores: Mapping[str, float | None], expected: set[str], threshold: float
) -> dict:
    predicted = {case for case, score in scores.items() if score is not None and score >= threshold}
    tp, fp, fn = len(predicted & expected), len(predicted - expected), len(expected - predicted)
    return {
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": len(scores) - tp - fp - fn,
        "precision": tp / len(predicted) if predicted else 0.0,
        "recall": tp / len(expected) if expected else 0.0,
        "f1": f1_score(tp, fp, fn),
        "false_positives": sorted(predicted - expected),
        "false_negatives": sorted(expected - predicted),
    }


def fit_threshold(
    scores: Mapping[str, float | None], expected: set[str], current: float
) -> dict:
    levels = sorted({score for score in scores.values() if score is not None})
    # A midpoint keeps the same decisions as the upper score, with room for rounding.
    candidates = {0.0, 1.0, current} | {(lo + hi) / 2 for lo, hi in zip(levels, levels[1:])}
    measured = (measure(scores, expected, threshold) for threshold in candidates)
    return max(
        measured,
        key=lambda row: (
            row["f1"],
            row["precision"],
            -abs(row["threshold"] - current),
            row["threshold"],
        ),
    )


def evaluate(
    profile: FlagProfile,
    scores: dict[str, list[dict[str, float | None]]],
    labels: Mapping[str, set[str]],
    *,
    min_support: int,
    fit: bool,
) -> tuple[dict, FlagProfile]:
    report = {}
    thresholds = {}
    for flag, columns in scores.items():
        expected = {case for case, flags in labels.items() if flag in flags}
        pooled = {
            case: max((column[case] for column in columns if column[case] is not None), default=None)
            for case in labels
        }
        current = measure(pooled, expected, profile.thresholds[flag])
        has_support = min(len(expected), len(labels) - len(expected)) >= min_support
        recommended = current
        status = "evaluated"
        if fit:
            status = "insufficient support"
            if has_support:
                recommended = fit_threshold(pooled, expected, current["threshold"])
                status = "fitted"
        thresholds[flag] = recommended["threshold"]
        report[flag] = {
            "positives": len(expected),
            "negatives": len(labels) - len(expected),
            "status": status,
            "current": current,
            "recommended": recommended,
            "hypotheses": [
                {"text": phrase, **measure(column, expected, current["threshold"])}
                for phrase, column in zip(profile.hypotheses[flag], columns, strict=True)
            ],
        }
    micro_f1 = {
        name: f1_score(*(sum(row[name][count] for row in report.values()) for count in ("tp", "fp", "fn")))
        for name in ("current", "recommended")
    }
    return {"micro_f1": micro_f1, "flags": report}, FlagProfile(profile.hypotheses, thresholds)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=PROJECT_ROOT / "validation_set")
    parser.add_argument("--labels", type=Path, default=PROJECT_ROOT / "validation_expected_results.csv")
    parser.add_argument("--profile", type=Path, help="JSON hypotheses and starting thresholds")
    parser.add_argument("--output", type=Path, help="directory for the report and recommended profile")
    parser.add_argument("--split", choices=("dev", "holdout"), help="reviewed annotation split")
    parser.add_argument(
        "--min-support", type=int, default=3, help="required positives and negatives per flag"
    )
    parser.add_argument("--evaluate-only", action="store_true", help="measure the supplied thresholds")
    args = parser.parse_args()
    if args.min_support < 1:
        parser.error("--min-support must be at least 1.")
    try:
        labels, split = read_labels(args.labels, args.split)
        fit = not args.evaluate_only and split != "holdout"
        output = (args.output or DEFAULT_OUTPUT / "flag_tuning" / split).resolve()
        profile = load_flag_profile(args.profile)
        cases = load_labeled_cases(scenario_files(args.input.resolve(), output), labels)
        if args.profile and fit and (output / "profile.json") == args.profile.resolve():
            raise ValueError("Choose a different output directory to keep the starting profile.")
        classifier = FlagClassifier(flag_hypotheses=profile.hypotheses)
        scores = collect_scores(cases, classifier, profile)
        results, recommended = evaluate(
            profile, scores, labels, min_support=args.min_support, fit=fit
        )
        output.mkdir(parents=True, exist_ok=True)
        write_json(output / "report.json", {"split": split, "scenarios": len(cases), **results})
        if fit:
            write_json(output / "profile.json", recommended.to_json())
    except (OSError, ValueError, ModelSetupError) as exc:
        parser.exit(1, f"Flag tuning failed: {exc}\n")

    print(f"{len(cases)} labeled scenarios ({split})")
    print(f"Current flag micro-F1  {results['micro_f1']['current']:.3f}")
    if fit:
        print(f"Fitted flag micro-F1   {results['micro_f1']['recommended']:.3f}")
        for flag, row in results["flags"].items():
            print(
                f"{flag:25} {row['current']['threshold']:.3f} -> "
                f"{row['recommended']['threshold']:.3f}  "
                f"{row['positives']} positives  {row['status']}"
            )
        print(f"Recommended profile   {output / 'profile.json'}")
    print(f"Hypothesis report     {output / 'report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
