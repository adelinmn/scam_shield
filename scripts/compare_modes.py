"""Compare all detector modes on both labeled datasets using one local model."""

import argparse
from pathlib import Path

from scam_detector.cli import DEFAULT_OUTPUT, run_batch, write_json
from scam_detector.detector import DetectionMode, ScamDetector
from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.model import FlagClassifier, ModelSetupError
from scam_detector.model_assets import PROJECT_ROOT
from scripts.validate import compare, read_results


DATASETS = {
    "validation": (PROJECT_ROOT / "validation_set", PROJECT_ROOT / "validation_expected_results.csv"),
    "testing": (
        PROJECT_ROOT / "testing_set" / "input",
        PROJECT_ROOT / "testing_set" / "validation_expected_results_100.csv",
    ),
}


class CachedClassifier:
    """Reuse raw neural outputs across modes for one dataset."""

    def __init__(self, classifier: FlagClassifier) -> None:
        self.classifier = classifier
        self.flag_scores = {}
        self.type_scores = {}

    def classify(self, text: str) -> dict[str, float]:
        if text not in self.flag_scores:
            self.flag_scores[text] = self.classifier.classify(text)
        return self.flag_scores[text]

    def score_hypotheses(self, texts, hypotheses) -> list[dict[str, float]]:
        key = (tuple(texts), tuple(
            (code, values if isinstance(values, str) else tuple(values))
            for code, values in hypotheses.items()
        ))
        if key not in self.type_scores:
            self.type_scores[key] = self.classifier.score_hypotheses(texts, hypotheses)
        return self.type_scores[key]


def metrics(expected: dict, actual: dict) -> dict:
    evaluation = compare(expected, actual)
    fields = evaluation["field_matches"]
    count = len(expected)
    flags = {}
    for code in FLAG_DEFINITIONS:
        truth = {case for case, row in expected.items() if code in row["red_flags"]}
        predicted = {case for case in expected.keys() & actual.keys() if code in actual[case]["red_flags"]}
        tp, fp, fn = len(truth & predicted), len(predicted - truth), len(truth - predicted)
        flags[code] = {
            "tp": tp, "fp": fp, "fn": fn,
            "precision": tp / (tp + fp) if tp + fp else 0.0,
            "recall": tp / (tp + fn) if tp + fn else 0.0,
            "f1": 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else 0.0,
        }
    safe = [case for case, row in expected.items() if row["verdict"] == "SAFE"]
    false_positive_ids = [
        case for case in safe if case in actual and actual[case]["verdict"] != "SAFE"
    ]
    return {
        **evaluation,
        "verdict_accuracy": fields["verdict"] / count,
        "scam_type_accuracy": fields["scam_type"] / count,
        "first_alert_accuracy": fields["first_alert"] / count,
        "exact_flag_set_match": fields["red_flags"] / count,
        "safe_false_positive_rate": len(false_positive_ids) / len(safe) if safe else 0.0,
        "safe_false_positive_ids": false_positive_ids,
        "per_flag": flags,
    }


def differences_from_model(baseline: dict, candidate: dict) -> dict:
    previous = {row["id"]: set(row["differences"]) for row in baseline["scenarios"]}
    corrected, regressed = {}, {}
    for row in candidate["scenarios"]:
        before = previous[row["id"]]
        after = set(row["differences"])
        if fixed := before - after:
            corrected[row["id"]] = sorted(fixed)
        if broken := after - before:
            regressed[row["id"]] = sorted(broken)
    return {"corrected": corrected, "regressed": regressed}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=["all", *DATASETS], default="all")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT / "rule_comparison")
    args = parser.parse_args()
    selected = list(DATASETS) if args.dataset == "all" else [args.dataset]
    try:
        model = FlagClassifier()
        report = {}
        for name in selected:
            inputs, labels = DATASETS[name]
            expected = read_results(labels)
            cached = CachedClassifier(model)
            data_report = {}
            for mode in (DetectionMode.MODEL_ONLY, DetectionMode.RULES_ONLY, DetectionMode.HYBRID):
                sensor = None if mode == DetectionMode.RULES_ONLY else cached
                detector = ScamDetector(sensor, mode=mode)
                destination = args.output / mode / name
                print(f"Evaluating {name} with {mode}", flush=True)
                run_batch(inputs, destination, detector.analyze_scenario)
                actual = read_results(destination / "results.csv")
                data_report[mode] = metrics(expected, actual)
                write_json(destination / "validation.json", data_report[mode])
                evaluated = data_report[mode]
                print(
                    f"{name} {mode} | verdict {evaluated['verdict_accuracy']:.1%} | "
                    f"type {evaluated['scam_type_accuracy']:.1%} | "
                    f"flags {evaluated['exact_flag_set_match']:.1%} | "
                    f"alert {evaluated['first_alert_accuracy']:.1%} | "
                    f"SAFE FP {evaluated['safe_false_positive_rate']:.1%}",
                    flush=True,
                )
            baseline = data_report[DetectionMode.MODEL_ONLY]
            data_report["hybrid_vs_model"] = differences_from_model(baseline, data_report[DetectionMode.HYBRID])
            report[name] = data_report
        destination = args.output / "comparison.json"
        write_json(destination, report)
        print(f"Comparison saved to {destination}")
    except (OSError, ValueError, ModelSetupError) as exc:
        parser.exit(1, f"Comparison failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
