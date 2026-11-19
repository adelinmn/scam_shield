"""Measure verdict, scam type, red flags, score and alert time from matching result IDs."""

import argparse
from collections import Counter
from pathlib import Path

from scam_detector.cli import write_json
from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.scoring import risk_score, verdict_for_score

from .validate import FIELDS, read_results


VERDICTS = ("SAFE", "SUSPICIOUS", "SCAM")


def rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def binary_metrics(tp: int, fp: int, fn: int) -> dict:
    return dict(
        tp=tp, fp=fp, fn=fn, support=tp + fn,
        precision=rate(tp, tp + fp), recall=rate(tp, tp + fn), f1=rate(2 * tp, 2 * tp + fp + fn),
    )


def evaluate(expected: dict[str, dict], actual: dict[str, dict]) -> dict:
    if expected.keys() != actual.keys() or not expected:
        missing = sorted(expected.keys() - actual.keys())
        extra = sorted(actual.keys() - expected.keys())
        raise ValueError(f"Expected a nonempty ID match. Missing: {missing}; extra: {extra}")
    totals = Counter()
    confusion = {verdict: dict.fromkeys(VERDICTS, 0) for verdict in VERDICTS}
    type_confusion = Counter()
    flag_counts = Counter()
    alert_errors = Counter(dict.fromkeys(("unexpected", "missing", "early", "late"), 0))
    for scenario_id, target in expected.items():
        got = actual[scenario_id]
        target_flags, got_flags = set(target["red_flags"]), set(got["red_flags"])
        equal = {field: target[field] == got[field] for field in FIELDS if field != "red_flags"}
        equal["red_flags"] = target_flags == got_flags
        totals.update(field for field, matches in equal.items() if matches)
        totals["all"] += all(equal.values())
        confusion[target["verdict"]][got["verdict"]] += 1
        type_confusion[target["scam_type"], got["scam_type"]] += 1
        target_alert, observed_alert = target["first_alert"], got["first_alert"]
        if target_alert != observed_alert:
            if target_alert is None:
                alert_errors["unexpected"] += 1
            elif observed_alert is None:
                alert_errors["missing"] += 1
            else:
                alert_errors["early" if observed_alert < target_alert else "late"] += 1
        for code in target_flags | got_flags:
            flag_counts[code, code in target_flags, code in got_flags] += 1
    type_labels = sorted({label for pair in type_confusion for label in pair})
    return {
        "scenario_count": len(expected),
        "accuracy": {field: rate(totals[field], len(expected)) for field in (*FIELDS, "all")},
        "alert_errors": alert_errors,
        "verdict_confusion": confusion,
        "verdicts": {
            label: binary_metrics(
                confusion[label][label],
                sum(confusion[other][label] for other in VERDICTS if other != label),
                sum(confusion[label][other] for other in VERDICTS if other != label),
            )
            for label in VERDICTS
        },
        "type_confusion": {
            label: {prediction: type_confusion[label, prediction] for prediction in type_labels}
            for label in type_labels
        },
        "types": {
            label: binary_metrics(
                type_confusion[label, label],
                sum(type_confusion[other, label] for other in type_labels if other != label),
                sum(type_confusion[label, other] for other in type_labels if other != label),
            )
            for label in type_labels
        },
        "flags": {
            code: binary_metrics(flag_counts[code, True, True], flag_counts[code, False, True],
                                 flag_counts[code, True, False])
            for code in FLAG_DEFINITIONS
        },
    }


def error_changes(expected: dict[str, dict], before: dict[str, dict], after: dict[str, dict]) -> dict:
    verdict_changes = {"fixed_false_alarms": [], "new_false_alarms": [], "fixed_missed_scams": [], "new_missed_scams": []}
    flag_changes = {code: Counter() for code in FLAG_DEFINITIONS}
    for scenario_id, target in sorted(expected.items()):
        old, new = before[scenario_id], after[scenario_id]
        if target["verdict"] == "SAFE" and (old["verdict"] == "SAFE") != (new["verdict"] == "SAFE"):
            key = "fixed_false_alarms" if new["verdict"] == "SAFE" else "new_false_alarms"
            verdict_changes[key].append(scenario_id)
        if target["verdict"] == "SCAM" and (old["verdict"] == "SCAM") != (new["verdict"] == "SCAM"):
            key = "fixed_missed_scams" if new["verdict"] == "SCAM" else "new_missed_scams"
            verdict_changes[key].append(scenario_id)
        for code in set(old["red_flags"]) ^ set(new["red_flags"]):
            if code in target["red_flags"]:
                error = "fixed_fn" if code in new["red_flags"] else "new_fn"
            else:
                error = "new_fp" if code in new["red_flags"] else "fixed_fp"
            flag_changes[code][error] += 1
    return {"verdict": verdict_changes, "flags": flag_changes}


def label_checks(expected: dict[str, dict]) -> dict:
    return {
        "score_conflicts_with_flags": [
            scenario_id for scenario_id, row in sorted(expected.items())
            if row["risk_score"] != risk_score(row["red_flags"])
        ],
        "verdict_conflicts_with_score": [
            scenario_id for scenario_id, row in sorted(expected.items())
            if row["verdict"] != verdict_for_score(row["risk_score"])
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", type=Path)
    parser.add_argument("results", type=Path)
    parser.add_argument("--before", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    expected, actual = read_results(args.expected), read_results(args.results)
    report = {"metrics": evaluate(expected, actual), "label_checks": label_checks(expected)}
    if args.before:
        before = read_results(args.before)
        report["before"] = evaluate(expected, before)
        report["changes"] = error_changes(expected, before, actual)
    if args.output:
        if args.output.resolve() in {path.resolve() for path in (args.expected, args.results, args.before) if path}:
            parser.error("The report cannot overwrite an input CSV")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.output, report)
    for metric, value in report["metrics"]["accuracy"].items():
        print(f"{metric:14} {value:7.2%}")


if __name__ == "__main__":
    main()
