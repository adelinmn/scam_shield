"""Compare aggregation and tune flag thresholds with held-out scenario families."""

import argparse
import json
import re
from collections import Counter
from dataclasses import dataclass
from itertools import combinations
from pathlib import Path

from scam_detector import ScamDetector
from scam_detector.cli import DEFAULT_OUTPUT, run_batch, scenario_files, write_json
from scam_detector.conversation import Conversation
from scam_detector.flag_definitions import AGGREGATIONS, FLAG_CONFIG_PATH, FLAG_DEFINITIONS, load_flag_config
from scam_detector.model import aggregate_scores
from scam_detector.rule_patterns import fold
from scam_detector.rules import RuleContext, RuleEngine, RuleStatus
from scam_detector.scam_types import load_scam_type_hypotheses
from scam_detector.scoring import verdict_for_score

from .evaluate import binary_metrics, evaluate, rate
from .score_cache import load_case
from .validate import read_results


@dataclass
class Case:
    conversation: Conversation
    recorded: dict
    evidence: dict[int, dict[str, RuleStatus]]

    @property
    def id(self) -> str:
        return self.conversation.id


class CachedClassifier:
    def __init__(self, case: Case, methods: dict[str, str], type_method: str):
        self.scores = {
            turn.text: {
                code: aggregate_scores(scores, methods[code])
                for code, scores in case.recorded["turns"][str(turn.number)].items()
            }
            for turn in case.conversation.messages if turn.role == "sender"
        }
        self.type_scores = {
            code: aggregate_scores(scores, type_method) for code, scores in case.recorded["scam_types"].items()
        }

    def classify(self, text):
        return self.scores[text]

    def score_hypotheses(self, texts, hypotheses):
        return [self.type_scores for _ in texts]


def load_cases(input_path: Path, cache_path: Path, rules: RuleEngine) -> list[Case]:
    data = json.loads(cache_path.read_bytes())
    flag_phrases = {code: list(config.phrases) for code, config in load_flag_config().items()}
    type_phrases = {code: list(phrases) for code, phrases in load_scam_type_hypotheses().items()}
    if data["format"] != 1 or data["flag_phrases"] != flag_phrases or data["type_phrases"] != type_phrases:
        raise ValueError("Hypotheses or cache format changed. Regenerate the score cache.")
    cases = []
    for path in scenario_files(input_path.resolve(), DEFAULT_OUTPUT):
        conversation, digest = load_case(path)
        recorded = data["cases"][conversation.id]
        if recorded["input_sha256"] != digest:
            raise ValueError(f"Input changed: {path.name}. Regenerate the score cache.")
        evidence = {
            turn.number: rules.evaluate(
                turn, RuleContext(conversation.channel, conversation.sender, conversation.messages[:index])
            )
            for index, turn in enumerate(conversation.messages) if turn.role == "sender"
        }
        cases.append(Case(conversation, recorded, evidence))
    ids = {case.id for case in cases}
    if len(ids) != len(cases) or ids != data["cases"].keys():
        raise ValueError("Scenario IDs do not exactly match the score cache.")
    return cases


def shingles(conversation: Conversation) -> set[tuple[str, ...]]:
    text = " ".join(message.text for message in conversation.messages if message.role == "sender")
    words = re.findall(r"[a-z]+", fold(text))
    return set(zip(words, words[1:], words[2:])) if len(words) >= 3 else {tuple(words)}


def grouped_folds(cases: list[Case], expected: dict, count: int = 3) -> list[list[list[str]]]:
    """Keep a scam category together and merge near-duplicate texts across labels."""
    parents = {case.id: case.id for case in cases}

    def root(key):
        while parents[key] != key:
            parents[key] = parents[parents[key]]
            key = parents[key]
        return key

    words = {case.id: shingles(case.conversation) for case in cases}
    for first, second in combinations(sorted(parents), 2):
        left, right = words[first], words[second]
        category = expected[first]["scam_type"]
        same_category = category != "NONE" and category == expected[second]["scam_type"]
        near_duplicate = len(left & right) / len(left | right) >= 0.45
        if same_category or near_duplicate:
            parents[root(second)] = root(first)

    groups = {}
    for case_id in sorted(parents):
        groups.setdefault(root(case_id), []).append(case_id)
    if len(groups) < count:
        raise ValueError(f"At least {count} scenario families are needed for {count}-fold tuning.")
    folds = [[] for _ in range(count)]
    distribution = [Counter() for _ in folds]
    total = Counter(row["verdict"] for row in expected.values())
    for group in sorted(groups.values(), key=lambda ids: (-len(ids), ids[0])):
        counts = Counter(expected[key]["verdict"] for key in group)
        index = min(range(count), key=lambda idx: (
            sum(distribution[idx][v] * n / total[v] for v, n in counts.items()),
            sum(distribution[idx].values()), idx,
        ))
        folds[index].append(group)
        distribution[index].update(counts)
    return folds


def predictions(cases: list[Case], rules: RuleEngine, thresholds: dict, methods: dict,
                *, type_method: str = "max", mode: str = "hybrid") -> dict:
    results = {}
    for case in cases:
        classifier = None if mode == "rules-only" else CachedClassifier(case, methods, type_method)
        detector = ScamDetector(classifier, thresholds=thresholds, rules=rules, mode=mode)
        results[case.id] = detector.analyze_conversation(case.conversation)
    return results


def firing_scores(cases: list[Case], methods: dict[str, str]) -> dict[str, dict[str, float]]:
    """Reduce turn scores to the exact scenario-level flag decision for any threshold."""
    scores = {}
    for case in cases:
        row = dict.fromkeys(FLAG_DEFINITIONS, -1.0)
        for number, evidence in case.evidence.items():
            raw = case.recorded["turns"][str(number)]
            for code, status in evidence.items():
                if status == RuleStatus.CONFIRMED:
                    row[code] = 1.0
                elif status == RuleStatus.UNKNOWN:
                    row[code] = max(row[code], aggregate_scores(raw[code], methods[code]))
        scores[case.id] = row
    return scores


def tune(expected: dict, scores: dict, starting: dict, grid: list[float],
         flags=tuple(FLAG_DEFINITIONS)) -> dict[str, float]:
    thresholds = dict(starting)
    for code in flags:
        thresholds[code] = min(max(thresholds[code], grid[0]), grid[-1])
    support = Counter(target["verdict"] for target in expected.values())
    for code in flags:
        points = FLAG_DEFINITIONS[code]
        rows = [
            (target["verdict"], code in target["red_flags"], scores[key][code], sum(
                weight for other, weight in FLAG_DEFINITIONS.items()
                if other != code and scores[key][other] >= thresholds[other]
            ))
            for key, target in expected.items()
        ]

        def objective(threshold):
            tp = fp = fn = false_alarm = missed_scam = 0
            correct = Counter()
            for verdict, has_flag, score, other_points in rows:
                active = score >= threshold
                tp += has_flag and active
                fp += not has_flag and active
                fn += has_flag and not active
                prediction = verdict_for_score(min(100, other_points + points * active))
                correct[verdict] += verdict == prediction
                false_alarm += verdict == "SAFE" and prediction != "SAFE"
                missed_scam += verdict == "SCAM" and prediction != "SCAM"
            f1 = binary_metrics(tp, fp, fn)["f1"]
            balanced_recall = sum(rate(correct[v], n) for v, n in support.items()) / len(support)
            value = (
                f1 + 0.6 * balanced_recall
                - 0.6 * rate(false_alarm, support["SAFE"])
                - 0.4 * rate(missed_scam, support["SCAM"])
            )
            return round(value, 12), -abs(threshold - starting[code]), threshold

        thresholds[code] = max((*grid, thresholds[code]), key=objective)
    return thresholds


def run_trials(cases: list[Case], expected: dict, rules: RuleEngine, grid: list[float],
               baseline_config: Path = FLAG_CONFIG_PATH) -> dict:
    config = load_flag_config(baseline_config)
    if any(item.phrases != load_flag_config()[code].phrases for code, item in config.items()):
        raise ValueError("Use a baseline configuration with the same phrases as the score cache.")
    thresholds = {code: item.threshold for code, item in config.items()}
    configured = {code: item.aggregation for code, item in config.items()}
    folds = grouped_folds(cases, expected)
    report = {
        "folds": folds, "range": [grid[0], grid[-1]], "grid": grid,
        "starting_thresholds": thresholds, "starting_aggregation": configured, "variants": {},
    }
    current = predictions(cases, rules, thresholds, configured)
    report["current"] = evaluate(expected, current)
    for mode in ("rules-only", "model-only"):
        report[mode] = evaluate(expected, predictions(cases, rules, thresholds, configured, mode=mode))

    for method in AGGREGATIONS:
        methods = dict.fromkeys(config, method)
        scores = firing_scores(cases, methods)
        fixed = predictions(cases, rules, thresholds, methods)
        type_variant = predictions(cases, rules, thresholds, configured, type_method=method)
        oof = {}
        focused_oof = {}
        fold_parameters = []
        focused_parameters = []
        focus = ("RF_PAYMENT_REQUEST", "RF_IMPERSONATION", "RF_SECRECY")
        for groups in folds:
            holdback = {key for group in groups for key in group}
            training = {key: row for key, row in expected.items() if key not in holdback}
            evaluation = [case for case in cases if case.id in holdback]
            params = tune(training, scores, thresholds, grid)
            focused = tune(training, scores, thresholds, grid, focus)
            fold_parameters.append(params)
            focused_parameters.append(focused)
            oof.update(predictions(evaluation, rules, params, methods))
            focused_oof.update(predictions(evaluation, rules, focused, methods))
        report["variants"][method] = {
            "fixed_flag_thresholds": evaluate(expected, fixed),
            "type_aggregation_only": evaluate(expected, type_variant),
            "out_of_fold_tuned": evaluate(expected, oof),
            "out_of_fold_priority_tuned": evaluate(expected, focused_oof),
            "fold_thresholds": fold_parameters,
            "focus_fold_thresholds": focused_parameters,
            "candidate_all_development": {
                code: {"phrases": config[code].phrases, "threshold": threshold, "aggregation": method}
                for code, threshold in tune(expected, scores, thresholds, grid).items()
            },
        }
        print(f"{method}: fixed {report['variants'][method]['fixed_flag_thresholds']['accuracy']['verdict']:.1%}, "
              f"out-of-fold tuned {report['variants'][method]['out_of_fold_tuned']['accuracy']['verdict']:.1%}",
              flush=True)

    secrecy = {}
    secrecy_folds = []
    scores = firing_scores(cases, configured)
    for groups in folds:
        holdback = {key for group in groups for key in group}
        training = {key: row for key, row in expected.items() if key not in holdback}
        truth = {key: expected[key] for key in holdback}
        params = tune(training, scores, thresholds, grid, ("RF_SECRECY",))
        fitted = predictions([case for case in cases if case.id in holdback], rules, params, configured)
        secrecy.update(fitted)
        secrecy_folds.append({
            "threshold": params["RF_SECRECY"],
            "before": evaluate(truth, {key: current[key] for key in holdback}),
            "after": evaluate(truth, fitted),
        })
    report["secrecy_only"] = {"out_of_fold": evaluate(expected, secrecy), "folds": secrecy_folds}
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("input", "expected", "scores", "output"):
        parser.add_argument(name, type=Path)
    parser.add_argument("--minimum", type=float, default=0.2)
    parser.add_argument("--maximum", type=float, default=0.995)
    parser.add_argument("--step", type=float, default=0.05)
    parser.add_argument("--baseline-config", type=Path, default=FLAG_CONFIG_PATH)
    parser.add_argument("--replay-output", type=Path, help="export a batch using the active flag config and cached NLI")
    args = parser.parse_args()
    if not 0 <= args.minimum < args.maximum <= 1 or not 0.005 <= args.step <= 1:
        parser.error("Use 0 <= minimum < maximum <= 1 and 0.005 <= step <= 1")
    if args.output.resolve() in {path.resolve() for path in (args.expected, args.scores, args.input, args.baseline_config)}:
        parser.error("The experiment report cannot overwrite an input")
    grid = sorted({args.minimum, args.maximum} | {
        round(args.minimum + i * args.step, 6) for i in range(1, 201)
        if args.minimum < round(args.minimum + i * args.step, 6) < args.maximum
    })
    rules = RuleEngine()
    cases = load_cases(args.input, args.scores, rules)
    expected = read_results(args.expected)
    if expected.keys() != {case.id for case in cases}:
        parser.error("Expected results and scenario IDs must match exactly")
    report = run_trials(cases, expected, rules, grid, args.baseline_config)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, report)
    if args.replay_output:
        settings = load_flag_config()
        thresholds = {code: item.threshold for code, item in settings.items()}
        methods = {code: item.aggregation for code, item in settings.items()}
        results = predictions(cases, rules, thresholds, methods)
        run_batch(args.input, args.replay_output, lambda scenario: results[scenario["id"]])


if __name__ == "__main__":
    main()
