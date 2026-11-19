import unittest

from scam_detector.conversation import parse_scenario
from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scripts.evaluate import error_changes, evaluate
from scripts.tune_flags import Case, grouped_folds, tune


def result(verdict, flags=(), score=0):
    return {
        "verdict": verdict, "scam_type": "NONE" if verdict == "SAFE" else "OTHER",
        "risk_score": score, "first_alert": 1 if score >= 25 else None, "red_flags": list(flags),
    }


class EvaluationTests(unittest.TestCase):
    def test_evaluation_checks_exact_ids_and_counts_flag_errors(self):
        expected = {
            "A": result("SAFE"),
            "B": result("SCAM", ("RF_PAYMENT_REQUEST", "RF_DATA_REQUEST"), 55),
        }
        before = {
            "A": result("SUSPICIOUS", ("RF_PAYMENT_REQUEST",), 25),
            "B": result("SUSPICIOUS", ("RF_PAYMENT_REQUEST",), 25),
        }
        metrics = evaluate(expected, before)
        self.assertEqual(metrics["accuracy"]["verdict"], 0)
        self.assertEqual(metrics["flags"]["RF_PAYMENT_REQUEST"]["precision"], 0.5)
        self.assertEqual(metrics["flags"]["RF_DATA_REQUEST"]["fn"], 1)
        report = error_changes(expected, before, expected)
        self.assertEqual(report["verdict"]["fixed_false_alarms"], ["A"])
        self.assertEqual(report["verdict"]["fixed_missed_scams"], ["B"])
        with self.assertRaisesRegex(ValueError, "Missing"):
            evaluate(expected, {"A": result("SAFE")})

    def test_tuning_changes_only_selected_flags_and_respects_grid(self):
        expected = {"A": result("SAFE"), "B": result("SUSPICIOUS", ("RF_PAYMENT_REQUEST",), 25)}
        starting = dict.fromkeys(FLAG_DEFINITIONS, 0.75)
        scores = {key: dict.fromkeys(FLAG_DEFINITIONS, -1.0) for key in expected}
        scores["A"]["RF_PAYMENT_REQUEST"] = 0.8
        scores["B"]["RF_PAYMENT_REQUEST"] = 0.96
        fitted = tune(expected, scores, starting, [0.5, 0.9, 0.99], ("RF_PAYMENT_REQUEST",))
        self.assertEqual(fitted, starting | {"RF_PAYMENT_REQUEST": 0.9})

    def test_grouping_keeps_rephrased_numbers_and_scam_category_together(self):
        rows = [
            ("A", "Confirmă acum taxa de o sută pentru dosar, virând 800 lei.", "OTHER"),
            ("B", "Confirmă acum taxa de o sută pentru dosar, virând 600 lei.", "NONE"),
            ("C", "Este necesar să trimiți o garanție pentru garaj.", "OTHER"),
            ("D", "Mâine este o zi frumoasă la munte.", "NONE"),
            ("E", "Cartea merge la bibliotecă în fiecare toamnă.", "NONE"),
        ]
        expected, cases = {}, []
        for key, text, category in rows:
            expected[key] = {"scam_type": category, "verdict": "SAFE" if category == "NONE" else "SCAM"}
            conversation = parse_scenario({
                "id": key, "channel": "sms",
                "sender": {"name": None, "address": None, "known_contact": False},
                "messages": [{"n": 1, "from": "sender", "text": text}],
            })
            cases.append(Case(conversation, {}, {}))
        folds = grouped_folds(cases, expected)
        self.assertIn(["A", "B", "C"], [group for fold in folds for group in fold])
