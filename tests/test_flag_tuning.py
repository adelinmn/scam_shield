import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock

from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.flag_profiles import FlagProfile, load_flag_profile
from scam_detector.model import FlagClassifier
from scripts.tune_flags import evaluate, fit_threshold, read_labels


class FlagProfileTests(unittest.TestCase):
    def test_partial_profile_replaces_only_named_hypotheses_and_thresholds(self):
        code = "RF_CODE_REQUEST"
        with TemporaryDirectory() as temp:
            path = Path(temp) / "profile.json"
            path.write_text(
                json.dumps({"hypotheses": {code: ["Prima.", "A doua.", "Prima."]},
                            "thresholds": {code: 0.61}}),
                encoding="utf-8",
            )
            profile = load_flag_profile(path)
            self.assertEqual(profile.hypotheses[code], ("Prima.", "A doua."))
            self.assertEqual(profile.thresholds[code], 0.61)
            self.assertEqual(set(profile.hypotheses), set(FLAG_DEFINITIONS))
            self.assertEqual(profile.thresholds["RF_URGENCY"], 0.75)
            path.write_text(json.dumps({"hypotheses": {code: []}}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "non-empty list"):
                load_flag_profile(path)

    def test_classifier_scores_variants_independently_and_uses_the_maximum(self):
        classifier = FlagClassifier.__new__(FlagClassifier)
        classifier._flag_keys = {"RF_CODE_REQUEST": ("RF_CODE_REQUEST:0", "RF_CODE_REQUEST:1")}
        classifier._flag_hypotheses = {
            "RF_CODE_REQUEST:0": "Expeditorul cere un cod de autentificare.",
            "RF_CODE_REQUEST:1": "Expeditorul cere codul primit prin SMS.",
        }
        classifier.score_hypotheses = Mock(
            return_value=[{"RF_CODE_REQUEST:0": 0.2, "RF_CODE_REQUEST:1": 0.81}]
        )
        self.assertEqual(classifier.classify("Mesaj."), {"RF_CODE_REQUEST": 0.81})
        classifier.score_hypotheses.assert_called_once_with(["Mesaj."], classifier._flag_hypotheses)


class ThresholdTests(unittest.TestCase):
    def test_fit_finds_threshold_between_positive_and_negative_scores(self):
        scores = {"positive": 0.65, "negative": 0.25, "no_sender": None}
        result = fit_threshold(scores, {"positive"}, 0.75)
        self.assertAlmostEqual(result["threshold"], 0.45)
        self.assertEqual((result["tp"], result["fp"], result["fn"], result["tn"]), (1, 0, 0, 2))

    def test_report_exposes_individual_hypotheses_and_support_guard(self):
        flag = "RF_THREAT"
        profile = FlagProfile({flag: ("A.", "B.")}, {flag: 0.75})
        scores = {flag: [{"P": 0.2, "N": 0.15}, {"P": 0.65, "N": 0.3}]}
        labels = {"P": {flag}, "N": set()}
        report, recommended = evaluate(profile, scores, labels, min_support=2, fit=True)
        self.assertEqual(report["flags"][flag]["status"], "insufficient support")
        self.assertEqual(recommended.thresholds[flag], 0.75)
        report, recommended = evaluate(profile, scores, labels, min_support=1, fit=True)
        self.assertGreater(report["micro_f1"]["recommended"], report["micro_f1"]["current"])
        self.assertEqual(report["flags"][flag]["hypotheses"][1]["false_negatives"], ["P"])
        self.assertLess(recommended.thresholds[flag], 0.65)

    def test_only_reviewed_annotations_in_the_requested_split_are_labels(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "labels.csv"
            path.write_text(
                "id,source_label,split,annotator_reviewed,expected_red_flags\n"
                "D1,ham,dev,YES,\nD2,smishing,dev,NO,\nH1,spam,holdout,YES,RF_URGENCY\n",
                encoding="utf-8",
            )
            self.assertEqual(read_labels(path, None), ({"D1": set()}, "dev"))
            self.assertEqual(read_labels(path, "holdout"), ({"H1": {"RF_URGENCY"}}, "holdout"))
            path.write_text("id,source_label,split\nD1,ham,dev\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "reviewed expected_red_flags"):
                read_labels(path, None)
