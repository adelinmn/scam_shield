import json
import unittest
from unittest.mock import Mock, patch

from scam_detector import ScamDetector, analyze_scenario
from scam_detector.conversation import ScenarioError, parse_scenario
from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.model_assets import PROJECT_ROOT
from scam_detector.rules import RuleEngine


class ConversationTests(unittest.TestCase):
    def setUp(self):
        path = PROJECT_ROOT / "validation_set" / "V04.json"
        self.scenario = json.loads(path.read_text(encoding="utf-8"))

    def test_accumulates_unique_sender_flags_and_records_first_alert(self):
        classifier = Mock()
        classifier.classify.side_effect = [
            dict.fromkeys(FLAG_DEFINITIONS, 0.1) | activations
            for activations in (
                {"RF_NEW_NUMBER": 0.85, "RF_SECRECY": 0.85},
                {"RF_NEW_NUMBER": 0.9, "RF_SECRECY": 0.8},
                {"RF_PAYMENT_REQUEST": 0.9, "RF_URGENCY": 0.75},
                {"RF_SECRECY": 0.9},
            )
        ]
        classifier.score_hypotheses.return_value = [{"FAMILY_EMERGENCY": 0.9, "OTHER": 0.2}]
        rules = Mock(wraps=RuleEngine())
        self.scenario["messages"].reverse()
        detector = ScamDetector(classifier, thresholds=dict.fromkeys(FLAG_DEFINITIONS, 0.75), rules=rules)
        result = detector.analyze_scenario(self.scenario)

        self.assertEqual(result["risk_score"], 80)
        self.assertEqual(result["first_alert"], 5)
        self.assertEqual(result["verdict"], "SCAM")
        self.assertEqual(result["scam_type"], "FAMILY_EMERGENCY")
        self.assertEqual(
            result["flag_messages"],
            {"RF_NEW_NUMBER": 1, "RF_PAYMENT_REQUEST": 5, "RF_URGENCY": 5, "RF_SECRECY": 6},
        )
        self.assertEqual([row["risk_score"] for row in result["message_results"]], [20, 20, 60, 80])
        self.assertEqual(set(result["model_scores"]), set(FLAG_DEFINITIONS))
        self.assertEqual(result["model_scores"]["RF_NEW_NUMBER"], 0.9)
        self.assertIn("Destinatar: Cine e?", classifier.score_hypotheses.call_args.args[0][0])
        self.assertEqual(classifier.classify.call_count, 4)
        for call in rules.evaluate.call_args_list:
            message, context = call.args
            self.assertEqual([previous.number for previous in context.previous_messages],
                             list(range(1, message.number)))

    def test_reader_only_scenario_is_safe(self):
        self.scenario["messages"] = [{"n": 1, "from": "reader", "text": "Trimite-mi codul SMS."}]
        classifier = Mock()
        result = ScamDetector(classifier).analyze_scenario(self.scenario)
        self.assertEqual((result["verdict"], result["scam_type"]), ("SAFE", "NONE"))
        self.assertIsNone(result["first_alert"])
        classifier.classify.assert_not_called()
        classifier.score_hypotheses.assert_not_called()

    def test_reuses_default_model(self):
        classifier = Mock()
        classifier.classify.return_value = dict.fromkeys(FLAG_DEFINITIONS, 0.0)
        with patch("scam_detector.detector.FlagClassifier", return_value=classifier) as load:
            with patch("scam_detector.detector._default_detector", None):
                first = analyze_scenario(self.scenario)
                second = analyze_scenario(self.scenario)
        self.assertEqual(first, second)
        load.assert_called_once_with()

    def test_metadata_and_normalization_preserve_original(self):
        original = "  Mulţumesc.\n Vezi exemplu.ro/awb și sună la 0800 100 200.  "
        self.scenario["messages"][0]["text"] = original
        parsed = parse_scenario(self.scenario)
        self.assertEqual(parsed.sender.phone_numbers, ("+40 7xx xxx 318",))
        self.assertFalse(parsed.sender.known_contact)
        message = parsed.messages[0]
        self.assertEqual(message.original_text, original)
        self.assertEqual(message.text, "Mulțumesc. Vezi exemplu.ro/awb și sună la 0800 100 200.")
        self.assertEqual(message.urls, ("exemplu.ro/awb",))
        self.assertEqual(message.phone_numbers, ("0800 100 200",))

    def test_duplicate_turn_numbers_are_invalid(self):
        self.scenario["messages"][1]["n"] = 1
        with self.assertRaises(ScenarioError):
            parse_scenario(self.scenario)
