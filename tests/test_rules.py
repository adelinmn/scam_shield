import unittest

from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.fusion import FlagFusionEngine
from scam_detector.rules import RuleEngine, RuleStatus


class RuleAndFusionTests(unittest.TestCase):
    def test_scaffold_is_neutral_for_every_flag(self):
        self.assertEqual(
            RuleEngine().evaluate(None), dict.fromkeys(FLAG_DEFINITIONS, RuleStatus.UNKNOWN)
        )

    def test_inclusive_per_flag_threshold_with_rule_overrides(self):
        scores = dict.fromkeys(FLAG_DEFINITIONS, 0.0)
        scores.update(RF_CODE_REQUEST=0.75, RF_URGENCY=0.6, RF_THREAT=0.74)
        fusion = FlagFusionEngine({"RF_URGENCY": 0.6})
        self.assertEqual(fusion.select(scores, {}), ["RF_CODE_REQUEST", "RF_URGENCY"])
        rules = {"RF_CODE_REQUEST": RuleStatus.REJECTED, "RF_PAYMENT_REQUEST": RuleStatus.CONFIRMED}
        self.assertEqual(fusion.select(scores, rules), ["RF_PAYMENT_REQUEST", "RF_URGENCY"])

    def test_invalid_thresholds_raise(self):
        for thresholds in ({"RF_UNKNOWN": 0.3}, {"RF_THREAT": True}, {"RF_THREAT": float("nan")}):
            with self.subTest(thresholds=thresholds), self.assertRaises(ValueError):
                FlagFusionEngine(thresholds)
