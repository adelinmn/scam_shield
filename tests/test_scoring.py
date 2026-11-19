import json
import unittest

from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.model_assets import PROJECT_ROOT
from scam_detector.scam_types import load_scam_type_hypotheses
from scam_detector.scoring import risk_score, verdict_for_score


class ScoringTests(unittest.TestCase):
    def test_weights_and_categories_match_the_official_catalog(self):
        catalog = json.loads((PROJECT_ROOT / "official_catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(FLAG_DEFINITIONS, catalog["red_flag_points"])
        self.assertEqual([*load_scam_type_hypotheses(), "NONE"], catalog["scam_types"])

    def test_score_counts_unique_flags_and_caps_at_100(self):
        self.assertEqual(risk_score([]), 0)
        self.assertEqual(risk_score(["RF_NEW_NUMBER", "RF_PAYMENT_REQUEST", "RF_NEW_NUMBER"]), 45)
        self.assertEqual(risk_score(FLAG_DEFINITIONS), 100)

    def test_verdict_band_edges(self):
        for score, expected in [(0, "SAFE"), (24, "SAFE"), (25, "SUSPICIOUS"),
                                (49, "SUSPICIOUS"), (50, "SCAM"), (100, "SCAM")]:
            with self.subTest(score=score):
                self.assertEqual(verdict_for_score(score), expected)
