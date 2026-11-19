import os
import socket
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.model import FlagClassifier, ModelSetupError


class ModelSetupTests(unittest.TestCase):
    def test_missing_local_model_gives_setup_error(self):
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ModelSetupError, "python -m scripts.download_model"):
                FlagClassifier(Path(directory))


@unittest.skipUnless(
    os.environ.get("SCAM_SHIELD_RUN_MODEL_TESTS") == "1", "Local model integration tests disabled."
)
class LocalModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.network = patch.object(
            socket.socket, "connect", side_effect=AssertionError("Attempted a network connection.")
        )
        cls.network.start()
        cls.addClassCleanup(cls.network.stop)
        cls.classifier = FlagClassifier(device="cpu")

    def test_independent_flag_scores_in_batch_and_on_repeated_runs(self):
        messages = ["Te rog trimite-mi codul primit prin SMS. E urgent!", "Astazi ploua."]
        batch = self.classifier.classify_many(messages)
        self.assertEqual(batch, self.classifier.classify_many(messages))
        self.assertEqual(len(batch), len(messages))
        self.assertNotEqual(batch[0], batch[1])
        for message, row in zip(messages, batch, strict=True):
            self.assertEqual(list(row), list(FLAG_DEFINITIONS))
            self.assertTrue(all(0 <= score <= 1 for score in row.values()))
            self.assertNotAlmostEqual(sum(row.values()), 1.0)
            alone = self.classifier.classify(message)
            for code, score in row.items():
                self.assertAlmostEqual(score, alone[code], places=5)

    def test_full_hypotheses_can_be_reordered_without_changing_score_mapping(self):
        text = "Instalați programul ca să vă putem ajuta de la distanță."
        scores = self.classifier.classify(text)
        hypotheses = {
            code: flag.description for code, flag in reversed(list(FLAG_DEFINITIONS.items()))
        }
        reordered = self.classifier.score_hypotheses([text], hypotheses)[0]
        for code in hypotheses:
            self.assertAlmostEqual(scores[code], reordered[code], places=6)

    def test_long_premise_is_truncated_to_the_local_model_limit(self):
        text = "Acesta este un mesaj. " * 600
        self.assertEqual(list(self.classifier.classify(text)), list(FLAG_DEFINITIONS))
