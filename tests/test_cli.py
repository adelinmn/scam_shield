import csv
import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scam_detector import ScamDetector
from scam_detector.cli import CSV_FIELDS, main, result_filename, run_batch
from scam_detector.flag_definitions import FLAG_DEFINITIONS
from scam_detector.model_assets import PROJECT_ROOT


class StubClassifier:
    def classify(self, text):
        return dict.fromkeys(FLAG_DEFINITIONS, 0.0)


class BatchTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.input = self.directory / "input"
        self.input.mkdir()
        self.output = self.directory / "outputs"
        self.analyze = ScamDetector(StubClassifier()).analyze_scenario

    def write_input(self, name, scenario_id):
        path = self.input / name
        path.parent.mkdir(parents=True, exist_ok=True)
        scenario = {
            "id": scenario_id,
            "channel": "sms",
            "sender": {"name": None, "address": None, "known_contact": False},
            "messages": [{"n": 1, "from": "sender", "text": "Bună ziua."}],
        }
        path.write_text(json.dumps(scenario), encoding="utf-8")
        return path

    def test_single_file_writes_all_outputs(self):
        source = self.write_input("one.json", "V01")
        summary, skipped = run_batch(source, self.output, self.analyze)
        self.assertEqual((summary, skipped),
                         ({"total_scenarios": 1, "scam": 0, "suspicious": 0, "safe": 1}, 0))
        self.assertEqual(
            json.loads((self.output / "summary.json").read_text(encoding="utf-8")), summary
        )
        result = json.loads((self.output / "scenarios" / "V01.json").read_text(encoding="utf-8"))
        self.assertEqual(result["id"], "V01")
        self.assertEqual(set(result["model_scores"]), set(FLAG_DEFINITIONS))
        with (self.output / "results.csv").open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            self.assertEqual(reader.fieldnames, list(CSV_FIELDS))
            self.assertEqual([row["id"] for row in reader], ["V01"])

    def test_directory_sorts_ids_skips_bad_files_and_prunes_only_generated_results(self):
        first = self.write_input("a.json", "V02")
        self.write_input("sub/b.JSON", "V01")
        self.write_input("duplicate.json", "V01")
        (self.input / "broken.json").write_text('{"text":"private message"', encoding="utf-8")
        (self.input / "invalid.json").write_text('{"id":"invalid"}', encoding="utf-8")
        (self.input / "oversized.json").write_text('{"n":' + "1" * 5000 + "}", encoding="utf-8")
        with redirect_stderr(io.StringIO()) as errors:
            summary, skipped = run_batch(self.input, self.output, self.analyze)
        self.assertEqual((summary["total_scenarios"], skipped), (2, 4))
        self.assertNotIn("private message", errors.getvalue())
        with (self.output / "results.csv").open(encoding="utf-8", newline="") as stream:
            self.assertEqual([row["id"] for row in csv.DictReader(stream)], ["V01", "V02"])

        unrelated = self.output / "scenarios" / "notes.json"
        unrelated.write_text("{}", encoding="utf-8")
        run_batch(first, self.output, self.analyze)
        self.assertFalse((self.output / "scenarios" / "V01.json").exists())
        self.assertTrue(unrelated.exists())
        tracked_paths = [
            self.output / "results.csv",
            self.output / "summary.json",
            self.output / "scenarios" / "V02.json",
        ]
        previous = [p.read_bytes() for p in tracked_paths]
        run_batch(first, self.output, self.analyze)
        self.assertEqual([p.read_bytes() for p in tracked_paths], previous)

    def test_arbitrary_ids_cannot_escape_output_or_create_reserved_filenames(self):
        for index, scenario_id in enumerate(("../outside", "CON", "NUL", "id, with space")):
            source = self.write_input(f"source-{index}.json", scenario_id)
            run_batch(source, self.output, self.analyze)
            filename = result_filename(scenario_id)
            self.assertTrue(filename.startswith("~"))
            with (self.output / "scenarios" / filename).open(encoding="utf-8") as stream:
                self.assertEqual(json.load(stream)["id"], scenario_id)

    def test_missing_input_reports_failure_without_creating_output(self):
        with redirect_stderr(io.StringIO()) as errors:
            status = main([str(self.input / "missing.json"), "--output", str(self.output)])
        self.assertEqual(status, 1)
        self.assertIn("Input does not exist", errors.getvalue())
        self.assertFalse(self.output.exists())

    def test_output_collision_preserves_existing_files(self):
        source = self.write_input("one.json", "V01")
        self.output.mkdir()
        summary = self.output / "summary.json"
        summary.write_text('{"notes":"keep this"}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Existing file conflicts"):
            run_batch(source, self.output, self.analyze)
        self.assertEqual(summary.read_text(encoding="utf-8"), '{"notes":"keep this"}')
        self.assertFalse((self.output / "scenarios").exists())

    def test_all_malformed_inputs_report_failure_with_empty_outputs(self):
        (self.input / "bad.json").write_text("]{", encoding="utf-8")
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()) as terminal:
            status = main([str(self.input), "--output", str(self.output)])
        self.assertEqual(status, 1)
        self.assertIn("Scenarios processed: 0", terminal.getvalue())
        self.assertIn("Files skipped: 1", terminal.getvalue())
        with (self.output / "summary.json").open(encoding="utf-8") as stream:
            self.assertEqual(json.load(stream)["total_scenarios"], 0)

    def test_missing_model_stops_batch_with_setup_instructions(self):
        source = self.write_input("one.json", "V01")
        with patch.dict(os.environ, {"SCAM_SHIELD_MODEL_DIR": str(self.input)}):
            with patch("scam_detector.detector._default_detector", None):
                with redirect_stderr(io.StringIO()) as errors:
                    status = main([str(source), "--output", str(self.output)])
        self.assertEqual(status, 1)
        self.assertIn("python -m scripts.download_model", errors.getvalue())
        self.assertFalse(self.output.exists())


@unittest.skipUnless(
    os.environ.get("SCAM_SHIELD_RUN_MODEL_TESTS") == "1", "Local model integration tests disabled."
)
class LauncherTests(unittest.TestCase):
    def test_real_single_file_launcher_is_repeatable(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "results"
            command = [
                sys.executable,
                "test.py",
                "validation_set/V04.json",
                "--output",
                str(output),
            ]
            env = dict(os.environ, HF_HUB_OFFLINE="1", SCAM_SHIELD_DEVICE="cpu")
            first = subprocess.run(
                command, cwd=PROJECT_ROOT, env=env, capture_output=True, text=True, check=True
            )
            result = output / "scenarios" / "V04.json"
            baseline = result.read_bytes()
            subprocess.run(
                command, cwd=PROJECT_ROOT, env=env, capture_output=True, text=True, check=True
            )
            self.assertEqual(result.read_bytes(), baseline)
            self.assertIn("Scenarios processed: 1", first.stdout)
            saved = json.loads(baseline)
            row = next(line for line in first.stdout.splitlines() if line.startswith("V04 "))
            self.assertEqual(
                row.split(),
                [
                    "V04",
                    saved["verdict"],
                    str(saved["risk_score"]),
                    str(saved["first_alert"] or "-"),
                    saved["scam_type"],
                ],
            )
