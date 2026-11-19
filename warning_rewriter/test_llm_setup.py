"""
Tests for the Ollama pre-flight check (llm_rewrite.check_ollama) and its use by the
entry point. No network and no Ollama required: the /api/tags call is patched.

Run from this folder:

    python -m unittest test_llm_setup -v
"""
import io
import json
import unittest
from contextlib import redirect_stderr
from unittest import mock

import llm_rewrite
from llm_rewrite import check_ollama, DEFAULT_MODEL
from writer import ScamShieldWriter
from run_validation import stub_detector


class _Resp:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _tags(*names):
    return mock.patch("urllib.request.urlopen", lambda *a, **k: _Resp({"models": [{"name": n} for n in names]}))


class TestCheckOllama(unittest.TestCase):
    def test_reports_not_running_with_install_steps(self):
        # port 1 is closed on every machine -> connection refused
        st = check_ollama(host="http://127.0.0.1:1", timeout=1.0)
        self.assertFalse(st["ok"])
        self.assertFalse(st["running"])
        self.assertFalse(st["has_model"])
        self.assertIsNotNone(st["error"])
        self.assertIn("https://ollama.com/download", st["message"])
        self.assertIn("ollama serve", st["message"])
        self.assertIn(f"ollama pull {DEFAULT_MODEL}", st["message"])

    def test_running_but_model_missing(self):
        with _tags("llama3:8b"):
            st = check_ollama()
        self.assertFalse(st["ok"])
        self.assertTrue(st["running"])
        self.assertFalse(st["has_model"])
        self.assertEqual(st["models"], ["llama3:8b"])
        self.assertIn(f"ollama pull {DEFAULT_MODEL}", st["message"])
        self.assertIn("llama3:8b", st["message"])       # shows what you do have
        self.assertIn("WITHOUT AI polish", st["message"])

    def test_running_with_model(self):
        with _tags("llama3:8b", DEFAULT_MODEL):
            st = check_ollama()
        self.assertTrue(st["ok"])
        self.assertTrue(st["has_model"])
        self.assertNotIn("ollama pull", st["message"])

    def test_bare_family_name_matches_a_tag(self):
        with _tags("gemma3:4b"):
            self.assertTrue(check_ollama(model="gemma3")["ok"])


class TestEntryPoint(unittest.TestCase):
    def test_writer_falls_back_and_explains(self):
        err = io.StringIO()
        with redirect_stderr(err):
            w = ScamShieldWriter(stub_detector, use_llm=True, host="http://127.0.0.1:1")
        self.assertIsNone(w.generate)                    # no LLM calls attempted
        self.assertFalse(w.llm_status["ok"])
        self.assertIn("ollama pull", err.getvalue())     # user was told what to install

        out = w.run("examples/E01.json")
        self.assertEqual(out["warning_source"], "template")   # still produces a warning
        self.assertTrue(out["warning_text"])

    def test_verify_llm_false_skips_the_check(self):
        w = ScamShieldWriter(stub_detector, use_llm=True, verify_llm=False)
        self.assertIsNotNone(w.generate)

    def test_use_llm_false_never_checks(self):
        w = ScamShieldWriter(stub_detector, use_llm=False)
        self.assertIsNone(w.generate)
        self.assertIsNone(w.llm_status)


if __name__ == "__main__":
    unittest.main(verbosity=2)
