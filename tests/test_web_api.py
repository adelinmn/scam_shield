"""
Contract tests for POST /api/analyze — the endpoint detector.js and warnings.js call.

The real detector needs torch/transformers, so `detect` is stubbed here; everything
after it (reshaping, the warning, the contact guard, HTTP handling) is the real code.

    python3 -m unittest discover -s tests -p "test_web_api.py" -v
"""
import json
import sys
import threading
import unittest
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "warning_rewriter"))

import server  # noqa: E402
import scam_warnings  # noqa: E402


# V04 as the real detector reports it: "Hi mum, new number" -> money at message 5.
V04_RESULT = {
    "id": "V04",
    "verdict": "SCAM",
    "risk_score": 80,
    "scam_type": "FAMILY_EMERGENCY",
    "first_alert": 5,
    "red_flags": ["RF_NEW_NUMBER", "RF_PAYMENT_REQUEST", "RF_URGENCY", "RF_SECRECY"],
    "flag_messages": {"RF_NEW_NUMBER": 1, "RF_PAYMENT_REQUEST": 5, "RF_URGENCY": 5, "RF_SECRECY": 6},
    "message_results": [
        {"n": 1, "red_flags": ["RF_NEW_NUMBER"], "risk_score": 20},
        {"n": 3, "red_flags": [], "risk_score": 20},
        {"n": 5, "red_flags": ["RF_PAYMENT_REQUEST", "RF_URGENCY"], "risk_score": 60},
        {"n": 6, "red_flags": ["RF_SECRECY"], "risk_score": 80},
    ],
}


def load_v04():
    return json.loads((ROOT / "validation_set" / "V04.json").read_text(encoding="utf-8"))


class TestAnalyzeEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_detect = server.detect
        server.detect = lambda scenario: dict(V04_RESULT)
        server.AppHandler.log_message = lambda *a, **k: None
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), partial(server.AppHandler, directory=str(ROOT)))
        cls.base = f"http://127.0.0.1:{cls.httpd.server_port}"
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        server.detect = cls.original_detect

    def post(self, body, path="/api/analyze"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        request = Request(self.base + path, data=raw, headers={"Content-Type": "application/json"})
        with urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())

    def test_result_matches_the_browser_contract(self):
        _, payload = self.post(load_v04())
        self.assertEqual(payload["verdict"], "SCAM")
        self.assertEqual(payload["scam_type"], "FAMILY_EMERGENCY")
        self.assertEqual(payload["risk_score"], 80)
        self.assertEqual(payload["first_alert"], 5)

        numbers = {m["n"] for m in load_v04()["messages"]}
        self.assertIsInstance(payload["red_flags"], list)
        for flag in payload["red_flags"]:
            self.assertIn(flag["code"], V04_RESULT["flag_messages"])
            self.assertIn(flag["message_number"], numbers)
        self.assertEqual(
            payload["red_flags"],
            [{"code": "RF_NEW_NUMBER", "message_number": 1},
             {"code": "RF_PAYMENT_REQUEST", "message_number": 5},
             {"code": "RF_URGENCY", "message_number": 5},
             {"code": "RF_SECRECY", "message_number": 6}],
        )

    def test_warning_is_ro_safe_and_about_the_alert_not_the_whole_thread(self):
        _, payload = self.post(load_v04())
        text = payload["warning_text"]
        self.assertIsInstance(text, str)
        self.assertIn("1.850 lei", text)                    # the amount from the message
        self.assertEqual(scam_warnings.contact_problems(text), [])   # official channels only
        self.assertEqual(scam_warnings.style_problems(text), [])     # <=3 sentences, no jargon
        self.assertNotIn("secret", text.lower())            # secrecy only appears at message 6
        self.assertIn("numărul pe care îl știți deja", text)

    def test_safe_scenario_has_no_warning(self):
        server.detect = lambda scenario: {"verdict": "SAFE", "risk_score": 0, "scam_type": "NONE",
                                          "first_alert": None, "red_flags": [], "flag_messages": {},
                                          "message_results": []}
        try:
            _, payload = self.post(load_v04())
        finally:
            server.detect = lambda scenario: dict(V04_RESULT)
        self.assertIsNone(payload["warning_text"])
        self.assertEqual(payload["red_flags"], [])

    def test_bad_json_is_rejected(self):
        with self.assertRaises(HTTPError) as caught:
            self.post(b"{not json")
        self.assertEqual(caught.exception.code, 400)
        caught.exception.close()

    def test_unknown_path_is_404(self):
        with self.assertRaises(HTTPError) as caught:
            self.post(load_v04(), path="/api/nope")
        self.assertEqual(caught.exception.code, 404)
        caught.exception.close()

    def test_missing_inference_deps_give_503_not_500(self):
        class ModelSetupError(RuntimeError):
            pass

        server.detect = lambda scenario: (_ for _ in ()).throw(
            ModelSetupError("Install inference dependencies with python -m pip install -r requirements.txt."))
        try:
            with self.assertRaises(HTTPError) as caught:
                self.post(load_v04())
        finally:
            server.detect = lambda scenario: dict(V04_RESULT)
        self.assertEqual(caught.exception.code, 503)
        body = json.loads(caught.exception.read())
        caught.exception.close()
        self.assertIn("Install inference dependencies", body["error"])
        self.assertIn("pip install -r requirements.txt", body["hint"])

    def test_validation_set_listing_still_works(self):
        with urlopen(self.base + "/api/validation-set", timeout=5) as response:
            names = json.loads(response.read())
        self.assertEqual(names[0], "V01.json")
        self.assertEqual(len(names), 11)


if __name__ == "__main__":
    unittest.main(verbosity=2)
