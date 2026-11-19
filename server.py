import json
import os
import sys
import threading
import traceback
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
REWRITER = ROOT / "warning_rewriter"
MAX_BODY_BYTES = 1_000_000
PORT = int(os.environ.get("SCAM_SHIELD_PORT", "8000"))

# One detector instance, one request at a time: torch inference is not guaranteed to be
# thread-safe, and the page only ever asks for one scenario after another.
_analyze_lock = threading.Lock()


def detect(scenario: dict) -> dict:
    """Run the official offline detector. Imported lazily: torch is heavy and optional."""
    from scam_detector import analyze_scenario

    return analyze_scenario(scenario)


def warning_for(scenario: dict, verdict: str, scam_type: str, flags: set[str]) -> str | None:
    """Build the Romanian template warning. No model, no network, no invented contacts."""
    if verdict == "SAFE":
        return None
    if str(REWRITER) not in sys.path:
        sys.path.insert(0, str(REWRITER))
    from scam_warnings import build_warning, load_conversation

    warning = build_warning(load_conversation(scenario), scam_type, flags, verdict)
    return warning.text if warning else None


def flags_at(result: dict, message_number: int | None) -> set[str]:
    """Red flags known by `message_number` (the first alert), not the whole thread."""
    return {
        flag
        for message in result.get("message_results") or ()
        if message_number is None or message["n"] <= message_number
        for flag in message.get("red_flags") or ()
    }


def analyze(scenario: dict) -> dict:
    """Detector output reshaped for the browser contract in app.js."""
    result = detect(scenario)
    codes = list(result.get("red_flags") or ())
    alert = result.get("first_alert")
    try:
        result["warning_text"] = warning_for(
            scenario, result.get("verdict", "SAFE"), result.get("scam_type", "NONE"),
            flags_at(result, alert) or set(codes),
        )
    except Exception:  # a broken warning must never hide the detection result
        traceback.print_exc()
        result["warning_text"] = None
    by_flag = result.get("flag_messages") or {}
    result["red_flags"] = [
        {"code": code, "message_number": by_flag.get(code)} for code in codes
    ]
    return result


def probe_detector() -> str | None:
    """Check the real inference stack at startup.

    Importing scam_detector alone is not enough: torch and transformers are imported
    lazily inside model.py, so it would look ready and then fail on the first request.
    """
    try:
        import torch  # noqa: F401
        import transformers  # noqa: F401
    except Exception as exc:
        return f"{type(exc).__name__}: {exc}"

    from scam_detector.model_assets import DEFAULT_MODEL_DIR, MODEL_FILES

    missing = [name for name in MODEL_FILES if not (DEFAULT_MODEL_DIR / name).is_file()]
    if missing:
        return f"model files missing in {DEFAULT_MODEL_DIR} ({', '.join(missing)})"
    return None


class AppHandler(SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"   # keep-alive; every reply sets Content-Length
    def do_GET(self):
        if urlsplit(self.path).path != "/api/validation-set":
            return super().do_GET()

        files = sorted(
            path.name
            for path in (ROOT / "validation_set").iterdir()
            if path.is_file() and path.suffix.lower() == ".json" and not path.name.startswith(".")
        )
        self.reply(200, files)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/analyze":
            return self.send_error(404)

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self.reply(400, {"error": "Invalid Content-Length."})
        if length <= 0:
            return self.reply(400, {"error": "Empty request body."})
        if length > MAX_BODY_BYTES:
            return self.reply(413, {"error": "Scenario is too large."})

        try:
            scenario = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return self.reply(400, {"error": "Body must be a valid JSON scenario."})

        try:
            with _analyze_lock:
                payload = analyze(scenario)
        except Exception as exc:
            if isinstance(exc, ImportError) or type(exc).__name__ == "ModelSetupError":
                return self.reply(503, {
                    "error": str(exc) or "The detector environment is not set up.",
                    "hint": "python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt",
                })
            if isinstance(exc, ValueError):  # includes ScenarioError
                return self.reply(400, {"error": str(exc)})
            traceback.print_exc()
            return self.reply(500, {"error": f"{type(exc).__name__}: {exc}"})

        self.reply(200, payload)

    def reply(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    problem = probe_detector()
    print(f"Scam Shield: http://localhost:{PORT}", flush=True)
    if problem:
        print(f"Detector   : UNAVAILABLE ({problem})", flush=True)
        print("             Install once: python3 -m venv .venv && . .venv/bin/activate "
              "&& pip install -r requirements.txt", flush=True)
        print("             The page still loads, but scenarios will show no result.", flush=True)
    else:
        print("Detector   : ready", flush=True)

    handler = partial(AppHandler, directory=str(ROOT))
    with ThreadingHTTPServer(("127.0.0.1", PORT), handler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
