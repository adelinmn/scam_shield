import json
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from scam_detector import analyze_scenario
from scam_detector.conversation import ScenarioError
from scam_detector.model import ModelSetupError


ROOT = Path(__file__).resolve().parent


class AppHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if urlsplit(self.path).path != "/api/validation-set":
            return super().do_GET()

        files = sorted(
            path.name
            for path in (ROOT / "validation_set").iterdir()
            if path.is_file() and path.suffix.lower() == ".json" and not path.name.startswith(".")
        )
        self.send_json(files)

    def do_POST(self):
        if urlsplit(self.path).path != "/api/analyze":
            self.send_json({"error": "Adresă necunoscută."}, HTTPStatus.NOT_FOUND)
            return
        if self.headers.get_content_type() != "application/json":
            self.send_json({"error": "Trimite un scenariu JSON."}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1:
                raise ValueError("Empty request body")
            scenario = json.loads(self.rfile.read(length))
        except (ValueError, RecursionError, OverflowError):
            self.send_json({"error": "Scenariul nu conține un JSON valid."}, HTTPStatus.BAD_REQUEST)
            return

        try:
            result = analyze_scenario(scenario)
        except ScenarioError:
            self.send_json({"error": "Scenariul nu respectă formatul așteptat."}, HTTPStatus.BAD_REQUEST)
            return
        except ModelSetupError as error:
            self.log_error("Detector setup: %s", error)
            self.send_json({"error": "Detectorul local nu este disponibil. Verifică instalarea modelului."},
                           HTTPStatus.SERVICE_UNAVAILABLE)
            return
        except Exception as error:
            self.log_error("Analysis failed: %s", type(error).__name__)
            self.send_json({"error": "Scenariul nu a putut fi analizat."}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        red_flags = [
            {"code": code, "message_number": message["n"]}
            for message in result["message_results"]
            for code in message["red_flags"]
        ]
        self.send_json({
            "id": result["id"],
            "verdict": result["verdict"],
            "risk_score": result["risk_score"],
            "scam_type": result["scam_type"],
            "first_alert": result["first_alert"],
            "red_flags": red_flags,
            "warning": (
                None if result["verdict"] == "SAFE"
                else "Verificați cererea printr-un canal oficial pe care îl cunoașteți."
            ),
        })

    def send_json(self, data, status=HTTPStatus.OK):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    handler = partial(AppHandler, directory=str(ROOT))
    with ThreadingHTTPServer(("127.0.0.1", 8000), handler) as server:
        print("Scam Shield: http://localhost:8000", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
