import json
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


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
        body = json.dumps(files).encode("utf-8")
        self.send_response(200)
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
