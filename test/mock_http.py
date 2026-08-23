import http.server
import json
import sys


BODY = b"hello-from-authz-mock"


class Handler(http.server.BaseHTTPRequestHandler):
    def respond(self):
        if self.path == "/identity":
            body = json.dumps({
                "user": self.headers.get("X-Authz-User"),
                "source": self.headers.get("X-Authz-Source"),
                "identity": self.headers.get("X-Authz-Identity"),
            }, separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def log_message(self, *args):
        pass


port = int(sys.argv[1]) if len(sys.argv) > 1 else 3456
http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
