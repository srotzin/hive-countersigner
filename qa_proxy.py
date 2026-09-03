"""Local QA shim. Serves /home/user/workspace/site statically and forwards the
briefing API paths to the local countersigner, mirroring the Render route
rewrites so Playwright sees the same same-origin behaviour as production.
Not deployed. Test scaffolding only."""
import http.server
import socketserver
import urllib.request
import urllib.error

SITE = "/home/user/workspace/site"
BACKEND = "http://127.0.0.1:8791"
API = ("/briefing/issue", "/briefing/check", "/briefing/qr", "/briefing/receipt")


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=SITE, **kw)

    def _is_api(self):
        p = self.path.split("?")[0]
        return any(p == a or p.startswith(a + "/") for a in API)

    def _proxy(self, body=None):
        req = urllib.request.Request(
            BACKEND + self.path, data=body, method=self.command,
            headers={k: v for k, v in self.headers.items()
                     if k.lower() in ("content-type", "accept")})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                data, status, ctype = r.read(), r.status, r.headers.get("Content-Type")
        except urllib.error.HTTPError as e:
            data, status, ctype = e.read(), e.code, e.headers.get("Content-Type")
        self.send_response(status)
        self.send_header("Content-Type", ctype or "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self._is_api():
            return self._proxy()
        return super().do_GET()

    def do_POST(self):
        if self._is_api():
            n = int(self.headers.get("Content-Length") or 0)
            return self._proxy(self.rfile.read(n))
        self.send_error(405)

    def log_message(self, *a):
        pass


class S(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


S(("127.0.0.1", 4173), H).serve_forever()
