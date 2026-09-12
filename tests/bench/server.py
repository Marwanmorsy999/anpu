#!/usr/bin/env python3
"""ANPU benchmark fixture: deliberately vulnerable local target.

Serves a small set of PLANTED signals for `anpu bench` ground-truth
measurement. stdlib only, no dependencies.

Signals planted (see ground-truth.yml for the machine-readable list):
  /search?q=      reflected input, unescaped, in element content
  /go?url=        302 redirect to the supplied absolute URL
  /.env            fake secrets with KEY= assignments
  /backup.zip     generated-in-memory ZIP archive
  /               no security headers + links exposing the vectors above

Everything else is a short 404 (including the scanner's own control
paths). All fixture secrets are fake by construction.
"""
import io
import os
import sys
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

FAKE_ENV = (
    "# FAKE fixture secrets for ANPU benchmark calibration.\n"
    "# Not real credentials. Safe to commit.\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7FAKEKEY12\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYFAKEKEY12\n"
    "DATABASE_URL=postgres://bench:bench-fake-pw@localhost:5432/benchdb\n"
    "STRIPE_SECRET_KEY=sk_test_FAKEKEY000000000000000000\n"
)


def make_backup_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", "ANPU benchmark fixture backup. Fake content.\n")
        zf.writestr("config/app.conf", "debug=true # fake fixture config\n")
    return buf.getvalue()


BACKUP_ZIP = make_backup_zip()

INDEX = """<!doctype html>
<html><head><title>ANPU bench fixture</title></head>
<body>
<h1>ANPU benchmark fixture</h1>
<p>Deliberately vulnerable local target for ground-truth measurement.</p>
<ul>
<li><a href="/search?q=anpu">search</a></li>
<li><a href="/go?url=https://example.com/">redirect</a></li>
<li><a href="/backup.zip">backup</a></li>
</ul>
<form action="/search" method="get"><input name="q" value=""><input type="submit"></form>
<form action="/comment" method="post"><input name="author" value=""><input type="submit" value="comment"></form>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "BenchFixture/1.0"

    def log_message(self, *args):  # keep bench output clean
        pass

    def _send(self, code, body: bytes, ctype="text/html; charset=utf-8"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        qs = parse_qs(u.query)
        if path == "/":
            self._send(200, INDEX.encode())
        elif path == "/search":
            q = qs.get("q", [""])[0]
            # Deliberate reflection, unescaped, in element content.
            body = ("<!doctype html><html><head><title>search</title></head>"
                    f"<body><p>You searched for: {q}</p></body></html>")
            self._send(200, body.encode())
        elif path == "/go":
            dest = qs.get("url", [""])[0]
            # Deliberate open redirect to any absolute http(s) URL.
            if dest.startswith(("http://", "https://", "//")):
                raw = dest.encode()
                self.send_response(302)
                self.send_header("Location", dest)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            else:
                self._send(400, b"missing or relative url parameter")
        elif path == "/.env":
            self._send(200, FAKE_ENV.encode(), "text/plain; charset=utf-8")
        elif path == "/backup.zip":
            self._send(200, BACKUP_ZIP, "application/zip")
        else:
            self._send(404, b"not found: " + path.encode()[:64])

    do_HEAD = do_GET

    def do_POST(self):
        # Fixture accepts the comment form so crawlers register a form
        # endpoint (application-like surface). Nothing is stored.
        u = urlparse(self.path)
        if u.path == "/comment":
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(min(length, 65536))
            self._send(200, b"noted (fixture stores nothing)")
        else:
            self._send(404, b"not found")


if __name__ == "__main__":
    port = int(os.environ.get("BENCH_PORT", sys.argv[1] if len(sys.argv) > 1 else "8901"))
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"bench fixture on 127.0.0.1:{port}", flush=True)
    srv.serve_forever()
