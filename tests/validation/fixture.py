import http.server
import ssl
import os
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18234
CERT = sys.argv[2] if len(sys.argv) > 2 else None
ROOT = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nDisallow: /secret\n"
        elif self.path == "/sitemap.xml":
            body = b'<?xml version="1.0"?><urlset><url><loc>http://127.0.0.1:%d/hidden</loc></url></urlset>' % PORT
        elif self.path == "/app.js.map":
            body = b'{"version":3,"sources":["app.js"],"mappings":""}'
        else:
            body = b'<html><head><title>fixture</title></head><body><a href="/secret">secret</a></body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Set-Cookie", "session=abc")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

httpd = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
if CERT:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, CERT)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()