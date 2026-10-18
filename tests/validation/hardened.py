import http.server, ssl, sys

PORT = int(sys.argv[1])
CERT = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<html><head><title>hardened</title></head><body>ok</body></html>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=()")
        self.send_header("Set-Cookie", "session=abc; Secure; HttpOnly; SameSite=Strict")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

httpd = http.server.HTTPServer(("0.0.0.0", PORT), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, CERT)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()