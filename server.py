import http.server
import socketserver
import ssl
import base64

USERNAME = "username"
PASSWORD = "pass"

auth_string_plaintext = USERNAME + ":" + PASSWORD
b64_auth_string = str(base64.b64encode(auth_string_plaintext.encode("utf-8")), "utf-8")
AUTH_TOKEN = "Basic " + b64_auth_string

class RequestHandler(http.server.BaseHTTPRequestHandler):
    def send(self, status_code, message):
        self.protocol_version = "HTTP/1.1"
        self.send_response(status_code)
        self.send_header("Content-Length", len(message))
        self.end_headers()
        self.wfile.write(bytes(message, "utf8"))

    def send_authhead(self):
        self.protocol_version = "HTTP/1.1"
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="User Visible Realm", charset="UTF-8"')
        self.end_headers()

    def do_GET(self):
        message = "Hello!"

        auth_header = self.headers.get("authorization")
        if not auth_header == AUTH_TOKEN:
            self.send_authhead()
            return

        self.send(200, "Hello!")
        return

PORT = 8443
Handler = RequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print("serving at port", PORT)
    httpd.socket = ssl.wrap_socket(httpd.socket,
        keyfile="key.pem",
        certfile='certificate.pem', server_side=True)
    httpd.serve_forever()
