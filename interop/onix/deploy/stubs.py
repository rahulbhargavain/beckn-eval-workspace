"""Stand-ins for the services around an ONIX adapter, stdlib only (runs under old system Pythons).
Port 443 (TLS, cert in OUT/certs): DeDi lookup, GET /registry/dedi/lookup/{subscriber}/subscribers.beckn.one/{keyId}
from registry.json. ONIX locks the registry URL to https://fabric.nfh.global/registry/dedi, so the caller maps that
host to 127.0.0.1 and trusts the throwaway CA; the response shape is the one ONIX's parser reads (UNVERIFIED against
the real DeDi service).
Port 3031: the BPP backend the adapter routes to; ACKs everything and appends each request to backend.log."""
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

OUT = sys.argv[1]
REG = json.load(open(f"{OUT}/registry.json"))


class Registry(BaseHTTPRequestHandler):
    def do_GET(self):
        parts = [unquote(p) for p in self.path.split("/") if p]
        if parts[:2] == ["registry", "dedi"]:
            parts = parts[2:]
        doc = None
        if len(parts) == 4 and parts[0] == "lookup" and parts[2] == "subscribers.beckn.one":
            doc = REG.get(parts[1], {}).get(parts[3])
        self.send_response(200 if doc else 404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(doc or {"error": "not found"}).encode())

    def log_message(self, *a):
        sys.stderr.write("registry %s\n" % (self.path,))


class Backend(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        with open(f"{OUT}/backend.log", "a") as f:
            f.write(json.dumps({"path": self.path, "bytes": len(body)}) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"message":{"ack":{"status":"ACK"}}}')

    def log_message(self, *a):
        pass


reg = HTTPServer(("127.0.0.1", 443), Registry)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(f"{OUT}/certs/server.crt", f"{OUT}/certs/server.key")
reg.socket = ctx.wrap_socket(reg.socket, server_side=True)
for srv in (reg, HTTPServer(("127.0.0.1", 3031), Backend)):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
print("stubs up", flush=True)
threading.Event().wait()
