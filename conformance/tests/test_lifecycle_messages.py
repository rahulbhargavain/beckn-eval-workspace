"""Auditability and clarity for lifecycle runs: the report pins the seed it used, and a node that answers a
callback step with 202 AckNoCallback is told so (the spec allows 202, but a lifecycle step needs its callback)."""
import base64
import hashlib
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import callbacks, runner  # noqa: E402

PROFILE = {"name": "p", "spec": "beckn-2.0.0", "role": "BPP"}
SEED = {"select": {"contract": {"commitments": []}}}


def canonical_sha256(doc):
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_the_report_pins_the_seed_by_hash_not_by_content():
    rep = runner.run([], PROFILE, "http://127.0.0.1:9", "p", seed=SEED)
    assert rep["seed_sha256"] == canonical_sha256(SEED)
    assert "commitments" not in json.dumps(rep)  # the seed itself may hold node-private detail


def test_a_run_without_a_seed_says_so_in_the_report():
    assert runner.run([], PROFILE, "http://127.0.0.1:9", "p")["seed_sha256"] is None


def test_the_seed_hash_is_covered_by_the_report_digest():
    rep = runner.run([], PROFILE, "http://127.0.0.1:9", "p", seed=SEED)
    forged = dict(rep, seed_sha256=canonical_sha256({"other": 1}))
    assert runner.digest(forged) != rep["digest"]


class Declines(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(202)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"message":{"status":"ACK"}}')

    def log_message(self, *a):
        pass


def test_202_on_a_callback_step_is_explained():
    srv = HTTPServer(("127.0.0.1", 0), Declines)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with callbacks.CallbackListener({}) as lis:
            ident = {"key_id": "h/keys/k|ed25519", "bap_id": "h", "bap_uri": lis.url, "network_id": "n",
                     "private_key_seed_b64": base64.b64encode(bytes(nacl_signing.SigningKey.generate())).decode()}
            s = {"id": "X", "level": "mandatory", "roles": ["BPP"], "spec": "s",
                 "request": {"method": "POST", "path": "/select", "auth": runner.SIGNED,
                             "body": {"context": {"action": "select"}, "message": {"contract": {}}}},
                 "expect": {"status": 200, "callback": {"action": "on_select", "within": 1}}}
            ok, why = runner._check(s, f"http://127.0.0.1:{srv.server_address[1]}", 5, runner.DEFAULT_FIXTURES, ident,
                                    {}, lis)
        assert not ok and "202" in why and "no callback" in why and "seed" in why, why
    finally:
        srv.shutdown()
