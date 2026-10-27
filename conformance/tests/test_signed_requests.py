"""Signed-request support in the conformance runner (tests written first).

Spec: Beckn 2.0.0 docs/Authentication_and_Trust.md - Authorization header with
keyId/created/expires/headers="(created) (expires) digest", digest BLAKE2b-512
over the exact body bytes, Ed25519 over the 3-line signing string.
Needs PyNaCl: run with the mockup venv (see docs/conformance.md).
"""
import base64
import hashlib
import json
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import runner  # noqa: E402

SEEN = []
SK = nacl_signing.SigningKey.generate()
IDENT = {"key_id": "h.example/keys/k1|ed25519", "bap_id": "h.example", "bap_uri": "https://h.example/b",
         "network_id": "example.org/net",
         "private_key_seed_b64": base64.b64encode(bytes(SK)).decode()}
RE = re.compile(r'keyId="([^"]+)",algorithm="ed25519",created="(\d+)",expires="(\d+)",'
                r'headers="\(created\) \(expires\) digest",signature="([^"]+)"')


class Verifier(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        m = RE.search(self.headers.get("Authorization", ""))
        ok = False
        if m:
            kid, c, e, sig = m.groups()
            digest = "BLAKE2b-512=" + base64.b64encode(hashlib.blake2b(raw, digest_size=64).digest()).decode()
            text = f"(created): {c}\n(expires): {e}\ndigest: {digest}"
            try:
                SK.verify_key.verify(text.encode(), base64.b64decode(sig))
                ok = kid == IDENT["key_id"] and int(e) > int(c)
            except Exception:
                ok = False
        SEEN.append(json.loads(raw))
        self.send_response(200 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"message": {"status": "ACK" if ok else "NACK"}}).encode())

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    SEEN.clear()
    s = HTTPServer(("127.0.0.1", 0), Verifier)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


def signed_scenario(tmp_path, id="S1"):
    (tmp_path / "b.json").write_text(json.dumps(
        {"context": {"action": "discover", "version": "2.0.0", "bapId": "x", "messageId": "x"}, "message": {}}))
    return {"id": id, "level": "mandatory", "roles": ["BPP"], "spec": "t",
            "request": {"method": "POST", "path": "/discover", "body": "b.json", "auth": "beckn-http-signature"},
            "expect": {"status": 200, "jsonpath": {"$.message.status": "ACK"}}}


PROFILE = {"name": "bpp-core", "spec": "t", "role": "BPP"}


def test_signed_request_accepted(server, tmp_path):
    rep = runner.run([signed_scenario(tmp_path)], PROFILE, server, "p", fixtures_root=tmp_path, identity=IDENT)
    assert rep["verdict"] == "CERTIFIED", rep["results"]


def test_context_is_templated_with_fresh_message_id(server, tmp_path):
    sc = [signed_scenario(tmp_path, "S1"), signed_scenario(tmp_path, "S2")]
    runner.run(sc, PROFILE, server, "p", fixtures_root=tmp_path, identity=IDENT)
    a, b = (m["context"] for m in SEEN)
    assert a["bapId"] == "h.example" and a["bapUri"] == "https://h.example/b"
    assert a["networkId"] == "example.org/net"
    assert uuid.UUID(a["messageId"]) and a["messageId"] != b["messageId"]


def test_missing_identity_fails_not_skips(server, tmp_path):
    rep = runner.run([signed_scenario(tmp_path)], PROFILE, server, "p", fixtures_root=tmp_path)
    assert rep["verdict"] == "FAILED" and "identity" in rep["results"][0]["detail"]
    assert SEEN == []


def test_wrong_key_is_rejected_by_server(server, tmp_path):
    bad = dict(IDENT, private_key_seed_b64=base64.b64encode(bytes(nacl_signing.SigningKey.generate())).decode())
    rep = runner.run([signed_scenario(tmp_path)], PROFILE, server, "p", fixtures_root=tmp_path, identity=bad)
    assert rep["verdict"] == "FAILED"


def test_unsigned_scenarios_unaffected(server, tmp_path):
    sc = signed_scenario(tmp_path)
    del sc["request"]["auth"]
    rep = runner.run([sc], PROFILE, server, "p", fixtures_root=tmp_path)
    assert rep["verdict"] == "FAILED"  # server answers 401 to unsigned


def test_identity_secret_never_in_report(server, tmp_path):
    rep = runner.run([signed_scenario(tmp_path)], PROFILE, server, "p", fixtures_root=tmp_path, identity=IDENT)
    assert IDENT["private_key_seed_b64"] not in json.dumps(rep)


def test_real_scenario_001_is_loadable_and_mandatory():
    ids = {s["id"]: s for s in runner.load_scenarios(runner.DEFAULT_SCENARIOS)}
    assert ids["DISC-001"]["level"] == "mandatory" and "BPP" in ids["DISC-001"]["roles"]
