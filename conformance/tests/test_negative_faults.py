"""Fault-injection scenarios (tests first). A scenario's request.fault makes the runner
send a deliberately wrong request; the server MUST reject it. A permissive server
(accepts everything) must therefore FAIL these scenarios.

Spec basis (Beckn 2.0.0): bad/unknown signer -> 401 Nack (beckn.yaml, AUT_* codes);
duplicate messageId -> `400 NackBadRequest` (Authentication_and_Trust.md 10.1);
malformed payload -> 400 Nack (SCH_*). Unknown-participant 401 is an assumption: the
spec lists AUT_SUBSCRIBER_NOT_FOUND / AUT_KEY_NOT_FOUND without fixing the status.
"""
import base64
import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import runner  # noqa: E402

SK = nacl_signing.SigningKey.generate()
KEY_ID = "h.example/keys/k1|ed25519"
IDENT = {"key_id": KEY_ID, "bap_id": "h.example", "bap_uri": "https://h.example/b",
         "network_id": "example.org/net", "private_key_seed_b64": base64.b64encode(bytes(SK)).decode()}
RE = re.compile(r'keyId="([^"]+)",algorithm="ed25519",created="(\d+)",expires="(\d+)",'
                r'headers="\(created\) \(expires\) digest",signature="([^"]+)"')
PROFILE = {"name": "bpp-core", "spec": "t", "role": "BPP"}


def make_server(strict=True):
    seen = set()

    class H(BaseHTTPRequestHandler):
        def reply(self, code, status="NACK"):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"message": {"status": status, "error": {"code": "X"}}}).encode())

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if not strict:
                return self.reply(200, "ACK")
            m = RE.search(self.headers.get("Authorization", ""))
            if not m or m.group(1) != KEY_ID:
                return self.reply(401)
            kid, c, e, sig = m.groups()
            d = "BLAKE2b-512=" + base64.b64encode(hashlib.blake2b(raw, digest_size=64).digest()).decode()
            try:
                SK.verify_key.verify(f"(created): {c}\n(expires): {e}\ndigest: {d}".encode(), base64.b64decode(sig))
            except Exception:
                return self.reply(401)
            try:
                doc = json.loads(raw)
                mid = doc["context"]["messageId"]
                doc["message"]
            except (ValueError, KeyError):
                return self.reply(400)
            if mid in seen:
                return self.reply(400)
            seen.add(mid)
            self.reply(200, "ACK")

        def log_message(self, *a):
            pass

    s = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


@pytest.fixture
def strict():
    s = make_server(True)
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


@pytest.fixture
def lax():
    s = make_server(False)
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


def neg(tmp_path, fault, status):
    (tmp_path / "b.json").write_text(json.dumps(
        {"context": {"action": "discover", "version": "2.0.0"}, "message": {"intent": {}}}))
    return {"id": "N-" + fault, "level": "mandatory", "roles": ["BPP"], "spec": "t",
            "request": {"method": "POST", "path": "/discover", "body": "b.json",
                        "auth": "beckn-http-signature", "fault": fault},
            "expect": {"status": status, "jsonpath": {"$.message.status": "NACK", "$.message.error.code": {"type": "string"}}}}


CASES = [("bad-signature", 401), ("unknown-participant", 401), ("replay", 400), ("replay-new-body", 400),
         ("invalid-json", 400), ("missing-message", 400)]


@pytest.mark.parametrize("fault,status", CASES)
def test_strict_server_passes(strict, tmp_path, fault, status):
    rep = runner.run([neg(tmp_path, fault, status)], PROFILE, strict, "p", fixtures_root=tmp_path, identity=IDENT)
    assert rep["verdict"] == "CERTIFIED", rep["results"]


@pytest.mark.parametrize("fault,status", CASES)
def test_permissive_server_fails(lax, tmp_path, fault, status):
    rep = runner.run([neg(tmp_path, fault, status)], PROFILE, lax, "p", fixtures_root=tmp_path, identity=IDENT)
    assert rep["verdict"] == "FAILED"


def test_replay_requires_first_request_accepted(strict, tmp_path):
    """If the first (legitimate) send is not accepted the replay result proves nothing."""
    bad = dict(IDENT, private_key_seed_b64=base64.b64encode(bytes(nacl_signing.SigningKey.generate())).decode())
    rep = runner.run([neg(tmp_path, "replay", 400)], PROFILE, strict, "p", fixtures_root=tmp_path, identity=bad)
    assert rep["verdict"] == "FAILED" and "precondition" in rep["results"][0]["detail"]


def test_unknown_fault_name_is_a_scenario_error(strict, tmp_path):
    with pytest.raises(runner.ScenarioError):
        runner.run([neg(tmp_path, "nonsense", 400)], PROFILE, strict, "p", fixtures_root=tmp_path, identity=IDENT)


def test_repo_negative_scenarios_exist_and_are_mandatory():
    s = {x["id"]: x for x in runner.load_scenarios(runner.DEFAULT_SCENARIOS)}
    for sid in ("NEG-001", "NEG-002", "NEG-003", "NEG-004", "NEG-005", "NEG-006",
                "PNNEG-001", "PNNEG-002", "PNNEG-003", "PNNEG-004"):
        assert s[sid]["level"] == "mandatory" and s[sid]["request"]["fault"]
