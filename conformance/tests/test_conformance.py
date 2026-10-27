"""Tests for the Peppol-style conformance runner (written before the runner).

Model: a participant runs the mandatory scenarios for its role against a test
endpoint; the runner emits a digest-protected report; the registry admits only
participants whose report is CERTIFIED, intact, for the right spec, and fresh.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from conformance import runner


class Stub(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        body = json.dumps({"message": {"ack": {"status": "ACK"}}}).encode()
        self.send_response(200 if self.path != "/bad" else 500)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    s = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{s.server_port}"
    s.shutdown()


def scenario(id, level="mandatory", path="/search", jp=None, roles=("BPP",), **kw):
    return {"id": id, "level": level, "roles": list(roles), "spec": "t-1",
            "request": {"method": "POST", "path": path, "body": {"x": 1}},
            "expect": {"status": 200, "jsonpath": jp or {}}, **kw}


PROFILE = {"name": "bpp-core", "spec": "t-1", "role": "BPP"}


def test_jsonpath_lite():
    d = {"a": {"b": [{"c": 5}]}}
    assert runner.jsonpath(d, "$.a.b[0].c") == 5
    assert runner.jsonpath(d, "$.a.z") is runner.MISSING


def test_all_mandatory_pass_is_certified(server):
    sc = [scenario("S1", jp={"$.message.ack.status": "ACK"})]
    rep = runner.run(sc, PROFILE, server, participant="bpp.example")
    assert rep["verdict"] == "CERTIFIED"


def test_failed_mandatory_blocks_certification(server):
    sc = [scenario("S1"), scenario("S2", path="/bad")]
    assert runner.run(sc, PROFILE, server, "p")["verdict"] == "FAILED"


def test_failed_recommended_only_warns(server):
    sc = [scenario("S1"), scenario("S2", level="recommended", path="/bad")]
    rep = runner.run(sc, PROFILE, server, "p")
    assert rep["verdict"] == "CERTIFIED" and rep["warnings"] == ["S2"]


def test_pending_mandatory_is_not_certifiable(server):
    sc = [scenario("S1"), scenario("S2", pending=True)]
    assert runner.run(sc, PROFILE, server, "p")["verdict"] == "INCOMPLETE"


def test_role_filter(server):
    sc = [scenario("S1"), scenario("S2", path="/bad", roles=("BAP",))]
    assert runner.run(sc, PROFILE, server, "p")["verdict"] == "CERTIFIED"


def test_unreachable_endpoint_fails():
    rep = runner.run([scenario("S1")], PROFILE, "http://127.0.0.1:9", "p", timeout=1)
    assert rep["verdict"] == "FAILED"


def test_no_applicable_scenarios_is_incomplete(server):
    assert runner.run([], PROFILE, server, "p")["verdict"] == "INCOMPLETE"


def test_jsonpath_mismatch_fails(server):
    sc = [scenario("S1", jp={"$.message.ack.status": "NACK"})]
    assert runner.run(sc, PROFILE, server, "p")["verdict"] == "FAILED"


def test_admit_accepts_good_report(server):
    rep = runner.run([scenario("S1")], PROFILE, server, "p")
    assert runner.admit(rep, spec="t-1", role="BPP") == (True, "ok")


def test_admit_rejects_tampered_report(server):
    rep = runner.run([scenario("S1", path="/bad")], PROFILE, server, "p")
    rep["verdict"] = "CERTIFIED"
    ok, why = runner.admit(rep, spec="t-1", role="BPP")
    assert not ok and "digest" in why


def test_admit_rejects_wrong_spec_role_and_stale(server):
    rep = runner.run([scenario("S1")], PROFILE, server, "p")
    assert not runner.admit(rep, spec="t-2", role="BPP")[0]
    assert not runner.admit(rep, spec="t-1", role="BAP")[0]
    assert not runner.admit(rep, spec="t-1", role="BPP", now=rep["issued_at"] + 10**9)[0]


def test_report_is_deterministic_digest(server):
    rep = runner.run([scenario("S1")], PROFILE, server, "p")
    assert rep["digest"] == runner.digest(rep)


def test_load_scenarios_skips_files_without_id(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(scenario("A")))
    (tmp_path / "b.json").write_text(json.dumps({"name": "legacy"}))
    assert [s["id"] for s in runner.load_scenarios(tmp_path)] == ["A"]
