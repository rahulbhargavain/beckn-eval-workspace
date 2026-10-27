"""Audit fixes (docs/audit-conformance.md), tests first. Needs PyNaCl (mockup venv)."""
import base64
import copy
import hashlib
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import runner  # noqa: E402

SK = nacl_signing.SigningKey.generate()
KEY_ID = "h.example/keys/k1|ed25519"
IDENT = {"key_id": KEY_ID, "bap_id": "h.example", "bap_uri": "https://h.example/b", "network_id": "n",
         "private_key_seed_b64": base64.b64encode(bytes(SK)).decode()}
_ISSUER_SK = nacl_signing.SigningKey.generate()
ISSUER = {"key_id": "op/keys/1", "private_key_seed_b64": base64.b64encode(bytes(_ISSUER_SK)).decode()}
ISSUER_PUB = base64.b64encode(bytes(_ISSUER_SK.verify_key)).decode()
PROFILE = {"name": "p", "spec": "t", "role": "BPP"}
RE = re.compile(r'keyId="([^"]+)",algorithm="ed25519",created="(\d+)",expires="(\d+)",'
                r'headers="\(created\) \(expires\) digest",signature="([^"]+)"')


def sc(id="S1", **kw):
    d = {"id": id, "level": "mandatory", "roles": ["BPP"], "spec": "t",
         "request": {"method": "POST", "path": "/x", "body": {"context": {"action": "a"}, "message": {}}},
         "expect": {"status": 200}}
    d.update(kw)
    return d


def serve(handler):
    s = HTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s


def url(srv):
    return f"http://127.0.0.1:{srv.server_port}"


def const_handler(code=200, body=b'{"message":{"status":"ACK","messageId":"m"}}', headers=None, record=None):
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(n)  # always drain: replying early makes Windows abort the client (WinError 10053)
            if record is not None:
                record.append((raw, dict(self.headers)))
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass
    return H


@pytest.fixture
def ok_server():
    s = serve(const_handler())
    yield url(s)
    s.shutdown()


def signed_req(**extra):
    return {"method": "POST", "path": "/x", "auth": runner.SIGNED,
            "body": {"context": {"action": "a", "transactionId": "t"}, "message": {}}, **extra}


# ---- F3 / F4: assertion operators, strict jsonpath ---------------------------------------------
def test_literal_null_is_not_exists(ok_server):
    s = sc(expect={"status": 200, "jsonpath": {"$.message.messageId": None}})
    assert runner.run([s], PROFILE, ok_server, "p")["verdict"] == "FAILED"


def test_json_null_does_not_satisfy_type_operator():
    srv = serve(const_handler(body=b'{"message":{"error":{"code":null}}}'))
    try:
        s = sc(expect={"status": 200, "jsonpath": {"$.message.error.code": {"type": "string"}}})
        assert runner.run([s], PROFILE, url(srv), "p")["verdict"] == "FAILED"
    finally:
        srv.shutdown()


@pytest.mark.parametrize("op,good", [({"exists": True}, True), ({"type": "string"}, True),
                                     ({"enum": ["ACK", "X"]}, True), ({"pattern": "^AC"}, True),
                                     ({"enum": ["NACK"]}, False), ({"type": "integer"}, False),
                                     ({"pattern": "^N"}, False)])
def test_operators(ok_server, op, good):
    s = sc(expect={"status": 200, "jsonpath": {"$.message.status": op}})
    assert (runner.run([s], PROFILE, ok_server, "p")["verdict"] == "CERTIFIED") is good


def test_literal_is_type_strict():
    assert runner.values_match(1, 1) and not runner.values_match(1, True)
    assert not runner.values_match(True, 1) and runner.values_match(True, True)


@pytest.mark.parametrize("bad", ["$.message.@type.x", "$['message'", "$message.status", "message", "$.a..b", "$."])
def test_bad_jsonpath_raises(bad):
    with pytest.raises(runner.ScenarioError):
        runner.jsonpath({"message": {}}, bad)


def test_quoted_keys_supported():
    doc = {"a": {"@type": 5, "x:y": 6}}
    assert runner.jsonpath(doc, "$.a['@type']") == 5
    assert runner.jsonpath(doc, "$.a['x:y']") == 6


def test_status_in_and_headers(ok_server):
    assert runner.run([sc(expect={"status_in": [200, 202]})], PROFILE, ok_server, "p")["verdict"] == "CERTIFIED"
    srv = serve(const_handler(headers={"Signature": 'Signature keyId="k",algorithm="ed25519"'}))
    try:
        good = sc(expect={"status": 200, "headers": {"signature": {"pattern": "keyId="}}})
        bad = sc(expect={"status": 200, "headers": {"X-Missing": {"exists": True}}})
        assert runner.run([good], PROFILE, url(srv), "p")["verdict"] == "CERTIFIED"
        assert runner.run([bad], PROFILE, url(srv), "p")["verdict"] == "FAILED"
    finally:
        srv.shutdown()


def test_message_id_echo_template():
    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            doc = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps({"message": {"messageId": doc["context"]["messageId"]}}).encode())

        def log_message(self, *a):
            pass
    srv = serve(H)
    try:
        s = sc(request=signed_req(),
               expect={"status": 200, "jsonpath": {"$.message.messageId": "{{request.context.messageId}}"}})
        rep = runner.run([s], PROFILE, url(srv), "p", identity=IDENT)
        assert rep["verdict"] == "CERTIFIED", rep["results"]
    finally:
        srv.shutdown()


# ---- F5: scenario validation -------------------------------------------------------------------
@pytest.mark.parametrize("patch", [{"level": "Mandatory"}, {"roles": ["bpp"]}, {"roles": []}, {"bogus": 1},
                                   {"request": {"path": "/x", "fault": "nope", "auth": runner.SIGNED}},
                                   {"expect": {}}, {"expect": {"status": 200, "status_in": [200]}}])
def test_invalid_scenarios_rejected(ok_server, patch):
    with pytest.raises(runner.ScenarioError):
        runner.run([sc(**patch)], PROFILE, ok_server, "p")


def test_loader_rejects_file_without_id(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps({"name": "legacy"}))
    with pytest.raises(runner.ScenarioError):
        runner.load_scenarios(tmp_path)


def test_loader_accepts_bom(tmp_path):
    (tmp_path / "a.json").write_bytes(b"\xef\xbb\xbf" + json.dumps(sc()).encode())
    assert runner.load_scenarios(tmp_path)[0]["id"] == "S1"


# ---- F6 / F7 / F8 / F10 / F11: request safety --------------------------------------------------
def test_redirect_not_followed_and_auth_not_forwarded():
    seen = []
    target = serve(const_handler(record=seen))
    redir = serve(const_handler(code=302, headers={"Location": url(target) + "/x"}))
    try:
        rep = runner.run([sc(request=signed_req())], PROFILE, url(redir), "p", identity=IDENT)
        assert rep["verdict"] == "FAILED" and seen == []
    finally:
        target.shutdown()
        redir.shutdown()


@pytest.mark.parametrize("body", ["../secret.json", "sub/../../secret.json"])
def test_body_path_traversal_rejected(tmp_path, ok_server, body):
    root = tmp_path / "fx"
    root.mkdir()
    (tmp_path / "secret.json").write_text("{}")
    s = sc(request={"method": "POST", "path": "/x", "body": body})
    rep = runner.run([s], PROFILE, ok_server, "p", fixtures_root=root)
    assert rep["verdict"] == "FAILED" and "outside" in rep["results"][0]["detail"]


def test_absolute_body_path_rejected(tmp_path, ok_server):
    f = tmp_path / "secret.json"
    f.write_text("{}")
    s = sc(request={"method": "POST", "path": "/x", "body": str(f)})
    assert runner.run([s], PROFILE, ok_server, "p", fixtures_root=tmp_path / "other")["verdict"] == "FAILED"


@pytest.mark.parametrize("path", [".attacker.test/x", "x", "//evil.test/x", "/a b"])
def test_bad_request_path_rejected(ok_server, path):
    s = sc(request={"method": "POST", "path": path, "body": {}})
    rep = runner.run([s], PROFILE, ok_server, "p")
    assert rep["verdict"] == "FAILED" and "path" in rep["results"][0]["detail"]


def test_bad_base_url_scheme():
    rep = runner.run([sc()], PROFILE, "file:///etc/passwd", "p")
    assert rep["verdict"] == "FAILED" and "base_url" in rep["results"][0]["detail"]


def test_inline_body_not_mutated(ok_server):
    s = sc(request=signed_req(fault="missing-message"))
    before = copy.deepcopy(s)
    runner.run([s], PROFILE, ok_server, "p", identity=IDENT)
    assert s == before


def test_long_server_text_truncated():
    srv = serve(const_handler(body=json.dumps({"message": {"status": "A" * 5000}}).encode()))
    try:
        s = sc(expect={"status": 200, "jsonpath": {"$.message.status": "B"}})
        rep = runner.run([s], PROFILE, url(srv), "p")
        assert len(rep["results"][0]["detail"]) < 400
    finally:
        srv.shutdown()


# ---- F12 / F14: replay faults ------------------------------------------------------------------
def test_replay_sends_different_authorization_header():
    seen = []
    srv = serve(const_handler(record=seen))
    try:
        runner.run([sc(request=signed_req(fault="replay"))], PROFILE, url(srv), "p", identity=IDENT)
        assert len(seen) == 2 and seen[0][0] == seen[1][0]
        assert seen[0][1]["Authorization"] != seen[1][1]["Authorization"]
    finally:
        srv.shutdown()


def test_replay_new_body_keeps_message_id_changes_body():
    seen = []
    srv = serve(const_handler(record=seen))
    try:
        runner.run([sc(request=signed_req(fault="replay-new-body"))], PROFILE, url(srv), "p", identity=IDENT)
        a, b = (json.loads(x[0])["context"] for x in seen)
        assert a["messageId"] == b["messageId"] and a["transactionId"] != b["transactionId"]
    finally:
        srv.shutdown()


def test_replay_precondition_accepts_202():
    srv = serve(const_handler(code=202))
    try:
        s = sc(request=signed_req(fault="replay"), expect={"status": 202})
        rep = runner.run([s], PROFILE, url(srv), "p", identity=IDENT)
        assert "precondition" not in rep["results"][0]["detail"]
    finally:
        srv.shutdown()


# ---- F1 / F2 / F9: scenario pinning and report authenticity ------------------------------------
def pinned(tmp_path, ids=("S1", "S2")):
    scs = [sc(i) for i in ids]
    return scs, runner.pin_profile(PROFILE, scs, tmp_path)


def signed_report(scs, prof, base, tmp_path, **kw):
    return runner.run(scs, prof, base, "alice", fixtures_root=tmp_path, issuer=ISSUER, **kw)


def adm(rep, prof, **kw):
    args = dict(spec="t", role="BPP", participant="alice", profile=prof, issuer_public_key_b64=ISSUER_PUB)
    args.update(kw)
    return runner.admit(rep, **args)


def test_pinned_full_run_is_admitted(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    rep = signed_report(scs, prof, ok_server, tmp_path)
    assert rep["verdict"] == "CERTIFIED", rep["results"]
    assert adm(rep, prof) == (True, "ok")


def test_subset_of_required_scenarios_is_incomplete(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    rep = signed_report(scs[:1], prof, ok_server, tmp_path)
    assert rep["verdict"] == "INCOMPLETE" and not adm(rep, prof)[0]


def test_altered_scenario_is_incomplete(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    scs[1]["expect"] = {"status": 200, "jsonpath": {}}
    assert signed_report(scs, prof, ok_server, tmp_path)["verdict"] == "INCOMPLETE"


def test_admit_rederives_from_results_not_verdict(ok_server, tmp_path):
    """Operator-signed but with empty results must still be refused by the registry."""
    scs, prof = pinned(tmp_path)
    rep = signed_report(scs, prof, ok_server, tmp_path)
    rep["results"] = []
    assert not adm(runner.resign(rep, ISSUER), prof)[0]


def test_admit_rejects_unsigned_and_wrong_issuer(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    unsigned = runner.run(scs, prof, ok_server, "alice", fixtures_root=tmp_path)
    assert "signature" in adm(unsigned, prof)[1]
    rep = signed_report(scs, prof, ok_server, tmp_path)
    other = base64.b64encode(bytes(nacl_signing.SigningKey.generate().verify_key)).decode()
    assert not adm(rep, prof, issuer_public_key_b64=other)[0]


def test_forged_report_with_recomputed_digest_rejected(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    rep = signed_report(scs, prof, ok_server, tmp_path)
    rep["participant"] = "mallory"
    rep["digest"] = runner.digest(rep)
    assert not adm(rep, prof, participant="mallory")[0]


def test_admit_checks_participant_profile_spec_role(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    rep = signed_report(scs, prof, ok_server, tmp_path)
    assert not adm(rep, prof, participant="bob")[0]
    assert not adm(rep, prof, spec="u")[0]
    assert not adm(rep, prof, role="BAP")[0]
    assert not adm(rep, dict(prof, name="other"))[0]


def test_admit_rejects_future_and_stale(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    future = signed_report(scs, prof, ok_server, tmp_path, now=time.time() + 10**8)
    assert "future" in adm(future, prof)[1]
    rep = signed_report(scs, prof, ok_server, tmp_path)
    assert not adm(rep, prof, now=rep["issued_at"] + 10**9)[0]


def test_admit_requires_pinned_profile(ok_server, tmp_path):
    scs, _ = pinned(tmp_path)
    rep = signed_report(scs, PROFILE, ok_server, tmp_path)
    assert not adm(rep, PROFILE)[0]


@pytest.mark.parametrize("junk", [{"x": 1}, [], "s", None, {"digest": "x"}])
def test_admit_never_raises(junk, tmp_path):
    _, prof = pinned(tmp_path)
    ok, why = adm(junk, prof)
    assert ok is False and isinstance(why, str)


def test_report_binds_target_and_harness(ok_server, tmp_path):
    scs, prof = pinned(tmp_path)
    rep = signed_report(scs, prof, ok_server, tmp_path, identity=IDENT)
    assert rep["base_url"] == ok_server and rep["harness_key_id"] == KEY_ID
    assert set(rep["scenario_hashes"]) == {"S1", "S2"} and "runner_version" in rep
    assert IDENT["private_key_seed_b64"] not in json.dumps(rep)


# ---- the mutant the audit showed was wrongly CERTIFIED -----------------------------------------
class Mutant(BaseHTTPRequestHandler):
    seen = set()

    def reply(self, code, status):
        self.send_response(code)
        self.end_headers()  # no Signature header
        self.wfile.write(json.dumps({"message": {"status": status, "error": {"code": "X"}}}).encode())

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        auth = self.headers.get("Authorization", "")
        m = RE.search(auth)
        if not m or m.group(1) != KEY_ID:
            return self.reply(401, "NACK")
        d = "BLAKE2b-512=" + base64.b64encode(hashlib.blake2b(raw, digest_size=64).digest()).decode()
        try:
            SK.verify_key.verify(f"(created): {m.group(2)}\n(expires): {m.group(3)}\ndigest: {d}".encode(),
                                 base64.b64decode(m.group(4)))
        except Exception:
            return self.reply(401, "NACK")
        try:
            doc = json.loads(raw)
            doc["message"]
        except (ValueError, KeyError):
            return self.reply(400, "NACK")
        if auth in Mutant.seen:  # replay cache keyed on header string
            return self.reply(400, "NACK")
        Mutant.seen.add(auth)
        self.reply(200, "ACK")

    def log_message(self, *a):
        pass


def test_repo_scenarios_reject_the_audit_mutant():
    Mutant.seen.clear()
    srv = serve(Mutant)
    try:
        scs = runner.load_scenarios(runner.DEFAULT_SCENARIOS)
        for role in ("DS", "BPP"):
            rep = runner.run(scs, {"name": "x", "spec": "s", "role": role}, url(srv), "m", identity=IDENT)
            assert rep["verdict"] == "FAILED", [r for r in rep["results"] if r["outcome"] == "pass"]
    finally:
        srv.shutdown()


def test_repo_profiles_are_pinned_and_current():
    scs = runner.load_scenarios(runner.DEFAULT_SCENARIOS)
    for name, role in (("ds-core", "DS"), ("bpp-core", "BPP")):
        path = runner.ROOT / "conformance" / "profiles" / f"{name}.json"
        prof = json.loads(path.read_text(encoding="utf-8-sig"))
        assert prof["role"] == role and prof["spec"] == "beckn-2.0.0"
        assert prof["required"] == runner.pin_profile(prof, scs, runner.DEFAULT_FIXTURES)["required"]
        assert len(prof["required"]) >= 3
