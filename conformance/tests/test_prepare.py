"""Safety rails for running against a shared public network (tests first)."""
import base64
import json
import os
import stat
import time

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import keygen, runner  # noqa: E402

PROFILE = {"name": "p", "spec": "t", "role": "BPP"}


def sc(id="S1", **kw):
    d = {"id": id, "level": "mandatory", "roles": ["BPP"], "spec": "t",
         "request": {"method": "POST", "path": "/x", "auth": runner.SIGNED, "body": {"context": {}, "message": {}}},
         "expect": {"status": 200}}
    d.update(kw)
    return d


IDENT = {"key_id": "k", "bap_id": "b", "bap_uri": "https://b.example", "network_id": "n",
         "private_key_seed_b64": base64.b64encode(bytes(nacl_signing.SigningKey.generate())).decode()}


def test_remote_host_refused_without_allowlist():
    with pytest.raises(runner.TargetNotAllowed):
        runner.run([sc()], PROFILE, "https://node.example.org", "p", identity=IDENT)


def test_remote_host_allowed_when_listed_and_loopback_always_ok(monkeypatch):
    sent = []
    monkeypatch.setattr(runner, "_send", lambda *a, **k: sent.append(a[0]) or (200, {}, b"{}"))
    runner.run([sc()], PROFILE, "https://node.example.org", "p", identity=IDENT, allow_hosts={"node.example.org"})
    runner.run([sc()], PROFILE, "http://127.0.0.1:1", "p", identity=IDENT)
    assert sent == ["https://node.example.org/x", "http://127.0.0.1:1/x"]


def test_allowlist_matches_exact_host_not_suffix():
    with pytest.raises(runner.TargetNotAllowed):
        runner.run([sc()], PROFILE, "https://node.example.org.evil.test", "p", identity=IDENT,
                   allow_hosts={"node.example.org"})


def test_plain_http_to_remote_refused_even_if_allowed():
    with pytest.raises(runner.TargetNotAllowed):
        runner.run([sc()], PROFILE, "http://node.example.org", "p", identity=IDENT, allow_hosts={"node.example.org"})


def test_dry_run_sends_nothing_and_lists_plan(monkeypatch):
    monkeypatch.setattr(runner, "_send", lambda *a, **k: pytest.fail("network used"))
    plan = runner.plan([sc("A", request={"method": "POST", "path": "/x", "auth": runner.SIGNED, "fault": "replay",
                                          "body": {}}), sc("B")], PROFILE, "https://node.example.org")
    assert [(p["id"], p["url"], p["fault"], p["requests"]) for p in plan] == [
        ("A", "https://node.example.org/x", "replay", 2), ("B", "https://node.example.org/x", None, 1)]


def test_delay_between_requests(monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "_send", lambda *a, **k: (200, {}, b"{}"))
    monkeypatch.setattr(runner.time, "sleep", lambda s: calls.append(s))
    runner.run([sc("A"), sc("B")], PROFILE, "http://127.0.0.1:1", "p", identity=IDENT, delay=1.5)
    assert calls and all(c == 1.5 for c in calls)


def test_only_filter_marks_report_as_probe_and_blocks_admission():
    rep = runner.run([sc("A"), sc("B")], PROFILE, "http://127.0.0.1:1", "p", identity=IDENT, only={"A"},
                     timeout=1)
    assert [r["id"] for r in rep["results"]] == ["A"] and rep["probe"] is True
    assert rep["verdict"] != "CERTIFIED"


def test_keygen_writes_identity_and_reports_only_public_key(tmp_path):
    out = tmp_path / "id.json"
    pub = keygen.make_identity(out, key_id="me/keys/k1|ed25519", bap_id="me.example", bap_uri="https://me.example/b",
                               network_id="n")
    doc = json.loads(out.read_text())
    assert set(doc) == {"key_id", "bap_id", "bap_uri", "network_id", "private_key_seed_b64"}
    sk = nacl_signing.SigningKey(base64.b64decode(doc["private_key_seed_b64"]))
    assert base64.b64encode(bytes(sk.verify_key)).decode() == pub
    assert doc["private_key_seed_b64"] not in pub


def test_keygen_refuses_to_overwrite(tmp_path):
    out = tmp_path / "id.json"
    out.write_text("{}")
    with pytest.raises(FileExistsError):
        keygen.make_identity(out, key_id="k", bap_id="b", bap_uri="https://b", network_id="n")
    assert out.read_text() == "{}"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_keygen_file_is_private(tmp_path):
    out = tmp_path / "id.json"
    keygen.make_identity(out, key_id="k", bap_id="b", bap_uri="https://b", network_id="n")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_keygen_rejects_non_https_callback_uri(tmp_path):
    with pytest.raises(ValueError):
        keygen.make_identity(tmp_path / "i.json", key_id="k", bap_id="b", bap_uri="http://b.example", network_id="n")
