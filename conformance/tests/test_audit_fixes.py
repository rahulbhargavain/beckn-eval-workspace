"""External audit findings A5, A6, A7 against the conformance harness, tests first.

A5  runner: no credentials in base_url, bounded response reads.
A6  admit(): rejects probe runs, reports with problems, duplicate result ids, even if signed.
A7  dedi: naive or malformed timestamps become a Report problem, never an exception.
"""
import base64
import copy
import enum
import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import dedi, runner  # noqa: E402


# ---------------------------------------------------------------- A5
@pytest.mark.parametrize("url", ["http://user:pw@127.0.0.1:8080", "https://user:pw@sut.example",
                                 "https://user@sut.example", "http://:pw@localhost:9"])
def test_credentials_in_base_url_are_refused(url):
    with pytest.raises(runner.TargetNotAllowed):
        runner.check_target(url, {"sut.example"})


def test_plain_urls_still_pass():
    runner.check_target("http://127.0.0.1:8080")
    runner.check_target("https://sut.example", {"sut.example"})


class Flood(BaseHTTPRequestHandler):
    size = runner.MAX_RESPONSE_BYTES + 50_000

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = b"x" * self.size
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_oversized_response_is_a_failure_not_an_out_of_memory():
    srv = HTTPServer(("127.0.0.1", 0), Flood)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        s = {"id": "X-1", "level": "mandatory", "roles": ["BPP"], "spec": "t", "name": "n",
             "request": {"method": "POST", "path": "/x", "body": {"a": 1}}, "expect": {"status": 200}}
        rep = runner.run([s], {"name": "p", "spec": "t", "role": "BPP"}, f"http://127.0.0.1:{srv.server_port}", "stub")
        r = rep["results"][0]
        assert r["outcome"] == "fail" and "larger than" in r["detail"], r
    finally:
        srv.shutdown()


# ---------------------------------------------------------------- A6
OP = nacl_signing.SigningKey.generate()
ISSUER = {"key_id": "op/keys/1", "private_key_seed_b64": base64.b64encode(bytes(OP)).decode()}
PUB = base64.b64encode(bytes(OP.verify_key)).decode()
PROFILE = {"name": "p", "spec": "beckn-2.0.0", "role": "BPP", "required": {"S1": "h1"}}


def good_report():
    rep = {"participant": "me", "profile": "p", "spec": "beckn-2.0.0", "role": "BPP", "issued_at": 1_800_000_000,
           "runner_version": runner.RUNNER_VERSION, "base_url": "http://127.0.0.1", "harness_key_id": None,
           "probe": False, "verdict": "CERTIFIED", "warnings": [], "problems": [],
           "scenario_hashes": {"S1": "h1"}, "results": [{"id": "S1", "level": "mandatory", "outcome": "pass", "detail": ""}]}
    rep["digest"] = runner.digest(rep)
    return runner.resign(rep, ISSUER)


def admit(rep):
    return runner.admit(rep, "beckn-2.0.0", "BPP", "me", PROFILE, PUB, now=1_800_000_100)


def test_baseline_report_is_admitted():
    assert admit(good_report()) == (True, "ok")


def test_a_signed_probe_report_claiming_certified_is_refused():
    rep = good_report()
    rep["probe"] = True
    assert admit(runner.resign(rep, ISSUER))[0] is False


def test_a_signed_report_with_problems_claiming_certified_is_refused():
    rep = good_report()
    rep["problems"] = ["required scenario S2 was not run"]
    ok, why = admit(runner.resign(rep, ISSUER))
    assert ok is False and "problems" in why


def test_duplicate_result_ids_are_refused_even_when_the_last_one_passes():
    rep = good_report()
    rep["results"] = [{"id": "S1", "level": "mandatory", "outcome": "fail", "detail": "x"}] + rep["results"]
    ok, why = admit(runner.resign(rep, ISSUER))
    assert ok is False and "duplicate" in why


def test_non_list_problems_or_results_do_not_crash_admit():
    rep = good_report()
    rep["problems"] = "none"
    assert admit(runner.resign(rep, ISSUER))[0] is False


# ---------------------------------------------------------------- A7
def test_parse_ts_requires_a_timezone():
    with pytest.raises(ValueError):
        dedi._parse_ts("2026-10-27T10:00:00")
    assert dedi._parse_ts("2026-10-27T10:00:00Z").tzinfo is not None


def test_a_naive_timestamp_is_reported_not_raised(tmp_path, monkeypatch):
    sk = nacl_signing.SigningKey.generate()
    cfg = {"role": "NP", "domain": "np1.example", "name": "NP", "nfo_name": "nfo-x", "network": "agri", "env": "prod",
           "kid": "key-1", "records": [{"record_name": "r", "subscriber_id": "np1.example",
                                        "url": "https://np1.example/b/", "type": "BPP", "countries": ["IND"],
                                        "signing_public_key": base64.b64encode(bytes(sk.verify_key)).decode()}]}
    now = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    paths = dedi.build(cfg, sk, tmp_path / "s", now)
    m = json.loads(paths["manifest"].read_text(encoding="utf-8"))
    m["next_update"] = "2026-11-03T10:00:00"  # naive
    paths["manifest"].write_text(json.dumps(dedi.sign_doc(m, sk, "key-1")), encoding="utf-8")
    monkeypatch.setattr(dedi, "shape_errors", lambda kind, doc: [])  # as if no date-time format checker is installed
    rep = dedi.verify_dir(tmp_path / "s", "np1.example", now)
    assert not rep.ok and any(p.startswith("SHAPE") for p in rep.problems), rep.problems


def test_jcs_serialises_int_subclasses_as_plain_integers():
    class Level(enum.IntEnum):
        HIGH = 5
    assert dedi.jcs({"n": Level.HIGH}) == b'{"n":5}'


# ---------------------------------------------------------------- round 2: B1, B2, B5
from conformance import signing as csigning  # noqa: E402


def test_b2_response_signature_has_no_grace_after_expires():
    """NFH-007: skew is tolerated on `created` only; `expires` has none (matches the mockup node)."""
    import hashlib
    import re
    now = 1_800_000_000
    ident = {"key_id": "h/keys/1|ed25519", "private_key_seed_b64": base64.b64encode(bytes(OP)).decode()}
    auth = csigning.authorization(ident, b"{}", now=now)
    body = b"{}"
    created, expires = now - 62, now - 2
    dig = "BLAKE2b-512=" + base64.b64encode(hashlib.blake2b(body, digest_size=64).digest()).decode()
    text = (f"(created): {created}\n(expires): {expires}\ndigest: {dig}\n"
            f"request-signature: {re.search(r'signature=\"([^\"]+)\"', auth).group(1)}")
    sig = base64.b64encode(OP.sign(text.encode()).signature).decode()
    hdr = (f'Signature keyId="s/keys/1|ed25519",algorithm="ed25519",created="{created}",expires="{expires}",'
           f'headers="(created) (expires) digest request-signature",signature="{sig}"')
    with pytest.raises(csigning.ResponseSignatureError, match="expired"):
        csigning.check_response({"signature": hdr}, body, auth, {"s/keys/1|ed25519": PUB}, now)


def _run_with_keys(keys):
    s = {"id": "X-1", "level": "mandatory", "roles": ["BPP"], "spec": "t", "name": "n",
         "request": {"method": "POST", "path": "/x", "body": {}}, "expect": {"status": 200}}
    prof = {"name": "p", "spec": "t", "role": "BPP", "required": {"X-1": runner.scenario_hash(s, runner.DEFAULT_FIXTURES)}}
    return runner.run([s], prof, "http://127.0.0.1:9", "me", sut_keys=keys, issuer=ISSUER), prof


def test_b1_the_signed_report_commits_to_the_sut_keys_that_were_trusted():
    rep, _ = _run_with_keys({"k2|ed25519": "BBBB", "k1|ed25519": "AAAA"})
    assert rep["sut_keys"] == {"k1|ed25519": "AAAA", "k2|ed25519": "BBBB"}


def test_b1_admit_can_require_the_registered_sut_key():
    rep = good_report()
    rep["sut_keys"] = {"k1|ed25519": "AAAA"}
    rep = runner.resign(rep, ISSUER)
    ok = lambda reg: runner.admit(rep, "beckn-2.0.0", "BPP", "me", PROFILE, PUB, now=1_800_000_100, registered_sut_keys=reg)
    assert ok({"k1|ed25519": "AAAA"}) == (True, "ok")
    assert ok({"k1|ed25519": "ZZZZ"})[0] is False          # a different key was trusted during the run
    assert ok({"k9|ed25519": "AAAA"})[0] is False          # a key id the participant never registered
    no_keys = runner.resign(good_report(), ISSUER)
    assert runner.admit(no_keys, "beckn-2.0.0", "BPP", "me", PROFILE, PUB, now=1_800_000_100,
                        registered_sut_keys={"k1|ed25519": "AAAA"})[0] is False   # no key recorded at all


def test_b5_dedi_cli_reports_a_naive_now_instead_of_a_traceback(tmp_path, capsys):
    rc = dedi.main(["verify", "--dir", str(tmp_path), "--domain", "x.example", "--now", "2026-10-27T10:00:00"])
    assert rc == 2 and "error:" in capsys.readouterr().err
