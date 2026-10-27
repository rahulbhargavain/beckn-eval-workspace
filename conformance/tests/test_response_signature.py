"""Cryptographic verification of the SUT's synchronous `Signature` response header.

Spec: docs/Authentication_and_Trust.md section 5 and 3.4, CON-004-23: every synchronous response,
whatever its status, carries `Signature` with headers="(created) (expires) digest request-signature",
a BLAKE2b-512 digest of the RESPONSE body, and request-signature equal to the `signature` value of the
request's Authorization header, signed by the responder's Ed25519 key.

Key trust is supplied by the operator (`sut_keys`: keyId -> base64 public key). The harness never
fetches a registry URL named in a response header: that would be a pre-authentication SSRF (S2).
Needs PyNaCl (mockup venv).
"""
import base64
import hashlib
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import runner, signing  # noqa: E402

HARNESS_SK = nacl_signing.SigningKey.generate()
IDENT = {"key_id": "h.example/keys/k1|ed25519", "bap_id": "h.example", "bap_uri": "https://h.example/b",
         "network_id": "example.org/net", "private_key_seed_b64": base64.b64encode(bytes(HARNESS_SK)).decode()}
SUT_SK = nacl_signing.SigningKey.generate()
SUT_KID = "sut.example/keys/k1|ed25519"
SUT_PUB = base64.b64encode(bytes(SUT_SK.verify_key)).decode()
TRUSTED = {SUT_KID: SUT_PUB}
NOW = 1_800_000_000
BODY = b'{"message":{"status":"ACK","messageId":"m"}}'
CHAIN = "(created) (expires) digest request-signature"


def sent_auth(body=b"{}"):
    return signing.authorization(IDENT, body, now=NOW)


def req_sig(auth):
    return re.search(r'signature="([^"]+)"', auth).group(1)


def b2(raw):
    return "BLAKE2b-512=" + base64.b64encode(hashlib.blake2b(raw, digest_size=64).digest()).decode()


def respond(auth, body=BODY, *, key=SUT_SK, kid=SUT_KID, created=NOW, expires=NOW + 60, chain_sig=None,
            digest_of=None, headers_attr=CHAIN, algorithm="ed25519", prefix="Signature ", lines=4):
    rs = chain_sig if chain_sig is not None else req_sig(auth)
    text = f"(created): {created}\n(expires): {expires}\ndigest: {b2(digest_of if digest_of is not None else body)}"
    if lines == 4:
        text += f"\nrequest-signature: {rs}"
    sig = base64.b64encode(key.sign(text.encode()).signature).decode()
    return (f'{prefix}keyId="{kid}",algorithm="{algorithm}",created="{created}",expires="{expires}",'
            f'headers="{headers_attr}",signature="{sig}"')


def check(header, auth=None, body=BODY, keys=TRUSTED, now=NOW):
    auth = auth or sent_auth()
    return signing.check_response({} if header is None else {"signature": header}, body, auth, keys, now)


# ---------------------------------------------------------------- unit: accepted
def test_a_correct_chained_response_signature_verifies():
    auth = sent_auth()
    assert check(respond(auth), auth) == SUT_KID


def test_both_header_spellings_are_accepted():
    """NFH-007 section 5 shows the header without the 'Signature ' scheme, beckn.yaml AckSignature with it."""
    auth = sent_auth()
    assert check(respond(auth, prefix=""), auth) == SUT_KID
    assert check(respond(auth, prefix="Signature "), auth) == SUT_KID


def test_error_responses_verify_the_same_way():
    auth = sent_auth()
    body = b'{"message":{"status":"NACK","error":{"code":"AUT_SIGNATURE_INVALID"}}}'
    assert check(respond(auth, body), auth, body) == SUT_KID


# ---------------------------------------------------------------- unit: each defect on its own
@pytest.mark.parametrize("header_kwargs,match", [
    (dict(headers_attr="(created) (expires) digest", lines=3), "headers must be"),
    (dict(headers_attr="digest (created) (expires) request-signature"), "headers must be"),
    (dict(algorithm="rsa-sha256"), "algorithm"),
    (dict(kid="stranger.example/keys/k|ed25519"), "no trusted key"),
    (dict(key=nacl_signing.SigningKey.generate()), "does not verify"),
    (dict(digest_of=b"another body"), "does not verify"),
    (dict(chain_sig="AAAA"), "does not verify"),
    (dict(created=NOW - 600, expires=NOW - 300), "expired"),
    (dict(created=NOW + 600, expires=NOW + 900), "future"),
    (dict(created=NOW, expires=NOW), "expires"),
], ids=["no-chain-line", "wrong-order", "algorithm", "unknown-key", "wrong-key", "digest-of-other-body",
        "chained-to-another-request", "expired", "created-in-future", "expires-not-after-created"])
def test_each_defect_is_rejected(header_kwargs, match):
    auth = sent_auth()
    with pytest.raises(signing.ResponseSignatureError, match=match):
        check(respond(auth, **header_kwargs), auth)


def test_body_altered_after_signing_is_rejected():
    auth = sent_auth()
    with pytest.raises(signing.ResponseSignatureError, match="does not verify"):
        check(respond(auth), auth, body=BODY + b" ")


def test_missing_and_garbled_headers_are_rejected():
    with pytest.raises(signing.ResponseSignatureError, match="missing"):
        check(None)
    with pytest.raises(signing.ResponseSignatureError, match="unparseable"):
        check('keyId="x"')
    with pytest.raises(signing.ResponseSignatureError, match="unparseable"):
        check(respond(sent_auth()) + ",extra=\"1\"")


def test_a_signature_of_the_wrong_length_is_rejected_not_raised():
    auth = sent_auth()
    h = re.sub(r'signature="[^"]+"', 'signature="AAAA"', respond(auth))
    with pytest.raises(signing.ResponseSignatureError, match="does not verify"):
        check(h, auth)


def test_no_trusted_keys_supplied_names_the_remedy():
    auth = sent_auth()
    with pytest.raises(signing.ResponseSignatureError, match="--sut-key"):
        check(respond(auth), auth, keys={})


def test_the_request_signature_is_taken_from_what_was_actually_sent():
    other = signing.authorization(IDENT, b'{"different":1}', now=NOW + 1)
    with pytest.raises(signing.ResponseSignatureError):
        check(respond(sent_auth()), other)


# ---------------------------------------------------------------- scenario schema
def scenario(**over):
    s = {"id": "X-1", "level": "mandatory", "roles": ["BPP"], "spec": "t", "name": "n",
         "request": {"method": "POST", "path": "/select", "body": {"context": {"action": "select"}, "message": {}},
                     "auth": runner.SIGNED},
         "expect": {"status": 200, "response_signature": {"chain": True}}}
    s.update(over)
    return s


def test_scenario_schema_accepts_response_signature():
    runner.validate_scenario(scenario())


def test_response_signature_needs_a_signed_request():
    s = scenario()
    del s["request"]["auth"]
    with pytest.raises(runner.ScenarioError):
        runner.validate_scenario(s)


@pytest.mark.parametrize("bad", [True, {}, {"chain": False}, {"chain": True, "x": 1}, "chain"])
def test_response_signature_value_is_strict(bad):
    s = scenario()
    s["expect"]["response_signature"] = bad
    with pytest.raises(runner.ScenarioError):
        runner.validate_scenario(s)


def test_every_signed_repo_scenario_demands_a_chained_response_signature():
    for s in runner.load_scenarios(runner.DEFAULT_SCENARIOS):
        if s["request"].get("auth") == runner.SIGNED:
            assert s["expect"].get("response_signature") == {"chain": True}, s["id"]


# ---------------------------------------------------------------- runner against a stub SUT
class Stub(BaseHTTPRequestHandler):
    mode = "good"
    status = 200

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        auth = self.headers.get("Authorization", "")
        body = json.dumps({"message": {"status": "ACK" if self.status == 200 else "NACK"}}).encode()
        t = int(time.time())  # a live server signs with the real clock; the unit tests inject NOW instead
        live = dict(created=t, expires=t + 60)
        h = {"good": lambda: respond(auth, body, **live),
             "wrong-chain": lambda: respond(auth, body, chain_sig="AAAA", **live),
             "no-chain-line": lambda: respond(auth, body, headers_attr="(created) (expires) digest", lines=3, **live),
             "other-key": lambda: respond(auth, body, key=nacl_signing.SigningKey.generate(), **live),
             "unsigned": lambda: None}[self.mode]()
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        if h:
            self.send_header("Signature", h)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def sut():
    srv = HTTPServer(("127.0.0.1", 0), Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    Stub.mode, Stub.status = "good", 200
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


PROFILE = {"name": "p", "spec": "t", "role": "BPP"}


def grade(url, mode, keys=TRUSTED, status=200, scen=None):
    Stub.mode, Stub.status = mode, status
    rep = runner.run([scen or scenario()], PROFILE, url, "stub", identity=IDENT, sut_keys=keys)
    return rep["results"][0]


def test_runner_passes_a_correctly_signed_response(sut):
    assert grade(sut, "good")["outcome"] == "pass", grade(sut, "good")


@pytest.mark.parametrize("mode,hint", [("wrong-chain", "does not verify"), ("no-chain-line", "headers must be"),
                                       ("other-key", "does not verify"), ("unsigned", "missing")])
def test_runner_fails_a_bad_response_signature(sut, mode, hint):
    r = grade(sut, mode)
    assert r["outcome"] == "fail" and hint in r["detail"], r


def test_runner_fails_when_no_trusted_key_was_supplied(sut):
    r = grade(sut, "good", keys=None)
    assert r["outcome"] == "fail" and "--sut-key" in r["detail"], r


def test_runner_checks_error_responses_too(sut):
    scen = scenario(expect={"status": 401, "response_signature": {"chain": True}})
    assert grade(sut, "good", status=401, scen=scen)["outcome"] == "pass"
    assert grade(sut, "wrong-chain", status=401, scen=scen)["outcome"] == "fail"


def test_chain_follows_the_signature_that_was_really_sent_under_a_fault(sut):
    s = scenario()
    s["request"]["fault"] = "bad-signature"
    s["expect"] = {"status": 401, "response_signature": {"chain": True}}
    assert grade(sut, "good", status=401, scen=s)["outcome"] == "pass"


def test_signature_check_is_graded_after_status_and_headers(sut):
    """A wrong status is reported as a status failure, not hidden behind the signature check."""
    r = grade(sut, "wrong-chain", status=500)
    assert r["outcome"] == "fail" and "status 500" in r["detail"]
