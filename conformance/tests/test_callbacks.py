"""The runner's local async `on_*` callback listener (conformance/callbacks.py), tests first.

It binds 127.0.0.1 only, accepts a callback only for a messageId the runner just sent, verifies the
chained Signature against an operator-supplied key (never fetched), and replies ACK/NACK.
"""
import base64
import hashlib
import json
import socket
import time
import urllib.error
import urllib.request

import pytest

nacl_signing = pytest.importorskip("nacl.signing")

from conformance import callbacks  # noqa: E402

SK = nacl_signing.SigningKey.generate()
KID = "sut.example/keys/k1|ed25519"
KEYS = {KID: base64.b64encode(bytes(SK.verify_key)).decode()}
REQ_SIG = "cmVxdWVzdC1zaWduYXR1cmU="  # what the runner sent in its own Authorization header
LONG_AGO = 1_000_000_000


def b2(raw):
    return "BLAKE2b-512=" + base64.b64encode(hashlib.blake2b(raw, digest_size=64).digest()).decode()


def auth_for(raw, *, key=SK, kid=KID, chain=REQ_SIG, created=None, expires=None, algorithm="ed25519",
             headers="(created) (expires) digest request-signature"):
    created = int(time.time()) if created is None else created
    expires = created + 60 if expires is None else expires
    text = f"(created): {created}\n(expires): {expires}\ndigest: {b2(raw)}\nrequest-signature: {chain}"
    sig = base64.b64encode(key.sign(text.encode()).signature).decode()
    return (f'Signature keyId="{kid}",algorithm="{algorithm}",created="{created}",expires="{expires}",'
            f'headers="{headers}",signature="{sig}"')


def body(mid="m-1", action="on_discover"):
    return json.dumps({"context": {"action": action, "messageId": mid, "transactionId": "t"},
                       "message": {"catalogs": []}}).encode()


@pytest.fixture
def lis():
    with callbacks.CallbackListener(KEYS) as srv:
        srv.expect("m-1", REQ_SIG)
        yield srv


def post(srv, path, raw, auth=None, method="POST"):
    h = {"Content-Type": "application/json"}
    if auth:
        h["Authorization"] = auth
    r = urllib.request.Request(srv.url + path, data=raw if method == "POST" else None, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def test_listener_binds_loopback_only(lis):
    assert lis.url.startswith("http://127.0.0.1:")
    assert lis.server.server_address[0] == "127.0.0.1"


def test_a_correct_chained_callback_is_acked_and_recorded(lis):
    raw = body()
    st, resp = post(lis, "/on_discover", raw, auth_for(raw))
    assert st == 200 and json.loads(resp)["message"]["status"] == "ACK"
    rec = lis.wait("m-1", 2)
    assert rec["ok"] and rec["action"] == "on_discover" and rec["body"]["message"] == {"catalogs": []}


@pytest.mark.parametrize("kw,why", [
    (dict(chain="b3RoZXI="), "does not verify"),
    (dict(key=nacl_signing.SigningKey.generate()), "does not verify"),
    (dict(kid="stranger/keys/k|ed25519"), "no trusted key"),
    (dict(algorithm="none"), "algorithm"),
    (dict(headers="(created) (expires) digest"), "headers must be"),
    (dict(created=LONG_AGO, expires=LONG_AGO + 60), "expired"),
], ids=["wrong-chain", "wrong-key", "unknown-key", "algorithm", "no-chain-header", "expired"])
def test_each_defective_callback_is_nacked_and_recorded_as_a_failure(lis, kw, why):
    raw = body()
    st, resp = post(lis, "/on_discover", raw, auth_for(raw, **kw))
    assert st == 401 and json.loads(resp)["message"]["status"] == "NACK"
    rec = lis.wait("m-1", 2)
    assert not rec["ok"] and why in rec["error"], rec


def test_callback_without_authorization_is_nacked(lis):
    st, _ = post(lis, "/on_discover", body())
    assert st == 401 and not lis.wait("m-1", 2)["ok"]


def test_unsolicited_message_id_is_refused_and_does_not_satisfy_an_expected_one(lis):
    raw = body("never-sent")
    st, _ = post(lis, "/on_discover", raw, auth_for(raw))
    assert st == 400 and lis.wait("m-1", 0.2) is None


def test_the_same_callback_is_accepted_once(lis):
    raw = body()
    a = auth_for(raw)
    assert post(lis, "/on_discover", raw, a)[0] == 200
    assert post(lis, "/on_discover", raw, a)[0] == 400


def test_path_and_context_action_must_agree(lis):
    raw = body(action="on_select")
    assert post(lis, "/on_discover", raw, auth_for(raw))[0] == 400


@pytest.mark.parametrize("path", ["/discover", "/on_", "/on_Discover", "/on_x/../y", "/on_x/y", "/"])
def test_only_on_action_paths_are_served(lis, path):
    raw = body()
    assert post(lis, path, raw, auth_for(raw))[0] in (400, 404)


def test_other_methods_are_refused(lis):
    assert post(lis, "/on_discover", b"", method="GET")[0] in (404, 405, 501)


def test_invalid_json_is_a_400(lis):
    raw = b'{"context": '
    assert post(lis, "/on_discover", raw, auth_for(raw))[0] == 400


def test_hostile_nesting_is_a_4xx_and_the_listener_keeps_serving(lis):
    raw = b"[" * 100_000
    assert post(lis, "/on_discover", raw, auth_for(raw))[0] == 400
    good = body()
    assert post(lis, "/on_discover", good, auth_for(good))[0] == 200


def test_oversized_body_is_refused_before_reading_it(lis):
    raw = b'{"context":{"messageId":"' + b"A" * (callbacks.MAX_BODY_BYTES + 10) + b'"}}'
    try:
        status = post(lis, "/on_discover", raw, auth_for(raw))[0]
    except (ConnectionError, urllib.error.URLError):  # the server refused and closed while we were still sending
        status = 413
    assert status == 413
    good = body()
    assert post(lis, "/on_discover", good, auth_for(good))[0] == 200


def test_wait_times_out_with_none(lis):
    assert lis.wait("m-1", 0.1) is None


def test_close_releases_the_port():
    srv = callbacks.CallbackListener(KEYS)
    port = srv.server.server_address[1]
    srv.close()
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
    finally:
        s.close()


@pytest.mark.parametrize("good", [True, False])
def test_the_verdict_is_published_only_after_the_reply_is_written(lis, monkeypatch, good):
    """The runner closes the listener as soon as wait() returns. If the verdict were published before the reply
    is written, the node's POST could be cut off mid-response (seen as a ReadError on Linux)."""
    import threading
    written = threading.Event()
    real = lis._reply

    def slow_reply(h, status, body_):
        time.sleep(0.3)
        real(h, status, body_)
        written.set()

    monkeypatch.setattr(lis, "_reply", slow_reply)
    raw = body()
    auth = auth_for(raw, chain=REQ_SIG if good else "b3RoZXI=")
    t = threading.Thread(target=post, args=(lis, "/on_discover", raw, auth))
    t.start()
    assert lis.wait("m-1", 2) is not None
    assert written.is_set(), "wait() returned before the reply was written"
    t.join(5)
