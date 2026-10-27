"""Expiry and replay protection (NFH-007 §3.2, §7 step 2, §8 step 2, §10)."""
import json
import time
from datetime import datetime, timedelta, timezone

from beckn_mock import client
import payloads as P


def _send(net, body, **kw):
    return client.post_signed(net.bpp_url + "/discover", body, net.bap.identity, **kw)


def test_expired_signature_rejected(net):
    now = int(time.time())
    res = _send(net, net.bap.envelope("discover", P.discover()), created=now - 120, expires=now - 60)
    assert res.status_code == 401
    assert res.json()["message"]["error"]["code"] == "AUT_SIGNATURE_INVALID"


def test_created_in_future_beyond_skew_rejected(net):
    """Default clock-skew tolerance is 5 s (NFH-007 §7 step 2, CON-004-13)."""
    now = int(time.time())
    res = _send(net, net.bap.envelope("discover", P.discover()), created=now + 60, expires=now + 120)
    assert res.status_code == 401


def test_created_within_skew_accepted(net):
    now = int(time.time())
    res = _send(net, net.bap.envelope("discover", P.discover()), created=now + 3, expires=now + 60)
    assert res.status_code == 200, res.text


def test_expires_not_after_created_rejected(net):
    """§3.2: expires MUST be greater than created."""
    now = int(time.time())
    res = _send(net, net.bap.envelope("discover", P.discover()), created=now, expires=now)
    assert res.status_code == 401


def test_expires_beyond_key_validity_rejected(net):
    """§3.2 / CON-004-07: expires MUST NOT exceed the signing key's registered expiry."""
    now = int(time.time())
    valid_until = net.registry.key(net.bap.identity.key_id)["validUntil"]
    res = _send(net, net.bap.envelope("discover", P.discover()), created=now, expires=valid_until + 10)
    assert res.status_code == 401


def test_context_ttl_elapsed_rejected(net):
    """beckn.yaml Context.ttl: receiver SHOULD reject when timestamp + ttl has elapsed.
    Spec gives no HTTP status; assumption: 400 NackBadRequest with CTX_TTL_EXPIRED."""
    old = (datetime.now(timezone.utc) - timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = net.bap.envelope("discover", P.discover(), timestamp=old, ttl="PT30S")
    res = _send(net, body)
    assert res.status_code == 400
    assert res.json()["message"]["error"]["code"] == "CTX_TTL_EXPIRED"


def test_exact_replay_rejected_and_processed_once(net):
    """NFH-007 §10.1: a request whose messageId matches a previously processed one MUST
    be rejected with 400 NackBadRequest. A byte-identical replay (same signature) is
    reported as AUT_REPLAY_DETECTED (assumption: the spec lists both
    AUT_REPLAY_DETECTED and CTX_MESSAGE_ID_DUPLICATE without saying which applies)."""
    body = net.bap.envelope("discover", P.discover())
    raw = json.dumps(body, separators=(",", ":")).encode()
    auth = client.auth_header_for(raw, net.bap.identity)
    first = client.post_raw(net.bpp_url + "/discover", raw, auth)
    assert first.status_code == 200
    second = client.post_raw(net.bpp_url + "/discover", raw, auth)
    assert second.status_code == 400
    assert second.json()["message"]["error"]["code"] == "AUT_REPLAY_DETECTED"
    time.sleep(0.5)
    assert [m for (_, m) in net.bpp.processed].count(body["context"]["messageId"]) == 1


def test_replayed_callback_rejected_by_bap(net):
    """NFH-007 §10.2 vs NFH-013 §9 conflict (see findings). Assumption: the CN accepts
    further *distinct* callbacks for a messageId but rejects a byte-identical replay
    (same messageId + same signature, the dedup key recommended by CON-013-23)."""
    r = net.bap.send("discover", P.discover())
    net.bap.wait_callback(r.message_id)
    entry = net.bap.callbacks_for(r.message_id)[0]
    res = client.post_raw(net.bap_url + "/on_discover", entry.raw, entry.authorization)
    assert res.status_code == 400
    assert res.json()["message"]["error"]["code"] == "AUT_REPLAY_DETECTED"
    assert len(net.bap.callbacks_for(r.message_id)) == 1


def test_unsolicited_callback_replay_rejected(net):
    """PN-initiated callbacks have no request-signature chain, so only messageId
    tracking stops replays. Spec (NFH-007 §10.3) requires the PN to use unique ids but
    never requires the CN to reject a repeat; assumption: CN rejects it."""
    contract = net.confirmed_contract()
    res = net.bpp.push_status(contract["id"])
    assert res.status_code == 200
    raw, auth = net.bpp.last_push
    again = client.post_raw(net.bap_url + "/on_status", raw, auth)
    assert again.status_code == 400
