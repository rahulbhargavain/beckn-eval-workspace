"""Request / callback / Ack signing per docs/Authentication_and_Trust.md (NFH-007)."""
import json
import time
import uuid

import pytest

from beckn_mock import client, signing, spec
import payloads as P


def _nack(res, http_status, codes=None):
    assert res.status_code == http_status, res.text
    body = res.json()
    assert body["message"]["status"] == "NACK"
    if codes:
        assert body["message"]["error"]["code"] in codes, body
    return body


def test_signing_vector_is_reproducible():
    """§3.1/§3.2: digest = 'BLAKE2b-512=' + b64(blake2b-512(body)); 3-line signing string,
    no trailing newline."""
    body = b'{"a":1}'
    d = signing.body_digest(body)
    assert d.startswith("BLAKE2b-512=")
    s = signing.signing_string(1746518400, 1746518700, d)
    assert s == f"(created): 1746518400\n(expires): 1746518700\ndigest: {d}"
    s4 = signing.signing_string(1, 2, d, request_signature="abc==")
    assert s4.endswith("\nrequest-signature: abc==")
    kp = signing.Keypair.generate()
    sig = kp.sign(s)
    assert signing.verify(kp.public_b64, s, sig)
    assert not signing.verify(kp.public_b64, s + "x", sig)


def test_valid_signed_request_is_acked(net):
    body = net.bap.envelope("discover", P.discover())
    res = client.post_signed(net.bpp_url + "/discover", body, net.bap.identity)
    assert res.status_code == 200
    assert spec.matches_pattern("Signature", res.request.headers["authorization"])


def test_bad_signature_rejected(net):
    """Body altered after signing -> digest mismatch -> 401 NackUnauthorized (NFH-007 §8)."""
    body = net.bap.envelope("discover", P.discover())
    raw = json.dumps(body, separators=(",", ":")).encode()
    auth = client.auth_header_for(raw, net.bap.identity)
    tampered = raw.replace(b"widget", b"gadget")
    res = client.post_raw(net.bpp_url + "/discover", tampered, auth)
    _nack(res, 401, {"AUT_SIGNATURE_INVALID"})
    assert spec.component_errors("NackUnauthorized", res.json()) == []
    assert net.bpp.processed == []


def test_signature_by_wrong_key_rejected(net):
    """Signature made with a key that is not the one registered for keyId."""
    body = net.bap.envelope("discover", P.discover())
    impostor = net.bap.identity.with_keypair(signing.Keypair.generate())
    res = client.post_signed(net.bpp_url + "/discover", body, impostor)
    _nack(res, 401, {"AUT_SIGNATURE_INVALID"})


def test_missing_authorization_rejected(net):
    body = json.dumps(net.bap.envelope("discover", P.discover())).encode()
    res = client.post_raw(net.bpp_url + "/discover", body, None)
    _nack(res, 401, {"AUT_SIGNATURE_MISSING"})
    # Every response carries a Signature header (NFH-007 §5), even this one.
    assert "signature" in res.headers


@pytest.mark.parametrize("mutation", ["algorithm", "headers", "garbage"])
def test_malformed_authorization_rejected(net, mutation):
    """§1: algorithm other than ed25519 -> 401. headers list must be exactly
    '(created) (expires) digest' for CN requests (§4)."""
    body = net.bap.envelope("discover", P.discover())
    raw = json.dumps(body, separators=(",", ":")).encode()
    auth = client.auth_header_for(raw, net.bap.identity)
    if mutation == "algorithm":
        auth = auth.replace('algorithm="ed25519"', 'algorithm="rsa-sha256"')
    elif mutation == "headers":
        auth = auth.replace('headers="(created) (expires) digest"', 'headers="(created) digest"')
    else:
        auth = "Bearer abc"
    _nack(client.post_raw(net.bpp_url + "/discover", raw, auth), 401)


def test_impersonation_of_other_participant_rejected(net):
    """Spec gap (see findings): NFH-007 never says the keyId's subscriber must equal
    context.bapId. Assumption: a request whose signer is not the subscriber named in
    context.bapId is rejected with 401 AUT_UNAUTHORIZED_ACTION."""
    evil = net.new_identity("evil-bap.mock.local", role="BAP", url=net.bap_url)
    body = net.bap.envelope("discover", P.discover())  # claims bapId = real BAP
    res = client.post_signed(net.bpp_url + "/discover", body, evil)
    _nack(res, 401, {"AUT_UNAUTHORIZED_ACTION"})


def test_ack_signature_chains_to_request(net):
    """§3.4/§5: response Signature header signs the response body and the incoming
    request's raw signature value."""
    body = net.bap.envelope("discover", P.discover())
    res = client.post_signed(net.bpp_url + "/discover", body, net.bap.identity)
    req_sig = signing.parse_authorization(res.request.headers["authorization"])["signature"]
    hdr = signing.parse_authorization(res.headers["signature"])
    assert hdr["headers"] == "(created) (expires) digest request-signature"
    s = signing.signing_string(int(hdr["created"]), int(hdr["expires"]),
                               signing.body_digest(res.content), request_signature=req_sig)
    assert signing.verify(net.bpp.identity.keypair.public_b64, s, hdr["signature"])


def test_callback_with_forged_request_signature_rejected(net):
    """§7 step 7: callback's request-signature must equal the CN's stored outbound
    signature for that messageId, else 401."""
    r = net.bap.send("discover", P.discover())
    net.bap.wait_callback(r.message_id)
    r2 = net.bap.send("discover", P.discover())  # pending messageId
    net.bap.wait_callback(r2.message_id)
    cb = net.bap.callbacks_for(r2.message_id)[0].body
    cb = dict(cb, context=dict(cb["context"], timestamp="2026-01-01T00:00:00Z"))
    res = client.post_signed(net.bap_url + "/on_discover", cb, net.bpp.identity,
                             request_signature="Zm9yZ2VkLXNpZ25hdHVyZQ==")
    _nack(res, 401)


def test_callback_signed_by_non_bpp_rejected(net):
    """A third party (validly registered) cannot answer on behalf of context.bppId."""
    r = net.bap.send("discover", P.discover())
    net.bap.wait_callback(r.message_id)
    rogue = net.new_identity("rogue-bpp.mock.local", role="BPP", url="https://rogue.invalid")
    cb = net.bap.callbacks_for(r.message_id)[0].body
    res = client.post_signed(net.bap_url + "/on_discover", cb, rogue,
                             request_signature=net.bap.outbound_signature(r.message_id))
    _nack(res, 401)


def test_pn_initiated_callback_accepted_for_active_transaction(net):
    """NFH-007 §6/§10.3, CON-013-12: PN-initiated callbacks use the 3-line string, fresh
    messageId, transactionId of an active confirmed transaction."""
    contract = net.confirmed_contract()
    res = net.bpp.push_status(contract["id"])
    assert res.status_code == 200, res.text
    assert any(not e.solicited for e in net.bap.all_callbacks())


def test_pn_initiated_callback_unknown_transaction_rejected(net):
    """NFH-007 §10.3: unknown transactionId -> 400 NackBadRequest."""
    contract = net.confirmed_contract()
    res = net.bpp.push_status(contract["id"], transaction_id=str(uuid.uuid4()))
    _nack(res, 400, {"CTX_TRANSACTION_ID_UNKNOWN"})


def test_bap_acks_are_signed(net):
    """CN's Ack to a callback also carries the Signature header (§7 step 8)."""
    contract = net.confirmed_contract()
    res = net.bpp.push_status(contract["id"])
    assert spec.matches_pattern("AckSignature", res.headers["signature"])
