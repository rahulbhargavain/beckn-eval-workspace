"""External audit of audit_snapshot (commit de731ca/79d61fd), findings A1, A3, A4, A8, tests first.

A1  pre-authentication body handling: bounded reads, no 500 on hostile nesting.
A3  key ids: strict character set, no query/fragment/dot segments, in implicit and explicit forms.
A4  the BAP's Ack verification applies the same header and key checks as inbound verification.
A8  Resource.quantity that is not an object is refused, not silently priced as 1.
"""
import time
import uuid

import httpx
import pytest

from beckn_mock import signing
from beckn_mock.node import MAX_BODY_BYTES, Reject
import payloads as PL


# ---------------------------------------------------------------- A1
@pytest.mark.parametrize("target", ["bap", "bpp"])
def test_oversized_body_is_refused_before_it_is_parsed(net, target):
    url, path = (net.bap_url, "/on_select") if target == "bap" else (net.bpp_url, "/discover")
    body = b'{"context":{"messageId":"' + b"A" * (MAX_BODY_BYTES + 10) + b'"}}'
    r = httpx.post(url + path, content=body, timeout=10)
    assert r.status_code == 400, r.status_code
    assert "SCH_INVALID_JSON" in r.text


@pytest.mark.parametrize("target", ["bap", "bpp"])
def test_hostile_nesting_gets_a_4xx_not_a_500(net, target):
    url, path = (net.bap_url, "/on_select") if target == "bap" else (net.bpp_url, "/discover")
    r = httpx.post(url + path, content=b"[" * 100_000, timeout=10)
    assert r.status_code in (400, 401), r.status_code
    again = httpx.post(url + path, content=b"{}", timeout=10)  # and the server is still serving
    assert again.status_code in (400, 401)


def test_a_normal_sized_flow_is_unaffected(net):
    r = net.bap.send("discover", PL.discover("widget"), transaction_id=str(uuid.uuid4()))
    assert r.status_code == 200 and net.bap.wait_callback(r.message_id)


# ---------------------------------------------------------------- A3
@pytest.mark.parametrize("bad", [
    "ns/reg/rec?x=1|ed25519", "ns/reg/rec#frag|ed25519", "ns/../rec|ed25519", "ns/reg/re c|ed25519",
    "ns/reg/%2e%2e|ed25519", "ns/reg/rec\\x|ed25519", "n s/reg/rec|ed25519", "ns/./rec|ed25519"])
def test_implicit_key_ids_are_strictly_checked(net, bad):
    with pytest.raises(Reject):
        net.bpp._key_url(bad)


def test_valid_implicit_key_id_still_resolves(net):
    assert net.bpp._key_url("bap.mock.local/keys/k1|ed25519").endswith("/dedi/lookup/bap.mock.local/keys/k1|ed25519")


@pytest.mark.parametrize("suffix", ["/../admin", "/a?b=1", "/a#f", "/%2e%2e/admin", "/a/./b", "//double"])
def test_explicit_key_urls_cannot_carry_traversal_query_or_fragment(net, suffix):
    with pytest.raises(Reject):
        net.bpp._key_url(f"{net.registry_url}{suffix}|ed25519")


def test_valid_explicit_key_url_on_a_trusted_registry_is_accepted(net):
    url = f"{net.registry_url}/dedi/lookup/bap.mock.local/keys/k1"
    assert net.bpp._key_url(url + "|ed25519") == url


# ---------------------------------------------------------------- A4
def _ack(net, our_sig, *, algorithm="ed25519", created=None, expires=None, kp=None, key_id=None, body=None):
    ident = net.bpp.identity
    kp, key_id = kp or ident.keypair, key_id or ident.key_id
    now = int(time.time())
    created = now if created is None else created
    expires = now + 60 if expires is None else expires
    body = body or b'{"message":{"status":"ACK"}}'
    text = signing.signing_string(created, expires, signing.body_digest(body), our_sig)
    header = (f'Signature keyId="{key_id}",algorithm="{algorithm}",created="{created}",expires="{expires}",'
              f'headers="{signing.CHAIN_HEADERS}",signature="{kp.sign(text)}"')
    return httpx.Response(200, content=body, headers={"signature": header})


def test_a_correct_ack_verifies(net):
    assert net.bap._verify_ack(_ack(net, "SIG"), "SIG", net.bpp.subscriber_id) is True


@pytest.mark.parametrize("kw", [
    dict(algorithm="none"),
    dict(created="FUTURE"),
    dict(expires="SAME_AS_CREATED"),
    dict(expires="PAST"),
], ids=["algorithm", "created-in-future", "expires-not-after-created", "expired"])
def test_ack_header_defects_are_rejected(net, kw):
    now = int(time.time())
    kw = dict(kw)
    if kw.get("created") == "FUTURE":
        kw["created"], kw["expires"] = now + 600, now + 900
    if kw.get("expires") == "SAME_AS_CREATED":
        kw["created"] = kw["expires"] = now
    if kw.get("expires") == "PAST":
        kw["created"], kw["expires"] = now - 600, now - 300
    assert net.bap._verify_ack(_ack(net, "SIG", **kw), "SIG", net.bpp.subscriber_id) is False


def test_ack_signed_by_a_key_whose_registration_has_lapsed_is_rejected(net):
    kp = signing.Keypair.generate()
    now = int(time.time())
    kid = "bpp.mock.local/keys/old|ed25519"
    net.registry.add_key(kid, net.bpp.subscriber_id, net.network_id, kp.public_b64, now - 1000, now - 500)
    assert net.bap._verify_ack(_ack(net, "SIG", kp=kp, key_id=kid), "SIG", net.bpp.subscriber_id) is False


def test_ack_whose_expiry_outlives_the_key_registration_is_rejected(net):
    kp = signing.Keypair.generate()
    now = int(time.time())
    kid = "bpp.mock.local/keys/short|ed25519"
    net.registry.add_key(kid, net.bpp.subscriber_id, net.network_id, kp.public_b64, now - 100, now + 30)
    assert net.bap._verify_ack(_ack(net, "SIG", kp=kp, key_id=kid, expires=now + 300), "SIG",
                               net.bpp.subscriber_id) is False


def test_ack_chained_to_another_request_is_rejected(net):
    assert net.bap._verify_ack(_ack(net, "OTHER"), "SIG", net.bpp.subscriber_id) is False


# ---------------------------------------------------------------- A8
def _catalog(net, txn):
    r = net.bap.send("discover", PL.discover("widget"), transaction_id=txn)
    return net.bap.wait_callback(r.message_id)["message"]["catalogs"][0]


@pytest.mark.parametrize("bad", [5, "5", 2.5, [1], True])
def test_non_object_quantity_is_refused_on_select(net, bad):
    txn = str(uuid.uuid4())
    cms = PL.commitments_from_catalog(_catalog(net, txn), 1)
    for r in cms[0]["resources"]:
        r["quantity"] = bad
    r = net.bap.send("select", {"contract": {"commitments": cms}}, transaction_id=txn)
    assert r.status_code == 400, r.body
    assert "quantity" in str(r.body).lower()


def test_non_object_quantity_on_update_is_a_4xx_not_a_500(net):
    contract = net.confirmed_contract()
    bad = PL.set_quantity(contract, 3)
    for cm in bad["commitments"]:
        for r in cm["resources"]:
            r["quantity"] = 5
    for extra in ({"try": True}, {"try": False, "requestDigest": {"digest": "BLAKE-512=" + "A" * 86 + "=="}}):
        r = net.bap.send("update", {"contract": bad}, transaction_id=net.last_transaction_id, context_extra=extra)
        assert 400 <= r.status_code < 500, (extra, r.status_code, r.body)


# ---------------------------------------------------------------- round 2: B3, B4, B6
import math  # noqa: E402

from beckn_mock import spec  # noqa: E402


def test_b4_malformed_timestamp_is_a_400_even_without_a_date_time_format_checker(net, monkeypatch):
    monkeypatch.setattr(spec, "request_errors", lambda path, body: [])
    body = {"context": {"action": "discover", "version": "2.0.0", "transactionId": "t", "messageId": "m",
                        "bapId": "x", "ttl": "PT30S", "timestamp": "not-a-date"}}
    with pytest.raises(Reject) as e:
        net.bpp.validate("/discover", body, "bapId")
    assert e.value.http_status == 400 and e.value.code == "CTX_INVALID_FIELD"


@pytest.mark.parametrize("bad", [float("inf"), float("nan"), -1, 10 ** 40])
def test_b6_catalog_prices_must_be_finite_and_priceable(net, bad):
    import copy
    from beckn_mock.catalogstore import CatalogRejected
    cat = copy.deepcopy(net.bpp.store.active()[0])
    cat["offers"][0]["considerations"][0]["considerationAttributes"]["value"] = bad
    with pytest.raises(CatalogRejected):
        net.bpp.store.publish(cat)


def test_b3_a_valid_callback_body_is_parsed_once(net, monkeypatch):
    calls = []
    orig = net.bap.parse_body
    monkeypatch.setattr(net.bap, "parse_body", lambda raw: (calls.append(1), orig(raw))[1])
    r = net.bap.send("discover", PL.discover("widget"), transaction_id=str(uuid.uuid4()))
    assert net.bap.wait_callback(r.message_id)
    assert len(calls) == 1, len(calls)
