"""Happy-path lifecycle: discover -> select -> init -> confirm -> status -> track ->
update (preview + commit) -> cancel (preview + commit) -> rate -> support.

Spec: api/v2.0.0/beckn.yaml (paths), docs/API.md "Lifecycle mapping",
docs/Communication_Protocol.md §2-§6, docs/Authentication_and_Trust.md §5-§7.
"""
import uuid

from beckn_mock import signing, spec
import payloads as P


def assert_ack(net, res, expected_status=200):
    """Every synchronous response: Ack schema, echoed messageId, signed `Signature`
    header that matches AckSignature pattern and chains to our request signature
    (NFH-007 §3.4/§5)."""
    assert res.status_code == expected_status, res.body
    schema = "Ack" if expected_status == 200 else "AckNoCallback"
    assert spec.component_errors(schema, res.body) == []
    assert res.body["message"]["status"] == "ACK"
    assert res.body["message"]["messageId"] == res.message_id
    assert spec.matches_pattern("AckSignature", res.headers["signature"])
    assert res.ack_signature_verified is True


def assert_callback(net, res, action):
    cb = net.bap.wait_callback(res.message_id)
    ctx = cb["context"]
    assert ctx["action"] == f"on_{action}"
    assert ctx["messageId"] == res.message_id          # CON-013-04
    assert ctx["transactionId"] == res.transaction_id  # CON-013-05
    assert ctx["version"] == "2.0.0"
    assert spec.request_errors(f"/on_{action}", cb) == []
    entry = net.bap.callbacks_for(res.message_id)[0]
    assert entry.solicited is True  # 4-line callback signing string (NFH-007 §3.3)
    return cb


def test_full_lifecycle_happy_path(net):
    bap = net.bap
    txn = str(uuid.uuid4())

    # discover (CN -> DS); DS role is co-hosted by the BPP in this mockup
    r = bap.send("discover", P.discover("widget"), transaction_id=txn)
    assert_ack(net, r)
    cb = assert_callback(net, r, "discover")
    catalog = cb["message"]["catalogs"][0]
    assert catalog["bppId"] == net.bpp.subscriber_id

    # select -> priced quote
    r = bap.send("select", {"contract": {"commitments": P.commitments_from_catalog(catalog, 2)}},
                 transaction_id=txn)
    assert_ack(net, r)
    contract = assert_callback(net, r, "select")["message"]["contract"]
    assert contract["status"]["code"] == "DRAFT"
    assert contract["consideration"][0]["considerationAttributes"]["value"] == 200

    # init -> billing/fulfilment details, PN returns payment terms
    contract["participants"] = [P.buyer_participant()]
    r = bap.send("init", {"contract": contract}, transaction_id=txn)
    assert_ack(net, r)
    contract = assert_callback(net, r, "init")["message"]["contract"]
    assert contract["settlements"][0]["status"] == "DRAFT"
    uuid.UUID(contract["id"])  # Contract.id is a PN-generated UUID

    # confirm with payment proof -> ACTIVE
    r = bap.send("confirm", {"contract": P.with_settlement_proof(contract)}, transaction_id=txn)
    assert_ack(net, r)
    contract = assert_callback(net, r, "confirm")["message"]["contract"]
    assert contract["status"]["code"] == "ACTIVE"
    assert contract["performance"]
    cid = contract["id"]

    # status
    r = bap.send("status", {"contract": contract}, transaction_id=txn)
    assert_ack(net, r)
    assert assert_callback(net, r, "status")["message"]["contract"]["id"] == cid

    # track
    r = bap.send("track", {"tracking": {"contract": contract, "url": "https://track.invalid/req",
                                        "status": "ACTIVE"}}, transaction_id=txn)
    assert_ack(net, r)
    tracking = assert_callback(net, r, "track")["message"]["tracking"]
    assert tracking["status"] == "ACTIVE" and tracking["url"].startswith("https://")

    # update: preview (try=true) must not change state
    r = bap.send("update", {"contract": P.set_quantity(contract, 3)}, transaction_id=txn,
                 context_extra={"try": True})
    assert_ack(net, r)
    preview = assert_callback(net, r, "update")
    assert preview["context"]["try"] is True
    assert preview["message"]["contract"]["consideration"][0]["considerationAttributes"]["value"] == 300
    assert net.bpp.contracts[cid]["consideration"][0]["considerationAttributes"]["value"] == 200
    # update: commit (try=false) with requestDigest of the preview callback
    r = bap.send("update", {"contract": P.set_quantity(contract, 3)}, transaction_id=txn,
                 context_extra={"try": False,
                                "requestDigest": {"digest": bap.callback_digest(r.message_id)}})
    assert_ack(net, r)
    contract = assert_callback(net, r, "update")["message"]["contract"]
    assert contract["consideration"][0]["considerationAttributes"]["value"] == 300

    # cancel: preview then commit
    r = bap.send("cancel", {"contract": contract}, transaction_id=txn, context_extra={"try": True})
    assert_ack(net, r)
    assert assert_callback(net, r, "cancel")["message"]["contract"]["status"]["code"] == "ACTIVE"
    r = bap.send("cancel", {"contract": contract}, transaction_id=txn,
                 context_extra={"try": False,
                                "requestDigest": {"digest": bap.callback_digest(r.message_id)}})
    assert_ack(net, r)
    contract = assert_callback(net, r, "cancel")["message"]["contract"]
    assert contract["status"]["code"] == "CANCELLED"

    # rate (contract is terminal: CANCELLED)
    r = bap.send("rate", {"ratingInputs": [{"target": {"id": cid}, "range": {"best": 5, "worst": 1, "value": 4}}]},
                 transaction_id=txn)
    assert_ack(net, r)
    ratings = assert_callback(net, r, "rate")["message"]["ratings"]
    assert ratings[0]["target"]["id"] == cid

    # support
    r = bap.send("support", {"support": {"orderId": cid, "descriptor": {"name": "Refund query"}}},
                 transaction_id=txn)
    assert_ack(net, r)
    support = assert_callback(net, r, "support")["message"]["support"]
    assert support["channels"]


def test_discover_no_match_returns_ack_no_callback(net):
    """202 AckNoCallback when nothing matches (beckn.yaml 'Standard Response Families');
    CON-013-09: no callback may follow."""
    r = net.bap.send("discover", P.discover("no-such-thing-xyz"))
    assert_ack(net, r, expected_status=202)
    assert r.body["message"]["error"]["code"] == "BIZ_NO_RESULTS_FOUND"
    assert net.bap.wait_callback(r.message_id, timeout=1.0, missing_ok=True) is None


def test_commit_without_request_digest_is_nacked(net):
    """beckn.yaml /update: when context.try is false the CN MUST include
    context.requestDigest; absent -> NackBadRequest."""
    contract = net.confirmed_contract()
    r = net.bap.send("update", {"contract": P.set_quantity(contract, 5)},
                     transaction_id=net.last_transaction_id, context_extra={"try": False})
    assert r.status_code == 400
    assert r.body["message"]["status"] == "NACK"
    assert spec.component_errors("NackBadRequest", r.body) == []
    assert net.bap.wait_callback(r.message_id, timeout=1.0, missing_ok=True) is None


def test_commit_with_wrong_request_digest_is_nacked(net):
    contract = net.confirmed_contract()
    wrong = signing.request_digest(b"not the preview body")
    r = net.bap.send("cancel", {"contract": contract}, transaction_id=net.last_transaction_id,
                     context_extra={"try": False, "requestDigest": {"digest": wrong}})
    assert r.status_code == 400
    assert net.bpp.contracts[contract["id"]]["status"]["code"] == "ACTIVE"


def test_rate_before_terminal_state_is_nacked(net):
    """beckn.yaml /rate precondition: contract MUST be COMPLETE or CANCELLED."""
    contract = net.confirmed_contract()
    r = net.bap.send("rate", {"ratingInputs": [{"target": {"id": contract["id"]}, "range": {"value": 5}}]},
                     transaction_id=net.last_transaction_id)
    assert r.status_code == 400
    assert r.body["message"]["error"]["code"] == "BIZ_INVALID_STATE_TRANSITION"
