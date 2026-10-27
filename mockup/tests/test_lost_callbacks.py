"""A callback that never arrives: what can a CN do today?

Spec: docs/Communication_Protocol.md. There is no normative callback timeout or redelivery; the FAQ
entry "What happens if a PN sends an Ack but then never delivers the promised callback?" is "TBA"
(see test_spec_gaps.py). These tests pin the practical recovery path available with the spec as
written: re-ask with `status` (new messageId), and never double-book on a retried `confirm`.

The fault is injected at the BAP's callback endpoint (it answers 503 for chosen actions), which is
equivalent to a dropped on_* delivery from the BPP's point of view. No proxy is needed: v2 has no
gateway in the call path.
"""
import time
import uuid

import payloads as PL


def _to_init(net, txn):
    bap = net.bap
    r = bap.send("discover", PL.discover("widget"), transaction_id=txn)
    cat = bap.wait_callback(r.message_id)["message"]["catalogs"][0]
    r = bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(cat, 2)}}, transaction_id=txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    contract["participants"] = [PL.buyer_participant()]
    return contract


def _init(net, contract, txn):
    r = net.bap.send("init", {"contract": contract}, transaction_id=txn)
    return r


def test_dropped_callback_is_recorded_not_raised(net):
    net.bap.drop_callbacks.add("on_select")
    txn = str(uuid.uuid4())
    r = net.bap.send("discover", PL.discover("widget"), transaction_id=txn)
    cat = net.bap.wait_callback(r.message_id)["message"]["catalogs"][0]
    r = net.bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(cat, 1)}}, transaction_id=txn)
    assert r.status_code == 200
    assert net.bap.wait_callback(r.message_id, timeout=0.6, missing_ok=True) is None
    time.sleep(0.2)
    assert [a for a, _ in net.bap.dropped] == ["on_select"]
    assert ("select", r.message_id, 503) in net.bpp.callbacks_sent
    assert net.bpp.errors == []


def test_lost_on_confirm_is_recoverable_with_status(net):
    bap, txn = net.bap, str(uuid.uuid4())
    contract = _to_init(net, txn)
    r = _init(net, contract, txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    bap.drop_callbacks.add("on_confirm")
    r = bap.send("confirm", {"contract": PL.with_settlement_proof(contract)}, transaction_id=txn)
    assert r.status_code == 200
    assert bap.wait_callback(r.message_id, timeout=0.6, missing_ok=True) is None
    assert contract["id"] in net.bpp.contracts, "the PN did commit; only the callback was lost"

    bap.drop_callbacks.clear()
    # A bare {"id": ...} is schema-invalid (known spec gap, test_spec_gaps), so the CN must have kept
    # the full contract it last saw in order to ask for its status.
    s = bap.send("status", {"contract": contract}, transaction_id=txn)
    assert s.status_code == 200 and s.message_id != r.message_id
    recovered = bap.wait_callback(s.message_id)["message"]["contract"]
    assert recovered["status"]["code"] == "ACTIVE" and recovered["id"] == contract["id"]


def test_retrying_confirm_after_a_lost_callback_does_not_double_book(net):
    bap, txn = net.bap, str(uuid.uuid4())
    contract = _to_init(net, txn)
    r = _init(net, contract, txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    bap.drop_callbacks.add("on_confirm")
    bap.send("confirm", {"contract": PL.with_settlement_proof(contract)}, transaction_id=txn)
    time.sleep(0.3)
    bap.drop_callbacks.clear()
    again = bap.send("confirm", {"contract": PL.with_settlement_proof(contract)}, transaction_id=txn)
    assert again.status_code == 400 and "BIZ_ALREADY_CONFIRMED" in str(again.body)
    assert list(net.bpp.contracts) == [contract["id"]]


def test_lost_on_init_then_retried_init_reuses_the_same_draft(net):
    bap, txn = net.bap, str(uuid.uuid4())
    contract = _to_init(net, txn)
    bap.drop_callbacks.add("on_init")
    r1 = _init(net, contract, txn)
    assert bap.wait_callback(r1.message_id, timeout=0.6, missing_ok=True) is None
    bap.drop_callbacks.clear()
    r2 = _init(net, contract, txn)
    retried = bap.wait_callback(r2.message_id)["message"]["contract"]
    drafts = [d for d in net.bpp.drafts.values() if "id" in d]
    assert len(drafts) == 1 and drafts[0]["id"] == retried["id"]


def test_the_bpp_does_not_redeliver_a_dropped_callback_on_its_own(net):
    """Documented behaviour, not a spec requirement: one delivery attempt per callback."""
    bap, txn = net.bap, str(uuid.uuid4())
    bap.drop_callbacks.add("on_select")
    r = bap.send("discover", PL.discover("widget"), transaction_id=txn)
    cat = bap.wait_callback(r.message_id)["message"]["catalogs"][0]
    r = bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(cat, 1)}}, transaction_id=txn)
    time.sleep(0.8)
    assert [x for x in net.bpp.callbacks_sent if x[0] == "select"] == [("select", r.message_id, 503)]
