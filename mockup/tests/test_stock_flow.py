"""The seller node sells only what the lot ledger has: select/init check stock, confirm takes it,
cancel and update give it back, and two buyers cannot both get the last kilograms."""
import uuid
from decimal import Decimal
from pathlib import Path

import pytest

from beckn_mock import packs as P
from beckn_mock.catalogstore import CatalogStore
from beckn_mock.lots import LotLedger
from beckn_mock.network import MockNetwork
from beckn_mock.policy import Policy
import payloads as PL

REPO = Path(__file__).resolve().parents[2]
REGISTRY = P.PackRegistry.from_dir(REPO / "packs")
POLICY = Policy.from_file(REPO / "packs" / "policies" / "kumaon-smallholder.json")


def lot(**over):
    base = dict(id="L-001", product="Turmeric fingers", grade="A", quantity=10, unitCode="KGM",
                originType="own-land", source=["hh-001"], harvestDate="2026-10-01")
    base.update(over)
    return base


@pytest.fixture
def hub():
    ledger = LotLedger()
    ledger.receive(lot())
    cat = ledger.catalog("catalog-hub-001", {"id": "provider-hub", "descriptor": {"name": "Hub"}},
                         {("Turmeric fingers", "A"): 180})
    store = CatalogStore(REGISTRY, POLICY)
    store.publish(cat)
    with MockNetwork(store=store, ledger=ledger) as n:
        n.ledger = ledger
        yield n
        assert n.bpp.errors == [], n.bpp.errors


def discover(net, txn):
    r = net.bap.send("discover", PL.discover("turmeric"), transaction_id=txn)
    return net.bap.wait_callback(r.message_id)["message"]["catalogs"][0]


def select(net, qty, txn=None):
    txn = txn or str(uuid.uuid4())
    cat = discover(net, txn)
    return txn, cat, net.bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(cat, qty)}},
                                  transaction_id=txn)


def buy(net, qty):
    txn, cat, r = select(net, qty)
    assert r.status_code == 200, r.body
    bap = net.bap
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    contract["participants"] = [PL.buyer_participant()]
    r = bap.send("init", {"contract": contract}, transaction_id=txn)
    assert r.status_code == 200, r.body
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    return txn, contract


def confirm(net, txn, contract):
    r = net.bap.send("confirm", {"contract": PL.with_settlement_proof(contract)}, transaction_id=txn)
    return r


def rid(net):
    return net.ledger.resource_id(lot())


def test_the_catalog_the_buyer_sees_states_the_stock_snapshot(hub):
    cat = discover(hub, str(uuid.uuid4()))
    assert cat["offers"][0]["offerAttributes"]["availableQuantity"] == 10


def test_select_for_more_than_is_on_hand_is_refused(hub):
    _, _, r = select(hub, 10.5)
    assert r.status_code == 400 and "BIZ_QUANTITY_UNAVAILABLE" in str(r.body)
    assert hub.ledger.available_for(rid(hub)) == Decimal(10)


def test_selecting_does_not_take_stock_but_confirming_does(hub):
    txn, contract = buy(hub, 4)
    assert hub.ledger.available_for(rid(hub)) == Decimal(10)
    r = confirm(hub, txn, contract)
    assert r.status_code == 200
    done = hub.bap.wait_callback(r.message_id)["message"]["contract"]
    assert done["status"]["code"] == "ACTIVE"
    assert hub.ledger.available_for(rid(hub)) == Decimal(6)


def test_two_buyers_cannot_both_get_the_last_kilograms(hub):
    t1, c1 = buy(hub, 7)
    t2, c2 = buy(hub, 7)          # both saw 10 kg, both quoted
    assert confirm(hub, t1, c1).status_code == 200
    second = confirm(hub, t2, c2)
    assert second.status_code == 400 and "BIZ_QUANTITY_UNAVAILABLE" in str(second.body)
    assert hub.ledger.available_for(rid(hub)) == Decimal(3)


def test_a_refused_confirm_leaves_no_contract_behind(hub):
    t1, c1 = buy(hub, 7)
    t2, c2 = buy(hub, 7)
    confirm(hub, t1, c1)
    confirm(hub, t2, c2)
    assert len(hub.bpp.contracts) == 1


def _two_phase(net, action, txn, contract, **msg):
    """try=true preview, then the commit chained to the preview's digest. Returns the commit's send result."""
    bap = net.bap
    r = bap.send(action, {"contract": contract}, transaction_id=txn, context_extra={"try": True})
    if r.status_code != 200:
        return r
    bap.wait_callback(r.message_id)
    digest = bap.callback_digest(r.message_id)
    r2 = bap.send(action, {"contract": contract}, transaction_id=txn,
                  context_extra={"try": False, "requestDigest": {"digest": digest}})
    if r2.status_code == 200:
        bap.wait_callback(r2.message_id)
    return r2


def _confirmed(net, qty):
    txn, contract = buy(net, qty)
    r = confirm(net, txn, contract)
    return txn, net.bap.wait_callback(r.message_id)["message"]["contract"]


def test_cancelling_returns_the_stock(hub):
    txn, done = _confirmed(hub, 6)
    assert hub.ledger.available_for(rid(hub)) == Decimal(4)
    r = _two_phase(hub, "cancel", txn, done)
    assert r.status_code == 200
    assert hub.ledger.available_for(rid(hub)) == Decimal(10)


def test_a_previewed_cancel_that_is_never_committed_keeps_the_stock_sold(hub):
    txn, done = _confirmed(hub, 6)
    r = hub.bap.send("cancel", {"contract": done}, transaction_id=txn, context_extra={"try": True})
    hub.bap.wait_callback(r.message_id)
    assert hub.ledger.available_for(rid(hub)) == Decimal(4)


def test_a_bigger_update_beyond_stock_is_refused(hub):
    txn, done = _confirmed(hub, 6)
    r = hub.bap.send("update", {"contract": PL.set_quantity(done, 11)}, transaction_id=txn, context_extra={"try": True})
    assert r.status_code == 400 and "BIZ_QUANTITY_UNAVAILABLE" in str(r.body)
    assert hub.ledger.available_for(rid(hub)) == Decimal(4)


def test_an_update_within_stock_adjusts_the_ledger_on_commit_only(hub):
    txn, done = _confirmed(hub, 6)
    bigger = PL.set_quantity(done, 10)           # 6 held + 4 free: allowed
    bap = hub.bap
    r = bap.send("update", {"contract": bigger}, transaction_id=txn, context_extra={"try": True})
    assert r.status_code == 200
    bap.wait_callback(r.message_id)
    assert hub.ledger.available_for(rid(hub)) == Decimal(4), "a preview must not move stock"
    r2 = bap.send("update", {"contract": bigger}, transaction_id=txn,
                  context_extra={"try": False, "requestDigest": {"digest": bap.callback_digest(r.message_id)}})
    assert r2.status_code == 200
    bap.wait_callback(r2.message_id)
    assert hub.ledger.available_for(rid(hub)) == Decimal(0)
    smaller = PL.set_quantity(done, 2)
    assert _two_phase(hub, "update", txn, smaller).status_code == 200
    assert hub.ledger.available_for(rid(hub)) == Decimal(8)


def test_stock_that_cannot_be_matched_to_the_ledger_is_not_sold(hub):
    """A node given a ledger must not sell a resource the ledger has never heard of."""
    txn, cat, r = select(hub, 1)
    assert r.status_code == 200
    hub.ledger.write_off("L-001", 10, reason="flood damage")
    _, _, r = select(hub, 1)
    assert r.status_code == 400 and "BIZ_QUANTITY_UNAVAILABLE" in str(r.body)
