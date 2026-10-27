"""Fractional quantities for physical commodities (graded harvests, bulk energy).

The core Beckn schema leaves Commitment.resources[].quantity unconstrained (Resource has no
quantity property), so integer-only was this mockup's own rule, not the spec's. The BPP now accepts
positive decimals with at most three places, up to 1e9, and computes totals exactly (Decimal),
rounding only the final total half-up to two places (an assumption: minor-unit rounding is a
network/currency decision, not specified here).
"""
import json
import uuid
from pathlib import Path

import pytest

from beckn_mock import packs as P
from beckn_mock.catalogstore import CatalogStore
from beckn_mock.network import MockNetwork
from beckn_mock.policy import Policy
import payloads as PL

PACKS_DIR = Path(__file__).resolve().parents[2] / "packs"
REGISTRY = P.PackRegistry.from_dir(PACKS_DIR)
POLICY = Policy.from_file(PACKS_DIR / "policies" / "eval-default.json")
RICE_PRICE = 95  # packs/catalogs/agri.json, offer-agri-rice


@pytest.fixture
def agri_net():
    store = CatalogStore(REGISTRY, POLICY)
    store.publish(json.loads((PACKS_DIR / "catalogs" / "agri.json").read_text(encoding="utf-8")))
    with MockNetwork(store=store) as n:
        yield n
        assert n.bpp.errors == [], n.bpp.errors


def _catalog(net, txn):
    r = net.bap.send("discover", PL.discover("Basmati"), transaction_id=txn)
    return net.bap.wait_callback(r.message_id)["message"]["catalogs"][0]


def _select(net, qty, txn=None):
    txn = txn or str(uuid.uuid4())
    cat = _catalog(net, txn)
    return net.bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(cat, qty)}},
                        transaction_id=txn), txn


@pytest.mark.parametrize("qty,total", [(1.5, 142.5), (0.25, 23.75), (3, 285), (1.333, 126.64), (0.001, 0.1)])
def test_fractional_quantities_are_priced_exactly(agri_net, qty, total):
    r, _ = _select(agri_net, qty)
    assert r.status_code == 200, r.body
    contract = agri_net.bap.wait_callback(r.message_id)["message"]["contract"]
    assert contract["consideration"][0]["considerationAttributes"]["value"] == total
    assert contract["commitments"][0]["resources"][0]["quantity"]["unitQuantity"] == qty
    assert contract["commitments"][0]["resources"][0]["quantity"]["unitCode"] == "KGM"


def test_float_noise_does_not_leak_into_totals(agri_net):
    """0.1 + 0.2 style drift: three lots of 0.1 kg at 95 must total 28.5, not 28.499999."""
    r, _ = _select(agri_net, 0.3)
    value = agri_net.bap.wait_callback(r.message_id)["message"]["contract"]["consideration"][0]["considerationAttributes"]["value"]
    assert value == 28.5


@pytest.mark.parametrize("bad", [0, 0.0, -1, -0.5, 1.2345, 1e12, 1e-7, "1.5", True, None, float("nan"), float("inf")],
                         ids=lambda v: repr(v))
def test_invalid_quantities_are_refused_synchronously(agri_net, bad):
    r, _ = _select(agri_net, bad)
    assert r.status_code == 400, r.body
    assert "BIZ_QUANTITY_UNAVAILABLE" in json.dumps(r.body)


def test_fractional_purchase_end_to_end(agri_net):
    bap, txn = agri_net.bap, str(uuid.uuid4())
    cat = _catalog(agri_net, txn)
    r = bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(cat, 2.5)}}, transaction_id=txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    contract["participants"] = [PL.buyer_participant()]
    r = bap.send("init", {"contract": contract}, transaction_id=txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    assert contract["consideration"][0]["considerationAttributes"]["value"] == 237.5
    r = bap.send("confirm", {"contract": PL.with_settlement_proof(contract)}, transaction_id=txn)
    done = bap.wait_callback(r.message_id)["message"]["contract"]
    assert done["status"]["code"] == "ACTIVE"
    assert done["consideration"][0]["considerationAttributes"]["value"] == 237.5


def test_client_cannot_underpay_by_confirming_a_different_fraction(agri_net):
    """Confirm recomputes from the catalog and the quantity it names; a stale lower total is ignored."""
    bap, txn = agri_net.bap, str(uuid.uuid4())
    cat = _catalog(agri_net, txn)
    r = bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(cat, 1)}}, transaction_id=txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    contract["participants"] = [PL.buyer_participant()]
    r = bap.send("init", {"contract": contract}, transaction_id=txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    paid = PL.with_settlement_proof(contract)
    paid["consideration"][0]["considerationAttributes"]["value"] = 0.01
    r = bap.send("confirm", {"contract": paid}, transaction_id=txn)
    done = bap.wait_callback(r.message_id)["message"]["contract"]
    assert done["consideration"][0]["considerationAttributes"]["value"] == RICE_PRICE
