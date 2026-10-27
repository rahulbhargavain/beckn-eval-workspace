"""End to end: each domain pack's sample catalog is discoverable, quotable and confirmable
through the signed BAP -> BPP flow, with no domain-specific code in the BPP."""
import json
import uuid
from pathlib import Path

import pytest

from beckn_mock import packs as P
from beckn_mock.catalogstore import CatalogStore
from beckn_mock.network import MockNetwork
import payloads as PL

REPO = Path(__file__).resolve().parents[2]
PACKS_DIR = REPO / "packs"
REGISTRY = P.PackRegistry.from_dir(PACKS_DIR)
DOMAINS = sorted(p.parent.name for p in PACKS_DIR.glob("*/catalog.json"))


@pytest.fixture
def domain_net():
    store = CatalogStore(REGISTRY)
    for d in DOMAINS:
        store.publish(json.loads((PACKS_DIR / d / "catalog.json").read_text(encoding="utf-8")))
    with MockNetwork(store=store) as n:
        yield n
        assert n.bpp.errors == [], n.bpp.errors


def _first_offer_price(domain):
    cat = json.loads((PACKS_DIR / domain / "catalog.json").read_text(encoding="utf-8"))
    return cat, cat["offers"][0]["considerations"][0]["considerationAttributes"]["value"]


def test_discover_without_text_returns_every_domain(domain_net):
    r = domain_net.bap.send("discover", {"intent": {}}, transaction_id=str(uuid.uuid4()))
    cb = domain_net.bap.wait_callback(r.message_id)
    ids = {c["id"] for c in cb["message"]["catalogs"]}
    want = {json.loads((PACKS_DIR / d / "catalog.json").read_text(encoding="utf-8"))["id"] for d in DOMAINS}
    assert ids == want


@pytest.mark.parametrize("domain", DOMAINS)
def test_select_quotes_from_the_domain_catalog(domain_net, domain):
    cat, price = _first_offer_price(domain)
    res = cat["resources"][0]
    word = res["descriptor"]["name"].split()[0]
    txn = str(uuid.uuid4())
    r = domain_net.bap.send("discover", PL.discover(word), transaction_id=txn)
    got = domain_net.bap.wait_callback(r.message_id)["message"]["catalogs"]
    assert [c["id"] for c in got] == [cat["id"]], "text search must narrow to the matching domain"
    offer = got[0]["offers"][0]
    r = domain_net.bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(got[0], 3)}},
                            transaction_id=txn)
    contract = domain_net.bap.wait_callback(r.message_id)["message"]["contract"]
    assert contract["consideration"][0]["considerationAttributes"]["value"] == price * 3
    unit = offer.get("offerAttributes", {}).get("unitCode")
    if unit:
        assert contract["commitments"][0]["resources"][0]["quantity"]["unitCode"] == unit


@pytest.mark.parametrize("domain", DOMAINS)
def test_full_purchase_for_each_domain(domain_net, domain):
    cat, price = _first_offer_price(domain)
    word = cat["resources"][0]["descriptor"]["name"].split()[0]
    bap, txn = domain_net.bap, str(uuid.uuid4())
    r = bap.send("discover", PL.discover(word), transaction_id=txn)
    catalog = bap.wait_callback(r.message_id)["message"]["catalogs"][0]
    r = bap.send("select", {"contract": {"commitments": PL.commitments_from_catalog(catalog, 2)}}, transaction_id=txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    contract["participants"] = [PL.buyer_participant()]
    r = bap.send("init", {"contract": contract}, transaction_id=txn)
    contract = bap.wait_callback(r.message_id)["message"]["contract"]
    r = bap.send("confirm", {"contract": PL.with_settlement_proof(contract)}, transaction_id=txn)
    done = bap.wait_callback(r.message_id)["message"]["contract"]
    assert done["status"]["code"] == "ACTIVE"
    assert done["consideration"][0]["considerationAttributes"]["value"] == price * 2


def test_client_cannot_substitute_an_offer_from_another_domain_price(domain_net):
    """Quote is recomputed from the catalog: a resource not in the named offer is refused."""
    agri, _ = _first_offer_price("agri-produce")
    energy, _ = _first_offer_price("energy-der")
    bad = [{"id": "c1", "status": {"descriptor": {"code": "DRAFT"}},
            "resources": [{"id": energy["resources"][0]["id"], "quantity": {"unitQuantity": 1, "unitCode": "UNIT"}}],
            "offer": {"id": agri["offers"][0]["id"], "resourceIds": [energy["resources"][0]["id"]]}}]
    r = domain_net.bap.send("select", {"contract": {"commitments": bad}}, transaction_id=str(uuid.uuid4()))
    assert r.status_code == 400, r.body
