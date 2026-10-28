"""Lot ledger for a Kumaon-style aggregation hub: lots in, grade-priced stock out, no overselling.

Smallholder lots arrive graded and assayed; the hub sells (or moves internally to its own factory)
only what is on hand. Every change is an append-only event, and on-hand always equals the event sum.
"""
import json
import threading
from decimal import Decimal
from pathlib import Path

import pytest

from beckn_mock import packs as P
from beckn_mock.catalogstore import CatalogStore
from beckn_mock.lots import LotError, LotLedger
from beckn_mock.policy import Policy

REPO = Path(__file__).resolve().parents[2]
REGISTRY = P.PackRegistry.from_dir(REPO / "packs")
POLICY = Policy.from_file(REPO / "packs" / "policies" / "kumaon-smallholder.json")


def lot(**over):
    base = dict(id="L-001", product="Turmeric fingers", grade="A", quantity=100, unitCode="KGM",
                originType="own-land", source=["hh-001", "hh-002"], harvestDate="2026-10-01",
                gradingStandard="e-NAM", moisturePercent=9.5, brixDegrees=None,
                certificationScheme="PGS-India", certificationScope="domestic", location="SIDC Bhimtal")
    base.update(over)
    return {k: v for k, v in base.items() if v is not None}


@pytest.fixture
def ledger():
    return LotLedger()


# ---------------------------------------------------------------- receiving
def test_a_received_lot_is_on_hand_and_available(ledger):
    lid = ledger.receive(lot())
    assert ledger.on_hand(lid) == Decimal(100) and ledger.available_for(ledger.resource_id(lot())) == Decimal(100)


@pytest.mark.parametrize("over,why", [
    (dict(originType="forest-parcel"), "originType"),
    (dict(originType=None), "originType"),
    (dict(source=[]), "source"),
    (dict(source=None), "source"),
    (dict(quantity=0), "quantity"),
    (dict(quantity=-5), "quantity"),
    (dict(quantity=True), "quantity"),
    (dict(quantity="12abc"), "quantity"),
    (dict(quantity=1.2345), "quantity"),
    (dict(quantity=float("inf")), "quantity"),
    (dict(quantity=2_000_000_000), "quantity"),
    (dict(grade=None), "grade"),
    (dict(product=""), "product"),
    (dict(certificationScope="worldwide"), "certificationScope"),
    (dict(moisturePercent=140), "moisturePercent"),
    (dict(unitCode="BUSHEL"), "unitCode"),
    (dict(id=None), "id"),
])
def test_invalid_lots_are_refused_with_the_field_named(ledger, over, why):
    with pytest.raises(LotError, match=why):
        ledger.receive(lot(**over))


def test_a_lot_id_cannot_be_received_twice(ledger):
    ledger.receive(lot())
    with pytest.raises(LotError, match="already"):
        ledger.receive(lot())


def test_forest_parcel_produce_is_refused_with_the_reason(ledger):
    with pytest.raises(LotError, match="Green Credit"):
        ledger.receive(lot(originType="gcp-forest-parcel"))


def test_fractional_quantities_are_exact(ledger):
    ledger.receive(lot(quantity="12.345"))
    rid = ledger.resource_id(lot())
    ledger.sell("order-1", {rid: "0.001"})
    assert ledger.on_hand_for(rid) == Decimal("12.344")


# ---------------------------------------------------------------- selling
def test_stock_is_allocated_first_in_first_out_across_lots(ledger):
    ledger.receive(lot(id="L-001", quantity=30))
    ledger.receive(lot(id="L-002", quantity=30))
    rid = ledger.resource_id(lot())
    alloc = ledger.sell("order-1", {rid: 45})
    assert alloc == [("L-001", Decimal(30)), ("L-002", Decimal(15))]
    assert ledger.available_for(rid) == Decimal(15)


def test_selling_more_than_available_changes_nothing(ledger):
    ledger.receive(lot(quantity=10))
    rid = ledger.resource_id(lot())
    with pytest.raises(LotError, match="insufficient"):
        ledger.sell("order-1", {rid: 10.001})
    assert ledger.available_for(rid) == Decimal(10)


def test_a_multi_item_sale_is_all_or_nothing(ledger):
    ledger.receive(lot(id="L-001", quantity=10))
    ledger.receive(lot(id="L-002", product="Ginger", quantity=1))
    a, b = ledger.resource_id(lot()), ledger.resource_id(lot(product="Ginger"))
    with pytest.raises(LotError, match="insufficient"):
        ledger.sell("order-1", {a: 5, b: 2})
    assert ledger.available_for(a) == Decimal(10) and ledger.available_for(b) == Decimal(1)


def test_the_same_order_reference_cannot_sell_twice(ledger):
    ledger.receive(lot())
    rid = ledger.resource_id(lot())
    ledger.sell("order-1", {rid: 5})
    with pytest.raises(LotError, match="already"):
        ledger.sell("order-1", {rid: 5})


def test_unsell_restores_the_stock_to_the_same_lots(ledger):
    ledger.receive(lot(id="L-001", quantity=30))
    ledger.receive(lot(id="L-002", quantity=30))
    rid = ledger.resource_id(lot())
    ledger.sell("order-1", {rid: 45})
    ledger.unsell("order-1")
    assert ledger.on_hand("L-001") == Decimal(30) and ledger.on_hand("L-002") == Decimal(30)
    ledger.unsell("order-1")  # idempotent: a retried cancel must not add stock twice
    assert ledger.available_for(rid) == Decimal(60)


def test_resell_changes_an_order_atomically(ledger):
    ledger.receive(lot(quantity=10))
    rid = ledger.resource_id(lot())
    ledger.sell("order-1", {rid: 4})
    ledger.resell("order-1", {rid: 9})
    assert ledger.available_for(rid) == Decimal(1)
    with pytest.raises(LotError, match="insufficient"):
        ledger.resell("order-1", {rid: 11})
    assert ledger.available_for(rid) == Decimal(1), "a failed change keeps the previous allocation"


def test_available_for_can_count_what_an_order_already_holds(ledger):
    ledger.receive(lot(quantity=10))
    rid = ledger.resource_id(lot())
    ledger.sell("order-1", {rid: 8})
    assert ledger.available_for(rid) == Decimal(2)
    assert ledger.available_for(rid, ref="order-1") == Decimal(10)


def test_concurrent_buyers_never_oversell(ledger):
    ledger.receive(lot(quantity=50))
    rid = ledger.resource_id(lot())
    results = []

    def buy(i):
        try:
            ledger.sell(f"order-{i}", {rid: 1})
            results.append(True)
        except LotError:
            results.append(False)

    threads = [threading.Thread(target=buy, args=(i,)) for i in range(120)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(results) == 50 and ledger.available_for(rid) == 0


# ---------------------------------------------------------------- the hub's own factory
def test_a_transfer_to_the_factory_draws_down_stock_without_a_sale(ledger):
    ledger.receive(lot(quantity=40))
    rid = ledger.resource_id(lot())
    ledger.transfer(rid, 15, to="factory", reference="batch-7")
    assert ledger.available_for(rid) == Decimal(25)
    kinds = [e["type"] for lid in ("L-001",) for e in ledger.events(lid)]
    assert kinds == ["receive", "transfer"]


def test_a_transfer_cannot_take_stock_that_is_sold(ledger):
    ledger.receive(lot(quantity=10))
    rid = ledger.resource_id(lot())
    ledger.sell("order-1", {rid: 8})
    with pytest.raises(LotError, match="insufficient"):
        ledger.transfer(rid, 3, to="factory", reference="batch-8")


def test_a_write_off_needs_a_reason_and_cannot_exceed_what_is_free(ledger):
    ledger.receive(lot(quantity=10))
    with pytest.raises(LotError, match="reason"):
        ledger.write_off("L-001", 1, reason="")
    with pytest.raises(LotError, match="insufficient"):
        ledger.write_off("L-001", 11, reason="spoilage")
    ledger.write_off("L-001", 2, reason="mould found at regrading")
    assert ledger.on_hand("L-001") == Decimal(8)


# ---------------------------------------------------------------- audit trail
def test_on_hand_always_equals_the_sum_of_the_events(ledger):
    ledger.receive(lot(quantity=100))
    rid = ledger.resource_id(lot())
    ledger.sell("o1", {rid: 30.5})
    ledger.transfer(rid, 10, to="factory", reference="b1")
    ledger.unsell("o1")
    ledger.sell("o2", {rid: 7})
    ledger.write_off("L-001", 1, reason="spill")
    total = sum(Decimal(str(e["delta"])) for e in ledger.events("L-001"))
    assert total == ledger.on_hand("L-001") == Decimal(100) - 7 - 10 - 1


def test_events_are_copies_not_the_ledger_itself(ledger):
    ledger.receive(lot())
    ledger.events("L-001")[0]["delta"] = 99999
    assert ledger.on_hand("L-001") == Decimal(100)


def test_every_event_names_who_the_stock_came_from_or_went_to(ledger):
    ledger.receive(lot())
    rid = ledger.resource_id(lot())
    ledger.sell("order-9", {rid: 1})
    ev = ledger.events("L-001")
    assert ev[0]["source"] == ["hh-001", "hh-002"] and ev[1]["ref"] == "order-9"


# ---------------------------------------------------------------- published catalog
def prices():
    return {("Turmeric fingers", "A"): 180, ("Turmeric fingers", "B"): 150}


def test_lots_publish_as_one_resource_per_product_and_grade(ledger):
    ledger.receive(lot(id="L-001", grade="A", quantity=40, moisturePercent=9.0))
    ledger.receive(lot(id="L-002", grade="A", quantity=60, moisturePercent=10.5))
    ledger.receive(lot(id="L-003", grade="B", quantity=20))
    cat = ledger.catalog("catalog-hub-001", {"id": "provider-hub", "descriptor": {"name": "Bhimtal hub"}}, prices())
    assert len(cat["resources"]) == 2 and len(cat["offers"]) == 2
    a = next(r for r in cat["resources"] if r["descriptor"]["name"].endswith("grade A"))
    attrs = a["resourceAttributes"]
    assert attrs["moisturePercent"] == 10.5, "the catalog states the worst lot, not the best"
    assert attrs["originType"] == "own-land" and attrs["certificationScope"] == "domestic"
    offer = next(o for o in cat["offers"] if a["id"] in o["resourceIds"])
    assert offer["offerAttributes"]["availableQuantity"] == 100
    assert offer["considerations"][0]["considerationAttributes"]["value"] == 180


def test_the_generated_catalog_passes_the_strict_policy_and_publishes(ledger):
    ledger.receive(lot())
    cat = ledger.catalog("catalog-hub-001", {"id": "provider-hub", "descriptor": {"name": "Hub"}}, prices())
    CatalogStore(REGISTRY, POLICY).publish(cat)


def test_stock_that_is_all_sold_is_left_out_of_the_catalog(ledger):
    ledger.receive(lot(quantity=5))
    ledger.receive(lot(id="L-002", product="Ginger", quantity=5))
    ledger.sell("o1", {ledger.resource_id(lot()): 5})
    cat = ledger.catalog("c", {"id": "p", "descriptor": {"name": "Hub"}}, {**prices(), ("Ginger", "A"): 90})
    assert [r["descriptor"]["name"].split()[0] for r in cat["resources"]] == ["Ginger"]


def test_a_product_without_a_price_is_not_published_silently(ledger):
    ledger.receive(lot(product="Mystery root"))
    with pytest.raises(LotError, match="price"):
        ledger.catalog("c", {"id": "p", "descriptor": {"name": "Hub"}}, prices())


def test_the_strict_policy_requires_a_provenance_type_and_limits_certificate_scope():
    base = {"@context": "https://packs.beckn-eval.invalid/schemas/Produce/v0.1/context.jsonld", "@type": "Produce",
            "originCountry": "IN"}
    assert POLICY.attribute_errors(base), "originType is required by this network"
    ok = dict(base, originType="own-land", certificationScope="export")
    assert not POLICY.attribute_errors(ok)
    assert POLICY.attribute_errors(dict(ok, certificationScope="galactic"))
    assert POLICY.attribute_errors(dict(ok, originType="gcp-forest-parcel"))
    assert not REGISTRY.attribute_errors(ok)
