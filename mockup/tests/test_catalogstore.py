"""Catalog store: validates against the Beckn Catalog schema plus domain packs, keeps versions,
and answers discovery queries across several catalogs."""
import copy
import json
from pathlib import Path

import pytest

from beckn_mock import packs as P
from beckn_mock.catalogstore import CatalogStore, CatalogRejected

REPO = Path(__file__).resolve().parents[2]
PACKS_DIR = REPO / "packs"
REGISTRY = P.PackRegistry.from_dir(PACKS_DIR)
SAMPLES = sorted(PACKS_DIR.glob("*/catalog.json"))


def _load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_each_pack_ships_a_sample_catalog():
    assert {p.parent.name for p in SAMPLES} >= {"agri-produce", "energy-der", "tourism-listing"}


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.parent.name)
def test_sample_catalogs_publish_cleanly(path):
    store = CatalogStore(REGISTRY)
    rec = store.publish(_load(path))
    assert rec["version"] == 1
    assert store.get(rec["id"])["id"] == rec["id"]


def test_publish_rejects_a_schema_invalid_catalog_and_leaves_store_unchanged():
    store = CatalogStore(REGISTRY)
    bad = _load(SAMPLES[0])
    del bad["provider"]
    with pytest.raises(CatalogRejected) as e:
        store.publish(bad)
    assert any("provider" in x for x in e.value.errors)
    assert store.ids() == []


def test_publish_rejects_bad_domain_attributes_with_a_path():
    store = CatalogStore(REGISTRY)
    cat = _load(PACKS_DIR / "energy-der" / "catalog.json")
    cat["resources"][0]["resourceAttributes"]["capacityKw"] = -5
    with pytest.raises(CatalogRejected) as e:
        store.publish(cat)
    assert any("resources[0].resourceAttributes" in x for x in e.value.errors), e.value.errors


def test_publish_rejects_offer_that_references_a_missing_resource():
    store = CatalogStore(REGISTRY)
    cat = _load(PACKS_DIR / "agri-produce" / "catalog.json")
    cat["offers"][0]["resourceIds"] = ["no-such-resource"]
    with pytest.raises(CatalogRejected):
        store.publish(cat)


def test_publish_rejects_offer_without_a_usable_price():
    store = CatalogStore(REGISTRY)
    cat = _load(PACKS_DIR / "agri-produce" / "catalog.json")
    cat["offers"][0]["considerations"][0]["considerationAttributes"]["value"] = "free"
    with pytest.raises(CatalogRejected):
        store.publish(cat)


def test_offer_and_resource_ids_must_be_unique_store_wide():
    store = CatalogStore(REGISTRY)
    store.publish(_load(PACKS_DIR / "agri-produce" / "catalog.json"))
    clash = _load(PACKS_DIR / "energy-der" / "catalog.json")
    clash["offers"][0]["id"] = _load(PACKS_DIR / "agri-produce" / "catalog.json")["offers"][0]["id"]
    with pytest.raises(CatalogRejected):
        store.publish(clash)


def test_republishing_bumps_the_version_and_keeps_history():
    store = CatalogStore(REGISTRY)
    cat = _load(PACKS_DIR / "agri-produce" / "catalog.json")
    store.publish(cat)
    cat2 = copy.deepcopy(cat)
    cat2["offers"][0]["considerations"][0]["considerationAttributes"]["value"] += 1
    rec = store.publish(cat2)
    assert rec["version"] == 2
    assert [h["version"] for h in store.history(cat["id"])] == [1, 2]
    assert store.get(cat["id"], version=1)["offers"][0] == cat["offers"][0]


def test_republishing_identical_content_is_idempotent():
    store = CatalogStore(REGISTRY)
    cat = _load(PACKS_DIR / "tourism-listing" / "catalog.json")
    store.publish(cat)
    assert store.publish(copy.deepcopy(cat))["version"] == 1


def test_deactivated_catalogs_are_not_discoverable_but_remain_in_history():
    store = CatalogStore(REGISTRY)
    cat = _load(PACKS_DIR / "tourism-listing" / "catalog.json")
    store.publish(cat)
    store.deactivate(cat["id"])
    assert store.active() == []
    assert store.history(cat["id"])


def test_discovery_spans_catalogs_and_filters_by_text():
    store = CatalogStore(REGISTRY)
    for p in SAMPLES:
        store.publish(_load(p))
    assert len(store.active()) == len(SAMPLES)
    every = store.search(None)
    assert len(every) == len(SAMPLES)
    hits = store.search("solar")
    assert len(hits) == 1 and hits[0]["id"] == _load(PACKS_DIR / "energy-der" / "catalog.json")["id"]
    for r in hits[0]["resources"]:
        assert "solar" in json.dumps(r).lower()
    assert store.search("zzz-no-such-thing") == []


def test_search_never_returns_the_stored_object_itself():
    store = CatalogStore(REGISTRY)
    store.publish(_load(SAMPLES[0]))
    out = store.search(None)
    out[0]["resources"].clear()
    assert store.search(None)[0]["resources"]


def test_load_dir_publishes_every_json_file(tmp_path):
    for p in SAMPLES:
        (tmp_path / f"{p.parent.name}.json").write_text(p.read_text(encoding="utf-8"), encoding="utf-8")
    store = CatalogStore.from_dir(tmp_path, REGISTRY)
    assert len(store.ids()) == len(SAMPLES)


def test_load_dir_fails_loudly_on_an_invalid_file(tmp_path):
    (tmp_path / "x.json").write_text("{}", encoding="utf-8")
    with pytest.raises(CatalogRejected):
        CatalogStore.from_dir(tmp_path, REGISTRY)
