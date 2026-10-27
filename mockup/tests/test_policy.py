"""Network policy layer: mandatory attributes and controlled vocabularies, kept out of the schemas
(docs/Schema_Design_Guide.md: no attribute is mandatory by default; networks choose by policy)."""
import json
from pathlib import Path

import pytest

from beckn_mock import packs as P
from beckn_mock.catalogstore import CatalogRejected, CatalogStore
from beckn_mock.policy import Policy, PolicyError

REPO = Path(__file__).resolve().parents[2]
PACKS_DIR = REPO / "packs"
REGISTRY = P.PackRegistry.from_dir(PACKS_DIR)
POLICY = Policy.from_file(PACKS_DIR / "policies" / "eval-default.json")


def _cat(name):
    return json.loads((PACKS_DIR / "catalogs" / f"{name}.json").read_text(encoding="utf-8"))


def test_policy_requires_listed_attributes():
    ctx = REGISTRY.context_for("EnergySource")
    errs = POLICY.attribute_errors({"@context": ctx, "@type": "EnergySource", "sourceType": "SOLAR_PV", "capacityKw": 5})
    assert any("meterId" in e for e in errs), errs


def test_policy_enforces_vocabulary():
    ctx = REGISTRY.context_for("ProduceTerms")
    errs = POLICY.attribute_errors({"@context": ctx, "@type": "ProduceTerms", "unitCode": "BUSHEL"})
    assert any("unitCode" in e for e in errs), errs
    assert POLICY.attribute_errors({"@context": ctx, "@type": "ProduceTerms", "unitCode": "KGM"}) == []


def test_policy_ignores_types_it_has_no_rule_for():
    assert POLICY.attribute_errors({"@context": "x", "@type": "NoRule"}) == []


def test_policy_examples_in_every_schema_dir():
    seen = 0
    for d in sorted((PACKS_DIR / "schemas").glob("*/*")):
        ex = json.loads((d / "examples.json").read_text(encoding="utf-8"))
        for bad in ex["invalid"]:
            if bad["layer"] == "policy":
                seen += 1
                assert REGISTRY.attribute_errors(bad["attributes"]) == [], bad["reason"]
                assert POLICY.attribute_errors(bad["attributes"]), bad["reason"]
        for good in ex["valid"]:
            assert POLICY.attribute_errors(good) == [], good
    assert seen >= 3


def test_store_without_policy_accepts_what_policy_would_reject():
    cat = _cat("energy")
    del cat["resources"][0]["resourceAttributes"]["meterId"]
    CatalogStore(REGISTRY).publish(cat)
    with pytest.raises(CatalogRejected) as e:
        CatalogStore(REGISTRY, POLICY).publish(cat)
    assert any("meterId" in x for x in e.value.errors), e.value.errors


def test_a_different_network_can_relax_the_rules(tmp_path):
    lax = tmp_path / "lax.json"
    lax.write_text(json.dumps({"name": "lax", "rules": []}), encoding="utf-8")
    cat = _cat("energy")
    del cat["resources"][0]["resourceAttributes"]["meterId"]
    CatalogStore(REGISTRY, Policy.from_file(lax)).publish(cat)


def test_malformed_policy_fails_loudly(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"name": "x", "rules": [{"type": "T", "require": "notalist"}]}), encoding="utf-8")
    with pytest.raises(PolicyError):
        Policy.from_file(bad)
