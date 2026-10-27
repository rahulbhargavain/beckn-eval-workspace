"""Domain schema packs, laid out per docs/Schema_Design_Guide.md and the beckn-agents
schema-builder checklist: one directory per schema and version, structural JSON Schema only.
Mandatory fields and closed value lists live in the policy layer (test_policy.py), not here.

The packs are this workspace's own, experimental, illustrative; none is an upstream Beckn
schema (UNVERIFIED against beckn/schemas and beckn/DEG, see MEMORY.md).
"""
import json
import re
from pathlib import Path

import pytest

from beckn_mock import packs as P

REPO = Path(__file__).resolve().parents[2]
PACKS_DIR = REPO / "packs"
REGISTRY = P.PackRegistry.from_dir(PACKS_DIR)
SCHEMA_DIRS = sorted(p.parent for p in (PACKS_DIR / "schemas").glob("*/*/schema.json"))
FILES = ["schema.json", "attributes.yaml", "context.jsonld", "vocab.jsonld", "README.md", "examples.json"]


def _ids(d):
    return f"{d.parent.name}-{d.name}"


def test_the_shortlisted_domains_are_present():
    assert {"Produce", "ProduceTerms", "EnergySource", "EnergyTerms", "Listing", "ListingTerms"} <= REGISTRY.type_names()


@pytest.mark.parametrize("d", SCHEMA_DIRS, ids=_ids)
def test_schema_directory_has_the_full_file_set(d):
    for f in FILES:
        assert (d / f).is_file(), f"{d}: missing {f}"


@pytest.mark.parametrize("d", SCHEMA_DIRS, ids=_ids)
def test_version_directory_is_semver_like(d):
    assert re.fullmatch(r"v\d+\.\d+", d.name), d.name


@pytest.mark.parametrize("d", SCHEMA_DIRS, ids=_ids)
def test_schema_id_names_its_own_directory(d):
    s = json.loads((d / "schema.json").read_text(encoding="utf-8"))
    assert s["$id"].endswith(f"/schemas/{d.parent.name}/{d.name}/schema.json"), s["$id"]
    assert REGISTRY.context_for(d.parent.name, d.name) == s["$id"].rsplit("/", 1)[0] + "/context.jsonld"


@pytest.mark.parametrize("d", SCHEMA_DIRS, ids=_ids)
def test_no_mandatory_fields_and_no_closed_enums_in_schemas(d):
    s = json.loads((d / "schema.json").read_text(encoding="utf-8"))
    assert set(s.get("required", [])) <= {"@context", "@type"}, "mandatory fields belong in policy"
    assert "enum" not in json.dumps(s), "closed value lists belong in vocab + policy"


@pytest.mark.parametrize("d", SCHEMA_DIRS, ids=_ids)
def test_type_names_follow_the_naming_rules(d):
    name = d.parent.name
    assert not re.search(r"(Offer|Item|Resource|Attributes)$", name), name
    assert not re.search(r"(With|And|Plus)", name), name


@pytest.mark.parametrize("d", SCHEMA_DIRS, ids=_ids)
def test_attributes_yaml_wraps_the_schema(d):
    import yaml
    a = yaml.safe_load((d / "attributes.yaml").read_text(encoding="utf-8"))
    s = json.loads((d / "schema.json").read_text(encoding="utf-8"))
    assert a["components"]["schemas"][d.parent.name]["properties"] == s["properties"]


@pytest.mark.parametrize("d", SCHEMA_DIRS, ids=_ids)
def test_vocab_terms_link_back_to_a_broader_concept(d):
    v = json.loads((d / "vocab.jsonld").read_text(encoding="utf-8"))
    for node in v["@graph"]:
        assert any(k in node for k in ("rdfs:subClassOf", "skos:broader", "owl:sameAs")), node.get("@id")


def _cases():
    for d in SCHEMA_DIRS:
        ex = json.loads((d / "examples.json").read_text(encoding="utf-8"))
        for i, attrs in enumerate(ex["valid"]):
            yield pytest.param(attrs, None, id=f"{_ids(d)}-valid-{i}")
        for i, bad in enumerate(ex["invalid"]):
            if bad["layer"] == "schema":
                yield pytest.param(bad["attributes"], bad["reason"], id=f"{_ids(d)}-invalid-{i}")


@pytest.mark.parametrize("attrs,reason", list(_cases()))
def test_schema_examples(attrs, reason):
    errs = REGISTRY.attribute_errors(attrs)
    if reason is None:
        assert errs == [], errs
    else:
        assert errs, f"expected a structural rejection ({reason})"


def test_every_schema_has_valid_and_invalid_examples():
    for d in SCHEMA_DIRS:
        ex = json.loads((d / "examples.json").read_text(encoding="utf-8"))
        assert len(ex["valid"]) >= 1 and len(ex["invalid"]) >= 1, _ids(d)


def test_missing_optional_fields_are_fine_at_the_schema_layer():
    ctx = REGISTRY.context_for("EnergySource")
    assert REGISTRY.attribute_errors({"@context": ctx, "@type": "EnergySource"}) == []


def test_unknown_context_is_refused_in_strict_mode():
    errs = REGISTRY.attribute_errors({"@context": "https://nowhere.invalid/x", "@type": "Produce"})
    assert errs and "unknown" in errs[0].lower()


def test_type_must_match_the_directory_of_its_context():
    errs = REGISTRY.attribute_errors({"@context": REGISTRY.context_for("Produce"), "@type": "EnergySource"})
    assert errs


def test_missing_context_or_type_is_refused():
    assert REGISTRY.attribute_errors({"@type": "Produce"})
    assert REGISTRY.attribute_errors({"@context": REGISTRY.context_for("Produce")})


def test_non_strict_mode_allows_unknown_contexts_but_still_validates_known_ones():
    lax = P.PackRegistry.from_dir(PACKS_DIR, strict=False)
    assert lax.attribute_errors({"@context": "https://other.invalid/x", "@type": "Anything"}) == []
    assert lax.attribute_errors({"@context": REGISTRY.context_for("Produce"), "@type": "Produce", "originCountry": "India"})


def test_external_upstream_schema_is_known_but_validation_is_deferred():
    ctx = "https://schema.nfh.global/PriceSpecification/v2.2/context.jsonld"
    assert ctx in REGISTRY.deferred_contexts()
    assert REGISTRY.attribute_errors({"@context": ctx, "@type": "PriceSpecification", "currency": "INR", "value": 5}) == []
    assert REGISTRY.attribute_errors({"@context": ctx, "@type": "SomethingElse"})


def _mk(root, type_name, ver, schema, ctx_ok=True):
    d = root / "schemas" / type_name / ver
    d.mkdir(parents=True)
    base = f"https://packs.beckn-eval.invalid/schemas/{type_name}/{ver}"
    (d / "schema.json").write_text(json.dumps(dict(schema, **{"$id": f"{base}/schema.json"})), encoding="utf-8")
    if ctx_ok:
        (d / "context.jsonld").write_text(json.dumps({"@context": {}}), encoding="utf-8")
    return base + "/context.jsonld"


def test_adding_a_domain_needs_only_files_no_code(tmp_path):
    ctx = _mk(tmp_path, "PetBoarding", "v0.1", {"type": "object", "properties": {"petKind": {"type": "string"}}})
    reg = P.PackRegistry.from_dir(tmp_path)
    assert reg.attribute_errors({"@context": ctx, "@type": "PetBoarding", "petKind": "dog"}) == []
    assert reg.attribute_errors({"@context": ctx, "@type": "PetBoarding", "petKind": 7})


def test_two_versions_of_a_schema_coexist(tmp_path):
    c1 = _mk(tmp_path, "Thing", "v1.0", {"type": "object", "properties": {"n": {"type": "integer"}}})
    c2 = _mk(tmp_path, "Thing", "v1.1", {"type": "object", "properties": {"n": {"type": "string"}}})
    reg = P.PackRegistry.from_dir(tmp_path)
    assert reg.attribute_errors({"@context": c1, "@type": "Thing", "n": 1}) == []
    assert reg.attribute_errors({"@context": c2, "@type": "Thing", "n": "x"}) == []
    assert reg.attribute_errors({"@context": c2, "@type": "Thing", "n": 1})
    assert reg.context_for("Thing") == c2, "latest version wins when none is named"


def test_schema_without_an_id_fails_loudly(tmp_path):
    d = tmp_path / "schemas" / "Bad" / "v1.0"
    d.mkdir(parents=True)
    (d / "schema.json").write_text("{}", encoding="utf-8")
    with pytest.raises(P.PackError):
        P.PackRegistry.from_dir(tmp_path)


def test_schema_id_must_match_its_directory(tmp_path):
    d = tmp_path / "schemas" / "Bad" / "v1.0"
    d.mkdir(parents=True)
    (d / "schema.json").write_text(json.dumps({"$id": "https://packs.beckn-eval.invalid/schemas/Other/v1.0/schema.json"}),
                                   encoding="utf-8")
    with pytest.raises(P.PackError):
        P.PackRegistry.from_dir(tmp_path)


def test_duplicate_context_is_refused(tmp_path):
    _mk(tmp_path, "A", "v1.0", {})
    ext = tmp_path / "external"
    ext.mkdir()
    (ext / "x.json").write_text(json.dumps({
        "context": f"https://packs.beckn-eval.invalid/schemas/A/v1.0/context.jsonld",
        "types": ["A"], "validation": "deferred"}), encoding="utf-8")
    with pytest.raises(P.PackError):
        P.PackRegistry.from_dir(tmp_path)
