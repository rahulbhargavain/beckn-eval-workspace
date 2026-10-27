"""Domain schema packs: attributes containers validated against pack schemas.

Spec: docs/Schema_Design_Guide.md (an Attributes container MUST carry @context and @type that
resolve to a published schema artifact; domains are added as schema artifacts, not core code).
The packs under packs/ are this workspace's own, experimental, illustrative; none of them is an
upstream Beckn schema (UNVERIFIED against beckn/schemas and beckn/DEG, see MEMORY.md).
"""
import json
from pathlib import Path

import pytest

from beckn_mock import packs as P

REPO = Path(__file__).resolve().parents[2]
PACKS_DIR = REPO / "packs"
REGISTRY = P.PackRegistry.from_dir(PACKS_DIR)


def test_the_three_shortlisted_domains_are_loaded():
    assert {"agri-produce", "energy-der", "tourism-listing"} <= set(REGISTRY.names())


def _cases():
    for name in REGISTRY.names():
        ex = json.loads((PACKS_DIR / name / "examples.json").read_text(encoding="utf-8"))
        for i, attrs in enumerate(ex["valid"]):
            yield pytest.param(name, attrs, None, id=f"{name}-valid-{i}")
        for i, bad in enumerate(ex["invalid"]):
            yield pytest.param(name, bad["attributes"], bad["reason"], id=f"{name}-invalid-{i}")


@pytest.mark.parametrize("pack,attrs,reason", list(_cases()))
def test_pack_examples(pack, attrs, reason):
    errs = REGISTRY.attribute_errors(attrs)
    if reason is None:
        assert errs == [], errs
    else:
        assert errs, f"{pack}: expected a rejection ({reason})"


def test_every_pack_has_both_valid_and_invalid_examples():
    for name in REGISTRY.names():
        ex = json.loads((PACKS_DIR / name / "examples.json").read_text(encoding="utf-8"))
        assert len(ex["valid"]) >= 2 and len(ex["invalid"]) >= 2, name


def test_unknown_context_is_refused_in_strict_mode():
    errs = REGISTRY.attribute_errors({"@context": "https://nowhere.invalid/x", "@type": "Produce"})
    assert errs and "unknown" in errs[0].lower()


def test_type_from_another_packs_context_is_refused():
    energy_ctx = REGISTRY.pack("energy-der").context
    errs = REGISTRY.attribute_errors({"@context": energy_ctx, "@type": "Produce", "commodity": "rice"})
    assert errs


def test_missing_context_or_type_is_refused():
    assert REGISTRY.attribute_errors({"@type": "Produce"})
    assert REGISTRY.attribute_errors({"@context": REGISTRY.pack("agri-produce").context})


def test_non_strict_mode_allows_unknown_contexts_but_still_validates_known_ones():
    lax = P.PackRegistry.from_dir(PACKS_DIR, strict=False)
    assert lax.attribute_errors({"@context": "https://other.invalid/x", "@type": "Anything"}) == []
    assert lax.attribute_errors({"@context": REGISTRY.pack("agri-produce").context, "@type": "Produce"})


def test_adding_a_domain_needs_only_files_no_code(tmp_path):
    d = tmp_path / "pets-boarding"
    d.mkdir()
    (d / "pack.json").write_text(json.dumps({
        "name": "pets-boarding", "version": "0.1.0", "status": "experimental",
        "context": "https://packs.beckn-eval.invalid/pets/v1",
        "types": {"Boarding": "boarding.schema.json"}}), encoding="utf-8")
    (d / "boarding.schema.json").write_text(json.dumps({
        "type": "object", "required": ["petKind"],
        "properties": {"petKind": {"enum": ["dog", "cat"]}}}), encoding="utf-8")
    reg = P.PackRegistry.from_dir(tmp_path)
    ctx = "https://packs.beckn-eval.invalid/pets/v1"
    assert reg.attribute_errors({"@context": ctx, "@type": "Boarding", "petKind": "dog"}) == []
    assert reg.attribute_errors({"@context": ctx, "@type": "Boarding", "petKind": "ferret"})


def test_malformed_pack_manifest_fails_loudly(tmp_path):
    d = tmp_path / "bad"
    d.mkdir()
    (d / "pack.json").write_text(json.dumps({"name": "bad"}), encoding="utf-8")
    with pytest.raises(P.PackError):
        P.PackRegistry.from_dir(tmp_path)


def test_duplicate_context_across_packs_is_refused(tmp_path):
    for n in ("a", "b"):
        d = tmp_path / n
        d.mkdir()
        (d / "pack.json").write_text(json.dumps({
            "name": n, "version": "1", "context": "https://packs.beckn-eval.invalid/same",
            "types": {"T": "t.json"}}), encoding="utf-8")
        (d / "t.json").write_text("{}", encoding="utf-8")
    with pytest.raises(P.PackError):
        P.PackRegistry.from_dir(tmp_path)


def test_pack_schema_files_cannot_escape_their_directory(tmp_path):
    d = tmp_path / "evil"
    d.mkdir()
    (tmp_path / "secret.json").write_text("{}", encoding="utf-8")
    (d / "pack.json").write_text(json.dumps({
        "name": "evil", "version": "1", "context": "https://packs.beckn-eval.invalid/evil",
        "types": {"T": "../secret.json"}}), encoding="utf-8")
    with pytest.raises(P.PackError):
        P.PackRegistry.from_dir(tmp_path)
