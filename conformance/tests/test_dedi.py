"""DeDi file-based onboarding: generator and validator, tests first.

Spec: LF-Decentralized-Trust-labs/decentralized-directory-protocol docs/publishing-dedi-files.md
(vendored schemas under conformance/dedi_vendor). Signing is Ed25519 over RFC 8785 (JCS) canonical
JSON as a detached JWS (EdDSA, b64:false). Needs PyNaCl and jsonschema (mockup venv).

Not covered: cross-checking signatures against an independent implementation (the upstream
examples carry placeholder signatures).
"""
import base64
import copy
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

nacl_signing = pytest.importorskip("nacl.signing")
pytest.importorskip("jsonschema")

from conformance import dedi, keygen  # noqa: E402

VENDOR = Path(__file__).resolve().parents[1] / "dedi_vendor"
NOW = datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
SK = nacl_signing.SigningKey.generate()
PUB = base64.b64encode(bytes(SK.verify_key)).decode()


def np_config(**over):
    cfg = {"role": "NP", "domain": "np1.example", "name": "NP One", "nfo_name": "nfo-x", "network": "agri",
           "env": "prod", "kid": "key-1", "validity_days": 7,
           "records": [{"record_name": "bpp-record", "subscriber_id": "np1.example",
                        "url": "https://np1.example/beckn/bpp/receiver/", "type": "BPP", "countries": ["IND"],
                        "signing_public_key": PUB}]}
    cfg.update(over)
    return cfg


def nfo_config(**over):
    cfg = {"role": "NFO", "domain": "nfo-x.example", "name": "NFO X", "nfo_name": "nfo-x", "network": "agri",
           "env": "prod", "kid": "key-1", "validity_days": 7,
           "records": [{"record_name": "np-1", "subscriber_id": "np1.example", "type": "Registry",
                        "url": "https://np1.example/dedi/nfo-x_agri_prod_registry"}]}
    cfg.update(over)
    return cfg


def read(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


@pytest.fixture
def pub(tmp_path):
    out = tmp_path / "site"
    paths = dedi.build(np_config(), SK, out, NOW)
    return out, paths


# ------------------------------------------------------------------ JCS (RFC 8785)
def test_jcs_sorts_keys_and_drops_whitespace():
    assert dedi.jcs({"b": [3, 1, {"z": None, "a": True}], "a": "x"}) == b'{"a":"x","b":[3,1,{"a":true,"z":null}]}'


def test_jcs_sorts_keys_by_utf16_code_units_not_code_points():
    # U+E000 sorts before U+10000 by code point, but after it in UTF-16 (D800 DC00 < E000).
    assert dedi.jcs({"": 1, "\U00010000": 2}) == '{"\U00010000":2,"":1}'.encode("utf-8")


def test_jcs_escapes_like_json_stringify():
    assert dedi.jcs("a\"b\\c\n\t\x01/é") == '"a\\"b\\\\c\\n\\t\\u0001/é"'.encode("utf-8")


def test_jcs_refuses_floats_and_unsafe_integers():
    with pytest.raises(dedi.DediError):
        dedi.jcs({"x": 1.5})
    with pytest.raises(dedi.DediError):
        dedi.jcs({"x": 2 ** 60})


# ------------------------------------------------------------------ detached JWS
def test_protected_header_matches_the_spec_example():
    assert dedi.PROTECTED_B64 == "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19"


def test_sign_then_verify_round_trip_and_format():
    doc = {"a": 1, "proof": {"verification_method": "key-1", "canonicalization": "JCS", "jws": ""}}
    signed = dedi.sign_doc(doc, SK, "key-1")
    jws = signed["proof"]["jws"]
    assert jws.startswith(dedi.PROTECTED_B64 + "..")
    assert dedi.signature_ok(signed, dedi.jwk(bytes(SK.verify_key), "key-1"))


def test_key_order_does_not_break_the_signature():
    signed = dedi.sign_doc({"a": 1, "b": 2}, SK, "key-1")
    reordered = {"proof": signed["proof"], "b": 2, "a": 1}
    assert dedi.signature_ok(reordered, dedi.jwk(bytes(SK.verify_key), "key-1"))


def test_tampering_or_wrong_key_fails():
    signed = dedi.sign_doc({"a": 1}, SK, "key-1")
    bad = copy.deepcopy(signed)
    bad["a"] = 2
    assert not dedi.signature_ok(bad, dedi.jwk(bytes(SK.verify_key), "key-1"))
    other = nacl_signing.SigningKey.generate()
    assert not dedi.signature_ok(signed, dedi.jwk(bytes(other.verify_key), "key-1"))


def test_wrong_algorithm_or_b64_header_is_rejected():
    signed = dedi.sign_doc({"a": 1}, SK, "key-1")
    hdr = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "b64": False, "crit": ["b64"]}).encode()).rstrip(b"=").decode()
    forged = copy.deepcopy(signed)
    forged["proof"]["jws"] = hdr + ".." + signed["proof"]["jws"].split("..")[1]
    assert not dedi.signature_ok(forged, dedi.jwk(bytes(SK.verify_key), "key-1"))


def test_non_detached_jws_is_rejected():
    signed = dedi.sign_doc({"a": 1}, SK, "key-1")
    h, s = signed["proof"]["jws"].split("..")
    bad = copy.deepcopy(signed)
    bad["proof"]["jws"] = f"{h}.e30.{s}"
    assert not dedi.signature_ok(bad, dedi.jwk(bytes(SK.verify_key), "key-1"))


# ------------------------------------------------------------------ build: NP
def test_build_writes_the_hosted_layout(pub):
    out, paths = pub
    assert (out / ".well-known" / "dedi.index.json").is_file()
    assert (out / "dedi" / "nfo-x_agri_prod_registry.json").is_file()
    assert Path(paths["manifest"]) == out / ".well-known" / "dedi.index.json"


def test_registry_naming_convention_for_np_and_nfo(tmp_path):
    a = dedi.build(np_config(), SK, tmp_path / "a", NOW)
    b = dedi.build(nfo_config(), SK, tmp_path / "b", NOW)
    assert read(a["registry"])["registry"]["name"] == "nfo-x_agri_prod_registry"
    assert read(b["registry"])["registry"]["name"] == "nfo-x_agri_prod_ref_registry"


def test_outputs_validate_against_the_vendored_schemas(pub):
    _, paths = pub
    assert dedi.shape_errors("dedi-file", read(paths["registry"])) == []
    assert dedi.shape_errors("dedi-manifest", read(paths["manifest"])) == []


def test_registry_fields_follow_the_spec(pub):
    _, paths = pub
    f = read(paths["registry"])
    assert f["source_url"] == "https://np1.example/dedi/nfo-x_agri_prod_registry.json"
    assert f["namespace"] == "np1.example" and f["publisher"]["domain"] == "np1.example"
    assert f["registry"]["state"] == "live"
    assert f["proof"]["verification_method"] == f["publisher"]["key"]["kid"] == "key-1"
    assert f["next_update"] == (NOW + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")


def test_digest_is_over_the_hosted_bytes_and_manifest_is_signed_last(pub):
    out, paths = pub
    m = read(paths["manifest"])
    raw = Path(paths["registry"]).read_bytes()
    assert m["files"][0]["digest"] == "sha-256:" + hashlib.sha256(raw).hexdigest()
    assert m["files"][0]["url"] == "https://np1.example/dedi/nfo-x_agri_prod_registry.json"
    assert dedi.signature_ok(m, m["keys"][0])


def test_publisher_key_is_in_the_manifest_keys(pub):
    _, paths = pub
    assert read(paths["registry"])["publisher"]["key"] in read(paths["manifest"])["keys"]


def test_private_key_material_never_appears_in_outputs(pub):
    out, _ = pub
    blob = b"".join(p.read_bytes() for p in out.rglob("*") if p.is_file())
    assert base64.b64encode(bytes(SK)) not in blob
    assert bytes(SK).hex().encode() not in blob
    assert base64.urlsafe_b64encode(bytes(SK)).rstrip(b"=") not in blob


def test_build_refuses_duplicate_record_names(tmp_path):
    cfg = np_config()
    cfg["records"].append(dict(cfg["records"][0]))
    with pytest.raises(dedi.DediError):
        dedi.build(cfg, SK, tmp_path / "x", NOW)


def test_build_refuses_records_that_fail_the_role_schema(tmp_path):
    cfg = np_config()
    cfg["records"][0]["type"] = "NOTAROLE"
    with pytest.raises(dedi.DediError):
        dedi.build(cfg, SK, tmp_path / "x", NOW)
    cfg = nfo_config()
    cfg["records"][0]["type"] = "Neither"
    with pytest.raises(dedi.DediError):
        dedi.build(cfg, SK, tmp_path / "y", NOW)


def test_build_refuses_a_non_https_domain_config(tmp_path):
    with pytest.raises(dedi.DediError):
        dedi.build(np_config(domain="http://np1.example"), SK, tmp_path / "x", NOW)


def test_build_never_overwrites_without_force(tmp_path):
    out = tmp_path / "site"
    dedi.build(np_config(), SK, out, NOW)
    with pytest.raises(dedi.DediError):
        dedi.build(np_config(), SK, out, NOW)
    dedi.build(np_config(), SK, out, NOW, force=True)


# ------------------------------------------------------------------ re-issue freshness (spec §9)
def test_reissue_without_changes_keeps_updated_at_but_moves_next_update(tmp_path):
    out = tmp_path / "site"
    first = dedi.build(np_config(), SK, out, NOW)
    a, am = read(first["registry"]), read(first["manifest"])  # same paths are overwritten below
    later = NOW + timedelta(days=5)
    second = dedi.build(np_config(), SK, out, later, prev_dir=out, force=True)
    b, bm = read(second["registry"]), read(second["manifest"])
    assert b["registry"]["updated_at"] == a["registry"]["updated_at"]
    assert b["next_update"] != a["next_update"]
    assert bm["updated_at"] == am["updated_at"] and bm["next_update"] != am["next_update"]


def test_reissue_with_changes_advances_updated_at(tmp_path):
    out = tmp_path / "site"
    dedi.build(np_config(), SK, out, NOW)
    cfg = np_config()
    cfg["records"][0]["url"] = "https://np1.example/beckn/bpp/v2/"
    later = NOW + timedelta(days=1)
    p = dedi.build(cfg, SK, out, later, prev_dir=out, force=True)
    assert read(p["registry"])["registry"]["updated_at"] == later.strftime("%Y-%m-%dT%H:%M:%SZ")


# ------------------------------------------------------------------ NFO reference registry
def test_nfo_reference_registry_builds_and_verifies(tmp_path):
    out = tmp_path / "nfo"
    dedi.build(nfo_config(), SK, out, NOW)
    r = dedi.verify_dir(out, "nfo-x.example", NOW)
    assert r.ok and r.authenticated, r.problems


# ------------------------------------------------------------------ verify
def test_verify_accepts_a_fresh_publication(pub):
    out, _ = pub
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert r.ok and r.authenticated, r.problems


def test_verify_rejects_a_tampered_record(pub):
    out, paths = pub
    f = read(paths["registry"])
    f["records"][0]["details"]["url"] = "https://evil.example/"
    Path(paths["registry"]).write_text(json.dumps(f), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.ok and any(p.startswith("SIGNATURE") for p in r.problems)


def test_verify_flags_a_digest_mismatch_after_resigning_the_registry_alone(pub):
    out, paths = pub
    f = read(paths["registry"])
    f["records"][0]["details"]["url"] = "https://np1.example/beckn/changed/"
    Path(paths["registry"]).write_text(json.dumps(dedi.sign_doc(f, SK, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.ok and any(p.startswith("DIGEST") for p in r.problems), r.problems


def test_verify_marks_a_key_missing_from_the_manifest_as_not_authenticated(pub):
    out, paths = pub
    other = nacl_signing.SigningKey.generate()
    f = read(paths["registry"])
    f["publisher"]["key"] = dedi.jwk(bytes(other.verify_key), "key-1")
    resigned = dedi.sign_doc(f, other, "key-1")
    Path(paths["registry"]).write_text(json.dumps(resigned), encoding="utf-8")
    m = read(paths["manifest"])
    m["files"][0]["digest"] = dedi.file_digest(Path(paths["registry"]).read_bytes())
    Path(paths["manifest"]).write_text(json.dumps(dedi.sign_doc(m, SK, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.authenticated and any(p.startswith("NOT_AUTHENTICATED") for p in r.problems), r.problems


def test_verify_rejects_a_manifest_not_signed_by_one_of_its_own_keys(pub):
    out, paths = pub
    m = read(paths["manifest"])
    other = nacl_signing.SigningKey.generate()
    Path(paths["manifest"]).write_text(json.dumps(dedi.sign_doc(m, other, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.ok and any(p.startswith("MANIFEST") for p in r.problems), r.problems


def test_verify_rejects_stale_files(pub):
    out, _ = pub
    r = dedi.verify_dir(out, "np1.example", NOW + timedelta(days=8))
    assert not r.ok and any(p.startswith("STALE") for p in r.problems), r.problems


def test_verify_rejects_a_manifest_served_for_another_domain(pub):
    out, _ = pub
    r = dedi.verify_dir(out, "someone-else.example", NOW)
    assert not r.ok and any(p.startswith("DOMAIN") for p in r.problems), r.problems


def test_verify_rejects_an_inactive_registry(pub):
    out, paths = pub
    f = read(paths["registry"])
    f["registry"]["state"] = "inactive"
    Path(paths["registry"]).write_text(json.dumps(dedi.sign_doc(f, SK, "key-1")), encoding="utf-8")
    m = read(paths["manifest"])
    m["files"][0]["digest"] = dedi.file_digest(Path(paths["registry"]).read_bytes())
    Path(paths["manifest"]).write_text(json.dumps(dedi.sign_doc(m, SK, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.ok and any(p.startswith("INACTIVE") for p in r.problems), r.problems


def test_verify_rejects_shape_violations(pub):
    out, paths = pub
    f = read(paths["registry"])
    f["surprise"] = True
    Path(paths["registry"]).write_text(json.dumps(dedi.sign_doc(f, SK, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.ok and any(p.startswith("SHAPE") for p in r.problems), r.problems


def test_verify_rejects_duplicate_record_names_and_bad_details(pub):
    out, paths = pub
    f = read(paths["registry"])
    f["records"].append(copy.deepcopy(f["records"][0]))
    f["records"][0]["details"]["type"] = "NOPE"
    Path(paths["registry"]).write_text(json.dumps(dedi.sign_doc(f, SK, "key-1")), encoding="utf-8")
    m = read(paths["manifest"])
    m["files"][0]["digest"] = dedi.file_digest(Path(paths["registry"]).read_bytes())
    Path(paths["manifest"]).write_text(json.dumps(dedi.sign_doc(m, SK, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    kinds = {p.split(":")[0] for p in r.problems}
    assert {"DUPLICATE_RECORD", "DETAILS_SCHEMA"} <= kinds, r.problems


def test_verify_rejects_a_source_url_that_is_not_where_it_was_served(pub):
    out, paths = pub
    f = read(paths["registry"])
    f["source_url"] = "https://np1.example/dedi/other.json"
    Path(paths["registry"]).write_text(json.dumps(dedi.sign_doc(f, SK, "key-1")), encoding="utf-8")
    m = read(paths["manifest"])
    m["files"][0]["digest"] = dedi.file_digest(Path(paths["registry"]).read_bytes())
    Path(paths["manifest"]).write_text(json.dumps(dedi.sign_doc(m, SK, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.ok and any(p.startswith("SOURCE_URL") for p in r.problems), r.problems


def test_verify_refuses_files_hosted_on_another_domain_when_checking_a_local_tree(pub):
    out, paths = pub
    m = read(paths["manifest"])
    m["files"][0]["url"] = "https://elsewhere.example/dedi/x.json"
    Path(paths["manifest"]).write_text(json.dumps(dedi.sign_doc(m, SK, "key-1")), encoding="utf-8")
    r = dedi.verify_dir(out, "np1.example", NOW)
    assert not r.ok and any(p.startswith("UNREACHABLE") for p in r.problems), r.problems


# ------------------------------------------------------------------ upstream shape fixtures
@pytest.mark.parametrize("name,kind", [("dedi.index.json", "dedi-manifest"), ("dedi.public-keys.json", "dedi-file"),
                                       ("dedi.revocations.json", "dedi-file"), ("dedi.digests.json", "dedi-digests")])
def test_upstream_example_files_pass_our_shape_check(name, kind):
    assert dedi.shape_errors(kind, read(VENDOR / "examples" / name)) == []


def test_upstream_examples_are_not_cryptographically_valid_and_we_say_so():
    m = read(VENDOR / "examples" / "dedi.index.json")
    assert not dedi.signature_ok(m, m["keys"][0])


# ------------------------------------------------------------------ CLI
def test_cli_build_then_verify_without_printing_the_seed(tmp_path, capsys):
    ident = tmp_path / "pub-identity.json"
    pubkey = keygen.make_identity(ident, "np1.example/keys/k1|ed25519", "np1.example", "https://np1.example/bap", "agri")
    cfg = np_config()
    cfg["records"][0]["signing_public_key"] = pubkey
    cfg_path = tmp_path / "cfg.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    out = tmp_path / "site"
    now = "2026-10-27T10:00:00Z"
    assert dedi.main(["build", "--config", str(cfg_path), "--identity", str(ident), "--out", str(out), "--now", now]) == 0
    seed = json.loads(ident.read_text(encoding="utf-8"))["private_key_seed_b64"]
    shown = capsys.readouterr()
    assert seed not in shown.out + shown.err
    assert dedi.main(["verify", "--dir", str(out), "--domain", "np1.example", "--now", now]) == 0
    assert dedi.main(["verify", "--dir", str(out), "--domain", "np1.example", "--now", "2026-12-01T00:00:00Z"]) == 1
