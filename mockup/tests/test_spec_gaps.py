"""Checks of the spec artefacts themselves. Each xfail documents a place where the
normative prose, the OpenAPI schema and/or the examples disagree, so a strict
schema-driven implementation cannot satisfy them all. See docs/mockup-findings.md.
"""
import json
import re

import pytest

from beckn_mock import spec


def _ctx(**kw):
    c = {"action": "status", "version": "2.0.0",
         "transactionId": "550e8400-e29b-41d4-a716-446655440001",
         "messageId": "550e8400-e29b-41d4-a716-446655440000", "bapId": "bap.example"}
    c.update(kw)
    return c


@pytest.mark.xfail(strict=True, reason="beckn.yaml Context schema has no 'required' list although "
                   "info.description item 2 says context MUST include action, version, "
                   "transactionId, messageId, bapId")
def test_context_schema_requires_minimum_fields():
    assert spec.request_errors("/discover", {"context": {}, "message": {"intent": {}}}) != []


@pytest.mark.xfail(strict=True, reason="StatusAction = allOf[Contract, required id] and Contract "
                   "requires commitments, so the /status request the path description asks for "
                   "(a Contract whose id identifies the contract) is schema-invalid")
def test_minimal_status_request_is_schema_valid():
    body = {"context": _ctx(), "message": {"contract": {"id": "550e8400-e29b-41d4-a716-446655440009"}}}
    assert spec.request_errors("/status", body) == []


@pytest.mark.xfail(strict=True, reason="Tracking requires url and status, so a /track *request* "
                   "must invent a tracking url/status it is asking for; Tracking.contract also "
                   "requires commitments")
def test_minimal_track_request_is_schema_valid():
    body = {"context": _ctx(action="track"),
            "message": {"tracking": {"contract": {"id": "550e8400-e29b-41d4-a716-446655440009"}}}}
    assert spec.request_errors("/track", body) == []


@pytest.mark.xfail(strict=True, reason="NFH-007 §5 example response header is "
                   "'Signature: keyId=...' with no 'Signature ' scheme prefix, but the "
                   "AckSignature schema pattern requires '^Signature keyId='")
def test_doc_ack_header_example_matches_schema_pattern():
    text = spec.doc_text("Authentication_and_Trust.md")
    m = re.search(r'^Signature: (keyId="[^\n]+)$', text, re.M)
    assert m, "example not found"
    value = m.group(1).replace("{created}", "1").replace("{expires}", "2") \
        .replace("{keyId}", "a/b/c|ed25519").replace("{base64_signature}", "QQ==")
    assert spec.matches_pattern("AckSignature", value)


@pytest.mark.xfail(strict=True, reason="Body digest prefix is 'BLAKE2b-512=' in NFH-007 §3.1 but "
                   "RequestDigest.digest pattern is '^BLAKE-512=' (and ONDC py-protocol-layer "
                   "signs with 'BLAKE-512=')")
def test_digest_prefix_consistent_between_signature_and_request_digest():
    assert spec.component_errors("RequestDigest", {"digest": "BLAKE2b-512=QUJD"}) == []


@pytest.mark.xfail(strict=True, reason="Error.code is a free string; the ErrorCode enum schema "
                   "exists but Error.code does not reference it, despite 'MUST be a value from "
                   "the ErrorCode enum'")
def test_error_code_constrained_to_enum():
    assert spec.component_errors("Error", {"code": "MADE_UP", "message": "x"}) != []


@pytest.mark.xfail(strict=True, reason="NFH-013 Example 1 uses non-UUID ids ('txn-f7e3c2a1') and "
                   "a v1-style message.order, contradicting CON-013-21/22 and ConfirmAction")
def test_communication_protocol_example_is_schema_valid():
    text = spec.doc_text("Communication_Protocol.md")
    m = re.search(r"\*\*Forward request \(CN → PN\):\*\*\s*```json\s*(\{.*?\})\s*```", text, re.S)
    assert m
    body = json.loads(m.group(1))
    assert spec.request_errors("/confirm", body) == []


@pytest.mark.xfail(strict=True, reason="RatingInput has additionalProperties:false and no field for "
                   "the rating value; 'range' is an untyped object, so where the score goes is "
                   "undefined")
def test_rating_value_has_a_defined_field():
    props = spec.component("RatingInput")["properties"]
    assert any(k in props for k in ("value", "ratingValue", "score"))


@pytest.mark.xfail(strict=True, reason="AsyncError is defined but no on_* message schema can carry "
                   "it (all On*Action are additionalProperties:false without an error field)")
def test_callbacks_can_carry_async_error():
    msg = spec.component("OnSelectAction")
    assert "error" in msg.get("properties", {})


def test_spec_version_is_2_0_0():
    """Not a gap: sanity check that we are reading the v2.0.0 contract."""
    assert spec.SPEC["info"]["version"] == "2.0.0"
    assert spec.component("Context")["properties"]["version"]["const"] == "2.0.0"
