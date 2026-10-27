"""Malformed payloads -> 400 NackBadRequest (beckn.yaml 'Standard Response Families')."""
import copy
import json

import pytest

from beckn_mock import client, spec
import payloads as P


def _post(net, path, body):
    return client.post_signed(net.bpp_url + path, body, net.bap.identity)


def _assert_nack400(res, code=None):
    assert res.status_code == 400, res.text
    body = res.json()
    assert spec.component_errors("NackBadRequest", body) == []
    if code:
        assert body["message"]["error"]["code"] == code, body


def test_invalid_json_nacked(net):
    raw = b'{"context": {"action": "discover", '
    res = client.post_raw(net.bpp_url + "/discover", raw, client.auth_header_for(raw, net.bap.identity))
    _assert_nack400(res, "SCH_INVALID_JSON")


def test_missing_message_nacked(net):
    body = net.bap.envelope("discover", P.discover())
    del body["message"]
    _assert_nack400(_post(net, "/discover", body), "SCH_SCHEMA_VALIDATION_FAILED")


def test_action_mismatch_nacked(net):
    """context.action must match the endpoint (path schema const)."""
    body = net.bap.envelope("discover", P.discover())
    _assert_nack400(_post(net, "/select", body))


def test_wrong_version_nacked(net):
    body = net.bap.envelope("discover", P.discover(), version="1.1.0")
    _assert_nack400(_post(net, "/discover", body))


def test_non_uuid_message_id_nacked(net):
    """Context.messageId format: uuid; CON-013-21. Note: JSON Schema 2020-12 treats
    'format' as annotation only, so a validator must opt in to format assertion."""
    body = net.bap.envelope("discover", P.discover(), messageId="msg-456")
    _assert_nack400(_post(net, "/discover", body))


def test_legacy_v1_field_nacked(net):
    """DiscoverAction is additionalProperties:false; the v1 'text_search' was removed."""
    body = net.bap.envelope("discover", {"intent": {"textSearch": "x"}, "text_search": "x"})
    _assert_nack400(_post(net, "/discover", body), "SCH_SCHEMA_VALIDATION_FAILED")


@pytest.mark.parametrize("field", ["action", "version", "transactionId", "messageId", "bapId"])
def test_context_minimum_fields_enforced(net, field):
    """beckn.yaml info.description 'Common Implementation Requirements' item 2: context
    MUST include action, version, transactionId, messageId, bapId. The Context schema
    itself has no 'required' list, so this is enforced in code (see test_spec_gaps).
    The prose says '`bapId` or `bppId`'; assumption: a forward request must carry bapId
    (the receiver needs it to identify the sender and route the callback)."""
    body = net.bap.envelope("discover", P.discover())
    del body["context"][field]
    _assert_nack400(_post(net, "/discover", body))


def test_select_unknown_offer_nacked(net):
    """Semantic validation failure -> NackBadRequest; callbacks have no error slot
    (see findings), so business errors detectable synchronously are NACKed."""
    commitments = [{"status": {"descriptor": {"code": "DRAFT"}},
                    "resources": [{"id": "nope", "quantity": {"unitQuantity": 1}}],
                    "offer": {"id": "nope", "resourceIds": ["nope"]}}]
    body = net.bap.envelope("select", {"contract": {"commitments": commitments}})
    res = _post(net, "/select", body)
    _assert_nack400(res)
    assert res.json()["message"]["error"]["code"] in {"BIZ_OFFER_NOT_FOUND", "BIZ_ITEM_NOT_FOUND"}


def test_bap_rejects_malformed_callback(net):
    """The CN validates inbound callbacks against the on_* schema as well."""
    r = net.bap.send("discover", P.discover())
    net.bap.wait_callback(r.message_id)
    r2 = net.bap.send("discover", P.discover())
    net.bap.wait_callback(r2.message_id)
    cb = copy.deepcopy(net.bap.callbacks_for(r2.message_id)[0].body)
    cb["message"] = {"catalogs": [{"id": "x"}]}  # Catalog requires descriptor, provider...
    res = client.post_signed(net.bap_url + "/on_discover", cb, net.bpp.identity,
                             request_signature=net.bap.outbound_signature(r2.message_id))
    _assert_nack400(res, "SCH_SCHEMA_VALIDATION_FAILED")


def test_nack_for_unparseable_body_still_schema_valid(net):
    """Nack schemas require message.messageId (uuid) even when none can be read from
    the body. Assumption: the nil UUID is returned."""
    raw = b"not json"
    res = client.post_raw(net.bpp_url + "/discover", raw, client.auth_header_for(raw, net.bap.identity))
    body = res.json()
    assert body["message"]["messageId"] == "00000000-0000-0000-0000-000000000000"
