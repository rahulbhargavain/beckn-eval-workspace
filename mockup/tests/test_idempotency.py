"""Duplicate messageId handling.

Spec: NFH-007 §10.1 (duplicate request messageId -> 400 NackBadRequest),
NFH-013 §5 / CON-013-16 (messageId never reused), §9 / CON-013-15 (CN must not
discard later callbacks with the same messageId).
"""
import time
import uuid

from beckn_mock import client
import payloads as P


def test_duplicate_message_id_different_body_rejected_once_processed(net):
    """Second confirm reusing a messageId (different body) is NACKed with
    CTX_MESSAGE_ID_DUPLICATE, is not processed, and creates no second contract."""
    contract = net.draft_contract_after_init()
    txn = net.last_transaction_id
    mid = str(uuid.uuid4())
    body1 = net.bap.envelope("confirm", {"contract": P.with_settlement_proof(contract)},
                             transaction_id=txn, messageId=mid, bppId=net.bpp.subscriber_id,
                             bppUri=net.bpp_url)
    first = client.post_signed(net.bpp_url + "/confirm", body1, net.bap.identity)
    assert first.status_code == 200
    body2 = dict(body1, context=dict(body1["context"], timestamp=body1["context"]["timestamp"][:-1] + ".5Z"))
    second = client.post_signed(net.bpp_url + "/confirm", body2, net.bap.identity)
    assert second.status_code == 400
    assert second.json()["message"]["error"]["code"] == "CTX_MESSAGE_ID_DUPLICATE"
    time.sleep(0.5)
    assert [m for (a, m) in net.bpp.processed if a == "confirm"].count(mid) == 1
    assert len([c for c in net.bpp.contracts.values() if c["status"]["code"] == "ACTIVE"]) == 1


def test_duplicate_scope_is_per_sender(net):
    """Spec is silent on the dedup scope. Assumption: (sender subscriber, messageId),
    so one participant cannot burn another participant's messageIds."""
    other = net.new_identity("other-bap.mock.local", role="BAP", url=net.bap_url)
    mid = str(uuid.uuid4())
    b_other = net.bap.envelope("discover", P.discover(), messageId=mid, bapId=other.subscriber_id)
    assert client.post_signed(net.bpp_url + "/discover", b_other, other).status_code == 200
    b_real = net.bap.envelope("discover", P.discover(), messageId=mid)
    assert client.post_signed(net.bpp_url + "/discover", b_real, net.bap.identity).status_code == 200


def test_bap_send_never_reuses_message_ids(net):
    ids = {net.bap.send("discover", P.discover()).message_id for _ in range(5)}
    assert len(ids) == 5


def test_multiple_distinct_callbacks_same_message_id_accepted(net):
    """CON-013-15: a PN MAY send several on_status for one status request; the CN MUST
    NOT discard later ones just because the messageId was seen."""
    contract = net.confirmed_contract()
    r = net.bap.send("status", {"contract": contract}, transaction_id=net.last_transaction_id)
    net.bap.wait_callback(r.message_id)
    res = net.bpp.send_followup(r.message_id)
    assert res.status_code == 200, res.text
    assert len(net.bap.callbacks_for(r.message_id)) == 2
