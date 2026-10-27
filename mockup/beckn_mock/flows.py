"""Canned flows used by tests that need a contract in a given state."""
import uuid


def _commitments(catalog, qty=2):
    offer = catalog["offers"][0]
    return [{"id": "commitment-1", "status": {"descriptor": {"code": "DRAFT"}},
             "resources": [{"id": r, "quantity": {"unitQuantity": qty, "unitCode": "UNIT"}}
                           for r in offer["resourceIds"]],
             "offer": {"id": offer["id"], "resourceIds": list(offer["resourceIds"])}}]


def _step(net, action, message, txn, **kw):
    r = net.bap.send(action, message, transaction_id=txn, **kw)
    assert r.status_code == 200, (action, r.body)
    return net.bap.wait_callback(r.message_id)


def until_init(net):
    txn = str(uuid.uuid4())
    net.last_transaction_id = txn
    cat = _step(net, "discover", {"intent": {"textSearch": "widget"}}, txn)["message"]["catalogs"][0]
    contract = _step(net, "select", {"contract": {"commitments": _commitments(cat)}}, txn)["message"]["contract"]
    contract["participants"] = [{"id": "buyer-1", "descriptor": {"name": "Test Buyer"}}]
    return _step(net, "init", {"contract": contract}, txn)["message"]["contract"]


def until_confirm(net):
    contract = until_init(net)
    for s in contract["settlements"]:
        s["status"] = "COMMITTED"
    return _step(net, "confirm", {"contract": contract}, net.last_transaction_id)["message"]["contract"]
