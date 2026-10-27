"""Message builders for tests. Shapes follow api/v2.0.0/beckn.yaml (components/schemas)."""
import copy


def discover(text="widget"):
    # DiscoverAction -> Intent.textSearch (beckn.yaml DiscoverAction / Intent)
    return {"intent": {"textSearch": text}}


def commitments_from_catalog(catalog, qty=2):
    """Build Contract.commitments from the first offer in an on_discover catalog.
    Commitment requires status, resources[{id, quantity}], offer{id, resourceIds}."""
    offer = catalog["offers"][0]
    return [{
        "id": "commitment-1",
        "status": {"descriptor": {"code": "DRAFT"}},
        "resources": [
            {"id": rid, "quantity": {"unitQuantity": qty, "unitCode": "UNIT"}}
            for rid in offer["resourceIds"]
        ],
        "offer": {"id": offer["id"], "resourceIds": list(offer["resourceIds"])},
    }]


def buyer_participant():
    return {
        "id": "buyer-1",
        "descriptor": {"name": "Test Buyer"},
        "participantAttributes": {
            "@context": "https://schema.example.org/mock/v1",
            "@type": "BillingDetails",
            "email": "buyer@example.org",
        },
    }


def with_settlement_proof(contract):
    c = copy.deepcopy(contract)
    for s in c.get("settlements", []):
        s["status"] = "COMMITTED"
        s["settlementAttributes"] = {
            "@context": "https://schema.example.org/mock/v1",
            "@type": "PaymentProof",
            "reference": "txn-ref-0001",
        }
    return c


def set_quantity(contract, qty):
    c = copy.deepcopy(contract)
    for cm in c["commitments"]:
        for r in cm["resources"]:
            r["quantity"] = {"unitQuantity": qty, "unitCode": "UNIT"}
    return c
