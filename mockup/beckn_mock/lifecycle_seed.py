"""The node-specific inputs the LIFE-001 lifecycle scenario needs for the mockup (see docs/conformance.md, "Seed")."""


def seed_for(net):
    return {
        "context": {"bppId": net.bpp.subscriber_id, "bppUri": net.bpp_url},
        "select": {"contract": {"commitments": [{
            "id": "commitment-1", "status": {"descriptor": {"code": "DRAFT"}},
            "resources": [{"id": "res-001", "quantity": {"unitQuantity": 1, "unitCode": "UNIT"}}],
            "offer": {"id": "offer-001", "resourceIds": ["res-001"]}}]}},
        "init": {"contract": {"participants": [{"id": "buyer-1", "descriptor": {"name": "Test Buyer"}}]}},
        "confirm": {"settlementsPatch": {"status": "DRAFT", "settlementAttributes": {
            "@context": "https://schema.example.org/mock/v1", "@type": "PaymentReference", "paymentReference": "TEST-REF-1"}}},
    }
