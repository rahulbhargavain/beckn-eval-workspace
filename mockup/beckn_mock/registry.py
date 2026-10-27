"""Mock subnet registry / GRR stand-in.

The dedi lookup API is out of scope of the Beckn spec (beckn.yaml info.description,
'Required Infrastructure Building Blocks' note), so the response shapes below are
mockup inventions:

  GET /dedi/lookup/{keyId}                 implicit keyId lookup (NFH-007 §2.3), keyId
                                           includes '|ed25519', not URL-encoded
  GET /{namespace}/{registry}/{record}     explicit keyId target URL (NFH-007 §2.2)
  GET /subscribers?networkId=..&subscriberId=..   subscriber_url lookup (beckn.yaml
                                           Context.bapId/bppId descriptions)
"""
import threading

from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse


class RegistryState:
    def __init__(self):
        self._lock = threading.Lock()
        self.subscribers = {}  # (networkId, subscriberId) -> record
        self.keys = {}         # implicit keyId -> record
        self.lookups = []      # request paths, for assertions

    def add_subscriber(self, subscriber_id, network_id, url, role, status="SUBSCRIBED"):
        with self._lock:
            self.subscribers[(network_id, subscriber_id)] = {
                "subscriberId": subscriber_id, "networkId": network_id, "subscriberUrl": url,
                "role": role, "status": status}

    def add_key(self, key_id, subscriber_id, network_id, public_b64, valid_from, valid_until):
        with self._lock:
            self.keys[key_id] = {
                "keyId": key_id, "subscriberId": subscriber_id, "networkId": network_id,
                "algorithm": "ed25519", "publicKey": public_b64, "status": "ACTIVE",
                "validFrom": valid_from, "validUntil": valid_until}

    def key(self, key_id):
        return self.keys[key_id]

    def revoke(self, key_id):
        with self._lock:
            self.keys[key_id]["status"] = "REVOKED"


def create_app(state: RegistryState) -> FastAPI:
    app = FastAPI(title="mock-registry", openapi_url=None, docs_url=None, redoc_url=None)

    @app.get("/subscribers")
    def subscriber(networkId: str = Query(...), subscriberId: str = Query(...)):
        state.lookups.append(f"/subscribers?{networkId}&{subscriberId}")
        rec = state.subscribers.get((networkId, subscriberId))
        return rec if rec else JSONResponse({"error": "not found"}, status_code=404)

    def _key(key_id):
        rec = state.keys.get(key_id)
        return dict(rec) if rec else JSONResponse({"error": "not found"}, status_code=404)

    @app.get("/dedi/lookup/{key_id:path}")
    def lookup(key_id: str):
        state.lookups.append("/dedi/lookup/" + key_id)
        return _key(key_id)

    @app.get("/{record_path:path}")
    def explicit(record_path: str):
        state.lookups.append("/" + record_path)
        return _key(record_path + "|ed25519")

    return app
