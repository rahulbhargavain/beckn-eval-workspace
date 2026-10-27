"""BAP (Consumer Node): sends signed forward requests, verifies signed Acks, receives
and verifies on_<action> callbacks (solicited: chained signature; PN-initiated:
standard signature + known active transaction)."""
import json
import threading
import time
import uuid
from dataclasses import dataclass

import httpx
from fastapi import Request
from fastapi.responses import Response

from . import signing, spec, urlguard
from .node import Identity, Node, Reject, dumps, iso_now, now_ts, raw_signature, read_body, same_url


@dataclass
class SendResult:
    status_code: int
    body: dict
    headers: httpx.Headers
    message_id: str
    transaction_id: str
    ack_signature_verified: bool
    raw: bytes


@dataclass
class CallbackEntry:
    action: str
    body: dict
    raw: bytes
    authorization: str
    solicited: bool


class BapNode(Node):
    def __init__(self, identity: Identity, registry_url, network_id, trusted_registries=(),
                 default_bpp_id=None, bpp_allowlist=None):
        super().__init__(identity, registry_url, network_id, trusted_registries)
        self.default_bpp_id = default_bpp_id
        self.bpp_allowlist = bpp_allowlist
        self.pending = {}            # messageId -> outbound record
        self.callbacks = {}          # messageId -> [CallbackEntry]
        self.callback_sigs = set()   # (messageId, signature) dedup keys (CON-013-23)
        self.confirmed = {}          # transactionId -> bppId
        self._cv = threading.Condition(self._lock)
        self.drop_callbacks = set()  # fault injection: on_* actions answered 503 and discarded
        self.dropped = []            # (action, messageId) discarded by the fault above
        for action in spec.ACTIONS:
            self.app.add_api_route(f"/on_{action}", self._endpoint(action), methods=["POST"])

    # ------------------------------------------------------------ outbound
    def _resolve_bpp(self, bpp_id):
        rec = self.lookup_subscriber_sync(bpp_id)
        if not rec or rec.get("status") != "SUBSCRIBED":
            raise urlguard.UnsafeURL(f"{bpp_id} not registered")
        urlguard.check_url(rec["subscriberUrl"], allowlist=self.bpp_allowlist)
        return rec["subscriberUrl"]

    def bpp_from_catalog(self, catalog):
        """Resolve the PN address from the registry; refuse catalogs whose bppUri disagrees."""
        url = self._resolve_bpp(catalog["bppId"])
        if "bppUri" in catalog and not same_url(catalog["bppUri"], url):
            raise urlguard.UnsafeURL("catalog bppUri does not match registry subscriber_url")
        return url

    def envelope(self, action, message, transaction_id=None, bpp_id=None, **ctx_overrides):
        bpp_id = bpp_id or self.default_bpp_id
        ctx = {"networkId": self.network_id, "action": action, "version": "2.0.0",
               "bapId": self.subscriber_id, "bapUri": self.identity.url,
               "bppId": bpp_id, "bppUri": self._resolve_bpp(bpp_id),
               "transactionId": transaction_id or str(uuid.uuid4()),
               "messageId": str(uuid.uuid4()), "timestamp": iso_now(), "ttl": "PT30S"}
        ctx.update(ctx_overrides)
        return {"context": ctx, "message": message}

    def send(self, action, message, transaction_id=None, bpp_id=None, context_extra=None) -> SendResult:
        body = self.envelope(action, message, transaction_id, bpp_id, **(context_extra or {}))
        ctx = body["context"]
        raw = dumps(body)
        created = now_ts()
        expires = created + self.signature_ttl
        auth = signing.sign_message(self.identity.keypair, self.identity.key_id, raw, created, expires)
        sig = raw_signature(auth)
        with self._lock:  # record before POST: the callback may beat the Ack back
            self.pending[ctx["messageId"]] = {
                "signature": sig, "request_digest": signing.request_digest(raw), "expires": expires,
                "transactionId": ctx["transactionId"], "action": action, "bppId": ctx["bppId"]}
        r = self.http.post(ctx["bppUri"].rstrip("/") + "/" + action, content=raw,
                           headers={"Authorization": auth, "Content-Type": "application/json"})
        verified = self._verify_ack(r, sig, ctx["bppId"])
        try:
            rbody = r.json()
        except ValueError:
            rbody = {}
        if r.status_code != 200:  # Nack or AckNoCallback: no callback will follow
            with self._lock:
                self.pending.pop(ctx["messageId"], None)
        return SendResult(r.status_code, rbody, r.headers, ctx["messageId"], ctx["transactionId"], verified, r.content)

    def _verify_ack(self, r, our_sig, responder_id):
        """NFH-007 §5: verify the responder's Signature header and its request-signature chain, applying
        the same algorithm, header, time-window and key-validity checks as inbound verification."""
        try:
            attrs = signing.parse_authorization(r.headers.get("signature"))
            now = now_ts()
            self.check_attrs(attrs, {signing.CHAIN_HEADERS}, now)
            key = self.resolve_key_sync(attrs["keyId"])
            if not key or key.get("subscriberId") != responder_id:
                return False
            self.check_key(key, int(attrs["expires"]), now)
            text = signing.signing_string(int(attrs["created"]), int(attrs["expires"]),
                                          signing.body_digest(r.content), our_sig)
            return signing.verify(key["publicKey"], text, attrs["signature"])
        except (signing.SignatureError, Reject, httpx.HTTPError):
            return False

    # ------------------------------------------------------------ inbound callbacks
    def _endpoint(self, action):
        cb_action = f"on_{action}"

        async def handler(request: Request):
            auth = request.headers.get("authorization")
            req_sig = raw_signature(auth)
            mid = None
            try:
                raw = await read_body(request)
            except Reject as rej:
                return self.nack(rej, None, req_sig)
            if cb_action in self.drop_callbacks:
                try:
                    mid = json.loads(raw).get("context", {}).get("messageId")
                except (ValueError, AttributeError):
                    pass
                self.dropped.append((cb_action, mid))
                return Response(status_code=503)
            try:
                # The CN must know which outbound request a chained callback answers before
                # it can rebuild the signing string, so peek at messageId first.
                try:
                    peek = self.parse_body(raw)
                    mid = peek.get("context", {}).get("messageId")
                except Reject:
                    peek = None

                def stored_sig(_attrs):
                    p = self.pending.get(mid)
                    return p["signature"] if p and p["expires"] + self.clock_skew >= now_ts() else None

                v = await self.verify_signature(raw, auth, {signing.STD_HEADERS, signing.CHAIN_HEADERS},
                                                request_signature_for=stored_sig)
                body = peek if peek is not None else self.parse_body(raw)
                ctx = self.validate("/" + cb_action, body, "bppId")
                if v.key["subscriberId"] != ctx["bppId"]:
                    raise Reject(401, "AUT_UNAUTHORIZED_ACTION", "signer is not context.bppId", mid)
                if ctx.get("bapId") not in (None, self.subscriber_id):
                    raise Reject(400, "CTX_INVALID_FIELD", "callback not addressed to this BAP", mid)
                if v.chained:
                    self._check_solicited(ctx, action, v)
                else:
                    self._check_unsolicited(ctx, v)
                self._record(action, ctx, body, raw, auth, v)
            except Reject as rej:
                return self.nack(rej, mid, req_sig)
            return self.ack(mid, req_sig)
        handler.__name__ = f"handle_on_{action}"
        return handler

    def _check_solicited(self, ctx, action, v):
        mid = ctx["messageId"]
        p = self.pending[mid]
        if p["bppId"] != ctx["bppId"]:
            raise Reject(401, "AUT_UNAUTHORIZED_ACTION", "callback from a different PN", mid)
        if p["action"] != action or p["transactionId"] != ctx["transactionId"]:
            raise Reject(400, "CTX_INVALID_FIELD", "callback does not match the request", mid)
        rd = ctx.get("requestDigest")
        if rd and rd.get("digest") != p["request_digest"]:
            raise Reject(400, "CTX_INVALID_FIELD", "requestDigest does not match our request", mid)
        with self._lock:
            key = (mid, v.attrs["signature"])
            if key in self.callback_sigs:
                raise Reject(400, "AUT_REPLAY_DETECTED", "callback replayed", mid)
            self.callback_sigs.add(key)

    def _check_unsolicited(self, ctx, v):
        mid = ctx["messageId"]
        if self.confirmed.get(ctx["transactionId"]) != ctx["bppId"]:
            raise Reject(400, "CTX_TRANSACTION_ID_UNKNOWN", "no active transaction with this PN", mid)
        if mid in self.pending:
            raise Reject(400, "CTX_INVALID_FIELD", "PN-initiated callback reuses a request messageId", mid)
        self.check_replay(ctx["bppId"], mid, v.attrs["signature"], v.attrs["expires"])

    def _record(self, action, ctx, body, raw, auth, v):
        with self._cv:
            self.callbacks.setdefault(ctx["messageId"], []).append(
                CallbackEntry(action, body, raw, auth, v.chained))
            if action == "confirm" and body["message"]["contract"].get("status", {}).get("code") == "ACTIVE":
                self.confirmed[ctx["transactionId"]] = ctx["bppId"]
            self._cv.notify_all()

    # ------------------------------------------------------------ test helpers
    def wait_callback(self, message_id, timeout=5.0, missing_ok=False, index=0):
        deadline = time.monotonic() + timeout
        with self._cv:
            while len(self.callbacks.get(message_id, [])) <= index:
                left = deadline - time.monotonic()
                if left <= 0:
                    if missing_ok:
                        return None
                    raise AssertionError(f"no callback for {message_id} within {timeout}s")
                self._cv.wait(left)
            return self.callbacks[message_id][index].body

    def callbacks_for(self, message_id):
        with self._lock:
            return list(self.callbacks.get(message_id, []))

    def all_callbacks(self):
        with self._lock:
            return [e for v in self.callbacks.values() for e in v]

    def callback_digest(self, message_id, index=0):
        return signing.request_digest(self.callbacks_for(message_id)[index].raw)

    def outbound_signature(self, message_id):
        return self.pending[message_id]["signature"]
