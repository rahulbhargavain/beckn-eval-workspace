"""Generic, domain-agnostic BPP (Provider Node). Also serves /discover for its own
catalog, i.e. it co-hosts the Discovery Service role (mockup simplification).

Every forward action: verify signature -> parse -> schema -> context -> sender
binding -> ttl -> replay -> callback-URL guard -> business checks -> signed Ack;
the on_<action> callback is delivered asynchronously, signed with the callback
signing string chained to the CN's request signature (NFH-007 §3.3/§6).
"""
import asyncio
import copy
import json
import uuid
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

from fastapi import Request

from . import signing, spec, urlguard
from .catalogstore import CatalogStore
from .lots import LotError
from .packs import PackRegistry
from .node import (Identity, Node, Reject, dumps, iso_now, now_ts, raw_signature, read_body, same_url)

DEFAULT_CATALOG = Path(__file__).with_name("catalog.json")
_CTX = "https://schema.example.org/mock/v1"


class BppNode(Node):
    http_follows_redirects = False

    def __init__(self, identity: Identity, registry_url, network_id, trusted_registries=(),
                 callback_allowlist=None, catalog_path=DEFAULT_CATALOG, callback_delay=0.05, store=None, ledger=None):
        super().__init__(identity, registry_url, network_id, trusted_registries)
        self.callback_allowlist = callback_allowlist
        if store is None:  # legacy single mock catalog: its mock/v1 context is not a pack, so non-strict
            store = CatalogStore(PackRegistry([], strict=False))
            store.publish(json.loads(Path(catalog_path).read_text(encoding="utf-8")))
        self.store = store
        self.ledger = ledger      # optional LotLedger: when set, only on-hand stock can be sold
        self.callback_delay = callback_delay
        self.contracts = {}       # contract id -> contract (authoritative PN view)
        self.owners = {}          # contract id -> (bapId, transactionId)
        self.drafts = {}          # (bapId, transactionId) -> draft contract
        self.previews = {}        # (contract id, action) -> (digest of preview callback, contract)
        self.inbound = {}         # messageId -> {"ctx", "signature"}
        self.processed = []       # (action, messageId) actually processed
        self.callbacks_sent = []  # (action, messageId, http status)
        self.last_push = None
        self._tasks = set()
        for action in spec.ACTIONS:
            self.app.add_api_route("/" + action, self._endpoint(action), methods=["POST"])

    # ------------------------------------------------------------------ inbound
    def _endpoint(self, action):
        async def handler(request: Request):
            auth = request.headers.get("authorization")
            req_sig = raw_signature(auth)
            mid = None
            try:
                raw = await read_body(request)
                v = await self.verify_signature(raw, auth, {signing.STD_HEADERS})
                body = self.parse_body(raw)
                ctx = self.validate("/" + action, body, "bapId")
                mid = ctx["messageId"]
                if v.key["subscriberId"] != ctx["bapId"]:
                    raise Reject(401, "AUT_UNAUTHORIZED_ACTION", "signer is not context.bapId", mid)
                sender = await self.lookup_subscriber(ctx["bapId"])
                if not sender or sender.get("status") != "SUBSCRIBED":
                    raise Reject(401, "AUT_SUBSCRIBER_NOT_FOUND", "bapId not registered", mid)
                self.check_replay(ctx["bapId"], mid, v.attrs["signature"], v.attrs["expires"])
                self._check_callback_url(ctx, sender)
                if ctx.get("bppId") not in (None, self.subscriber_id) or (
                        "bppUri" in ctx and not same_url(ctx["bppUri"], self.identity.url)):
                    raise Reject(400, "CTX_INVALID_BPP_URI", "request not addressed to this BPP", mid)
                outcome = self._business(action, ctx, body["message"])
            except Reject as rej:
                return self.nack(rej, mid, req_sig)
            self.processed.append((action, mid))
            if outcome is None:  # AckNoCallback
                return self.ack(mid, req_sig, 202, {"code": "BIZ_NO_RESULTS_FOUND",
                                                     "message": "no matching catalog"})
            self.inbound[mid] = {"ctx": ctx, "signature": req_sig, "digest": signing.request_digest(raw)}
            self._spawn(self._deliver(action, ctx, outcome, req_sig, signing.request_digest(raw)))
            return self.ack(mid, req_sig)
        handler.__name__ = f"handle_{action}"
        return handler

    def _check_callback_url(self, ctx, sender):
        uri = ctx.get("bapUri")
        if not uri:
            raise Reject(400, "CTX_CALLBACK_URL_MISSING", "context.bapUri is required", ctx["messageId"])
        if not same_url(uri, sender.get("subscriberUrl")):
            raise Reject(400, "CTX_INVALID_FIELD", "bapUri does not match registry subscriber_url",
                         ctx["messageId"])
        try:
            urlguard.check_url(uri, allowlist=self.callback_allowlist)
        except urlguard.UnsafeURL as e:
            raise Reject(400, "CTX_INVALID_FIELD", f"callback URL refused: {e}", ctx["messageId"]) from None

    # ------------------------------------------------------------------ outbound
    def _spawn(self, coro):
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def _callback_body(self, action, ctx, message, request_digest=None, message_id=None, txn=None):
        cctx = {k: v for k, v in ctx.items() if k not in ("requestDigest", "try") and not k.startswith("_")}
        cctx.update(action=f"on_{action}", version="2.0.0", bppId=self.subscriber_id,
                    bppUri=self.identity.url, timestamp=iso_now(), ttl="PT30S")
        if message_id:
            cctx["messageId"] = message_id
        if txn:
            cctx["transactionId"] = txn
        if action in ("update", "cancel"):
            cctx["try"] = bool(ctx.get("try", False))
        if request_digest:
            cctx["requestDigest"] = {"digest": request_digest}
        body = {"context": cctx, "message": message}
        errs = spec.request_errors(f"/on_{action}", body)
        if errs:  # self-check: never emit schema-invalid callbacks
            raise RuntimeError(f"on_{action} would be invalid: {errs[:3]}")
        return body

    async def _deliver(self, action, ctx, outcome, req_sig, req_digest):
        await asyncio.sleep(self.callback_delay)  # Ack goes out first (CON-013-02)
        try:
            message, after_send = outcome
            body = self._callback_body(action, ctx, message, req_digest)
            raw = dumps(body)
            if after_send:
                after_send(raw)
            urlguard.check_url(ctx["bapUri"], allowlist=self.callback_allowlist)  # re-check at send
            now = now_ts()
            auth = signing.sign_message(self.identity.keypair, self.identity.key_id, raw, now,
                                        now + self.signature_ttl, request_signature=req_sig)
            r = await self.ahttp.post(ctx["bapUri"].rstrip("/") + f"/on_{action}", content=raw,
                                      headers={"Authorization": auth, "Content-Type": "application/json"},
                                      follow_redirects=self.http_follows_redirects)
            self.callbacks_sent.append((action, ctx["messageId"], r.status_code))
        except Exception as e:  # noqa: BLE001 - recorded for test diagnostics
            self.errors.append(f"on_{action} {ctx.get('messageId')}: {e!r}")

    def _post_sync(self, url, raw, auth):
        return self.http.post(url, content=raw, follow_redirects=self.http_follows_redirects,
                              headers={"Authorization": auth, "Content-Type": "application/json"})

    def push_status(self, contract_id, transaction_id=None):
        """PN-initiated on_status (NFH-013 §8): fresh messageId, 3-line signature."""
        bap_id, txn = self.owners[contract_id]
        sender = self.lookup_subscriber_sync(bap_id)
        ctx = {"action": "status", "bapId": bap_id, "bapUri": sender["subscriberUrl"],
               "transactionId": transaction_id or txn, "messageId": str(uuid.uuid4()),
               "networkId": self.network_id}
        body = self._callback_body("status", ctx, {"contract": self.contracts[contract_id]})
        raw = dumps(body)
        urlguard.check_url(ctx["bapUri"], allowlist=self.callback_allowlist)
        now = now_ts()
        auth = signing.sign_message(self.identity.keypair, self.identity.key_id, raw, now, now + 60)
        self.last_push = (raw, auth)
        return self._post_sync(ctx["bapUri"].rstrip("/") + "/on_status", raw, auth)

    def send_followup(self, message_id):
        """A further solicited on_status for an earlier /status (NFH-013 §9)."""
        rec = self.inbound[message_id]
        cid = rec["ctx"]["_contract_id"]
        c = copy.deepcopy(self.contracts[cid])
        c["performance"][0]["status"] = {"code": "IN_PROGRESS"}
        body = self._callback_body("status", rec["ctx"], {"contract": c}, rec["digest"])
        raw = dumps(body)
        now = now_ts()
        auth = signing.sign_message(self.identity.keypair, self.identity.key_id, raw, now, now + 60,
                                    request_signature=rec["signature"])
        return self._post_sync(rec["ctx"]["bapUri"].rstrip("/") + "/on_status", raw, auth)

    # ------------------------------------------------------------------ business
    def _business(self, action, ctx, msg):
        """Returns (callback message, after_send hook) or None for AckNoCallback.
        Raises Reject for synchronous semantic failures."""
        fn = getattr(self, f"_on_{action}")
        return fn(ctx, msg)

    def _bad(self, ctx, code, text):
        return Reject(400, code, text, ctx["messageId"])

    def _offers(self):
        return self.store.offer_index()

    def _price(self, offer):
        return offer["considerations"][0]["considerationAttributes"]

    _MAX_QTY = Decimal(10) ** 9
    _QTY_STEP = Decimal("0.001")    # at most three decimal places
    _MONEY_STEP = Decimal("0.01")   # assumption: two minor-unit places, half-up, on the final total only

    def _qty(self, ctx, q):
        """A positive finite decimal, at most three places, up to 1e9. The core schema leaves
        quantity unconstrained, so this is the mockup's own rule."""
        if isinstance(q, bool) or not isinstance(q, (int, float)):
            raise self._bad(ctx, "BIZ_QUANTITY_UNAVAILABLE", "quantity must be a number")
        d = Decimal(q) if isinstance(q, int) else Decimal(repr(q))
        if not d.is_finite() or d <= 0 or d > self._MAX_QTY or d != d.quantize(self._QTY_STEP):
            raise self._bad(ctx, "BIZ_QUANTITY_UNAVAILABLE",
                            "quantity must be positive, at most 1e9, with at most three decimal places")
        return d

    @staticmethod
    def _num(d):
        """Decimal -> JSON number: an int when whole, else the shortest float that round-trips."""
        return int(d) if d == d.to_integral_value() else float(d)

    def _quote(self, ctx, commitments):
        """Recompute price from the catalog; never trust client-supplied considerations."""
        offers, total, out, currency = self._offers(), Decimal(0), [], "INR"
        for i, cm in enumerate(commitments):
            offer = offers.get(cm["offer"]["id"])
            if not offer:
                raise self._bad(ctx, "BIZ_OFFER_NOT_FOUND", f"offer {cm['offer']['id']} not in catalog")
            res = []
            for r in cm["resources"]:
                if r["id"] not in offer["resourceIds"]:
                    raise self._bad(ctx, "BIZ_ITEM_NOT_FOUND", f"resource {r['id']} not in offer")
                qd = r.get("quantity", {})
                if not isinstance(qd, dict):
                    raise self._bad(ctx, "SCH_SCHEMA_VALIDATION_FAILED",
                                    "resource quantity must be an object such as {\"unitQuantity\": 2}")
                q = self._qty(ctx, qd.get("unitQuantity", 1))
                price = self._price(offer)
                value = price["value"]
                total += (Decimal(value) if isinstance(value, int) else Decimal(repr(value))) * q
                currency = price["currency"]
                unit = (offer.get("offerAttributes") or {}).get("unitCode", "UNIT")
                res.append({"id": r["id"], "quantity": {"unitQuantity": self._num(q), "unitCode": unit}})
            out.append({"id": cm.get("id") or f"commitment-{i + 1}",
                        "status": {"descriptor": {"code": "DRAFT"}}, "resources": res,
                        "offer": {"id": offer["id"], "resourceIds": list(offer["resourceIds"]),
                                  "descriptor": offer.get("descriptor", {})}})
        total = total.quantize(self._MONEY_STEP, rounding=ROUND_HALF_UP)
        consideration = [{"id": "consideration-1", "status": {"code": "DRAFT"},
                          "considerationAttributes": {"@context": _CTX, "@type": "PriceSpecification",
                                                      "currency": currency, "value": self._num(total)}}]
        return out, consideration

    def _wanted(self, ctx, commitments):
        """{resource id: total quantity} across commitments, using the same quantity rules as quoting."""
        want = {}
        for cm in commitments:
            for r in cm["resources"]:
                q = self._qty(ctx, (r.get("quantity") or {}).get("unitQuantity", 1))
                want[r["id"]] = want.get(r["id"], Decimal(0)) + q
        return want

    def _stock_check(self, ctx, commitments, ref=None):
        """Advisory check at select/init/update: is it on hand now? The sale itself is taken at confirm."""
        if self.ledger is None:
            return
        for rid, q in self._wanted(ctx, commitments).items():
            have = self.ledger.available_for(rid, ref=ref)
            if q > have:
                raise self._bad(ctx, "BIZ_QUANTITY_UNAVAILABLE", f"only {self._num(have)} of {rid} is on hand")

    def _owned(self, ctx, contract_id):
        if contract_id not in self.contracts or self.owners[contract_id][0] != ctx["bapId"]:
            raise self._bad(ctx, "BIZ_ORDER_NOT_FOUND", "unknown contract")
        return self.contracts[contract_id]

    # discover (DS role)
    def _on_discover(self, ctx, msg):
        found = self.store.search(msg["intent"].get("textSearch"))
        if not found:
            return None
        return {"catalogs": [dict(c, bppId=self.subscriber_id, bppUri=self.identity.url) for c in found]}, None

    def _on_select(self, ctx, msg):
        commitments, consideration = self._quote(ctx, msg["contract"]["commitments"])
        self._stock_check(ctx, msg["contract"]["commitments"])
        draft = {"commitments": commitments, "consideration": consideration, "status": {"code": "DRAFT"}}
        self.drafts[(ctx["bapId"], ctx["transactionId"])] = draft
        return {"contract": draft}, None

    def _on_init(self, ctx, msg):
        c = msg["contract"]
        if not c.get("participants"):
            raise self._bad(ctx, "SCH_REQUIRED_FIELD_MISSING", "init requires participant billing details")
        commitments, consideration = self._quote(ctx, c["commitments"])
        self._stock_check(ctx, c["commitments"])
        prev = self.drafts.get((ctx["bapId"], ctx["transactionId"]), {})
        draft = {"id": prev.get("id") or str(uuid.uuid4()), "commitments": commitments,
                 "consideration": consideration, "participants": c["participants"],
                 "settlements": [{"id": "settlement-1", "considerationId": "consideration-1", "status": "DRAFT"}],
                 "status": {"code": "DRAFT"}}
        self.drafts[(ctx["bapId"], ctx["transactionId"])] = draft
        return {"contract": draft}, None

    def _on_confirm(self, ctx, msg):
        c = msg["contract"]
        draft = self.drafts.get((ctx["bapId"], ctx["transactionId"]))
        if not draft or "id" not in draft:
            raise self._bad(ctx, "BIZ_INVALID_STATE_TRANSITION", "confirm requires a prior init")
        if draft["id"] in self.contracts:
            raise self._bad(ctx, "BIZ_ALREADY_CONFIRMED", "contract already confirmed")
        if not any(s.get("status") == "COMMITTED" or s.get("settlementAttributes")
                   for s in c.get("settlements", [])):
            raise self._bad(ctx, "BIZ_PAYMENT_FAILED", "no payment proof in settlements")
        commitments, consideration = self._quote(ctx, c["commitments"])
        if self.ledger is not None:  # the sale: all-or-nothing, so a refused confirm leaves no contract behind
            try:
                self.ledger.sell(draft["id"], self._wanted(ctx, c["commitments"]))
            except LotError as e:
                raise self._bad(ctx, "BIZ_QUANTITY_UNAVAILABLE", str(e)) from None
        for cm in commitments:
            cm["status"] = {"descriptor": {"code": "ACTIVE"}}
        consideration[0]["status"] = {"code": "ACTIVE"}
        contract = dict(draft, commitments=commitments, consideration=consideration,
                        participants=c.get("participants", draft.get("participants", [])),
                        settlements=[{"id": "settlement-1", "considerationId": "consideration-1",
                                      "status": "COMMITTED"}],
                        performance=[{"id": "performance-1", "status": {"code": "PENDING"},
                                      "commitmentIds": [cm["id"] for cm in commitments]}],
                        status={"code": "ACTIVE"})
        self.contracts[contract["id"]] = contract
        self.owners[contract["id"]] = (ctx["bapId"], ctx["transactionId"])
        return {"contract": contract}, None

    def _on_status(self, ctx, msg):
        c = self._owned(ctx, msg["contract"]["id"])
        ctx["_contract_id"] = c["id"]  # remembered for follow-up pushes; stripped from callbacks
        return {"contract": copy.deepcopy(c)}, None

    def _on_track(self, ctx, msg):
        c = self._owned(ctx, msg["tracking"]["contract"]["id"])
        return {"tracking": {"contract": copy.deepcopy(c), "url": f"https://track.mock.invalid/{c['id']}",
                             "status": "ACTIVE" if c["status"]["code"] == "ACTIVE" else "INACTIVE"}}, None

    def _two_phase(self, ctx, action, contract_id, make_preview, commit):
        key = (contract_id, action)
        if ctx.get("try") is True:
            preview = make_preview()

            def remember(raw):
                self.previews[key] = (signing.request_digest(raw), preview)
            return {"contract": preview}, remember
        rd = ctx.get("requestDigest")
        if not rd:
            raise self._bad(ctx, "CTX_MISSING_FIELD", "context.requestDigest required when try is false")
        stored = self.previews.get(key)
        if not stored or stored[0] != rd["digest"]:
            raise self._bad(ctx, "CTX_INVALID_FIELD", "requestDigest does not match the preview response")
        del self.previews[key]
        return {"contract": commit(stored[1])}, None

    def _on_update(self, ctx, msg):
        c = self._owned(ctx, msg["contract"]["id"])
        if c["status"]["code"] != "ACTIVE":
            raise self._bad(ctx, "BIZ_INVALID_STATE_TRANSITION", "only ACTIVE contracts can be updated")
        self._quote(ctx, msg["contract"]["commitments"])  # same quantity rules on preview and commit
        self._stock_check(ctx, msg["contract"]["commitments"], ref=c["id"])

        def preview():
            commitments, consideration = self._quote(ctx, msg["contract"]["commitments"])
            for cm in commitments:
                cm["status"] = {"descriptor": {"code": "ACTIVE"}}
            consideration[0]["status"] = {"code": "ACTIVE"}
            return dict(copy.deepcopy(c), commitments=commitments, consideration=consideration)

        def shape(commitments):
            return [[(r["id"], (r.get("quantity") or {}).get("unitQuantity", 1)) for r in cm["resources"]]
                    for cm in commitments]

        def commit(p):
            if shape(p["commitments"]) != shape(msg["contract"]["commitments"]):
                raise self._bad(ctx, "BIZ_UPDATE_INCONSISTENT", "commit differs from previewed update")
            if self.ledger is not None:
                try:
                    self.ledger.resell(c["id"], self._wanted(ctx, p["commitments"]))
                except LotError as e:
                    raise self._bad(ctx, "BIZ_QUANTITY_UNAVAILABLE", str(e)) from None
            self.contracts[c["id"]] = p
            return copy.deepcopy(p)
        return self._two_phase(ctx, "update", c["id"], preview, commit)

    def _on_cancel(self, ctx, msg):
        c = self._owned(ctx, msg["contract"]["id"])
        if c["status"]["code"] == "CANCELLED":
            raise self._bad(ctx, "BIZ_ALREADY_CANCELLED", "already cancelled")

        def preview():
            return dict(copy.deepcopy(c), descriptor={"name": "Cancellation terms",
                                                      "shortDesc": "Full refund, no penalty"})

        def commit(_p):
            if self.ledger is not None:
                self.ledger.unsell(c["id"])
            done = copy.deepcopy(c)
            done["status"] = {"code": "CANCELLED"}
            for cm in done["commitments"]:
                cm["status"] = {"descriptor": {"code": "CLOSED"}}
            self.contracts[c["id"]] = done
            return copy.deepcopy(done)
        return self._two_phase(ctx, "cancel", c["id"], preview, commit)

    def _on_rate(self, ctx, msg):
        out = []
        for ri in msg["ratingInputs"]:
            tid = ri["target"].get("id")
            if tid not in self.contracts or self.owners[tid][0] != ctx["bapId"]:
                raise self._bad(ctx, "BIZ_RATING_TARGET_NOT_FOUND", f"unknown rating target {tid}")
            if self.contracts[tid]["status"]["code"] not in ("COMPLETE", "CANCELLED"):
                raise self._bad(ctx, "BIZ_INVALID_STATE_TRANSITION", "contract not in a terminal state")
            out.append({"target": {"id": tid}, "range": dict(ri["range"], recorded=True)})
        return {"ratings": out}, None

    def _on_support(self, ctx, msg):
        s = msg["support"]
        if "orderId" in s:
            self._owned(ctx, s["orderId"])
        ticket = f"ticket-{uuid.uuid4()}"
        support = {"descriptor": {"name": "Support ticket created", "code": ticket},
                   "channels": [{"@context": _CTX, "@type": "ContactPoint",
                                 "email": f"support@{self.subscriber_id}", "ticketId": ticket}]}
        if "orderId" in s:
            support["orderId"] = s["orderId"]
        return {"support": support}, None
