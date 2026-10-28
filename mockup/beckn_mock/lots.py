"""Lot ledger for an aggregation hub: what is physically on hand, where it came from, what was sold.

Smallholder produce arrives as graded, assayed lots. The hub sells it through the seller node (BPP) or
moves it to its own factory; neither may take more than is on hand. Every change is an append-only event,
so on-hand quantity is always the sum of a lot's events and any figure can be traced to a household.

Scope: one process, in memory. Persistence, expiry of stale state and a physical stock count are not
covered here (see docs/mockup-findings.md, A2). Quantities are Decimal with at most three places.
"""
import copy
import hashlib
import re
import threading
from decimal import Decimal, InvalidOperation

ORIGIN_TYPES = ("own-land", "lawful-collection")
CERT_SCOPES = ("domestic", "export")
UNITS = ("KGM", "TNE", "C62", "LTR")
MAX_QTY = Decimal(10) ** 9
_STEP = Decimal("0.001")
_ID = re.compile(r"^[A-Za-z0-9._:\-]{1,64}$")
_CTX_PRODUCE = "https://packs.beckn-eval.invalid/schemas/Produce/v0.1/context.jsonld"
_CTX_TERMS = "https://packs.beckn-eval.invalid/schemas/ProduceTerms/v0.1/context.jsonld"
_CTX_PRICE = "https://schema.nfh.global/PriceSpecification/v2.2/context.jsonld"


class LotError(ValueError):
    pass


def _dec(x, field):
    if isinstance(x, bool) or not isinstance(x, (int, float, str, Decimal)):
        raise LotError(f"{field} must be a number")
    try:
        d = x if isinstance(x, Decimal) else Decimal(x) if isinstance(x, int) else Decimal(repr(x) if isinstance(x, float) else x.strip())
    except InvalidOperation:
        raise LotError(f"{field} must be a number") from None
    if not d.is_finite() or d <= 0 or d > MAX_QTY or d != d.quantize(_STEP):
        raise LotError(f"{field} must be positive, at most 1e9, with at most three decimal places")
    return d


def _num(d):
    return int(d) if d == d.to_integral_value() else float(d)


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")


def _text(lot, field, required=True):
    v = lot.get(field)
    if v is None and not required:
        return None
    if not isinstance(v, str) or not v.strip():
        raise LotError(f"{field} is required and must be non-empty text")
    return v.strip()


def _pct(lot, field):
    v = lot.get(field)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0 <= v <= 100 or v != v:
        raise LotError(f"{field} must be a number from 0 to 100")
    return v


class LotLedger:
    def __init__(self):
        self._lock = threading.RLock()
        self._lots = {}      # lot id -> normalised lot
        self._order = []     # receipt order, for first-in-first-out
        self._events = {}    # lot id -> [event]
        self._held = {}      # order reference -> [(lot id, qty)]
        self._seq = 0

    # ------------------------------------------------------------ identity of a sellable resource
    @staticmethod
    def _key(lot):
        return (lot["product"], lot["grade"], lot["unitCode"], lot["originType"], lot.get("gradingStandard"),
                lot.get("certificationScheme"), lot.get("certificationScope"))

    def resource_id(self, lot):
        n = self._normalise(lot, check_id=False)
        h = hashlib.sha256("|".join(str(x) for x in self._key(n)).encode()).hexdigest()[:6]
        return f"res-{_slug(n['product'])}-{_slug(n['grade'])}-{h}"

    # ------------------------------------------------------------ receiving
    def _normalise(self, lot, check_id=True):
        if not isinstance(lot, dict):
            raise LotError("lot must be an object")
        out = {}
        if check_id:
            lid = lot.get("id")
            if not isinstance(lid, str) or not _ID.fullmatch(lid):
                raise LotError("id is required (letters, digits and . _ : - only, up to 64)")
            out["id"] = lid
        out["product"] = _text(lot, "product")
        out["grade"] = _text(lot, "grade")
        unit = lot.get("unitCode", "KGM")
        if unit not in UNITS:
            raise LotError(f"unitCode {unit!r} is not one of {list(UNITS)}")
        out["unitCode"] = unit
        origin = lot.get("originType")
        if origin not in ORIGIN_TYPES:
            hint = (" Produce from Green Credit Programme forest parcels is outside this pipeline."
                    if isinstance(origin, str) and re.search(r"forest|gcp|green", origin, re.I) else "")
            raise LotError(f"originType must be one of {list(ORIGIN_TYPES)}.{hint}")
        out["originType"] = origin
        src = lot.get("source")
        if (not isinstance(src, list) or not src or len(src) > 1000
                or not all(isinstance(x, str) and x.strip() for x in src)):
            raise LotError("source must list at least one household or group id")
        out["source"] = [x.strip() for x in src]
        scope = lot.get("certificationScope")
        if scope is not None and scope not in CERT_SCOPES:
            raise LotError(f"certificationScope must be one of {list(CERT_SCOPES)}")
        for f in ("gradingStandard", "certificationScheme", "harvestDate", "location"):
            v = _text(lot, f, required=False)
            if v is not None:
                out[f] = v
        if scope is not None:
            out["certificationScope"] = scope
        for f in ("moisturePercent", "brixDegrees"):
            v = _pct(lot, f)
            if v is not None:
                out[f] = v
        return out

    def receive(self, lot):
        n = self._normalise(lot)
        qty = _dec(lot.get("quantity"), "quantity")
        with self._lock:
            if n["id"] in self._lots:
                raise LotError(f"lot {n['id']} already received")
            n["resource"] = self.resource_id(n)
            self._lots[n["id"]] = n
            self._order.append(n["id"])
            self._events[n["id"]] = []
            self._append(n["id"], "receive", qty, source=list(n["source"]))
        return n["id"]

    # ------------------------------------------------------------ reading
    def _append(self, lot_id, kind, delta, **extra):
        self._seq += 1
        self._events[lot_id].append(dict(seq=self._seq, type=kind, lot=lot_id, delta=delta, **extra))

    def events(self, lot_id):
        with self._lock:
            return copy.deepcopy(self._events[lot_id])

    def on_hand(self, lot_id):
        with self._lock:
            return sum((e["delta"] for e in self._events[lot_id]), Decimal(0))

    def _lots_of(self, rid):
        return [l for l in self._order if self._lots[l]["resource"] == rid]

    def on_hand_for(self, rid):
        with self._lock:
            return sum((self.on_hand(l) for l in self._lots_of(rid)), Decimal(0))

    def available_for(self, rid, ref=None):
        """Free stock of a resource; with `ref`, also what that order already holds."""
        with self._lock:
            held = Decimal(0)
            if ref is not None:
                held = sum((q for lid, q in self._held.get(ref, []) if self._lots[lid]["resource"] == rid), Decimal(0))
            return self.on_hand_for(rid) + held

    # ------------------------------------------------------------ planning and applying movements
    def _plan(self, items, credit=None):
        """First-in-first-out allocation for {resource id: qty}; nothing is changed. `credit` adds back
        quantity per lot (what an order being changed already holds)."""
        credit = credit or {}
        left = {l: self.on_hand(l) + credit.get(l, Decimal(0)) for l in self._order}
        plan = []
        for rid, raw in items.items():
            want = _dec(raw, f"quantity of {rid}")
            need = want
            for lid in self._lots_of(rid):
                take = min(left[lid], need)
                if take > 0:
                    plan.append((lid, take))
                    left[lid] -= take
                    need -= take
                if need == 0:
                    break
            if need > 0:
                free = sum((left[l] for l in self._lots_of(rid)), Decimal(0)) + (want - need)
                raise LotError(f"insufficient stock for {rid}: wanted {want}, available {free}")
        return plan

    @staticmethod
    def _ref(ref, what="order reference"):
        if not isinstance(ref, str) or not ref.strip():
            raise LotError(f"{what} is required")
        return ref

    def sell(self, ref, items):
        """Take stock for order `ref` all-or-nothing. Returns the [(lot id, qty)] it was drawn from."""
        self._ref(ref)
        with self._lock:
            if ref in self._held:
                raise LotError(f"order {ref} already holds stock")
            plan = self._plan(items)
            for lid, q in plan:
                self._append(lid, "sell", -q, ref=ref)
            self._held[ref] = list(plan)
            return list(plan)

    def unsell(self, ref):
        """Give an order's stock back to the lots it came from. Idempotent. True when something was returned."""
        with self._lock:
            plan = self._held.pop(ref, None)
            for lid, q in plan or []:
                self._append(lid, "unsell", q, ref=ref)
            return bool(plan)

    def resell(self, ref, items):
        """Change what an order holds, atomically: either the new allocation or the old one stays."""
        self._ref(ref)
        with self._lock:
            old = self._held.get(ref)
            if old is None:
                raise LotError(f"order {ref} holds no stock")
            credit = {}
            for lid, q in old:
                credit[lid] = credit.get(lid, Decimal(0)) + q
            plan = self._plan(items, credit)
            for lid, q in old:
                self._append(lid, "unsell", q, ref=ref)
            for lid, q in plan:
                self._append(lid, "sell", -q, ref=ref)
            self._held[ref] = list(plan)
            return list(plan)

    def transfer(self, rid, qty, to, reference):
        """Move free stock to the hub's own factory (or elsewhere) without a sale."""
        self._ref(to, "destination")
        self._ref(reference, "reference")
        with self._lock:
            for lid, q in self._plan({rid: qty}):
                self._append(lid, "transfer", -q, to=to, ref=reference)

    def write_off(self, lot_id, qty, reason):
        if not isinstance(reason, str) or not reason.strip():
            raise LotError("a write-off needs a reason")
        q = _dec(qty, "quantity")
        with self._lock:
            if lot_id not in self._lots:
                raise LotError(f"unknown lot {lot_id}")
            if q > self.on_hand(lot_id):
                raise LotError(f"insufficient stock in {lot_id}: wanted {q}, on hand {self.on_hand(lot_id)}")
            self._append(lot_id, "write_off", -q, reason=reason.strip())

    # ------------------------------------------------------------ publishing
    def catalog(self, catalog_id, provider, prices, currency="INR", origin_country="IN"):
        """Beckn catalog of what is on hand now: one resource and offer per product, grade and certificate.

        `prices` maps (product, grade) to a price per unit. The catalog states the least favourable lot
        figure for each assay value (highest moisture, lowest Brix, earliest harvest) so a buyer is never
        promised better than the worst lot in the group. availableQuantity is a snapshot."""
        with self._lock:
            groups = {}
            for lid in self._order:
                lot = self._lots[lid]
                if self.on_hand(lid) > 0:
                    groups.setdefault(lot["resource"], []).append(lot)
            resources, offers = [], []
            for rid, lots in groups.items():
                first = lots[0]
                price = prices.get((first["product"], first["grade"]))
                if isinstance(price, bool) or not isinstance(price, (int, float)) or price < 0:
                    raise LotError(f"no price for {first['product']!r} grade {first['grade']!r}")
                attrs = {"@context": _CTX_PRODUCE, "@type": "Produce", "originCountry": origin_country,
                         "originType": first["originType"]}
                for f in ("gradingStandard", "certificationScheme", "certificationScope"):
                    if f in first:
                        attrs[f] = first[f]
                moist = [l["moisturePercent"] for l in lots if "moisturePercent" in l]
                brix = [l["brixDegrees"] for l in lots if "brixDegrees" in l]
                harvest = [l["harvestDate"] for l in lots if "harvestDate" in l]
                if moist:
                    attrs["moisturePercent"] = max(moist)
                if brix:
                    attrs["brixDegrees"] = min(brix)
                if harvest:
                    attrs["harvestDate"] = min(harvest)
                name = f"{first['product']} grade {first['grade']}"
                resources.append({"id": rid, "descriptor": {"name": name, "shortDesc": f"{first['originType']} lots, "
                                                                            f"graded to {first.get('gradingStandard', 'hub standard')}"},
                                  "resourceAttributes": attrs})
                offers.append({
                    "id": "offer-" + rid[len("res-"):], "descriptor": {"name": f"{name} per {first['unitCode']}"},
                    "resourceIds": [rid],
                    "offerAttributes": {"@context": _CTX_TERMS, "@type": "ProduceTerms", "unitCode": first["unitCode"],
                                        "availableQuantity": _num(self.on_hand_for(rid))},
                    "considerations": [{"id": "price-" + rid[len("res-"):], "considerationAttributes": {
                        "@context": _CTX_PRICE, "@type": "PriceSpecification", "currency": currency, "value": price}}]})
            return {"id": catalog_id, "descriptor": {"name": f"{provider['descriptor']['name']} lots"},
                    "provider": provider, "resources": resources, "offers": offers}
