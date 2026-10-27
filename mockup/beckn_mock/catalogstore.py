"""In-memory catalog store: validates against the Beckn Catalog schema and the domain packs,
versions every publish, and answers discovery queries across catalogs.

Rejects before storing, so a failed publish leaves the store untouched.
"""
import copy
import json
import time
from pathlib import Path

from . import spec


class CatalogRejected(Exception):
    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors[:5]))


def _digest(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class CatalogStore:
    def __init__(self, packs, policy=None):
        self.packs = packs
        self.policy = policy
        self._versions = {}   # catalog id -> [{"version", "published_at", "catalog"}]
        self._inactive = set()

    @classmethod
    def from_dir(cls, directory, packs, policy=None):
        store = cls(packs, policy)
        for path in sorted(Path(directory).glob("*.json")):
            try:
                store.publish(json.loads(path.read_text(encoding="utf-8")))
            except ValueError as e:
                raise CatalogRejected([f"{path.name}: not valid JSON ({e})"]) from None
            except CatalogRejected as e:
                raise CatalogRejected([f"{path.name}: {x}" for x in e.errors]) from None
        return store

    # ------------------------------------------------------------------ validation
    def _errors(self, cat):
        if not isinstance(cat, dict):
            return ["catalog must be an object"]
        errs = list(spec.component_errors("Catalog", cat))
        if errs:
            return errs
        res_ids = [r["id"] for r in cat.get("resources", [])]
        if len(set(res_ids)) != len(res_ids):
            errs.append("duplicate resource id inside the catalog")
        offer_ids = [o["id"] for o in cat.get("offers", [])]
        if len(set(offer_ids)) != len(offer_ids):
            errs.append("duplicate offer id inside the catalog")
        taken_r, taken_o = self._taken_ids(exclude=cat["id"])
        errs += [f"resource id {i!r} already used by another catalog" for i in res_ids if i in taken_r]
        errs += [f"offer id {i!r} already used by another catalog" for i in offer_ids if i in taken_o]

        def check(path, attrs):
            errs.extend(f"{path}{e}" if e.startswith("[") or e.startswith(".") else f"{path}: {e}"
                        for e in self.packs.attribute_errors(attrs) + (
                            self.policy.attribute_errors(attrs) if self.policy else []))

        if "providerAttributes" in cat["provider"]:
            check("provider.providerAttributes", cat["provider"]["providerAttributes"])
        for i, r in enumerate(cat.get("resources", [])):
            if "resourceAttributes" in r:
                check(f"resources[{i}].resourceAttributes", r["resourceAttributes"])
        for i, o in enumerate(cat.get("offers", [])):
            base = f"offers[{i}]"
            if "offerAttributes" in o:
                check(f"{base}.offerAttributes", o["offerAttributes"])
            missing = [r for r in o.get("resourceIds", []) if r not in res_ids]
            if missing:
                errs.append(f"{base}.resourceIds references unknown resource {missing[0]!r}")
            cons = o.get("considerations") or []
            for j, c in enumerate(cons):
                if "considerationAttributes" in c:
                    check(f"{base}.considerations[{j}].considerationAttributes", c["considerationAttributes"])
            price = cons[0].get("considerationAttributes") if cons else None
            ok = (isinstance(price, dict) and isinstance(price.get("currency"), str)
                  and isinstance(price.get("value"), (int, float)) and not isinstance(price.get("value"), bool)
                  and price["value"] >= 0)
            if not ok:
                errs.append(f"{base}.considerations[0] needs considerationAttributes with currency and a numeric value >= 0")
        return errs

    def _taken_ids(self, exclude):
        r, o = set(), set()
        for cid, vs in self._versions.items():
            if cid == exclude:
                continue
            cat = vs[-1]["catalog"]
            r.update(x["id"] for x in cat.get("resources", []))
            o.update(x["id"] for x in cat.get("offers", []))
        return r, o

    # ------------------------------------------------------------------ writes
    def publish(self, catalog):
        errs = self._errors(catalog)
        if errs:
            raise CatalogRejected(errs)
        cid = catalog["id"]
        versions = self._versions.setdefault(cid, [])
        if versions and _digest(versions[-1]["catalog"]) == _digest(catalog):
            return {"id": cid, "version": versions[-1]["version"]}
        rec = {"version": len(versions) + 1, "published_at": int(time.time()), "catalog": copy.deepcopy(catalog)}
        versions.append(rec)
        self._inactive.discard(cid)
        return {"id": cid, "version": rec["version"]}

    def deactivate(self, catalog_id):
        if catalog_id not in self._versions:
            raise KeyError(catalog_id)
        self._inactive.add(catalog_id)

    # ------------------------------------------------------------------ reads
    def ids(self):
        return sorted(self._versions)

    def get(self, catalog_id, version=None):
        vs = self._versions[catalog_id]
        rec = vs[-1] if version is None else vs[version - 1]
        return copy.deepcopy(rec["catalog"])

    def history(self, catalog_id):
        return [{"version": v["version"], "published_at": v["published_at"]} for v in self._versions[catalog_id]]

    def active(self):
        return [copy.deepcopy(vs[-1]["catalog"]) for cid, vs in sorted(self._versions.items())
                if cid not in self._inactive]

    def search(self, text):
        """Active catalogs narrowed to resources whose descriptor matches `text` (all when empty)."""
        needle = (text or "").lower()
        out = []
        for cat in self.active():
            if needle:
                keep = [r for r in cat.get("resources", [])
                        if any(needle in (r.get("descriptor", {}).get(k) or "").lower()
                               for k in ("name", "shortDesc", "longDesc"))]
                if not keep:
                    continue
                ids = {r["id"] for r in keep}
                cat["resources"] = keep
                cat["offers"] = [o for o in cat.get("offers", []) if ids & set(o["resourceIds"])]
            out.append(cat)
        return out

    def offer_index(self):
        """offer id -> offer, across active catalogs (ids are unique store-wide)."""
        return {o["id"]: o for cat in self.active() for o in cat.get("offers", [])}
