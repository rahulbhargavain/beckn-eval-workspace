"""DeDi file-based onboarding: build and verify the registry file and manifest.

Spec: LF-Decentralized-Trust-labs/decentralized-directory-protocol docs/publishing-dedi-files.md
(schemas vendored in conformance/dedi_vendor). Files are signed with Ed25519 over the RFC 8785
(JCS) canonical JSON of the document minus `proof`, as a detached JWS (alg EdDSA, b64 false).

The private seed is read from an identity file you own, held only in memory, and never printed or
written. Not built: a discovery list, a digests file, inline registries on the build side, hosted
(dedi.global) registries, and cross-checks against another implementation of the signature.
"""
import argparse
import base64
import copy
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

VENDOR = Path(__file__).with_name("dedi_vendor")
FMT = "%Y-%m-%dT%H:%M:%SZ"
_RAW = "https://raw.githubusercontent.com/LF-Decentralized-Trust-labs/decentralized-directory-protocol/refs/heads/main/schemas/"
ROLE_SCHEMA = {"NP": _RAW + "beckn_subscriber.json", "NFO": _RAW + "beckn_subscriber_reference.json"}
_ROLE_KIND = {"beckn_subscriber.json": "beckn_subscriber", "beckn_subscriber_reference.json": "beckn_subscriber_reference"}
_SCHEMA_FILES = {"dedi-file": "dedi-file.schema.json", "dedi-manifest": "dedi-manifest.schema.json",
                 "dedi-digests": "dedi-digests.schema.json", "beckn_subscriber": "beckn_subscriber.json",
                 "beckn_subscriber_reference": "beckn_subscriber_reference.json"}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


class DediError(Exception):
    pass


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


PROTECTED = {"alg": "EdDSA", "b64": False, "crit": ["b64"]}
PROTECTED_B64 = b64u(json.dumps(PROTECTED, separators=(",", ":")).encode("ascii"))


# ------------------------------------------------------------------ RFC 8785 canonical JSON
def _jcs(o, out):
    if o is None:
        out.append("null")
    elif o is True:
        out.append("true")
    elif o is False:
        out.append("false")
    elif isinstance(o, str):
        out.append(json.dumps(o, ensure_ascii=False))
    elif isinstance(o, int):
        if abs(o) > 2 ** 53 - 1:
            raise DediError("integer outside the interoperable JSON range")
        out.append(str(int(o)))
    elif isinstance(o, float):
        raise DediError("floats are not supported by this canonicalizer")
    elif isinstance(o, (list, tuple)):
        out.append("[")
        for i, v in enumerate(o):
            if i:
                out.append(",")
            _jcs(v, out)
        out.append("]")
    elif isinstance(o, dict):
        if not all(isinstance(k, str) for k in o):
            raise DediError("object keys must be strings")
        out.append("{")
        for i, k in enumerate(sorted(o, key=lambda s: s.encode("utf-16-be", "surrogatepass"))):
            if i:
                out.append(",")
            out.append(json.dumps(k, ensure_ascii=False) + ":")
            _jcs(o[k], out)
        out.append("}")
    else:
        raise DediError(f"cannot canonicalize {type(o).__name__}")


def jcs(obj) -> bytes:
    out = []
    _jcs(obj, out)
    try:
        return "".join(out).encode("utf-8")
    except UnicodeEncodeError:
        raise DediError("string contains a lone surrogate") from None


# ------------------------------------------------------------------ detached JWS
def jwk(public_raw: bytes, kid: str) -> dict:
    return {"kid": kid, "kty": "OKP", "crv": "Ed25519", "x": b64u(public_raw)}


def _signing_input(doc) -> bytes:
    return PROTECTED_B64.encode("ascii") + b"." + jcs({k: v for k, v in doc.items() if k != "proof"})


def sign_doc(doc, signing_key, kid) -> dict:
    sig = signing_key.sign(_signing_input(doc)).signature
    body = {k: v for k, v in doc.items() if k != "proof"}
    body["proof"] = {"verification_method": kid, "canonicalization": "JCS", "jws": PROTECTED_B64 + ".." + b64u(sig)}
    return body


def signature_ok(doc, key_jwk) -> bool:
    """True only for a detached EdDSA/b64:false JWS over JCS(doc minus proof) by `key_jwk`."""
    try:
        from nacl.signing import VerifyKey
        proof = doc["proof"]
        if proof.get("canonicalization") != "JCS":
            return False
        head, middle, sig = proof["jws"].split(".")
        if middle != "" or json.loads(b64u_decode(head)) != PROTECTED:
            return False
        if key_jwk.get("kty") != "OKP" or key_jwk.get("crv") != "Ed25519":
            return False
        raw = b64u_decode(key_jwk["x"])
        if len(raw) != 32:
            return False
        VerifyKey(raw).verify(head.encode("ascii") + b"." + jcs({k: v for k, v in doc.items() if k != "proof"}),
                              b64u_decode(sig))
        return True
    except Exception:  # noqa: BLE001 - any malformation means "not valid"
        return False


def file_digest(raw: bytes) -> str:
    return "sha-256:" + hashlib.sha256(raw).hexdigest()


# ------------------------------------------------------------------ shape checks (vendored schemas)
_VALIDATORS = {}


def _validator(kind):
    if kind not in _VALIDATORS:
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT7
        reg = Registry()
        schemas = {}
        for k, fn in _SCHEMA_FILES.items():
            s = json.loads((VENDOR / "schemas" / fn).read_text(encoding="utf-8"))
            schemas[k] = s
            if "$id" in s:
                reg = reg.with_resource(s["$id"], Resource.from_contents(s, default_specification=DRAFT7))
        for k, s in schemas.items():
            _VALIDATORS[k] = Draft7Validator(s, registry=reg, format_checker=Draft7Validator.FORMAT_CHECKER)
    return _VALIDATORS[kind]


def shape_errors(kind, doc):
    errs = sorted(_validator(kind).iter_errors(doc), key=lambda e: list(e.absolute_path))
    return [("$" + "".join(f"[{p!r}]" if isinstance(p, int) else f".{p}" for p in e.absolute_path)) + f": {e.message}"
            for e in errs]


# ------------------------------------------------------------------ build
def _ts(dt):
    return dt.astimezone(timezone.utc).strftime(FMT)


def _parse_ts(s):
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp lacks a timezone")  # comparing naive and aware datetimes would raise TypeError
    return dt


def _check_config(cfg):
    if cfg.get("role") not in ROLE_SCHEMA:
        raise DediError("role must be NP or NFO")
    dom = cfg.get("domain")
    if not isinstance(dom, str) or not _DOMAIN.match(dom):
        raise DediError("domain must be a bare lowercase host name (no scheme or path)")
    for k in ("nfo_name", "network", "env", "kid"):
        if not isinstance(cfg.get(k), str) or not _NAME.match(cfg[k]):
            raise DediError(f"{k} must be a plain name")
    days = cfg.get("validity_days", 7)
    if not isinstance(days, int) or not 1 <= days <= 365:
        raise DediError("validity_days must be 1..365")
    recs = cfg.get("records")
    if not isinstance(recs, list) or not recs:
        raise DediError("records must be a non-empty list")
    return days


def _records(cfg):
    kind = _ROLE_KIND[ROLE_SCHEMA[cfg["role"]].rsplit("/", 1)[1]]
    out, seen = [], set()
    for r in cfg["records"]:
        name = r.get("record_name")
        if not isinstance(name, str) or not name:
            raise DediError("every record needs a record_name")
        if name in seen:
            raise DediError(f"duplicate record_name {name!r}")
        seen.add(name)
        details = {k: v for k, v in r.items() if k != "record_name"}
        errs = shape_errors(kind, details)
        if errs:
            raise DediError(f"record {name!r} fails the {kind} schema: {errs[0]}")
        out.append({"record_name": name, "details": details})
    return out


def _previous(prev_dir, reg_name):
    if prev_dir is None:
        return None, None
    try:
        reg = json.loads((Path(prev_dir) / "dedi" / f"{reg_name}.json").read_text(encoding="utf-8"))
        man = json.loads((Path(prev_dir) / ".well-known" / "dedi.index.json").read_text(encoding="utf-8"))
        return reg, man
    except (OSError, ValueError):
        return None, None


def build(config, signing_key, out_dir, now, prev_dir=None, force=False):
    """Write <out>/dedi/<registry>.json then <out>/.well-known/dedi.index.json. Order matters: the
    manifest's digest commits to the registry file's final hosted bytes."""
    cfg = copy.deepcopy(config)
    days = _check_config(cfg)
    domain, kid = cfg["domain"], cfg["kid"]
    suffix = "ref_registry" if cfg["role"] == "NFO" else "registry"
    reg_name = f"{cfg['nfo_name']}_{cfg['network']}_{cfg['env']}_{suffix}"
    records = _records(cfg)
    out = Path(out_dir)
    reg_path, man_path = out / "dedi" / f"{reg_name}.json", out / ".well-known" / "dedi.index.json"
    if not force and (reg_path.exists() or man_path.exists()):
        raise DediError(f"{out} already holds a publication; pass force to replace it")
    key = jwk(bytes(signing_key.verify_key), kid)
    url = f"https://{domain}/dedi/{reg_name}.json"
    next_update, stamp = _ts(now + timedelta(days=days)), _ts(now)
    prev_reg, prev_man = _previous(prev_dir, reg_name)

    registry_core = {"name": reg_name, "schema": ROLE_SCHEMA[cfg["role"]], "state": "live"}
    updated = stamp
    if prev_reg and prev_reg.get("records") == records and prev_reg.get("publisher", {}).get("key") == key \
            and {k: v for k, v in prev_reg["registry"].items() if k != "updated_at"} == registry_core:
        updated = prev_reg["registry"]["updated_at"]
    doc = {"dedi_version": "0.1", "type": "dedi-file", "source_url": url, "next_update": next_update,
           "publisher": {"domain": domain, "key": key}, "namespace": domain,
           "registry": dict(registry_core, updated_at=updated), "records": records}
    signed = sign_doc(doc, signing_key, kid)
    reg_path.parent.mkdir(parents=True, exist_ok=True)
    reg_path.write_text(json.dumps(signed, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    digest = file_digest(reg_path.read_bytes())  # over the hosted bytes, after signing

    entry = {"registry": reg_name, "url": url, "digest": digest, "schema": ROLE_SCHEMA[cfg["role"]]}
    manifest_core = (domain, [key], [(reg_name, url)])
    m_updated = stamp
    if prev_man and (prev_man.get("domain"), prev_man.get("keys"),
                     [(f.get("registry"), f.get("url")) for f in prev_man.get("files", [])]) == manifest_core:
        m_updated = prev_man["updated_at"]
    manifest = {"dedi_version": "0.1", "type": "dedi-manifest", "domain": domain}
    if cfg.get("name"):
        manifest["name"] = cfg["name"]
    manifest.update(keys=[key], updated_at=m_updated, next_update=next_update, files=[entry])
    man_path.parent.mkdir(parents=True, exist_ok=True)
    man_path.write_text(json.dumps(sign_doc(manifest, signing_key, kid), indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    return {"registry": reg_path, "manifest": man_path, "digest": digest, "jwk": key}


# ------------------------------------------------------------------ verify
@dataclass
class Report:
    problems: list = field(default_factory=list)
    authenticated: bool = True

    @property
    def ok(self):
        return not self.problems


def _same_key(a, b):
    return all(a.get(k) == b.get(k) for k in ("kid", "kty", "crv", "x"))


def verify_bytes(manifest_raw, files, domain, now):
    """Spec section 7.3 over bytes in hand. `files` maps URL to raw bytes (None when unreachable)."""
    rep = Report()

    def bad(code, msg):
        rep.problems.append(f"{code}: {msg}")

    try:
        manifest = json.loads(manifest_raw)
    except ValueError:
        bad("SHAPE", "manifest is not valid JSON")
        rep.authenticated = False
        return rep
    shape = shape_errors("dedi-manifest", manifest)
    if shape:
        bad("SHAPE", f"manifest: {shape[0]}")
        rep.authenticated = False
        return rep
    if manifest["domain"] != domain:
        bad("DOMAIN", f"manifest names {manifest['domain']!r} but was served for {domain!r}")
        rep.authenticated = False
    signer = next((k for k in manifest["keys"] if k.get("kid") == manifest["proof"]["verification_method"]), None)
    if signer is None or not signature_ok(manifest, signer):
        bad("MANIFEST", "not signed by one of its own listed keys")
        rep.authenticated = False
    def stale(ts, label):
        try:
            return _parse_ts(ts) < now
        except ValueError:
            bad("SHAPE", f"{label}: next_update is not a timezone-aware timestamp")
            rep.authenticated = False
            return False

    if stale(manifest["next_update"], "manifest"):
        bad("STALE", "manifest is past next_update")
    names = [f.get("registry") for f in manifest["files"] if "registry" in f and "dedi_version" not in f]
    if len(names) != len(set(names)):
        bad("DUPLICATE_REGISTRY", "two manifest entries share a registry name")

    manifest_url = f"https://{domain}/.well-known/dedi.index.json"
    for entry in manifest["files"]:
        inline = "dedi_version" in entry
        url = manifest_url if inline else entry["url"]
        label = entry.get("registry", {}).get("name", "inline") if inline else entry.get("registry", "?")
        if inline:
            raw, doc = None, entry
        else:
            raw = files.get(url)
            if raw is None:
                bad("UNREACHABLE", f"{url} could not be read")
                rep.authenticated = False
                continue
            if entry.get("digest") and entry["digest"] != file_digest(raw):
                bad("DIGEST", f"{label}: manifest digest does not match the hosted bytes")
            try:
                doc = json.loads(raw)
            except ValueError:
                bad("SHAPE", f"{label}: not valid JSON")
                rep.authenticated = False
                continue
        shape = shape_errors("dedi-file", doc)
        if shape:
            bad("SHAPE", f"{label}: {shape[0]}")
            rep.authenticated = False
            continue
        key = doc["publisher"]["key"]
        if doc["proof"]["verification_method"] != key["kid"] or not signature_ok(doc, key):
            bad("SIGNATURE", f"{label}: signature does not verify against the embedded publisher key")
            rep.authenticated = False
            continue
        if doc["publisher"]["domain"] != domain or not any(_same_key(key, k) for k in manifest["keys"]):
            bad("NOT_AUTHENTICATED", f"{label}: publisher key is not listed by {domain}'s manifest")
            rep.authenticated = False
        if stale(doc["next_update"], label):
            bad("STALE", f"{label}: file is past next_update")
        if doc["registry"]["state"] != "live":
            bad("INACTIVE", f"{label}: registry state is {doc['registry']['state']}")
        if doc["source_url"] != url:
            bad("SOURCE_URL", f"{label}: source_url {doc['source_url']!r} is not where it was served ({url})")
        if not inline and entry.get("registry") != doc["registry"]["name"]:
            bad("REGISTRY_NAME", f"{label}: manifest and file disagree on the registry name")
        seen = set()
        kind = None
        sch = doc["registry"]["schema"]
        if isinstance(sch, str):
            kind = _ROLE_KIND.get(sch.rsplit("/", 1)[-1])
        for r in doc["records"]:
            if r["record_name"] in seen:
                bad("DUPLICATE_RECORD", f"{label}: {r['record_name']!r} appears twice")
            seen.add(r["record_name"])
            if kind:
                errs = shape_errors(kind, r["details"])
                if errs:
                    bad("DETAILS_SCHEMA", f"{label}/{r['record_name']}: {errs[0]}")
    return rep


def verify_dir(root, domain, now):
    """Verify a local tree laid out as it would be hosted: <root>/.well-known/dedi.index.json and
    the file paths its URLs name (only URLs on `domain` are read; others are reported)."""
    root = Path(root).resolve()
    try:
        manifest_raw = (root / ".well-known" / "dedi.index.json").read_bytes()
    except OSError:
        rep = Report(authenticated=False)
        rep.problems.append("UNREACHABLE: no .well-known/dedi.index.json under the directory")
        return rep
    files = {}
    try:
        for entry in json.loads(manifest_raw).get("files", []):
            u = urlsplit(entry.get("url", "")) if "url" in entry else None
            if u and u.hostname == domain:
                p = (root / u.path.lstrip("/")).resolve()
                if root in p.parents and p.is_file():
                    files[entry["url"]] = p.read_bytes()
    except (ValueError, AttributeError):
        pass
    return verify_bytes(manifest_raw, files, domain, now)


# ------------------------------------------------------------------ CLI
def _load_seed(path):
    from nacl.signing import SigningKey
    try:
        return SigningKey(base64.b64decode(json.loads(Path(path).read_text(encoding="utf-8"))["private_key_seed_b64"]))
    except (OSError, ValueError, KeyError) as e:
        raise DediError(f"cannot read a private key seed from {path} ({type(e).__name__})") from None


def _now(arg):
    return _parse_ts(arg) if arg else datetime.now(timezone.utc)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="write the signed registry file and manifest")
    b.add_argument("--config", required=True)
    b.add_argument("--identity", required=True, help="identity JSON holding private_key_seed_b64 (never printed)")
    b.add_argument("--out", required=True)
    b.add_argument("--now")
    b.add_argument("--reissue", action="store_true", help="re-issue over --out, keeping updated_at if unchanged")
    b.add_argument("--force", action="store_true")
    v = sub.add_parser("verify", help="verify a local tree laid out as it will be hosted")
    v.add_argument("--dir", required=True)
    v.add_argument("--domain", required=True)
    v.add_argument("--now")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "build":
            cfg = json.loads(Path(a.config).read_text(encoding="utf-8"))
            res = build(cfg, _load_seed(a.identity), a.out, _now(a.now),
                        prev_dir=a.out if a.reissue else None, force=a.force or a.reissue)
            print("registry file:", res["registry"])
            print("manifest:     ", res["manifest"])
            print("digest:       ", res["digest"])
            print("publisher key (public JWK):", json.dumps(res["jwk"]))
            print("Next: host both files at their URLs, then enter the domain on the NFH onboarding portal yourself.")
            return 0
        rep = verify_dir(a.dir, a.domain, _now(a.now))
        for p in rep.problems:
            print(p)
        print("authenticated:", rep.authenticated, "| ok:", rep.ok)
        return 0 if rep.ok else 1
    except (DediError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
