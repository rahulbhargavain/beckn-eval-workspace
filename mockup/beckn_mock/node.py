"""Shared network-participant machinery: identities, key resolution, inbound signature
verification, envelope checks, replay cache and signed synchronous responses."""
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI
from fastapi.responses import Response

from . import signing, spec, urlguard

NIL_UUID = "00000000-0000-0000-0000-000000000000"
VERSION = "2.0.0"


@dataclass(frozen=True)
class Identity:
    subscriber_id: str
    key_id: str
    keypair: signing.Keypair
    url: str
    role: str

    def with_keypair(self, kp):
        return replace(self, keypair=kp)

    def with_key_id(self, key_id):
        return replace(self, key_id=key_id)


class Reject(Exception):
    def __init__(self, http_status, code, message, message_id=None):
        super().__init__(f"{http_status} {code}: {message}")
        self.http_status, self.code, self.message, self.message_id = http_status, code, message, message_id


@dataclass
class Verified:
    attrs: dict            # parsed Authorization attributes
    key: dict              # registry key record
    chained: bool


def now_ts():
    return int(time.time())


def iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def dumps(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


_DUR = re.compile(r"^P(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$")


def parse_duration(value):
    """Minimal ISO 8601 duration parser (stdlib has none); years/months are rejected
    because they have no fixed length."""
    m = _DUR.match(value or "")
    if not m or value in ("P", "PT"):
        raise ValueError(f"unsupported ISO 8601 duration: {value!r}")
    w, d, h, mi, s = m.groups()
    return timedelta(weeks=int(w or 0), days=int(d or 0), hours=int(h or 0),
                     minutes=int(mi or 0), seconds=float(s or 0))


MAX_BODY_BYTES = 1_048_576  # request bodies are capped before any hashing or parsing
_KEY_SEG = re.compile(r"^[A-Za-z0-9._:@-]+$")


async def read_body(request) -> bytes:
    """Read a request body, refusing more than MAX_BODY_BYTES (pre-authentication, so keep it cheap)."""
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        raise Reject(400, "SCH_INVALID_JSON", f"body larger than {MAX_BODY_BYTES} bytes")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > MAX_BODY_BYTES:
            raise Reject(400, "SCH_INVALID_JSON", f"body larger than {MAX_BODY_BYTES} bytes")
    return bytes(buf)


class Node:
    """Base for BAP/BPP. `trusted_registries` are URL prefixes for explicit keyIds."""

    clock_skew = 5          # NFH-007 §7 step 2 default
    signature_ttl = 60      # lifetime of signatures we produce

    def __init__(self, identity: Identity, registry_url: str, network_id: str, trusted_registries=()):
        self.identity = identity
        self.registry_url = registry_url.rstrip("/")
        self.network_id = network_id
        self.trusted_registries = [t.rstrip("/") + "/" for t in trusted_registries]
        self.app = FastAPI(title=identity.subscriber_id, openapi_url=None, docs_url=None, redoc_url=None)
        self._lock = threading.RLock()
        self._seen = {}     # (sender, messageId) -> {"sig": str, "until": ts}
        self.errors = []
        # Shared clients: creating an httpx client loads the CA bundle (~0.25 s on Windows).
        self.http = httpx.Client(timeout=5, follow_redirects=False)
        self._ahttp = None

    @property
    def ahttp(self):
        if self._ahttp is None:  # created lazily inside the server's event loop
            self._ahttp = httpx.AsyncClient(timeout=5, follow_redirects=False)
        return self._ahttp

    def close(self):
        self.http.close()

    @property
    def subscriber_id(self):
        return self.identity.subscriber_id

    # ---------------- registry ----------------
    def _key_url(self, key_id):
        base, sep, alg = key_id.rpartition("|")
        if not sep or alg != "ed25519":
            raise Reject(401, "AUT_SIGNATURE_INVALID", "keyId must end with |ed25519")
        if base.startswith(("http://", "https://")):
            # Explicit keyId (NFH-007 §2.2). Never fetch from untrusted registries: the URL
            # is attacker-supplied and fetched before the request is authenticated.
            if not any(base.startswith(t) for t in self.trusted_registries):
                raise Reject(401, "AUT_KEY_NOT_FOUND", "explicit keyId registry not trusted")
            parts = urlsplit(base)
            segs = parts.path.split("/")[1:]
            if (parts.query or parts.fragment or "@" in parts.netloc or "\\" in base or "%" in parts.path
                    or any(s in ("", ".", "..") for s in segs)):
                raise Reject(401, "AUT_SIGNATURE_INVALID", "explicit keyId URL has an unsafe path, query or fragment")
            return base
        parts = base.split("/")
        if len(parts) != 3 or not all(_KEY_SEG.match(p) and p not in (".", "..") for p in parts):
            raise Reject(401, "AUT_SIGNATURE_INVALID", "implicit keyId must be ns/registry/record of [A-Za-z0-9._:@-]")
        return f"{self.registry_url}/dedi/lookup/{key_id}"

    async def resolve_key(self, key_id):
        url = self._key_url(key_id)
        try:
            r = await self.ahttp.get(url)
        except httpx.HTTPError as e:
            raise Reject(401, "AUT_KEY_NOT_FOUND", f"registry unreachable: {e}") from None
        if r.status_code != 200:
            raise Reject(401, "AUT_KEY_NOT_FOUND", "key not found in registry")
        rec = r.json()
        if rec.get("algorithm") != "ed25519" or not rec.get("publicKey"):
            raise Reject(401, "AUT_KEY_NOT_FOUND", "registry record has no ed25519 key")
        return rec

    def lookup_subscriber_sync(self, subscriber_id):
        r = self.http.get(f"{self.registry_url}/subscribers",
                          params={"networkId": self.network_id, "subscriberId": subscriber_id})
        return r.json() if r.status_code == 200 else None

    async def lookup_subscriber(self, subscriber_id):
        r = await self.ahttp.get(f"{self.registry_url}/subscribers",
                                 params={"networkId": self.network_id, "subscriberId": subscriber_id})
        return r.json() if r.status_code == 200 else None

    def resolve_key_sync(self, key_id):
        r = self.http.get(self._key_url(key_id))
        return r.json() if r.status_code == 200 else None

    # ---------------- verification ----------------
    def check_attrs(self, attrs, allowed_headers, now):
        """Algorithm, declared headers and time window of a parsed Signature (shared by requests, callbacks, Acks)."""
        if attrs["algorithm"] != "ed25519":
            raise Reject(401, "AUT_SIGNATURE_INVALID", "algorithm must be ed25519")
        if attrs["headers"] not in allowed_headers:
            raise Reject(401, "AUT_SIGNATURE_INVALID", f"unexpected headers list {attrs['headers']!r}")
        created, expires = int(attrs["created"]), int(attrs["expires"])
        if expires <= created:
            raise Reject(401, "AUT_SIGNATURE_INVALID", "expires must be greater than created")
        if created > now + self.clock_skew:
            raise Reject(401, "AUT_SIGNATURE_INVALID", "created is in the future")
        if expires < now:
            raise Reject(401, "AUT_SIGNATURE_INVALID", "signature expired")

    @staticmethod
    def check_key(key, expires, now):
        if key.get("status") != "ACTIVE" or int(key.get("validUntil", 0)) < now:
            raise Reject(401, "AUT_KEY_EXPIRED_OR_REVOKED", "signing key revoked or expired")
        if expires > int(key["validUntil"]):
            raise Reject(401, "AUT_SIGNATURE_INVALID", "expires exceeds key registration (CON-004-07)")

    async def verify_signature(self, raw: bytes, auth: str | None, allowed_headers,
                               request_signature_for=None) -> Verified:
        """NFH-007 §7 / §8. `request_signature_for(attrs)` returns the CN's own stored
        signature for chained callbacks (the value is not transmitted on the wire)."""
        if not auth:
            raise Reject(401, "AUT_SIGNATURE_MISSING", "Authorization header missing")
        try:
            attrs = signing.parse_authorization(auth)
        except signing.SignatureError:
            raise Reject(401, "AUT_SIGNATURE_INVALID", "malformed Authorization header") from None
        if not auth.startswith("Signature "):
            raise Reject(401, "AUT_SIGNATURE_INVALID", "Authorization scheme must be 'Signature'")
        now = now_ts()
        self.check_attrs(attrs, allowed_headers, now)
        key = await self.resolve_key(attrs["keyId"])
        self.check_key(key, int(attrs["expires"]), now)
        created, expires = int(attrs["created"]), int(attrs["expires"])
        chained = attrs["headers"] == signing.CHAIN_HEADERS
        req_sig = request_signature_for(attrs) if chained else None
        if chained and req_sig is None:
            raise Reject(401, "AUT_SIGNATURE_INVALID", "no outbound request matches this callback")
        text = signing.signing_string(created, expires, signing.body_digest(raw), req_sig)
        if not signing.verify(key["publicKey"], text, attrs["signature"]):
            raise Reject(401, "AUT_SIGNATURE_INVALID", "signature verification failed")
        return Verified(attrs, key, chained)

    def parse_body(self, raw: bytes):
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):  # deep nesting is hostile input, not a crash
            raise Reject(400, "SCH_INVALID_JSON", "body is not valid UTF-8 JSON") from None
        if not isinstance(body, dict):
            raise Reject(400, "SCH_INVALID_JSON", "body must be a JSON object")
        return body

    def validate(self, path, body, sender_field):
        mid = _message_id(body)
        errs = spec.request_errors(path, body)
        if errs:
            raise Reject(400, "SCH_SCHEMA_VALIDATION_FAILED", "; ".join(errs[:5]), mid)
        ctx = body["context"]
        for f in ("action", "version", "transactionId", "messageId", sender_field):
            if f not in ctx:
                raise Reject(400, "CTX_MISSING_FIELD", f"context.{f} is required", mid)
        if ctx.get("networkId") not in (None, self.network_id):
            raise Reject(400, "CTX_INVALID_FIELD", "unknown networkId", mid)
        if "ttl" in ctx:
            try:
                ttl = parse_duration(ctx["ttl"])
            except ValueError as e:
                raise Reject(400, "CTX_INVALID_FIELD", str(e), mid) from None
            if "timestamp" in ctx:
                ts = datetime.fromisoformat(ctx["timestamp"].replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > ts + ttl:
                    raise Reject(400, "CTX_TTL_EXPIRED", "timestamp + ttl has elapsed", mid)
        return ctx

    def check_replay(self, sender, message_id, signature, expires):
        """Returns silently if new; raises on duplicates. Entries are kept at least until
        the signature can no longer be accepted (expires + skew)."""
        now = now_ts()
        with self._lock:
            for k in [k for k, v in self._seen.items() if v["until"] < now]:
                del self._seen[k]
            prev = self._seen.get((sender, message_id))
            if prev:
                if prev["sig"] == signature:
                    raise Reject(400, "AUT_REPLAY_DETECTED", "replayed message", message_id)
                raise Reject(400, "CTX_MESSAGE_ID_DUPLICATE", "messageId already used", message_id)
            self._seen[(sender, message_id)] = {"sig": signature, "until": int(expires) + self.clock_skew}

    # ---------------- responses ----------------
    def sign_response(self, raw: bytes, request_signature: str) -> str:
        now = now_ts()
        return signing.sign_message(self.identity.keypair, self.identity.key_id, raw, now,
                                    now + self.signature_ttl, request_signature=request_signature)

    def respond(self, http_status, body, request_signature):
        raw = dumps(body)
        return Response(content=raw, status_code=http_status, media_type="application/json",
                        headers={"Signature": self.sign_response(raw, request_signature or "")})

    def ack(self, message_id, request_signature, http_status=200, error=None):
        msg = {"status": "ACK", "messageId": message_id}
        if error:
            msg["error"] = error
        return self.respond(http_status, {"message": msg}, request_signature)

    def nack(self, rej: Reject, message_id, request_signature):
        mid = rej.message_id or message_id or NIL_UUID
        try:
            uuid.UUID(mid)
        except (ValueError, TypeError, AttributeError):
            mid = NIL_UUID
        body = {"message": {"status": "NACK", "messageId": mid,
                            "error": {"code": rej.code, "message": rej.message}}}
        return self.respond(rej.http_status, body, request_signature)


def _message_id(body):
    ctx = body.get("context") if isinstance(body, dict) else None
    mid = ctx.get("messageId") if isinstance(ctx, dict) else None
    return mid if isinstance(mid, str) else None


def raw_signature(auth):
    try:
        return signing.parse_authorization(auth)["signature"]
    except signing.SignatureError:
        return ""


def same_url(a, b):
    return isinstance(a, str) and isinstance(b, str) and a.rstrip("/") == b.rstrip("/")


def check_target(url, allowlist):
    urlguard.check_url(url, allowlist=allowlist)
