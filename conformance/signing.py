"""Beckn 2.0.0 HTTP Signature for the harness (docs/Authentication_and_Trust.md).

Independent of the mockup on purpose: the harness must not trust the code it tests.
PyNaCl is imported lazily so unsigned scenarios work without it.
"""
import base64
import hashlib
import time


def _digest(raw: bytes) -> str:
    return "BLAKE2b-512=" + base64.b64encode(hashlib.blake2b(raw, digest_size=64).digest()).decode()


def authorization(identity: dict, raw: bytes, now=None, ttl=60) -> str:
    from nacl.signing import SigningKey  # lazy: only signed scenarios need it
    created = int(now if now is not None else time.time())
    expires = created + ttl
    text = f"(created): {created}\n(expires): {expires}\ndigest: {_digest(raw)}"
    key = SigningKey(base64.b64decode(identity["private_key_seed_b64"]))
    sig = base64.b64encode(key.sign(text.encode()).signature).decode()
    return (f'Signature keyId="{identity["key_id"]}",algorithm="ed25519",created="{created}",'
            f'expires="{expires}",headers="(created) (expires) digest",signature="{sig}"')


# ---------------------------------------------------------------- verifying the SUT's response
import re  # noqa: E402

RESPONSE_HEADERS = "(created) (expires) digest request-signature"
RESPONSE_SKEW = 5  # seconds of clock difference tolerated on `created`; `expires` gets none
_RESPONSE_RE = re.compile(
    r'^(?:Signature )?keyId="(?P<keyId>[^"]+)",algorithm="(?P<algorithm>[^"]+)",created="(?P<created>\d+)",'
    r'expires="(?P<expires>\d+)",headers="(?P<headers>[^"]+)",signature="(?P<signature>[A-Za-z0-9+/]+=*)"$')


class ResponseSignatureError(ValueError):
    pass


def _verify_chain(raw_header, body, request_signature, trusted_keys, now):
    """Shared by response and callback checks: a chained 4-line signature over `body`."""
    from nacl.signing import VerifyKey
    now = int(time.time()) if now is None else now
    m = _RESPONSE_RE.match((raw_header or "").strip())
    if not m:
        raise ResponseSignatureError("unparseable Signature header")
    a = m.groupdict()
    if a["algorithm"] != "ed25519":
        raise ResponseSignatureError(f"algorithm must be ed25519, got {a['algorithm']!r}")
    if a["headers"] != RESPONSE_HEADERS:
        raise ResponseSignatureError(f"headers must be {RESPONSE_HEADERS!r}, got {a['headers']!r}")
    pub = (trusted_keys or {}).get(a["keyId"])
    if pub is None:
        raise ResponseSignatureError(
            f"no trusted key for keyId {a['keyId']!r}; supply it with --sut-key KEYID=BASE64_PUBLIC_KEY")
    created, expires = int(a["created"]), int(a["expires"])
    if expires <= created:
        raise ResponseSignatureError("expires must be after created")
    if created > now + RESPONSE_SKEW:
        raise ResponseSignatureError("created is in the future")
    if expires < now:  # skew is tolerated on `created` only (NFH-007)
        raise ResponseSignatureError("signature expired")
    if not request_signature:
        raise ResponseSignatureError("the request carried no signature to chain to")
    text = (f"(created): {created}\n(expires): {expires}\ndigest: {_digest(body)}\n"
            f"request-signature: {request_signature}")
    try:
        key = VerifyKey(base64.b64decode(pub, validate=True))
        key.verify(text.encode(), base64.b64decode(a["signature"], validate=True))
    except Exception:  # noqa: BLE001 - bad key, bad length or bad signature all mean "does not verify"
        raise ResponseSignatureError(
            "signature does not verify (digest of the body, times, or request-signature differ, "
            "or the key is wrong)") from None
    return a["keyId"]


def signature_of(authorization):
    """The `signature` attribute of an Authorization header the harness sent, or None."""
    m = re.search(r'signature="([^"]+)"', authorization or "")
    return m.group(1) if m else None


def check_response(headers, body, sent_authorization, trusted_keys, now=None):
    """Verify a synchronous response's `Signature` header (NFH-007 sections 3.4 and 5, CON-004-23).

    `headers` has lower-cased names; `trusted_keys` maps keyId to a base64 Ed25519 public key supplied
    by the operator. A keyId in the response is never resolved over the network here: that would be a
    pre-authentication fetch to an attacker-chosen URL. Returns the keyId, raises ResponseSignatureError.
    Both header spellings are accepted (with and without the 'Signature ' scheme), because the spec's
    prose and its OpenAPI pattern disagree.
    """
    raw = headers.get("signature")
    if not raw:
        raise ResponseSignatureError("missing Signature response header")
    if not _RESPONSE_RE.match(raw.strip()):
        raise ResponseSignatureError("unparseable Signature response header")
    chained = signature_of(sent_authorization)
    if not chained:
        # keep the historic order of checks: key and header problems are reported before this one
        _verify_chain(raw, body, None, trusted_keys, now)
    return _verify_chain(raw, body, chained, trusted_keys, now)


def check_callback(authorization, body, request_signature, trusted_keys, now=None):
    """Verify an inbound `on_*` callback's Authorization header, chained to `request_signature`
    (the signature the harness sent on the request it answers). Same trust rules as check_response."""
    if not authorization:
        raise ResponseSignatureError("missing Authorization header")
    return _verify_chain(authorization, body, request_signature, trusted_keys, now)
