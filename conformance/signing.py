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
