"""Beckn HTTP Signature primitives (docs/Authentication_and_Trust.md, NFH-007).

Ed25519 via PyNaCl; BLAKE2b-512 via hashlib (stdlib supports 64-byte digests).
"""
import base64
import hashlib
import re
from dataclasses import dataclass

import nacl.exceptions
import nacl.signing

DIGEST_PREFIX = "BLAKE2b-512="          # NFH-007 §3.1
REQUEST_DIGEST_PREFIX = "BLAKE-512="    # beckn.yaml RequestDigest.digest pattern (differs!)
STD_HEADERS = "(created) (expires) digest"
CHAIN_HEADERS = "(created) (expires) digest request-signature"

_HEADER_RE = re.compile(
    r'^(?:Signature )?keyId="(?P<keyId>[^"]+)",algorithm="(?P<algorithm>[^"]+)",'
    r'created="(?P<created>\d+)",expires="(?P<expires>\d+)",headers="(?P<headers>[^"]+)",'
    r'signature="(?P<signature>[A-Za-z0-9+/]+=*)"$')


class SignatureError(ValueError):
    pass


def _b2(data: bytes) -> str:
    return base64.b64encode(hashlib.blake2b(data, digest_size=64).digest()).decode()


def body_digest(data: bytes) -> str:
    return DIGEST_PREFIX + _b2(data)


def request_digest(data: bytes) -> str:
    """Value for context.requestDigest.digest (pattern ^BLAKE-512=...)."""
    return REQUEST_DIGEST_PREFIX + _b2(data)


def signing_string(created: int, expires: int, digest: str, request_signature: str | None = None) -> str:
    lines = [f"(created): {created}", f"(expires): {expires}", f"digest: {digest}"]
    if request_signature is not None:
        lines.append(f"request-signature: {request_signature}")
    return "\n".join(lines)


@dataclass(frozen=True)
class Keypair:
    signing_key: nacl.signing.SigningKey

    @classmethod
    def generate(cls):
        return cls(nacl.signing.SigningKey.generate())

    @property
    def public_b64(self) -> str:
        return base64.b64encode(bytes(self.signing_key.verify_key)).decode()

    def sign(self, text: str) -> str:
        return base64.b64encode(self.signing_key.sign(text.encode("utf-8")).signature).decode()


def verify(public_b64: str, text: str, signature_b64: str) -> bool:
    try:
        key = nacl.signing.VerifyKey(base64.b64decode(public_b64, validate=True))
        key.verify(text.encode("utf-8"), base64.b64decode(signature_b64, validate=True))
        return True
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False


def format_header(key_id: str, created: int, expires: int, signature: str, chained: bool) -> str:
    headers = CHAIN_HEADERS if chained else STD_HEADERS
    return (f'Signature keyId="{key_id}",algorithm="ed25519",created="{created}",'
            f'expires="{expires}",headers="{headers}",signature="{signature}"')


def parse_authorization(value: str | None) -> dict:
    """Strict parse in the attribute order fixed by the beckn.yaml Signature pattern.
    Accepts the 'Signature ' scheme prefix as optional because NFH-007 §5 shows the
    response header without it while the AckSignature pattern requires it."""
    if not value:
        raise SignatureError("missing")
    m = _HEADER_RE.match(value.strip())
    if not m:
        raise SignatureError("unparseable")
    return m.groupdict()


def sign_message(keypair: Keypair, key_id: str, body: bytes, created: int, expires: int,
                 request_signature: str | None = None) -> str:
    s = signing_string(created, expires, body_digest(body), request_signature)
    return format_header(key_id, created, expires, keypair.sign(s), chained=request_signature is not None)
