"""Low-level signed HTTP helpers, used by tests to craft (also hostile) requests."""
import time

import httpx

from . import signing
from .node import dumps

_CLIENT = httpx.Client(timeout=10, follow_redirects=False)


def auth_header_for(raw: bytes, identity, created=None, expires=None, request_signature=None):
    created = int(time.time()) if created is None else created
    expires = created + 60 if expires is None else expires
    return signing.sign_message(identity.keypair, identity.key_id, raw, created, expires, request_signature)


def post_raw(url, raw: bytes, auth, extra_headers=None):
    headers = {"Content-Type": "application/json"}
    if auth is not None:
        headers["Authorization"] = auth
    headers.update(extra_headers or {})
    return _CLIENT.post(url, content=raw, headers=headers)


def post_signed(url, body, identity, created=None, expires=None, request_signature=None):
    raw = body if isinstance(body, bytes) else dumps(body)
    return post_raw(url, raw, auth_header_for(raw, identity, created, expires, request_signature))
