"""Shared fixtures for the Beckn v2.0.0 mockup tests.

Every test gets a fresh in-process network: a mock registry, one BPP (which also
acts as the Discovery Service for its own catalog, see docs/mockup-findings.md),
and one BAP. All servers are uvicorn instances bound to 127.0.0.1 on ephemeral
ports, started in background threads and stopped at teardown.
"""
import pytest

from beckn_mock.network import MockNetwork


@pytest.fixture
def net():
    with MockNetwork() as n:
        yield n
        # Internal failures (e.g. a callback that would violate the on_* schema) are
        # recorded rather than raised inside the server; surface them here.
        assert n.bpp.errors == [], n.bpp.errors


@pytest.fixture
def open_net():
    """Network whose BPP runs in 'open' callback mode: no explicit allowlist, so the
    SSRF guard falls back to rejecting private / loopback / link-local targets.
    The real BAP lives on 127.0.0.1, so only negative tests make sense here."""
    with MockNetwork(callback_allowlist=None) as n:
        yield n
