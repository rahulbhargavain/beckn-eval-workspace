"""Outbound-URL guard for callback / request targets (SSRF defence).

The Beckn spec only says bapUri/bppUri MUST match the registry's subscriber_url
(beckn.yaml Context). Everything here is mockup policy:

* only http/https, no userinfo, explicit host, port != 0;
* allowlist mode: the URL origin must exactly equal a configured origin;
* open mode (allowlist=None): every address the host resolves to must be globally
  routable (no loopback, private, link-local, CGNAT, reserved, multicast, unspecified);
  non-canonical numeric hosts (decimal/octal/hex IPv4) are refused outright.

Known residual risk: httpx resolves the name again when connecting (DNS-rebinding
TOCTOU); see docs/mockup-findings.md.
"""
import ipaddress
import re
import socket
from urllib.parse import urlsplit


class UnsafeURL(ValueError):
    pass


_DEFAULT_PORTS = {"http": 80, "https": 443}
_NUMERICISH = re.compile(r"^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$", re.I)


def _origin(url):
    p = urlsplit(url)
    scheme = (p.scheme or "").lower()
    if scheme not in _DEFAULT_PORTS:
        raise UnsafeURL(f"scheme not allowed: {scheme!r}")
    if p.username is not None or p.password is not None or "@" in p.netloc:
        raise UnsafeURL("userinfo not allowed")
    host = p.hostname
    if not host:
        raise UnsafeURL("missing host")
    try:
        port = p.port
    except ValueError as e:
        raise UnsafeURL(f"bad port: {e}") from None
    port = port if port is not None else _DEFAULT_PORTS[scheme]
    if port == 0:
        raise UnsafeURL("port 0")
    return scheme, host.lower().rstrip("."), port


def default_resolver(host):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror as e:
        raise UnsafeURL(f"cannot resolve {host}: {e}") from None


def _is_public(addr):
    ip = ipaddress.ip_address(addr.split("%")[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_url(url, allowlist=None, resolver=default_resolver):
    """Raise UnsafeURL unless `url` is an acceptable outbound target. Returns the
    list of vetted addresses in open mode, [] in allowlist mode."""
    scheme, host, port = _origin(url)
    if allowlist is not None:
        allowed = {_origin(a) for a in allowlist}
        if (scheme, host, port) not in allowed:
            raise UnsafeURL(f"origin not allowlisted: {scheme}://{host}:{port}")
        return []
    try:
        addrs = [str(ipaddress.ip_address(host))]
    except ValueError:
        if _NUMERICISH.match(host):
            raise UnsafeURL(f"non-canonical numeric host: {host}") from None
        addrs = resolver(host)
    if not addrs:
        raise UnsafeURL("no addresses")
    bad = [a for a in addrs if not _is_public(a)]
    if bad:
        raise UnsafeURL(f"non-public address(es) {bad} for {host}")
    return addrs
