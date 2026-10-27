"""mitmproxy addon: resolve, validate, then pin every upstream TCP connection."""

import ipaddress
import re
import socket
from urllib.parse import urlsplit

try:
    from .network_policy import is_public_address, parse_ip_literal
except ImportError:  # Script loaded directly by mitmdump inside its container.
    from network_policy import is_public_address, parse_ip_literal


_DENIED_SUFFIXES = (".localhost", ".local", ".internal", ".test", ".invalid", ".example")


class DestinationDenied(ValueError):
    pass


def _normalized_host(host: str) -> str:
    value = host.strip().rstrip(".").lower()
    if not value or any(ch in value for ch in "\\/%?#@[]"):
        raise DestinationDenied("invalid host")
    literal = parse_ip_literal(value)
    if literal is not None:
        return literal.compressed
    try:
        normalized = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise DestinationDenied("invalid hostname") from None
    if ("." not in normalized or normalized.endswith(_DENIED_SUFFIXES)
            or len(normalized) > 253
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in normalized.split("."))):
        raise DestinationDenied("non-public hostname")
    return normalized


def _public_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = parse_ip_literal(value)
    if address is None:
        raise DestinationDenied("invalid resolved address") from None
    if not is_public_address(address):
        raise DestinationDenied("non-public resolved address")
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        if not address.ipv4_mapped.is_global:
            raise DestinationDenied("non-public mapped address")
    return address


def pin_public_destination(host: str, port: int, resolver=socket.getaddrinfo) -> tuple[str, int, str]:
    """Return one pinned public IP after validating every A/AAAA answer."""
    if port not in (80, 443):
        raise DestinationDenied("port is not allowed")
    normalized = _normalized_host(host)
    literal = parse_ip_literal(normalized)
    if literal is None:
        try:
            answers = resolver(normalized, port, type=socket.SOCK_STREAM)
        except OSError:
            raise DestinationDenied("DNS resolution failed") from None
        addresses = list(dict.fromkeys(answer[4][0] for answer in answers))
        if not addresses:
            raise DestinationDenied("DNS returned no address")
        validated = [_public_address(address) for address in addresses]
    else:
        validated = [_public_address(str(literal))]
    return str(validated[0]), port, normalized


def _parse_connect_host(value: str) -> tuple[str, int]:
    try:
        parsed = urlsplit("//" + value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise DestinationDenied("invalid CONNECT authority") from None
    if not host or parsed.path or parsed.query or parsed.fragment:
        raise DestinationDenied("invalid CONNECT authority")
    if port is None:
        port = 443
    if port not in (80, 443):
        raise DestinationDenied("port is not allowed")
    return host, port


class EgressFilter:
    """No flow data is logged; upstream hostnames are checked at connect time."""

    def http_connect(self, flow):
        try:
            host, port = _parse_connect_host(flow.request.host_header)
            pin_public_destination(host, port)
        except (DestinationDenied, AttributeError, TypeError, ValueError):
            flow.response = __import__("mitmproxy.http", fromlist=["Response"]).Response.make(403, b"Destination blocked")

    def request(self, flow):
        try:
            parsed = urlsplit(flow.request.url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if parsed.scheme not in ("http", "https") or not host:
                raise DestinationDenied("scheme is not allowed")
            pin_public_destination(host, port)
        except (DestinationDenied, ValueError, TypeError, AttributeError):
            flow.response = __import__("mitmproxy.http", fromlist=["Response"]).Response.make(403, b"Destination blocked")

    def server_connect(self, data):
        address = data.server.address
        if not address:
            data.server.error = "destination unavailable"
            return
        host, port = address
        try:
            pinned_ip, pinned_port, original_host = pin_public_destination(host, port)
        except (DestinationDenied, ValueError, TypeError, AttributeError):
            data.server.error = "destination blocked"
            return
        data.server.address = (pinned_ip, pinned_port)
        # Preserve TLS certificate validation/SNI for the requested hostname.
        if not _is_ip(original_host):
            data.server.sni = original_host


def _is_ip(host: str) -> bool:
    return parse_ip_literal(host) is not None


addons = [EgressFilter()]
