"""IP literal normalization and special-use address denylist shared with tests."""

import ipaddress
import socket


_DENIED_RANGES = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
    "2001::/23", "2001:db8::/32", "2002::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
))


def parse_ip_literal(value: str):
    """Parse standard and legacy inet_aton IPv4 notations without DNS."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        try:
            return ipaddress.IPv4Address(socket.inet_aton(value))
        except OSError:
            return None


def is_public_address(address) -> bool:
    if isinstance(address, str):
        try:
            address = ipaddress.ip_address(address)
        except ValueError:
            return False
    if not address.is_global or address.is_multicast or address.is_unspecified or address.is_reserved:
        return False
    return not any(address.version == network.version and address in network for network in _DENIED_RANGES)
