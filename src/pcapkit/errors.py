"""Exceptions raised by pcapkit.

The readers raise :class:`PcapError` for files that cannot be parsed.  The DNS
decoder raises :class:`DnsDecodeError` for malformed DNS payloads; the packet
decoder catches it and records the problem on the packet instead of aborting.
"""


class PcapError(Exception):
    """Raised when a capture file cannot be read or is not a supported format."""


class DnsDecodeError(ValueError):
    """Raised when a DNS payload is malformed or truncated."""
