"""Reader and writer for the classic libpcap file format.

The reader accepts all four magic numbers (little/big endian, microsecond or
nanosecond timestamps), reports the link type and tolerates truncated or corrupt
records by returning the packets that could be read and listing warnings.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .errors import PcapError
from .models import Capture, CapturedPacket, InterfaceInfo
from .util import LINKTYPE_NAMES

GLOBAL_HEADER_LENGTH = 24
RECORD_HEADER_LENGTH = 16
MAX_RECORD_LENGTH = 16 * 1024 * 1024

# magic bytes -> (byte order, nanosecond timestamps)
PCAP_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xd4\xc3\xb2\xa1": ("little", False),
    b"\xa1\xb2\xc3\xd4": ("big", False),
    b"\x4d\x3c\xb2\xa1": ("little", True),
    b"\xa1\xb2\x3c\x4d": ("big", True),
}


def read_pcap(path: str | Path) -> Capture:
    """Read a classic pcap file from disk."""
    source = Path(path).name
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PcapError(f"cannot read {source}: {exc}") from exc
    return parse_pcap(data, source=source)


def parse_pcap(data: bytes, source: str = "<memory>") -> Capture:
    """Parse classic pcap bytes into a :class:`Capture`."""
    if len(data) < GLOBAL_HEADER_LENGTH:
        raise PcapError(
            f"{source}: file is too short for a pcap global header "
            f"({len(data)} of {GLOBAL_HEADER_LENGTH} bytes)"
        )
    magic = data[:4]
    if magic not in PCAP_MAGICS:
        raise PcapError(f"{source}: unknown pcap magic number {magic.hex()}")
    byte_order, nanosecond = PCAP_MAGICS[magic]
    endian = "<" if byte_order == "little" else ">"
    version_major, version_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(
        endian + "HHiIII", data[4:GLOBAL_HEADER_LENGTH]
    )

    warnings: list[str] = []
    if version_major != 2:
        warnings.append(
            f"pcap: unexpected global header version {version_major}.{version_minor} "
            "(expected 2.4); parsing as classic pcap"
        )
    if snaplen == 0:
        warnings.append("pcap: global header snaplen is zero; record lengths are not validated")
    if linktype not in LINKTYPE_NAMES:
        warnings.append(f"pcap: link type {linktype} is not in the known link type table")
    if linktype != 1:
        warnings.append(
            f"pcap: link type {linktype} ({LINKTYPE_NAMES.get(linktype, 'unknown')}) "
            "is not Ethernet; frames will be reported without protocol decoding"
        )

    timestamp_divisor_ns = 1 if nanosecond else 1000
    fraction_limit = 1_000_000_000 if nanosecond else 1_000_000
    packets: list[CapturedPacket] = []
    offset = GLOBAL_HEADER_LENGTH
    record_number = 0

    while offset < len(data):
        record_number += 1
        remaining = len(data) - offset
        if remaining < RECORD_HEADER_LENGTH:
            warnings.append(
                f"pcap: truncated record header for record {record_number} "
                f"({remaining} of {RECORD_HEADER_LENGTH} bytes)"
            )
            break
        timestamp_seconds, timestamp_fraction, captured_length, original_length = struct.unpack(
            endian + "IIII", data[offset : offset + RECORD_HEADER_LENGTH]
        )
        offset += RECORD_HEADER_LENGTH

        if captured_length > MAX_RECORD_LENGTH:
            warnings.append(
                f"pcap: record {record_number} has a corrupt captured length "
                f"({captured_length} bytes); stopped before reading the payload"
            )
            break
        if snaplen and captured_length > snaplen:
            warnings.append(
                f"pcap: record {record_number} captured length {captured_length} "
                f"exceeds the global snaplen {snaplen}"
            )
        if original_length < captured_length:
            warnings.append(
                f"pcap: record {record_number} original length {original_length} is "
                f"smaller than its captured length {captured_length}"
            )
        if timestamp_fraction >= fraction_limit:
            warnings.append(
                f"pcap: record {record_number} timestamp fraction {timestamp_fraction} "
                "is out of range for the capture format"
            )
        if captured_length == 0:
            warnings.append(f"pcap: record {record_number} contains no packet data")

        available = len(data) - offset
        truncated = available < captured_length
        if truncated:
            warnings.append(
                f"pcap: truncated record {record_number} data "
                f"({available} of {captured_length} bytes)"
            )
            payload = data[offset:]
            offset = len(data)
        else:
            payload = data[offset : offset + captured_length]
            offset += captured_length

        packets.append(
            CapturedPacket(
                timestamp_ns=timestamp_seconds * 1_000_000_000
                + timestamp_fraction * timestamp_divisor_ns,
                data=payload,
                original_length=original_length,
                truncated=truncated,
                linktype=linktype,
            )
        )
        if truncated:
            break

    interface = InterfaceInfo(
        index=0,
        linktype=linktype,
        snaplen=snaplen,
        timestamp_resolution=9 if nanosecond else 6,
    )
    return Capture(
        source=source,
        format="pcap",
        byte_order=byte_order,
        version=f"{version_major}.{version_minor}",
        snaplen=snaplen,
        linktype=linktype,
        packets=packets,
        interfaces=[interface],
        warnings=warnings,
    )


def write_pcap(
    path: str | Path,
    packets: list[CapturedPacket] | tuple[CapturedPacket, ...],
    *,
    linktype: int = 1,
    snaplen: int = 65535,
    nanosecond: bool = False,
    byte_order: str = "little",
) -> int:
    """Write classic pcap bytes and return the number of records written.

    The writer is used by the demo generator and the tests; it always emits
    version 2.4 with an all-zero thiszone and sigfigs field.
    """
    if byte_order not in ("little", "big"):
        raise ValueError("byte_order must be 'little' or 'big'")
    endian = "<" if byte_order == "little" else ">"
    magic = struct.pack(endian + "I", 0xA1B23C4D if nanosecond else 0xA1B2C3D4)

    buffer = bytearray(magic)
    buffer += struct.pack(endian + "HHiIII", 2, 4, 0, 0, snaplen, linktype)
    record_count = 0
    for packet in packets:
        captured_length = len(packet.data)
        if captured_length > 0xFFFFFFFF:  # pragma: no cover - unreachable for real frames
            raise ValueError("packet is too large to store in a pcap file")
        seconds, fraction_ns = divmod(packet.timestamp_ns, 1_000_000_000)
        if seconds < 0:
            raise ValueError("pcap timestamps cannot be negative")
        fraction = fraction_ns if nanosecond else fraction_ns // 1000
        buffer += struct.pack(
            endian + "IIII",
            seconds,
            fraction,
            captured_length,
            packet.original_length,
        )
        buffer += packet.data
        record_count += 1

    try:
        Path(path).write_bytes(bytes(buffer))
    except OSError as exc:
        raise PcapError(f"cannot write {Path(path).name}: {exc}") from exc
    return record_count
