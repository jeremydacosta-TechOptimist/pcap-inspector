"""Reader for the pcapng capture file format.

Only the blocks needed to recover packets are interpreted: Section Header Block
(SHB), Interface Description Block (IDB) and Enhanced Packet Block (EPB).
Unknown or obsolete blocks are skipped with a warning instead of failing, and
multi-interface captures keep the interface index on every packet.
"""

from __future__ import annotations

import struct
from pathlib import Path

from .errors import PcapError
from .models import Capture, CapturedPacket, InterfaceInfo

BLOCK_SHB = 0x0A0D0D0A
BLOCK_IDB = 0x00000001
BLOCK_PB = 0x00000002
BLOCK_SPB = 0x00000003
BLOCK_EPB = 0x00000006
BYTE_ORDER_MAGIC = 0x1A2B3C4D
SHB_BYTES = b"\x0a\x0d\x0d\x0a"
BLOCK_HEADER_LENGTH = 8
BLOCK_FOOTER_LENGTH = 4
MIN_BLOCK_LENGTH = BLOCK_HEADER_LENGTH + BLOCK_FOOTER_LENGTH

OPTION_ENDOFOPT = 0
IDB_OPTION_NAME = 2
IDB_OPTION_DESCRIPTION = 3
IDB_OPTION_TSRESOL = 9
IDB_OPTION_TSOFFSET = 14


def read_pcapng(path: str | Path) -> Capture:
    """Read a pcapng file from disk."""
    source = Path(path).name
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise PcapError(f"cannot read {source}: {exc}") from exc
    return parse_pcapng(data, source=source)


def parse_pcapng(data: bytes, source: str = "<memory>") -> Capture:
    """Parse pcapng bytes into a :class:`Capture`."""
    if len(data) < MIN_BLOCK_LENGTH + 16:
        raise PcapError(f"{source}: file is too short for a pcapng section header block")

    packets: list[CapturedPacket] = []
    warnings: list[str] = []
    all_interfaces: list[InterfaceInfo] = []
    section_interfaces: list[InterfaceInfo] = []
    endian: str | None = None
    byte_order = "little"
    version = "1.0"
    first_section = True
    section_number = 0
    offset = 0

    while offset < len(data):
        remaining = len(data) - offset
        if remaining < BLOCK_HEADER_LENGTH:
            warnings.append(
                f"pcapng: {remaining} trailing byte(s) are too short for a block header"
            )
            break
        if data[offset : offset + 4] == SHB_BYTES:
            if remaining < 28:
                warnings.append("pcapng: truncated section header block")
                break
            byte_order_magic = data[offset + 8 : offset + 12]
            if byte_order_magic == struct.pack("<I", BYTE_ORDER_MAGIC):
                block_endian, block_byte_order = "<", "little"
            elif byte_order_magic == struct.pack(">I", BYTE_ORDER_MAGIC):
                block_endian, block_byte_order = ">", "big"
            else:
                raise PcapError(
                    f"{source}: invalid pcapng section header block "
                    f"(byte-order magic {byte_order_magic.hex()})"
                )
            total_length = struct.unpack(block_endian + "I", data[offset + 4 : offset + 8])[0]
            if not _block_length_ok(data, offset, total_length, warnings, block_endian):
                break
            major, minor = struct.unpack(block_endian + "HH", data[offset + 12 : offset + 16])
            if first_section:
                version = f"{major}.{minor}"
                byte_order = block_byte_order
                first_section = False
            endian = block_endian
            section_interfaces = []
            section_number += 1
            offset += total_length
            continue

        if endian is None:
            raise PcapError(
                f"{source}: pcapng data does not start with a section header block"
            )
        block_type, total_length = struct.unpack(endian + "II", data[offset : offset + 8])
        if not _block_length_ok(data, offset, total_length, warnings, endian):
            break
        body = data[offset + BLOCK_HEADER_LENGTH : offset + total_length - BLOCK_FOOTER_LENGTH]

        if block_type == BLOCK_IDB:
            interface = _parse_interface(body, endian, len(section_interfaces), warnings)
            section_interfaces.append(interface)
            all_interfaces.append(interface)
            if len(all_interfaces) > 1 and len(section_interfaces) == 1:
                warnings.append(
                    "pcapng: capture contains multiple sections; interface indexes restart "
                    "in each section"
                )
        elif block_type == BLOCK_EPB:
            packet = _parse_enhanced_packet(
                body, endian, section_interfaces, warnings, len(packets) + 1
            )
            if packet is not None:
                packets.append(packet)
        elif block_type == BLOCK_SPB:
            warnings.append("pcapng: skipped a Simple Packet Block (not supported)")
        elif block_type == BLOCK_PB:
            warnings.append("pcapng: skipped an obsolete Packet Block (not supported)")
        else:
            warnings.append(
                f"pcapng: skipped block type 0x{block_type:08x} ({total_length} bytes)"
            )
        offset += total_length

    if not all_interfaces:
        warnings.append("pcapng: no interface description block was found")
    linktype = all_interfaces[0].linktype if all_interfaces else 0
    snaplen = all_interfaces[0].snaplen if all_interfaces else 0

    return Capture(
        source=source,
        format="pcapng",
        byte_order=byte_order,
        version=version,
        snaplen=snaplen,
        linktype=linktype,
        packets=packets,
        interfaces=all_interfaces,
        warnings=warnings,
    )


def _block_length_ok(
    data: bytes, offset: int, total_length: int, warnings: list[str], endian: str
) -> bool:
    """Validate a block's total length and trailing length field."""
    remaining = len(data) - offset
    if total_length < MIN_BLOCK_LENGTH or total_length % 4 != 0:
        warnings.append(
            f"pcapng: block at offset {offset} has an invalid total length {total_length}"
        )
        return False
    if total_length > remaining:
        warnings.append(
            f"pcapng: truncated block at offset {offset} "
            f"({remaining} of {total_length} bytes available)"
        )
        return False
    trailing_length = struct.unpack(
        endian + "I", data[offset + total_length - BLOCK_FOOTER_LENGTH : offset + total_length]
    )[0]
    if trailing_length != total_length:
        warnings.append(
            f"pcapng: block at offset {offset} has mismatched length fields "
            f"({total_length} and {trailing_length})"
        )
        return False
    return True


def _parse_options(body: bytes, endian: str) -> dict[int, bytes]:
    """Parse a pcapng option list; later duplicates of a code are ignored."""
    options: dict[int, bytes] = {}
    position = 0
    while position + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[position : position + 4])
        position += 4
        if code == OPTION_ENDOFOPT:
            break
        padded_length = (length + 3) // 4 * 4
        value = body[position : position + length]
        if len(value) < length:
            break
        options.setdefault(code, value)
        position += padded_length
    return options


def _parse_interface(
    body: bytes, endian: str, index: int, warnings: list[str]
) -> InterfaceInfo:
    """Parse an Interface Description Block body."""
    if len(body) < 8:
        warnings.append(f"pcapng: interface {index} description block is truncated")
        return InterfaceInfo(index=index, linktype=1, snaplen=0)
    linktype, _reserved, snaplen = struct.unpack(endian + "HHI", body[:8])
    options = _parse_options(body[8:], endian)
    resolution = 6
    resolution_binary = False
    if IDB_OPTION_TSRESOL in options:
        raw = options[IDB_OPTION_TSRESOL]
        if raw:
            resolution = raw[0] & 0x7F
            resolution_binary = bool(raw[0] & 0x80)
    offset_ns = 0
    if IDB_OPTION_TSOFFSET in options:
        raw_offset = options[IDB_OPTION_TSOFFSET]
        if len(raw_offset) == 8:
            seconds = struct.unpack(endian + "q", raw_offset)[0]
            offset_ns = seconds * 1_000_000_000
    return InterfaceInfo(
        index=index,
        linktype=linktype,
        snaplen=snaplen,
        name=_decode_option_text(options.get(IDB_OPTION_NAME, b"")),
        description=_decode_option_text(options.get(IDB_OPTION_DESCRIPTION, b"")),
        timestamp_resolution=resolution,
        timestamp_resolution_binary=resolution_binary,
        timestamp_offset_ns=offset_ns,
    )


def _decode_option_text(raw: bytes) -> str:
    """Decode an optional UTF-8 pcapng option string, replacing bad bytes."""
    return raw.decode("utf-8", "replace") if raw else ""


def _parse_enhanced_packet(
    body: bytes,
    endian: str,
    interfaces: list[InterfaceInfo],
    warnings: list[str],
    packet_number: int,
) -> CapturedPacket | None:
    """Parse an Enhanced Packet Block body into a captured packet."""
    if len(body) < 20:
        warnings.append(f"pcapng: enhanced packet block {packet_number} is truncated")
        return None
    interface_id, timestamp_high, timestamp_low, captured_length, original_length = struct.unpack(
        endian + "IIIII", body[:20]
    )
    packet_data = body[20 : 20 + captured_length]
    truncated = len(packet_data) < captured_length
    if truncated:
        warnings.append(
            f"pcapng: packet {packet_number} is truncated "
            f"({len(packet_data)} of {captured_length} captured bytes)"
        )
    linktype = 1
    resolution = 6
    resolution_binary = False
    offset_ns = 0
    if interface_id < len(interfaces):
        interface = interfaces[interface_id]
        linktype = interface.linktype
        resolution = interface.timestamp_resolution
        resolution_binary = interface.timestamp_resolution_binary
        offset_ns = interface.timestamp_offset_ns
        if interface.snaplen and captured_length > interface.snaplen:
            warnings.append(
                f"pcapng: packet {packet_number} captured length {captured_length} "
                f"exceeds interface snaplen {interface.snaplen}"
            )
    else:
        warnings.append(
            f"pcapng: packet {packet_number} references unknown interface {interface_id}"
        )
    if original_length < captured_length:
        warnings.append(
            f"pcapng: packet {packet_number} original length {original_length} is "
            f"smaller than its captured length {captured_length}"
        )
    timestamp_units = (timestamp_high << 32) | timestamp_low
    timestamp_ns = _units_to_nanoseconds(
        timestamp_units, resolution, resolution_binary
    ) + offset_ns
    return CapturedPacket(
        timestamp_ns=timestamp_ns,
        data=packet_data,
        original_length=original_length,
        interface_id=interface_id,
        truncated=truncated,
        linktype=linktype,
    )


def _units_to_nanoseconds(units: int, exponent: int, binary: bool) -> int:
    """Convert pcapng timestamp units to nanoseconds for the given resolution."""
    if binary:
        return units * 1_000_000_000 // (1 << exponent)
    if exponent <= 9:
        return units * 10 ** (9 - exponent)
    return units // 10 ** (exponent - 9)
