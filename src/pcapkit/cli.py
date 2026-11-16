"""Command line interface for pcapkit.

Exit codes: 0 for success, 1 for a runtime failure (unreadable or malformed
capture) and 2 for bad command-line usage, which argparse produces itself.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import analyze
from .decode import describe_packet
from .demo import write_demo_capture
from .errors import PcapError
from .reader import read_capture
from .report import render_html, render_markdown, render_text
from .util import (
    format_bit_rate,
    format_bytes,
    format_count,
    format_duration,
    format_packet_rate,
    format_timestamp,
    iso_timestamp,
)
from .version import __version__

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1

FORMAT_EXTENSIONS = {"html": "report.html", "text": "report.txt", "markdown": "report.md"}


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse command tree."""
    parser = argparse.ArgumentParser(
        prog="pcapkit",
        description=(
            "Zero-dependency packet capture analyzer for classic pcap and pcapng "
            "files. Decodes Ethernet, VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, "
            "ICMPv6 and DNS, then aggregates flows and renders reports."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"pcapkit {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    demo_parser = subparsers.add_parser(
        "demo",
        help="generate a synthetic demo capture",
        description=(
            "Generate a deterministic synthetic capture with ARP, DNS, HTTP, "
            "ICMP, ICMPv6, VLAN and QinQ traffic so the tool can be tried "
            "without an existing pcap file."
        ),
    )
    demo_parser.add_argument(
        "-o",
        "--output",
        default="demo.pcap",
        metavar="PATH",
        help="output capture path (default: demo.pcap)",
    )
    demo_parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite the output file when it already exists",
    )
    demo_parser.set_defaults(handler=_handle_demo)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="print a packet-by-packet view of a capture",
        description=(
            "Decode every packet and print the capture metadata, a one-line "
            "summary per packet and aggregate capture statistics."
        ),
    )
    inspect_parser.add_argument("file", metavar="FILE", help="pcap or pcapng capture")
    inspect_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="print machine-readable JSON instead of text",
    )
    inspect_parser.add_argument(
        "--limit",
        type=_non_negative_int,
        default=30,
        metavar="N",
        help="maximum number of packets to list; 0 lists all (default: 30)",
    )
    inspect_parser.set_defaults(handler=_handle_inspect)

    flows_parser = subparsers.add_parser(
        "flows",
        help="aggregate conversations, talkers and protocol distribution",
        description=(
            "Aggregate decoded packets into bidirectional 5-tuple flows and "
            "print the busiest conversations, top talkers and protocol mix."
        ),
    )
    flows_parser.add_argument("file", metavar="FILE", help="pcap or pcapng capture")
    flows_parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="print machine-readable JSON instead of text",
    )
    flows_parser.add_argument(
        "--top",
        type=_non_negative_int,
        default=10,
        metavar="N",
        help="entries to show in each table; 0 shows all (default: 10)",
    )
    flows_parser.set_defaults(handler=_handle_flows)

    report_parser = subparsers.add_parser(
        "report",
        help="render a standalone report from a capture",
        description=(
            "Render a self-contained HTML report with inline SVG charts and "
            "tables, or a plain-text/Markdown summary."
        ),
    )
    report_parser.add_argument("file", metavar="FILE", help="pcap or pcapng capture")
    report_parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="PATH",
        help="output path (default: report.html / report.txt / report.md)",
    )
    report_parser.add_argument(
        "--format",
        choices=sorted(FORMAT_EXTENSIONS),
        default="html",
        help="output format (default: html)",
    )
    report_parser.add_argument(
        "--top",
        type=_non_negative_int,
        default=10,
        metavar="N",
        help="entries to show in each table; 0 shows all (default: 10)",
    )
    report_parser.set_defaults(handler=_handle_report)
    return parser


def _non_negative_int(text: str) -> int:
    """Argparse type for a non-negative integer."""
    try:
        value = int(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r} is not an integer") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("value must be zero or greater")
    return value


def _load_analysis(path: str):
    """Read a capture and analyse it, converting failures into PcapError."""
    capture = read_capture(path)
    return analyze(capture)


def _handle_demo(args: argparse.Namespace) -> int:
    output = Path(args.output)
    if output.exists() and not args.force:
        raise PcapError(
            f"{output} already exists; pass --force to overwrite it"
        )
    capture = write_demo_capture(str(output))
    analysis = analyze(capture)
    summary = analysis.summary
    protocols = ", ".join(
        f"{label} {count}" for label, count in analysis.protocol_distribution()
    )
    print(
        f"Created {output} with {format_count(summary.packets)} packets "
        f"({format_bytes(summary.captured_bytes)} captured)."
    )
    print(f"Protocols: {protocols}")
    print("Next steps:")
    print(f"  pcapkit inspect {output}")
    print(f"  pcapkit flows {output}")
    print(f"  pcapkit report {output} -o report.html")
    return EXIT_OK


def _handle_inspect(args: argparse.Namespace) -> int:
    analysis = _load_analysis(args.file)
    capture = analysis.capture
    summary = analysis.summary
    if args.as_json:
        payload = {
            "generator": f"pcapkit {__version__}",
            "capture": capture.to_dict(),
            "summary": summary.to_dict(),
            "packets": analysis.packet_summaries(args.limit),
        }
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    print(f"Source: {capture.source}")
    print(
        f"Format: {capture.format} {capture.version} ({capture.byte_order}-endian), "
        f"link type {capture.linktype_display}, snaplen {format_count(capture.snaplen)}"
    )
    print(
        f"Packets: {format_count(summary.packets)} "
        f"({format_count(summary.truncated_packets)} truncated, "
        f"{format_count(summary.packets_with_errors)} with decode errors, "
        f"{format_count(len(capture.warnings))} capture warning(s))"
    )
    print(
        "Time span: "
        + (
            f"{format_timestamp(summary.first_timestamp_ns)} to "
            f"{format_timestamp(summary.last_timestamp_ns)} "
            f"({format_duration(summary.duration_ns)})"
            if summary.first_timestamp_ns is not None
            and summary.last_timestamp_ns is not None
            else "no packets"
        )
    )
    print(
        f"Average rate: {format_packet_rate(summary.packets_per_second)}, "
        f"{format_bit_rate(summary.bits_per_second)}"
    )
    print()
    decoded = analysis.decoded
    selected = decoded if args.limit == 0 else decoded[: args.limit]
    if not decoded:
        print("No packets to display.")
    else:
        print(f"  {'#':>3}  {'Timestamp (UTC)':<26} {'Length':>6}  Summary")
        for packet in selected:
            print(
                f"  {packet.index:>3}  {iso_timestamp(packet.timestamp_ns):<26} "
                f"{packet.captured_length:>6}  {describe_packet(packet)}"
            )
        hidden = len(decoded) - len(selected)
        if hidden > 0:
            print(
                f"  ... {format_count(hidden)} more packet(s); "
                "use --limit 0 to list them all"
            )
    print()
    print(
        "Protocols: "
        + ", ".join(
            f"{label} {count}" for label, count in analysis.protocol_distribution()
        )
    )
    print(
        "Top talkers: "
        + ", ".join(
            f"{talker.address} ({format_bytes(talker.bytes_total)})"
            for talker in analysis.top_talkers(5)
        )
    )
    return EXIT_OK


def _handle_flows(args: argparse.Namespace) -> int:
    analysis = _load_analysis(args.file)
    capture = analysis.capture
    summary = analysis.summary
    if args.as_json:
        payload = {
            "generator": f"pcapkit {__version__}",
            "capture": capture.to_dict(),
            "summary": summary.to_dict(),
            "protocols": [
                {"protocol": label, "packets": count}
                for label, count in analysis.protocol_distribution()
            ],
            "flows": [flow.to_dict() for flow in analysis.flows],
            "talkers": [talker.to_dict() for talker in analysis.top_talkers(args.top)],
        }
        print(json.dumps(payload, indent=2))
        return EXIT_OK

    print(f"Source: {capture.source} ({capture.format}, {capture.linktype_display})")
    print(
        f"Packets: {format_count(summary.packets)}, "
        f"bytes: {format_count(summary.captured_bytes)}, "
        f"duration: {format_duration(summary.duration_ns)}, "
        f"flows: {format_count(summary.flow_count)}"
    )
    print(
        "Protocols: "
        + ", ".join(
            f"{label} {count}" for label, count in analysis.protocol_distribution()
        )
    )
    print()
    flows = analysis.top_flows(args.top)
    print(f"Top conversations ({format_count(len(flows))} shown, sorted by bytes)")
    print(
        f"{'Protocol':<10}{'Initiator':<28}{'Responder':<28}"
        f"{'Packets':>8}{'Bytes':>10}{'Duration':>12}"
    )
    print("-" * 96)
    for flow in flows:
        print(
            f"{flow.protocol:<10}{flow.initiator:<28}{flow.responder:<28}"
            f"{format_count(flow.packets):>8}{format_count(flow.bytes):>10}"
            f"{format_duration(flow.duration_ns):>12}"
        )
    print()
    talkers = analysis.top_talkers(args.top)
    print(f"Top talkers ({format_count(len(talkers))} shown, sorted by bytes)")
    print(
        f"{'Address':<40}{'Packets':>8}{'Sent':>14}{'Received':>14}{'Total':>14}"
    )
    print("-" * 90)
    for talker in talkers:
        print(
            f"{talker.address:<40}{format_count(talker.packets):>8}"
            f"{format_bytes(talker.bytes_sent):>14}"
            f"{format_bytes(talker.bytes_received):>14}"
            f"{format_bytes(talker.bytes_total):>14}"
        )
    return EXIT_OK


def _handle_report(args: argparse.Namespace) -> int:
    analysis = _load_analysis(args.file)
    output = Path(args.output) if args.output else Path(FORMAT_EXTENSIONS[args.format])
    if args.format == "html":
        content = render_html(analysis, top=args.top)
    elif args.format == "markdown":
        content = render_markdown(analysis, top=args.top)
    else:
        content = render_text(analysis, top=args.top)
    try:
        output.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise PcapError(f"cannot write {output}: {exc}") from exc
    summary = analysis.summary
    print(
        f"Wrote {args.format.upper()} report to {output} "
        f"({format_count(summary.packets)} packets, "
        f"{format_count(summary.flow_count)} conversations, "
        f"{format_count(len(content))} bytes)"
    )
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Entry point used by both ``python -m pcapkit`` and the console script."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except PcapError as exc:
        print(f"pcapkit: error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR
    except OSError as exc:
        print(f"pcapkit: error: {exc}", file=sys.stderr)
        return EXIT_RUNTIME_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
