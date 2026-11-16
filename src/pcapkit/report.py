"""Render capture analysis as a standalone HTML page or text/markdown summaries.

The HTML report is fully self-contained: styles are inline, the bar charts are
inline SVG generated from the analysis data, and no external asset or script is
referenced.  All dynamic strings are HTML-escaped.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .analysis import CaptureAnalysis
from .models import DecodedPacket
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

CHART_WIDTH = 720
CHART_ROW_HEIGHT = 28
CHART_LABEL_WIDTH = 210
CHART_VALUE_WIDTH = 110
CHART_ACCENT = "#2563eb"

_STYLES = """
:root {
  color-scheme: light;
  --ink: #111827;
  --muted: #6b7280;
  --line: #e5e7eb;
  --panel: #f9fafb;
  --accent: #2563eb;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", system-ui, -apple-system, Arial, sans-serif;
  color: var(--ink);
  background: #ffffff;
  line-height: 1.5;
}
header.page, main, footer { max-width: 1040px; margin: 0 auto; padding: 0 24px; }
header.page { padding-top: 40px; }
h1 { font-size: 1.7rem; margin: 0 0 6px; }
h2 { font-size: 1.2rem; margin: 0 0 14px; }
.subtitle { color: var(--muted); margin: 0 0 8px; }
code { background: var(--panel); border: 1px solid var(--line); border-radius: 4px; padding: 1px 5px; }
section { margin: 34px 0; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 14px; }
.card .label { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.04em; }
.card .value { font-size: 1.15rem; font-weight: 600; margin-top: 3px; overflow-wrap: anywhere; }
table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.92rem; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); }
th { background: var(--panel); font-weight: 600; color: var(--muted); white-space: nowrap; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
tr:last-child td { border-bottom: none; }
.chart { width: 100%; height: auto; display: block; }
.chart-label { font-size: 13px; fill: var(--ink); }
.chart-value { font-size: 13px; fill: var(--muted); font-variant-numeric: tabular-nums; }
.chart-bar:hover { opacity: 0.8; }
.muted { color: var(--muted); }
.empty { color: var(--muted); font-style: italic; }
.legend { color: var(--muted); font-size: 0.85rem; margin: 2px 0 12px; }
.legend span.swatch { display: inline-block; width: 11px; height: 11px; border-radius: 2px; margin-right: 4px; vertical-align: -1px; }
.notes li { margin: 3px 0; }
footer { color: var(--muted); font-size: 0.85rem; padding: 26px 24px 42px; border-top: 1px solid var(--line); margin-top: 40px; }
@media (max-width: 620px) { .cards { grid-template-columns: repeat(2, 1fr); } }
""".strip()


def render_html(
    analysis: CaptureAnalysis, *, title: str | None = None, top: int = 10
) -> str:
    """Render a complete standalone HTML report."""
    capture = analysis.capture
    page_title = title or f"pcapkit capture report - {capture.source}"
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    parts: list[str] = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{html.escape(page_title)}</title>",
        f"<style>{_STYLES}</style>",
        "</head>",
        "<body>",
        '<header class="page">',
        f"<h1>pcapkit capture report</h1>",
        '<p class="subtitle">'
        f"Source: <code>{html.escape(capture.source)}</code> &middot; "
        f"{html.escape(capture.format)} capture &middot; "
        f"generated {html.escape(generated)} by pcapkit {__version__}"
        "</p>",
        "</header>",
        "<main>",
        _html_summary(analysis),
        _html_protocols(analysis, top),
        _html_talkers(analysis, top),
        _html_flows(analysis, top),
    ]
    dns_section = _html_dns(analysis, top)
    if dns_section:
        parts.append(dns_section)
    parts.extend(
        [
            _html_notes(analysis),
            "</main>",
            "<footer>",
            f"<p>Generated locally by pcapkit {__version__}. "
            "Self-contained report: no external assets or scripts.</p>",
            "</footer>",
            "</body>",
            "</html>",
        ]
    )
    return "\n".join(parts) + "\n"


def _html_summary(analysis: CaptureAnalysis) -> str:
    capture = analysis.capture
    summary = analysis.summary
    cards = [
        ("Packets", format_count(summary.packets)),
        ("Captured bytes", format_bytes(summary.captured_bytes)),
        ("Wire bytes", format_bytes(summary.wire_bytes)),
        ("Duration", format_duration(summary.duration_ns)),
        ("Average rate", format_packet_rate(summary.packets_per_second)),
        ("Average throughput", format_bit_rate(summary.bits_per_second)),
        ("DNS messages", format_count(summary.dns_messages)),
        ("Conversations", format_count(summary.flow_count)),
    ]
    card_html = "\n".join(
        f'<div class="card"><div class="label">{html.escape(label)}</div>'
        f'<div class="value">{html.escape(value)}</div></div>'
        for label, value in cards
    )
    interfaces = "".join(
        f"<li>{html.escape(interface.linktype_display)}"
        f"{', name ' + html.escape(interface.name) if interface.name else ''}"
        f"{', snaplen ' + format_count(interface.snaplen) if interface.snaplen else ''}</li>"
        for interface in capture.interfaces
    )
    details = (
        "<table>"
        "<tr><th>Capture format</th>"
        f"<td>{html.escape(capture.format)} {html.escape(capture.version)}</td></tr>"
        "<tr><th>Byte order</th>"
        f"<td>{html.escape(capture.byte_order)}-endian</td></tr>"
        "<tr><th>Link type</th>"
        f"<td>{html.escape(capture.linktype_display)}</td></tr>"
        "<tr><th>Snaplen</th>"
        f"<td>{format_count(capture.snaplen)} bytes</td></tr>"
        "<tr><th>Packets</th>"
        f"<td>{format_count(summary.packets)}</td></tr>"
        "<tr><th>Captured bytes</th>"
        f"<td>{format_count(summary.captured_bytes)}</td></tr>"
        "<tr><th>Wire bytes</th>"
        f"<td>{format_count(summary.wire_bytes)}</td></tr>"
        "<tr><th>Time span</th><td>"
        f"{html.escape(_format_time_range(summary.first_timestamp_ns, summary.last_timestamp_ns))}"
        "</td></tr>"
        "<tr><th>Truncated packets</th>"
        f"<td>{format_count(summary.truncated_packets)}</td></tr>"
        "<tr><th>Packets with decode errors</th>"
        f"<td>{format_count(summary.packets_with_errors)}</td></tr>"
        "</table>"
    )
    interfaces_block = (
        f'<p class="muted">Interfaces:</p><ul class="notes">{interfaces}</ul>'
        if interfaces
        else ""
    )
    return (
        '<section id="summary">'
        "<h2>Capture summary</h2>"
        f'<div class="cards">{card_html}</div>'
        f"{details}"
        f"{interfaces_block}"
        "</section>"
    )


def _html_protocols(analysis: CaptureAnalysis, top: int) -> str:
    distribution = analysis.protocol_distribution()
    if not distribution:
        chart = '<p class="empty">No packets captured.</p>'
    else:
        rows = distribution[:top]
        items = [
            (
                label,
                float(count),
                f"{label}: {format_count(count)} packet(s)",
                f"{format_count(count)}",
            )
            for label, count in rows
        ]
        chart = _svg_bar_chart(items)
        hidden = len(distribution) - len(rows)
        if hidden > 0:
            chart += (
                f'<p class="muted">Showing {len(rows)} of {len(distribution)} '
                "protocol labels.</p>"
            )
    return (
        '<section id="protocols">'
        "<h2>Protocol distribution</h2>"
        '<p class="muted">Packet counts by highest decoded protocol.</p>'
        f"{chart}"
        "</section>"
    )


def _html_talkers(analysis: CaptureAnalysis, top: int) -> str:
    talkers = analysis.top_talkers(top)
    if not talkers:
        return (
            '<section id="talkers"><h2>Top talkers</h2>'
            '<p class="empty">No IP traffic captured.</p></section>'
        )
    items = [
        (
            talker.address,
            float(talker.bytes_total),
            f"{talker.address}: {format_bytes(talker.bytes_total)} total "
            f"(sent {format_bytes(talker.bytes_sent)}, received "
            f"{format_bytes(talker.bytes_received)})",
            format_bytes(talker.bytes_total),
        )
        for talker in talkers
    ]
    chart = _svg_bar_chart(items)
    rows = "\n".join(
        "<tr>"
        f"<td><code>{html.escape(talker.address)}</code></td>"
        f'<td class="num">{format_count(talker.packets)}</td>'
        f'<td class="num">{format_bytes(talker.bytes_sent)}</td>'
        f'<td class="num">{format_bytes(talker.bytes_received)}</td>'
        f'<td class="num">{format_bytes(talker.bytes_total)}</td>'
        "</tr>"
        for talker in talkers
    )
    return (
        '<section id="talkers">'
        "<h2>Top talkers</h2>"
        '<p class="muted">Frame bytes per IPv4/IPv6 address, sent plus received.</p>'
        f"{chart}"
        "<table>"
        "<tr><th>Address</th><th class=\"num\">Packets</th>"
        "<th class=\"num\">Sent</th><th class=\"num\">Received</th>"
        "<th class=\"num\">Total</th></tr>"
        f"{rows}"
        "</table>"
        "</section>"
    )


def _html_flows(analysis: CaptureAnalysis, top: int) -> str:
    flows = analysis.top_flows(top)
    if not flows:
        return (
            '<section id="flows"><h2>Top conversations</h2>'
            '<p class="empty">No IP conversations captured.</p></section>'
        )
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(flow.protocol)}</td>"
        f"<td><code>{html.escape(flow.initiator)}</code></td>"
        f"<td><code>{html.escape(flow.responder)}</code></td>"
        f'<td class="num">{format_count(flow.packets)}</td>'
        f'<td class="num">{format_count(flow.bytes)}</td>'
        f'<td class="num">{format_duration(flow.duration_ns)}</td>'
        f"<td>{html.escape(format_timestamp(flow.first_timestamp_ns))}</td>"
        "</tr>"
        for flow in flows
    )
    hidden = len(analysis.flows) - len(flows)
    note = (
        f'<p class="muted">Showing the {len(flows)} busiest of '
        f"{len(analysis.flows)} conversations.</p>"
        if hidden > 0
        else ""
    )
    return (
        '<section id="flows">'
        "<h2>Top conversations</h2>"
        '<p class="muted">Bidirectional 5-tuple flows sorted by bytes.</p>'
        f"{note}"
        "<table>"
        "<tr><th>Protocol</th><th>Initiator</th><th>Responder</th>"
        "<th class=\"num\">Packets</th><th class=\"num\">Bytes</th>"
        "<th class=\"num\">Duration</th><th>Started (UTC)</th></tr>"
        f"{rows}"
        "</table>"
        "</section>"
    )


def _html_dns(analysis: CaptureAnalysis, top: int) -> str:
    packets = [packet for packet in analysis.dns_packets if packet.dns is not None][:top]
    if not packets:
        return ""
    rows = []
    for packet in packets:
        message = packet.dns
        assert message is not None
        question = message.questions[0] if message.questions else None
        answers = "; ".join(
            f"{record.name} {record.rtype_name} {record.value}"
            for record in message.answers
        )
        if len(answers) > 120:
            answers = answers[:117] + "..."
        rows.append(
            "<tr>"
            f"<td>{html.escape(format_timestamp(packet.timestamp_ns))}</td>"
            f"<td><code>{html.escape(_direction(packet))}</code></td>"
            f"<td>{html.escape(message.kind)}</td>"
            f"<td>{html.escape(question.name if question else '-')}</td>"
            f"<td>{html.escape(question.qtype_name if question else '-')}</td>"
            f"<td>{html.escape(message.rcode_name if message.is_response else '-')}</td>"
            f"<td>{html.escape(answers or '-')}</td>"
            "</tr>"
        )
    return (
        '<section id="dns">'
        "<h2>DNS activity</h2>"
        '<p class="muted">Decoded DNS messages over UDP port 53.</p>'
        "<table>"
        "<tr><th>Time (UTC)</th><th>Direction</th><th>Kind</th>"
        "<th>Name</th><th>Type</th><th>Rcode</th><th>Answers</th></tr>"
        + "\n".join(rows)
        + "</table></section>"
    )


def _html_notes(analysis: CaptureAnalysis) -> str:
    capture = analysis.capture
    warnings = list(capture.warnings)
    errors = [
        f"Packet {packet.index}: {error}"
        for packet in analysis.decoded
        for error in packet.errors
    ]
    items = [html.escape(warning) for warning in warnings]
    items.extend(html.escape(error) for error in errors[:10])
    if len(errors) > 10:
        items.append(f"... and {len(errors) - 10} more decoder error(s).")
    if not items:
        items.append("No capture warnings or decoding errors were reported.")
    note_summary = (
        f"{format_count(analysis.summary.notes_count)} decoder note(s) "
        "recorded (fragments, undecoded protocols)."
    )
    return (
        '<section id="notes">'
        "<h2>Capture notes</h2>"
        f'<p class="muted">{note_summary}</p>'
        "<ul class=\"notes\">"
        + "".join(f"<li>{item}</li>" for item in items)
        + "</ul></section>"
    )


def _direction(packet: DecodedPacket) -> str:
    source = (
        f"{packet.source_ip}:{packet.source_port}"
        if packet.source_ip is not None and packet.source_port is not None
        else str(packet.source_ip)
    )
    destination = (
        f"{packet.destination_ip}:{packet.destination_port}"
        if packet.destination_ip is not None and packet.destination_port is not None
        else str(packet.destination_ip)
    )
    return f"{source} -> {destination}"


def _format_time_range(first: int | None, last: int | None) -> str:
    if first is None or last is None:
        return "no packets"
    return f"{format_timestamp(first)} to {format_timestamp(last)}"


def _svg_bar_chart(items: list[tuple[str, float, str, str]]) -> str:
    """Render a horizontal bar chart as inline SVG.

    Each item is ``(label, value, tooltip, value_text)``; the tooltip carries the
    long description, while ``value_text`` is kept short to fit the chart.
    """
    if not items:
        return '<p class="empty">No data.</p>'
    chart_width = CHART_WIDTH - CHART_LABEL_WIDTH - CHART_VALUE_WIDTH
    height = CHART_ROW_HEIGHT * len(items) + 8
    max_value = max(value for _label, value, _tooltip, _text in items) or 1.0
    lines = [
        f'<svg class="chart" viewBox="0 0 {CHART_WIDTH} {height}" '
        'role="img" aria-label="bar chart">'
    ]
    for index, (label, value, tooltip, value_text) in enumerate(items):
        y = 4 + index * CHART_ROW_HEIGHT
        bar_width = 0.0 if value <= 0 else max(2.0, value / max_value * chart_width)
        lines.append(
            f'<text class="chart-label" x="0" y="{y + 17}">{html.escape(label)}</text>'
        )
        lines.append(
            f'<rect class="chart-bar" x="{CHART_LABEL_WIDTH}" y="{y}" '
            f'width="{bar_width:.1f}" height="{CHART_ROW_HEIGHT - 12}" rx="2" '
            f'fill="{CHART_ACCENT}"><title>{html.escape(tooltip)}</title></rect>'
        )
        lines.append(
            f'<text class="chart-value" x="{CHART_LABEL_WIDTH + bar_width + 8:.1f}" '
            f'y="{y + 17}">{html.escape(value_text)}</text>'
        )
    lines.append("</svg>")
    return "\n".join(lines)


def render_text(analysis: CaptureAnalysis, *, top: int = 10) -> str:
    """Render a plain-text capture summary and tables."""
    summary = analysis.summary
    capture = analysis.capture
    lines = [
        f"Capture: {capture.source}",
        f"Format: {capture.format} {capture.version} ({capture.byte_order}-endian), "
        f"link type {capture.linktype_display}, snaplen {format_count(capture.snaplen)}",
        f"Time span: {_format_time_range(summary.first_timestamp_ns, summary.last_timestamp_ns)}",
        f"Packets: {format_count(summary.packets)} "
        f"({format_count(summary.captured_bytes)} bytes captured, "
        f"{format_count(summary.wire_bytes)} bytes on the wire)",
        f"Average rate: {format_packet_rate(summary.packets_per_second)}, "
        f"{format_bit_rate(summary.bits_per_second)}",
        f"Conversations: {format_count(summary.flow_count)}, "
        f"talkers: {format_count(summary.talker_count)}, "
        f"DNS messages: {format_count(summary.dns_messages)}",
        f"Problems: {format_count(summary.truncated_packets)} truncated packet(s), "
        f"{format_count(summary.packets_with_errors)} with decode errors, "
        f"{format_count(len(capture.warnings))} capture warning(s)",
    ]
    lines.extend(["", "Protocol distribution"])
    lines.append("-" * 60)
    for label, count in analysis.protocol_distribution()[:top]:
        lines.append(f"{label:<24}{format_count(count):>8} packets")
    lines.extend(["", f"Top conversations ({len(analysis.top_flows(top))} shown, sorted by bytes)"])
    lines.append("-" * 100)
    lines.append(
        f"{'Protocol':<10}{'Initiator':<28}{'Responder':<28}"
        f"{'Packets':>8}{'Bytes':>10}{'Duration':>12}"
    )
    for flow in analysis.top_flows(top):
        lines.append(
            f"{flow.protocol:<10}{flow.initiator:<28}{flow.responder:<28}"
            f"{format_count(flow.packets):>8}{format_count(flow.bytes):>10}"
            f"{format_duration(flow.duration_ns):>12}"
        )
    lines.extend(["", f"Top talkers ({len(analysis.top_talkers(top))} shown, sorted by bytes)"])
    lines.append("-" * 90)
    lines.append(
        f"{'Address':<40}{'Packets':>8}{'Sent':>14}{'Received':>14}{'Total':>14}"
    )
    for talker in analysis.top_talkers(top):
        lines.append(
            f"{talker.address:<40}{format_count(talker.packets):>8}"
            f"{format_bytes(talker.bytes_sent):>14}"
            f"{format_bytes(talker.bytes_received):>14}"
            f"{format_bytes(talker.bytes_total):>14}"
        )
    if capture.warnings:
        lines.extend(["", "Capture warnings"])
        lines.append("-" * 60)
        lines.extend(f"- {warning}" for warning in capture.warnings)
    return "\n".join(lines) + "\n"


def render_markdown(analysis: CaptureAnalysis, *, top: int = 10) -> str:
    """Render a Markdown capture summary with tables."""
    summary = analysis.summary
    capture = analysis.capture
    lines = [
        f"# Capture report: {capture.source}",
        "",
        "## Capture summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Format | {capture.format} {capture.version} ({capture.byte_order}-endian) |",
        f"| Link type | {capture.linktype_display} |",
        f"| Snaplen | {format_count(capture.snaplen)} bytes |",
        f"| Time span | {_format_time_range(summary.first_timestamp_ns, summary.last_timestamp_ns)} |",
        f"| Packets | {format_count(summary.packets)} |",
        f"| Captured bytes | {format_count(summary.captured_bytes)} |",
        f"| Wire bytes | {format_count(summary.wire_bytes)} |",
        f"| Average rate | {format_packet_rate(summary.packets_per_second)} |",
        f"| Average throughput | {format_bit_rate(summary.bits_per_second)} |",
        f"| Conversations | {format_count(summary.flow_count)} |",
        f"| DNS messages | {format_count(summary.dns_messages)} |",
        f"| Truncated packets | {format_count(summary.truncated_packets)} |",
        "",
        "## Protocol distribution",
        "",
        "| Protocol | Packets |",
        "| --- | ---: |",
    ]
    lines.extend(
        f"| {label} | {format_count(count)} |"
        for label, count in analysis.protocol_distribution()[:top]
    )
    lines.extend(["", "## Top conversations", "", "| Protocol | Initiator | Responder | Packets | Bytes | Duration |", "| --- | --- | --- | ---: | ---: | ---: |"])
    lines.extend(
        f"| {flow.protocol} | {flow.initiator} | {flow.responder} | "
        f"{format_count(flow.packets)} | {format_count(flow.bytes)} | "
        f"{format_duration(flow.duration_ns)} |"
        for flow in analysis.top_flows(top)
    )
    lines.extend(["", "## Top talkers", "", "| Address | Packets | Sent | Received | Total |", "| --- | ---: | ---: | ---: | ---: |"])
    lines.extend(
        f"| {talker.address} | {format_count(talker.packets)} | "
        f"{format_bytes(talker.bytes_sent)} | {format_bytes(talker.bytes_received)} | "
        f"{format_bytes(talker.bytes_total)} |"
        for talker in analysis.top_talkers(top)
    )
    if analysis.dns_packets:
        lines.extend(
            [
                "",
                "## DNS activity",
                "",
                "| Time (UTC) | Direction | Kind | Name | Type | Rcode |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for packet in analysis.dns_packets[:top]:
            message = packet.dns
            assert message is not None
            question = message.questions[0] if message.questions else None
            lines.append(
                f"| {iso_timestamp(packet.timestamp_ns)} | {_direction(packet)} | "
                f"{message.kind} | {question.name if question else '-'} | "
                f"{question.qtype_name if question else '-'} | "
                f"{message.rcode_name if message.is_response else '-'} |"
            )
    if capture.warnings:
        lines.extend(["", "## Capture warnings", ""])
        lines.extend(f"- {warning}" for warning in capture.warnings)
    return "\n".join(lines) + "\n"
