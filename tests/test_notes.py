from pathlib import Path

from network_security_classroom.labs import (
    ArpDevice,
    ArpScanResult,
    DnsObservationResult,
    TlsCertificateResult,
    TcpHandshakeResult,
)
from network_security_classroom.lessons import get_lesson
from network_security_classroom.notes import (
    export_arp_markdown,
    export_dns_markdown,
    export_lesson_markdown,
    export_tls_markdown,
    export_tcp_markdown,
    render_lesson_markdown,
)


def test_render_lesson_markdown_contains_title_and_summary():
    lesson = get_lesson("host")
    text = render_lesson_markdown(lesson)
    assert "# What Is a Host?" in text
    assert "## Summary" in text


def test_export_lesson_markdown_writes_file():
    lesson = get_lesson("zero-day")
    output = Path("tests") / "_tmp_zero_day.md"
    if output.exists():
        output.unlink()
    path = export_lesson_markdown(lesson, str(output))
    assert path == output
    assert output.exists()
    output.unlink()


def test_export_arp_markdown_writes_file():
    result = ArpScanResult(
        network="192.168.1.0/24",
        devices=[ArpDevice(ip="192.168.1.5", mac="AA:BB", role_hint="active client")],
    )
    output = Path("tests") / "_tmp_arp.md"
    if output.exists():
        output.unlink()
    path = export_arp_markdown(result, str(output))
    assert path == output
    assert output.exists()
    output.unlink()


def test_export_tcp_markdown_writes_file():
    result = TcpHandshakeResult(
        target="192.168.1.1",
        port=443,
        state="open",
        explanation="A service appears to be listening.",
    )
    output = Path("tests") / "_tmp_tcp.md"
    if output.exists():
        output.unlink()
    path = export_tcp_markdown(result, str(output))
    assert path == output
    assert output.exists()
    output.unlink()


def test_export_dns_markdown_writes_file():
    result = DnsObservationResult(
        source_host="192.168.1.25",
        queried_domain="example.com",
        transport="udp/53",
        explanation="Observers can see the lookup target.",
    )
    output = Path("tests") / "_tmp_dns.md"
    if output.exists():
        output.unlink()
    path = export_dns_markdown(result, str(output))
    assert path == output
    assert output.exists()
    output.unlink()


def test_export_tls_markdown_writes_file():
    result = TlsCertificateResult(
        target="example.com",
        port=443,
        subject="CN=example.com",
        issuer="CN=Demo CA",
        valid_from="2026-01-01T00:00:00Z",
        valid_to="2027-01-01T00:00:00Z",
        explanation="A certificate helps establish identity.",
    )
    output = Path("tests") / "_tmp_tls.md"
    if output.exists():
        output.unlink()
    path = export_tls_markdown(result, str(output))
    assert path == output
    assert output.exists()
    output.unlink()
