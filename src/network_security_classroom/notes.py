"""Markdown note generation for Network Security Classroom."""

from __future__ import annotations

from pathlib import Path

from .lessons import Lesson
from .labs import (
    ArpScanResult,
    DnsObservationResult,
    TlsCertificateResult,
    TcpHandshakeResult,
    render_arp_markdown,
    render_dns_markdown,
    render_tls_markdown,
    render_tcp_markdown,
)


def render_lesson_markdown(lesson: Lesson) -> str:
    return (
        f"# {lesson.title}\n\n"
        f"Slug: `{lesson.slug}`\n\n"
        f"## Summary\n\n"
        f"{lesson.summary}\n\n"
        f"## Notes\n\n"
        f"{lesson.body}\n"
    )


def export_lesson_markdown(lesson: Lesson, output_path: str | None = None) -> Path:
    path = Path(output_path) if output_path else Path(f"{lesson.slug}.md")
    path.write_text(render_lesson_markdown(lesson), encoding="utf-8")
    return path


def export_arp_markdown(result: ArpScanResult, output_path: str | None = None) -> Path:
    path = Path(output_path) if output_path else Path("arp-discovery.md")
    path.write_text(render_arp_markdown(result), encoding="utf-8")
    return path


def export_tcp_markdown(result: TcpHandshakeResult, output_path: str | None = None) -> Path:
    path = Path(output_path) if output_path else Path("tcp-handshake.md")
    path.write_text(render_tcp_markdown(result), encoding="utf-8")
    return path


def export_dns_markdown(result: DnsObservationResult, output_path: str | None = None) -> Path:
    path = Path(output_path) if output_path else Path("dns-metadata.md")
    path.write_text(render_dns_markdown(result), encoding="utf-8")
    return path


def export_tls_markdown(result: TlsCertificateResult, output_path: str | None = None) -> Path:
    path = Path(output_path) if output_path else Path("tls-certificate.md")
    path.write_text(render_tls_markdown(result), encoding="utf-8")
    return path
