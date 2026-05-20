"""Safe lab helpers for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import ipaddress
import json
import socket
import ssl
from datetime import datetime, timezone
from urllib import request
from urllib.error import URLError


@dataclass(frozen=True)
class ArpDevice:
    ip: str
    mac: str
    role_hint: str


@dataclass(frozen=True)
class ArpScanResult:
    network: str
    devices: list[ArpDevice]


@dataclass(frozen=True)
class TcpHandshakeResult:
    target: str
    port: int
    state: str
    explanation: str


@dataclass(frozen=True)
class DnsObservationResult:
    source_host: str
    queried_domain: str
    transport: str
    explanation: str


@dataclass(frozen=True)
class TlsCertificateResult:
    target: str
    port: int
    subject: str
    issuer: str
    valid_from: str
    valid_to: str
    trust_state: str
    explanation: str


@dataclass(frozen=True)
class HttpHeaderResult:
    url: str
    status_code: int
    headers: dict[str, str]
    explanation: str


class ArpBackend:
    """Interface for ARP discovery implementations."""

    def scan(self, network: str) -> ArpScanResult:  # pragma: no cover - interface only
        raise NotImplementedError


class DemoArpBackend(ArpBackend):
    """Deterministic backend for safe local demos and tests."""

    def scan(self, network: str) -> ArpScanResult:
        return ArpScanResult(
            network=network,
            devices=[
                ArpDevice(ip=_guess_gateway_ip(network), mac="AA:BB:CC:11:22:33", role_hint="likely gateway"),
                ArpDevice(ip=_guess_client_ip(network), mac="DE:AD:BE:EF:44:55", role_hint="active client"),
            ],
        )


class LiveArpBackend(ArpBackend):
    """Optional Scapy-backed ARP discovery for local lab use."""

    def scan(self, network: str) -> ArpScanResult:
        scapy = _load_scapy_all()
        packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=network)
        answered, _ = scapy.srp(packet, timeout=3, verbose=False)

        devices = []
        for _, received in answered:
            ip = str(received.psrc)
            devices.append(
                ArpDevice(
                    ip=ip,
                    mac=str(received.hwsrc),
                    role_hint=_infer_role_hint(network, ip),
                )
            )
        return ArpScanResult(network=network, devices=devices)


class TcpBackend:
    """Interface for TCP handshake implementations."""

    def probe(self, target: str, port: int, demo_state: str = "open") -> TcpHandshakeResult:  # pragma: no cover
        raise NotImplementedError


class DemoTcpBackend(TcpBackend):
    """Deterministic backend for teaching handshake states."""

    def probe(self, target: str, port: int, demo_state: str = "open") -> TcpHandshakeResult:
        normalized_state = validate_demo_tcp_state(demo_state)
        return TcpHandshakeResult(
            target=target,
            port=port,
            state=normalized_state,
            explanation=_tcp_explanation(normalized_state, port),
        )


class LiveTcpBackend(TcpBackend):
    """Optional Scapy-backed single-port SYN probe for local learning labs."""

    def probe(self, target: str, port: int, demo_state: str = "open") -> TcpHandshakeResult:
        del demo_state
        scapy = _load_scapy_all()
        packet = scapy.IP(dst=target) / scapy.TCP(dport=port, flags="S")
        response = scapy.sr1(packet, timeout=2, verbose=False)

        if response is None:
            state = "filtered"
        elif response.haslayer(scapy.TCP):
            flags = int(response.getlayer(scapy.TCP).flags)
            if flags == 0x12:
                state = "open"
            elif flags == 0x14:
                state = "closed"
            else:
                state = "filtered"
        else:
            state = "filtered"

        return TcpHandshakeResult(
            target=target,
            port=port,
            state=state,
            explanation=_tcp_explanation(state, port),
        )


class DnsBackend:
    """Interface for DNS observation implementations."""

    def observe(self, demo_domain: str = "example.com") -> DnsObservationResult:  # pragma: no cover
        raise NotImplementedError


class DemoDnsBackend(DnsBackend):
    """Deterministic backend for teaching DNS metadata visibility."""

    def observe(self, demo_domain: str = "example.com") -> DnsObservationResult:
        domain = validate_demo_domain(demo_domain)
        return DnsObservationResult(
            source_host="192.168.1.25",
            queried_domain=domain,
            transport="udp/53",
            explanation=_dns_explanation(domain),
        )


class LiveDnsBackend(DnsBackend):
    """Optional Scapy-backed DNS observation for local learning labs."""

    def observe(self, demo_domain: str = "example.com") -> DnsObservationResult:
        del demo_domain
        scapy = _load_scapy_all()
        packets = []

        def packet_callback(packet):
            if packet.haslayer(scapy.DNS) and packet.haslayer(scapy.DNSQR):
                packets.append(packet)
                return True
            return False

        scapy.sniff(filter="udp port 53", prn=packet_callback, count=1, timeout=5, store=False)
        if not packets:
            return DnsObservationResult(
                source_host="unknown",
                queried_domain="none observed",
                transport="udp/53",
                explanation=(
                    "No DNS query was observed during the capture window. "
                    "That can happen if no device made a visible DNS request during the short sample period."
                ),
            )

        packet = packets[0]
        source = str(packet[scapy.IP].src) if packet.haslayer(scapy.IP) else "unknown"
        domain = str(packet[scapy.DNSQR].qname).rstrip(".")
        return DnsObservationResult(
            source_host=source,
            queried_domain=domain,
            transport="udp/53",
            explanation=_dns_explanation(domain),
        )


class TlsBackend:
    """Interface for TLS certificate inspection."""

    def inspect(
        self,
        target: str,
        port: int,
        demo_trust_state: str = "valid",
    ) -> TlsCertificateResult:  # pragma: no cover
        raise NotImplementedError


class DemoTlsBackend(TlsBackend):
    """Deterministic backend for teaching certificate fields."""

    def inspect(self, target: str, port: int, demo_trust_state: str = "valid") -> TlsCertificateResult:
        trust_state = validate_demo_trust_state(demo_trust_state)
        subject = f"CN={target}"
        issuer = "CN=Demo Intermediate CA"
        valid_from = "2026-01-01T00:00:00Z"
        valid_to = "2027-01-01T00:00:00Z"

        if trust_state == "hostname-mismatch":
            subject = "CN=api.example.com"
        elif trust_state == "expired":
            valid_from = "2024-01-01T00:00:00Z"
            valid_to = "2025-01-01T00:00:00Z"
        elif trust_state == "self-signed":
            issuer = f"CN={target}"

        return TlsCertificateResult(
            target=target,
            port=port,
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            trust_state=trust_state,
            explanation=_tls_explanation(target, trust_state),
        )


class LiveTlsBackend(TlsBackend):
    """Socket/SSL-backed certificate inspection for local learning labs."""

    def inspect(self, target: str, port: int, demo_trust_state: str = "valid") -> TlsCertificateResult:
        del demo_trust_state
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as wrapped:
                cert = wrapped.getpeercert()

        subject = _flatten_name(cert.get("subject", ()))
        issuer = _flatten_name(cert.get("issuer", ()))
        valid_from = _normalize_cert_time(cert.get("notBefore", ""))
        valid_to = _normalize_cert_time(cert.get("notAfter", ""))
        trust_state = _infer_live_trust_state(target, subject, issuer, valid_to)
        return TlsCertificateResult(
            target=target,
            port=port,
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_to=valid_to,
            trust_state=trust_state,
            explanation=_tls_explanation(target, trust_state),
        )


class HttpBackend:
    """Interface for HTTP header inspection."""

    def inspect(self, url: str) -> HttpHeaderResult:  # pragma: no cover
        raise NotImplementedError


class DemoHttpBackend(HttpBackend):
    """Deterministic backend for teaching security-relevant headers."""

    def inspect(self, url: str) -> HttpHeaderResult:
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
        }
        return HttpHeaderResult(
            url=url,
            status_code=200,
            headers=headers,
            explanation=_http_explanation(headers),
        )


class LiveHttpBackend(HttpBackend):
    """urllib-backed HTTP header inspection for learning labs."""

    def inspect(self, url: str) -> HttpHeaderResult:
        try:
            with request.urlopen(url, timeout=10) as response:
                headers = {key.casefold(): value for key, value in response.headers.items()}
                status_code = getattr(response, "status", 200)
        except URLError as exc:
            raise RuntimeError(f"HTTP inspection failed: {exc}") from exc

        return HttpHeaderResult(
            url=url,
            status_code=status_code,
            headers=headers,
            explanation=_http_explanation(headers),
        )


def validate_network_range(network: str) -> str:
    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid network range: {network}") from exc
    return str(parsed)


def get_arp_backend(name: str = "demo") -> ArpBackend:
    normalized = name.strip().casefold()
    if normalized == "demo":
        return DemoArpBackend()
    if normalized == "live":
        return LiveArpBackend()
    raise ValueError(f"Unknown ARP backend: {name}")


def run_arp_discovery(
    network: str,
    backend: ArpBackend | None = None,
    backend_name: str = "demo",
) -> ArpScanResult:
    normalized = validate_network_range(network)
    active_backend = backend or get_arp_backend(backend_name)
    return active_backend.scan(normalized)


def validate_target_host(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("Target host cannot be blank")
    return value


def validate_port(port: int | str) -> int:
    try:
        numeric = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid port: {port}") from exc
    if numeric < 1 or numeric > 65535:
        raise ValueError(f"Invalid port: {port}")
    return numeric


def validate_demo_tcp_state(state: str) -> str:
    normalized = state.strip().casefold()
    if normalized not in {"open", "closed", "filtered"}:
        raise ValueError(f"Invalid demo TCP state: {state}")
    return normalized


def get_tcp_backend(name: str = "demo") -> TcpBackend:
    normalized = name.strip().casefold()
    if normalized == "demo":
        return DemoTcpBackend()
    if normalized == "live":
        return LiveTcpBackend()
    raise ValueError(f"Unknown TCP backend: {name}")


def run_tcp_handshake(
    target: str,
    port: int | str,
    backend: TcpBackend | None = None,
    backend_name: str = "demo",
    demo_state: str = "open",
) -> TcpHandshakeResult:
    normalized_target = validate_target_host(target)
    normalized_port = validate_port(port)
    active_backend = backend or get_tcp_backend(backend_name)
    return active_backend.probe(normalized_target, normalized_port, demo_state=demo_state)


def validate_demo_domain(domain: str) -> str:
    value = domain.strip().lower()
    if not value or "." not in value or " " in value:
        raise ValueError(f"Invalid demo domain: {domain}")
    return value


def get_dns_backend(name: str = "demo") -> DnsBackend:
    normalized = name.strip().casefold()
    if normalized == "demo":
        return DemoDnsBackend()
    if normalized == "live":
        return LiveDnsBackend()
    raise ValueError(f"Unknown DNS backend: {name}")


def run_dns_observation(
    backend: DnsBackend | None = None,
    backend_name: str = "demo",
    demo_domain: str = "example.com",
) -> DnsObservationResult:
    active_backend = backend or get_dns_backend(backend_name)
    return active_backend.observe(demo_domain=demo_domain)


def get_tls_backend(name: str = "demo") -> TlsBackend:
    normalized = name.strip().casefold()
    if normalized == "demo":
        return DemoTlsBackend()
    if normalized == "live":
        return LiveTlsBackend()
    raise ValueError(f"Unknown TLS backend: {name}")


def run_tls_inspection(
    target: str,
    port: int | str,
    backend: TlsBackend | None = None,
    backend_name: str = "demo",
    demo_trust_state: str = "valid",
) -> TlsCertificateResult:
    normalized_target = validate_target_host(target)
    normalized_port = validate_port(port)
    active_backend = backend or get_tls_backend(backend_name)
    return active_backend.inspect(
        normalized_target,
        normalized_port,
        demo_trust_state=demo_trust_state,
    )


def validate_demo_trust_state(state: str) -> str:
    normalized = state.strip().casefold()
    if normalized not in {"valid", "hostname-mismatch", "expired", "self-signed"}:
        raise ValueError(f"Invalid demo trust state: {state}")
    return normalized


def validate_url(url: str) -> str:
    value = url.strip()
    if not value.startswith(("http://", "https://")):
        raise ValueError(f"Invalid URL: {url}")
    return value


def get_http_backend(name: str = "demo") -> HttpBackend:
    normalized = name.strip().casefold()
    if normalized == "demo":
        return DemoHttpBackend()
    if normalized == "live":
        return LiveHttpBackend()
    raise ValueError(f"Unknown HTTP backend: {name}")


def run_http_inspection(
    url: str,
    backend: HttpBackend | None = None,
    backend_name: str = "demo",
) -> HttpHeaderResult:
    normalized_url = validate_url(url)
    active_backend = backend or get_http_backend(backend_name)
    return active_backend.inspect(normalized_url)


def render_arp_summary(result: ArpScanResult) -> str:
    lines = [
        f"ARP discovery for {result.network}",
        "",
        "This scan shows which hosts answered a local address-resolution request.",
        "",
    ]
    if not result.devices:
        lines.append("No devices responded.")
        return "\n".join(lines)

    for device in result.devices:
        lines.append(f"- {device.ip}  {device.mac}  ({device.role_hint})")
    return "\n".join(lines)


def render_arp_markdown(result: ArpScanResult) -> str:
    lines = [
        "# ARP Discovery Notes",
        "",
        f"Network: `{result.network}`",
        "",
        "## What This Means",
        "",
        "ARP discovery asks local devices to identify which MAC address belongs to which IP address.",
        "This is one of the simplest ways to understand who is alive on a local subnet.",
        "",
        "## Devices",
        "",
    ]
    if not result.devices:
        lines.append("No devices responded.")
        return "\n".join(lines) + "\n"

    for device in result.devices:
        lines.append(f"- `{device.ip}` | `{device.mac}` | {device.role_hint}")
    return "\n".join(lines) + "\n"


def render_tcp_summary(result: TcpHandshakeResult) -> str:
    return (
        f"TCP handshake check for {result.target}:{result.port}\n\n"
        f"State: {result.state}\n\n"
        f"{result.explanation}"
    )


def render_tcp_markdown(result: TcpHandshakeResult) -> str:
    return (
        "# TCP Handshake Notes\n\n"
        f"Target: `{result.target}`\n\n"
        f"Port: `{result.port}`\n\n"
        f"State: `{result.state}`\n\n"
        "## Interpretation\n\n"
        f"{result.explanation}\n"
    )


def render_dns_summary(result: DnsObservationResult) -> str:
    return (
        f"DNS metadata observation\n\n"
        f"Source host: {result.source_host}\n"
        f"Queried domain: {result.queried_domain}\n"
        f"Transport: {result.transport}\n\n"
        f"{result.explanation}"
    )


def render_dns_markdown(result: DnsObservationResult) -> str:
    return (
        "# DNS Metadata Notes\n\n"
        f"Source host: `{result.source_host}`\n\n"
        f"Queried domain: `{result.queried_domain}`\n\n"
        f"Transport: `{result.transport}`\n\n"
        "## Interpretation\n\n"
        f"{result.explanation}\n"
    )


def render_tls_summary(result: TlsCertificateResult) -> str:
    return (
        f"TLS certificate inspection for {result.target}:{result.port}\n\n"
        f"Subject: {result.subject}\n"
        f"Issuer: {result.issuer}\n"
        f"Valid from: {result.valid_from}\n"
        f"Valid to: {result.valid_to}\n\n"
        f"Trust assessment: {result.trust_state}\n\n"
        f"{result.explanation}"
    )


def render_tls_markdown(result: TlsCertificateResult) -> str:
    return (
        "# TLS Certificate Notes\n\n"
        f"Target: `{result.target}`\n\n"
        f"Port: `{result.port}`\n\n"
        f"Subject: `{result.subject}`\n\n"
        f"Issuer: `{result.issuer}`\n\n"
        f"Valid from: `{result.valid_from}`\n\n"
        f"Valid to: `{result.valid_to}`\n\n"
        f"Trust assessment: `{result.trust_state}`\n\n"
        "## Interpretation\n\n"
        f"{result.explanation}\n"
    )


def render_http_summary(result: HttpHeaderResult) -> str:
    interesting = _interesting_http_header_lines(result.headers)
    header_lines = "\n".join(interesting) if interesting else "No tracked security headers found."
    return (
        f"HTTP header inspection for {result.url}\n\n"
        f"Status: {result.status_code}\n\n"
        f"{header_lines}\n\n"
        f"{result.explanation}"
    )


def render_http_markdown(result: HttpHeaderResult) -> str:
    interesting = _interesting_http_header_lines(result.headers)
    header_lines = "\n".join(f"- {line}" for line in interesting) if interesting else "- No tracked security headers found."
    return (
        "# HTTP Header Notes\n\n"
        f"URL: `{result.url}`\n\n"
        f"Status: `{result.status_code}`\n\n"
        "## Observed Headers\n\n"
        f"{header_lines}\n\n"
        "## Interpretation\n\n"
        f"{result.explanation}\n"
    )


def _guess_gateway_ip(network: str) -> str:
    parsed = ipaddress.ip_network(network, strict=False)
    first_host = next(parsed.hosts(), parsed.network_address)
    return str(first_host)


def _guess_client_ip(network: str) -> str:
    parsed = ipaddress.ip_network(network, strict=False)
    hosts = list(parsed.hosts())
    if len(hosts) >= 2:
        return str(hosts[1])
    if hosts:
        return str(hosts[0])
    return str(parsed.network_address)


def _infer_role_hint(network: str, ip: str) -> str:
    return "likely gateway" if ip == _guess_gateway_ip(network) else "active client"


def _tcp_explanation(state: str, port: int) -> str:
    if state == "open":
        return (
            f"The remote host answered the SYN request in a way that suggests a service is listening on port {port}. "
            "This usually means the network path is open and an application is ready to accept a connection."
        )
    if state == "closed":
        return (
            f"The remote host responded in a way that suggests nothing is listening on port {port}. "
            "That means the host is reachable, but this specific service door is shut."
        )
    return (
        f"No useful handshake response came back for port {port}. "
        "That often means a firewall or filter is silently dropping the traffic, or the path is otherwise blocked."
    )


def _dns_explanation(domain: str) -> str:
    return (
        f"A DNS lookup for {domain} can reveal intent even when later application traffic is encrypted. "
        "This is why metadata matters: observers may not see page content, but they can still learn where a device is trying to go."
    )


def _tls_explanation(target: str, trust_state: str) -> str:
    base = (
        f"A TLS certificate helps a client decide whether it is really talking to {target} or an impostor. "
        "The subject and issuer help describe identity, while the validity window helps show whether the certificate is current."
    )
    if trust_state == "hostname-mismatch":
        return base + " In this case, the certificate name does not appear to match the host you asked for, which is a classic hostname warning."
    if trust_state == "expired":
        return base + " In this case, the certificate appears to be outside its validity window, which usually means the certificate needs renewal."
    if trust_state == "self-signed":
        return base + " In this case, the certificate appears self-signed, which can be normal in a lab but requires extra trust decisions in real environments."
    return base + " In this case, nothing obvious stands out in the simplified trust interpretation."


def _http_explanation(headers: dict[str, str]) -> str:
    present = []
    missing = []
    tracked = {
        "strict-transport-security": "HSTS helps force HTTPS after trust is established.",
        "content-security-policy": "CSP can limit where scripts, frames, and other content may load from.",
        "x-content-type-options": "nosniff helps reduce MIME confusion issues.",
        "x-frame-options": "frame protections help reduce clickjacking risk.",
        "referrer-policy": "referrer policy can reduce how much navigation context leaks outward.",
    }
    for key, explanation in tracked.items():
        if key in headers:
            present.append(explanation)
        else:
            missing.append(key)

    parts = []
    if present:
        parts.append("Present protections: " + " ".join(present))
    if missing:
        parts.append("Missing tracked headers: " + ", ".join(missing) + ".")
    return " ".join(parts) if parts else "No tracked security header guidance available."


def _flatten_name(name_parts) -> str:
    pairs = []
    for group in name_parts:
        for key, value in group:
            pairs.append(f"{key}={value}")
    return ", ".join(pairs) if pairs else "unknown"


def _normalize_cert_time(value: str) -> str:
    if not value:
        return "unknown"
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return parsed.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return value


def _infer_live_trust_state(target: str, subject: str, issuer: str, valid_to: str) -> str:
    target_lower = target.casefold()
    subject_lower = subject.casefold()
    issuer_lower = issuer.casefold()

    if target_lower not in subject_lower:
        return "hostname-mismatch"
    if subject_lower == issuer_lower:
        return "self-signed"
    if _is_past(valid_to):
        return "expired"
    return "valid"


def _is_past(value: str) -> bool:
    if value == "unknown":
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed < datetime.now(timezone.utc)
    except ValueError:
        return False


def _interesting_http_header_lines(headers: dict[str, str]) -> list[str]:
    keys = [
        "strict-transport-security",
        "content-security-policy",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
    ]
    lines = []
    for key in keys:
        if key in headers:
            lines.append(f"{key}: {headers[key]}")
    return lines


def _load_scapy_all():
    try:
        return importlib.import_module("scapy.all")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Live ARP backend requires the optional 'scapy' dependency. "
            "Install with: pip install -e .[live]"
        ) from exc
