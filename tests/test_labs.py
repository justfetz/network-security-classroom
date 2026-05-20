from network_security_classroom.labs import (
    ArpDevice,
    ArpScanResult,
    DemoDnsBackend,
    DemoArpBackend,
    DemoHttpBackend,
    DemoTlsBackend,
    DemoTcpBackend,
    DnsObservationResult,
    HttpHeaderResult,
    LiveArpBackend,
    LiveDnsBackend,
    LiveHttpBackend,
    LiveTlsBackend,
    LiveTcpBackend,
    TlsCertificateResult,
    TcpHandshakeResult,
    get_arp_backend,
    get_dns_backend,
    get_http_backend,
    get_tls_backend,
    get_tcp_backend,
    render_arp_markdown,
    render_arp_summary,
    render_dns_markdown,
    render_dns_summary,
    render_http_markdown,
    render_http_summary,
    render_tls_markdown,
    render_tls_summary,
    render_tcp_markdown,
    render_tcp_summary,
    run_arp_discovery,
    run_dns_observation,
    run_http_inspection,
    run_tls_inspection,
    run_tcp_handshake,
    validate_demo_domain,
    validate_demo_trust_state,
    validate_demo_tcp_state,
    validate_network_range,
    validate_port,
    validate_target_host,
    validate_url,
)


def test_validate_network_range_normalizes_subnet():
    assert validate_network_range("192.168.1.14/24") == "192.168.1.0/24"


def test_validate_network_range_rejects_bad_input():
    try:
        validate_network_range("not-a-network")
    except ValueError as exc:
        assert "Invalid network range" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_run_arp_discovery_returns_demo_devices():
    result = run_arp_discovery("192.168.1.0/24")
    assert result.network == "192.168.1.0/24"
    assert len(result.devices) == 2


def test_get_arp_backend_returns_demo_backend():
    backend = get_arp_backend("demo")
    assert isinstance(backend, DemoArpBackend)


def test_get_arp_backend_returns_live_backend():
    backend = get_arp_backend("live")
    assert isinstance(backend, LiveArpBackend)


def test_get_arp_backend_rejects_unknown_backend():
    try:
        get_arp_backend("weird")
    except ValueError as exc:
        assert "Unknown ARP backend" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_live_backend_errors_cleanly_without_scapy():
    try:
        run_arp_discovery("192.168.1.0/24", backend_name="live")
    except RuntimeError as exc:
        assert "optional 'scapy' dependency" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")


def test_validate_target_host_rejects_blank():
    try:
        validate_target_host("   ")
    except ValueError as exc:
        assert "cannot be blank" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_validate_port_accepts_and_rejects_values():
    assert validate_port("443") == 443
    try:
        validate_port("70000")
    except ValueError as exc:
        assert "Invalid port" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_validate_demo_tcp_state_rejects_bad_value():
    try:
        validate_demo_tcp_state("weird")
    except ValueError as exc:
        assert "Invalid demo TCP state" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_get_tcp_backend_returns_demo_backend():
    backend = get_tcp_backend("demo")
    assert isinstance(backend, DemoTcpBackend)


def test_get_tcp_backend_returns_live_backend():
    backend = get_tcp_backend("live")
    assert isinstance(backend, LiveTcpBackend)


def test_run_tcp_handshake_demo_open():
    result = run_tcp_handshake("192.168.1.1", 443, backend_name="demo", demo_state="open")
    assert result.state == "open"
    assert "service is listening" in result.explanation


def test_run_tcp_handshake_demo_filtered():
    result = run_tcp_handshake("192.168.1.1", 443, backend_name="demo", demo_state="filtered")
    assert result.state == "filtered"
    assert "firewall or filter" in result.explanation


def test_run_tcp_handshake_live_errors_cleanly_without_scapy():
    try:
        run_tcp_handshake("192.168.1.1", 443, backend_name="live")
    except RuntimeError as exc:
        assert "optional 'scapy' dependency" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")


def test_render_tcp_summary_and_markdown():
    result = TcpHandshakeResult(
        target="192.168.1.1",
        port=443,
        state="closed",
        explanation="The host is reachable, but this specific service door is shut.",
    )
    summary = render_tcp_summary(result)
    markdown = render_tcp_markdown(result)
    assert "State: closed" in summary
    assert "Target: `192.168.1.1`" in markdown


def test_validate_demo_domain_rejects_bad_value():
    try:
        validate_demo_domain("not a domain")
    except ValueError as exc:
        assert "Invalid demo domain" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_get_dns_backend_returns_demo_backend():
    backend = get_dns_backend("demo")
    assert isinstance(backend, DemoDnsBackend)


def test_get_dns_backend_returns_live_backend():
    backend = get_dns_backend("live")
    assert isinstance(backend, LiveDnsBackend)


def test_run_dns_observation_demo():
    result = run_dns_observation(backend_name="demo", demo_domain="openai.com")
    assert result.queried_domain == "openai.com"
    assert "metadata matters" in result.explanation


def test_run_dns_observation_live_errors_cleanly_without_scapy():
    try:
        run_dns_observation(backend_name="live")
    except RuntimeError as exc:
        assert "optional 'scapy' dependency" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")


def test_render_dns_summary_and_markdown():
    result = DnsObservationResult(
        source_host="192.168.1.25",
        queried_domain="example.com",
        transport="udp/53",
        explanation="Observers can see the lookup target.",
    )
    summary = render_dns_summary(result)
    markdown = render_dns_markdown(result)
    assert "Queried domain: example.com" in summary
    assert "Queried domain: `example.com`" in markdown


def test_get_tls_backend_returns_demo_backend():
    backend = get_tls_backend("demo")
    assert isinstance(backend, DemoTlsBackend)


def test_get_tls_backend_returns_live_backend():
    backend = get_tls_backend("live")
    assert isinstance(backend, LiveTlsBackend)


def test_run_tls_inspection_demo():
    result = run_tls_inspection("example.com", 443, backend_name="demo")
    assert result.subject == "CN=example.com"
    assert "identity" in result.explanation
    assert result.trust_state == "valid"


def test_run_tls_inspection_demo_hostname_mismatch():
    result = run_tls_inspection(
        "example.com",
        443,
        backend_name="demo",
        demo_trust_state="hostname-mismatch",
    )
    assert result.trust_state == "hostname-mismatch"
    assert "does not appear to match" in result.explanation


def test_validate_demo_trust_state_rejects_bad_value():
    try:
        validate_demo_trust_state("strange")
    except ValueError as exc:
        assert "Invalid demo trust state" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_render_tls_summary_and_markdown():
    result = TlsCertificateResult(
        target="example.com",
        port=443,
        subject="CN=example.com",
        issuer="CN=Demo CA",
        valid_from="2026-01-01T00:00:00Z",
        valid_to="2027-01-01T00:00:00Z",
        trust_state="valid",
        explanation="A certificate helps establish identity.",
    )
    summary = render_tls_summary(result)
    markdown = render_tls_markdown(result)
    assert "Subject: CN=example.com" in summary
    assert "Issuer: `CN=Demo CA`" in markdown
    assert "Trust assessment: valid" in summary


def test_validate_url_rejects_non_http_scheme():
    try:
        validate_url("example.com")
    except ValueError as exc:
        assert "Invalid URL" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_get_http_backend_returns_demo_backend():
    backend = get_http_backend("demo")
    assert isinstance(backend, DemoHttpBackend)


def test_get_http_backend_returns_live_backend():
    backend = get_http_backend("live")
    assert isinstance(backend, LiveHttpBackend)


def test_run_http_inspection_demo():
    result = run_http_inspection("https://example.com", backend_name="demo")
    assert result.status_code == 200
    assert "strict-transport-security" in result.headers
    assert "Present protections" in result.explanation


def test_render_http_summary_and_markdown():
    result = HttpHeaderResult(
        url="https://example.com",
        status_code=200,
        headers={"strict-transport-security": "max-age=31536000"},
        explanation="Present protections: HSTS helps force HTTPS after trust is established.",
    )
    summary = render_http_summary(result)
    markdown = render_http_markdown(result)
    assert "Status: 200" in summary
    assert "strict-transport-security" in markdown


def test_render_arp_summary_includes_role_hints():
    result = ArpScanResult(
        network="192.168.1.0/24",
        devices=[ArpDevice(ip="192.168.1.1", mac="AA:BB", role_hint="likely gateway")],
    )
    text = render_arp_summary(result)
    assert "likely gateway" in text


def test_render_arp_markdown_contains_network_and_devices():
    result = ArpScanResult(
        network="192.168.1.0/24",
        devices=[ArpDevice(ip="192.168.1.10", mac="DE:AD", role_hint="active client")],
    )
    text = render_arp_markdown(result)
    assert "Network: `192.168.1.0/24`" in text
    assert "`192.168.1.10`" in text
