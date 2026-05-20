from pathlib import Path

from network_security_classroom import cli
from network_security_classroom.ask import get_ask_provider as real_get_ask_provider
from network_security_classroom.cli import run
from network_security_classroom.memory import create_recent_context


def test_cli_no_args_shows_welcome(capsys):
    result = run([])
    out = capsys.readouterr().out
    assert result == 0
    assert "Network Security Classroom" in out
    assert "nsc explore topics" in out


def test_cli_lists_lessons(capsys):
    result = run(["lesson", "list"])
    out = capsys.readouterr().out
    assert result == 0
    assert "host" in out
    assert "zero-day" in out
    assert "tls-metadata" in out


def test_cli_shows_unknown_lesson_error(capsys):
    result = run(["lesson", "show", "missing"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Unknown lesson: missing" in err


def test_cli_exports_notes(capsys):
    output = Path("tests") / "_tmp_handshake.md"
    if output.exists():
        output.unlink()
    result = run(["notes", "export", "--lesson", "handshake", "--output", str(output)])
    out = capsys.readouterr().out
    assert result == 0
    assert output.exists()
    assert "Exported notes to" in out
    output.unlink()


def test_cli_runs_arp_lab(capsys):
    result = run(["lab", "arp", "--range", "192.168.1.0/24"])
    out = capsys.readouterr().out
    assert result == 0
    assert "ARP backend: demo" in out
    assert "ARP discovery for 192.168.1.0/24" in out
    assert "likely gateway" in out


def test_cli_lesson_show_saves_recent_context(monkeypatch, capsys):
    captured = {}

    def fake_save_recent_context(context):
        captured["context"] = context

    monkeypatch.setattr(cli, "save_recent_context", fake_save_recent_context)
    result = run(["lesson", "show", "handshake"])
    out = capsys.readouterr().out
    assert result == 0
    assert "What Is a TCP Handshake?" in out
    assert captured["context"].slug == "handshake"
    assert captured["context"].kind == "lesson"


def test_cli_rejects_invalid_arp_range(capsys):
    result = run(["lab", "arp", "--range", "bad-range"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Invalid network range" in err


def test_cli_rejects_live_backend_without_scapy(capsys):
    result = run(["lab", "arp", "--range", "192.168.1.0/24", "--backend", "live"])
    err = capsys.readouterr().err
    assert result == 1
    assert "optional 'scapy' dependency" in err


def test_cli_runs_tcp_lab(capsys):
    result = run(["lab", "tcp", "--target", "192.168.1.1", "--port", "443"])
    out = capsys.readouterr().out
    assert result == 0
    assert "TCP backend: demo" in out
    assert "TCP handshake check for 192.168.1.1:443" in out
    assert "State: open" in out


def test_cli_runs_tcp_lab_with_closed_demo_state(capsys):
    result = run(
        ["lab", "tcp", "--target", "192.168.1.1", "--port", "443", "--demo-state", "closed"]
    )
    out = capsys.readouterr().out
    assert result == 0
    assert "State: closed" in out


def test_cli_rejects_invalid_tcp_port(capsys):
    result = run(["lab", "tcp", "--target", "192.168.1.1", "--port", "70000"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Invalid port" in err


def test_cli_rejects_live_tcp_backend_without_scapy(capsys):
    result = run(["lab", "tcp", "--target", "192.168.1.1", "--port", "443", "--backend", "live"])
    err = capsys.readouterr().err
    assert result == 1
    assert "optional 'scapy' dependency" in err


def test_cli_runs_dns_lab(capsys):
    result = run(["lab", "dns", "--demo-domain", "openai.com"])
    out = capsys.readouterr().out
    assert result == 0
    assert "DNS backend: demo" in out
    assert "Queried domain: openai.com" in out


def test_cli_rejects_invalid_demo_domain(capsys):
    result = run(["lab", "dns", "--demo-domain", "not a domain"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Invalid demo domain" in err


def test_cli_rejects_live_dns_backend_without_scapy(capsys):
    result = run(["lab", "dns", "--backend", "live"])
    err = capsys.readouterr().err
    assert result == 1
    assert "optional 'scapy' dependency" in err


def test_cli_runs_tls_lab(capsys):
    result = run(["lab", "tls", "--target", "example.com", "--port", "443"])
    out = capsys.readouterr().out
    assert result == 0
    assert "TLS backend: demo" in out
    assert "TLS certificate inspection for example.com:443" in out
    assert "Subject: CN=example.com" in out
    assert "Trust assessment: valid" in out


def test_cli_runs_tls_lab_with_hostname_mismatch(capsys):
    result = run(
        [
            "lab",
            "tls",
            "--target",
            "example.com",
            "--port",
            "443",
            "--demo-trust-state",
            "hostname-mismatch",
        ]
    )
    out = capsys.readouterr().out
    assert result == 0
    assert "Trust assessment: hostname-mismatch" in out


def test_cli_rejects_invalid_tls_port(capsys):
    result = run(["lab", "tls", "--target", "example.com", "--port", "70000"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Invalid port" in err


def test_cli_runs_http_lab(capsys):
    result = run(["lab", "http", "--url", "https://example.com"])
    out = capsys.readouterr().out
    assert result == 0
    assert "HTTP backend: demo" in out
    assert "HTTP header inspection for https://example.com" in out
    assert "strict-transport-security" in out


def test_cli_rejects_invalid_http_url(capsys):
    result = run(["lab", "http", "--url", "example.com"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Invalid URL" in err


def test_cli_lists_exploration_topics(capsys):
    result = run(["explore", "topics"])
    out = capsys.readouterr().out
    assert result == 0
    assert "metadata" in out
    assert "zero-day" in out


def test_cli_shows_exploration_topic(capsys):
    result = run(["explore", "topic", "metadata"])
    out = capsys.readouterr().out
    assert result == 0
    assert "Metadata and Visibility" in out
    assert "Why it matters" in out


def test_cli_suggests_next_topics(capsys):
    result = run(["explore", "next", "zero-day"])
    out = capsys.readouterr().out
    assert result == 0
    assert "If zero-day interests you" in out
    assert "- detection" in out


def test_cli_rejects_unknown_exploration_topic(capsys):
    result = run(["explore", "topic", "missing"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Unknown exploration topic: missing" in err


def test_cli_runs_local_ask_mode(capsys):
    result = run(["ask", "why does metadata matter?"])
    out = capsys.readouterr().out
    assert result == 0
    assert "Source: local" in out
    assert "Related topics:" in out


def test_cli_shows_ask_status(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "load_ask_config",
        lambda: cli.AskConfig(provider="local", model="", openai_api_key="", hf_api_key=""),
    )
    monkeypatch.setattr(cli, "get_config_path", lambda: Path("C:/fake/.nsc/config.toml"))
    monkeypatch.setattr(cli, "get_recent_context_path", lambda: Path("C:/fake/.nsc/recent_context.json"))
    monkeypatch.setattr(
        cli,
        "load_recent_context",
        lambda: create_recent_context(
            kind="lab",
            slug="tls",
            title="TLS Certificate Lab",
            summary="You inspected a certificate recently.",
        ),
    )
    result = run(["ask", "--status"])
    out = capsys.readouterr().out
    assert result == 0
    assert "Provider: local" in out
    assert "Config path:" in out
    assert "Recent context configured: yes" in out
    assert "Recent context title: TLS Certificate Lab" in out


def test_cli_runs_ask_setup_with_provider_override(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_ask_setup", lambda provider_override=None: Path("C:/fake/.nsc/config.toml"))
    result = run(["ask", "--setup", "--provider", "local"])
    out = capsys.readouterr().out
    assert result == 0
    assert "Saved ask configuration" in out


def test_cli_runs_ask_mode_with_recent_context(monkeypatch, capsys):
    class FakeProvider:
        def answer(self, question, recent_context=None):
            assert recent_context is not None
            assert recent_context.slug == "tcp"
            return real_get_ask_provider(cli.AskConfig(provider="local")).answer(question, recent_context=recent_context)

    monkeypatch.setattr(
        cli,
        "load_recent_context",
        lambda: create_recent_context(
            kind="lab",
            slug="tcp",
            title="TCP Handshake Lab",
            summary="You tested 192.168.1.1:443 and observed a filtered handshake state.",
        ),
    )
    monkeypatch.setattr(cli, "get_ask_provider", lambda config: FakeProvider())
    result = run(["ask", "what does that mean?"])
    out = capsys.readouterr().out
    assert result == 0
    assert "Recent context used:" in out
    assert "TCP Handshake Lab" in out
