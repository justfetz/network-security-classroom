from pathlib import Path

from network_security_classroom import cli
from network_security_classroom.cli import run


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


def test_cli_rejects_invalid_tls_port(capsys):
    result = run(["lab", "tls", "--target", "example.com", "--port", "70000"])
    err = capsys.readouterr().err
    assert result == 1
    assert "Invalid port" in err


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
    result = run(["ask", "--status"])
    out = capsys.readouterr().out
    assert result == 0
    assert "Provider: local" in out
    assert "Config path:" in out


def test_cli_runs_ask_setup_with_provider_override(monkeypatch, capsys):
    monkeypatch.setattr(cli, "run_ask_setup", lambda provider_override=None: Path("C:/fake/.nsc/config.toml"))
    result = run(["ask", "--setup", "--provider", "local"])
    out = capsys.readouterr().out
    assert result == 0
    assert "Saved ask configuration" in out
