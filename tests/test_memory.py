from pathlib import Path

from network_security_classroom.memory import (
    create_recent_context,
    get_recent_context_path,
    load_recent_context,
    save_recent_context,
)


def test_save_and_load_recent_context_round_trip():
    home = Path("tests") / "_tmp_home_memory"
    if home.exists():
        for child in sorted(home.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        home.rmdir()

    context = create_recent_context(
        kind="lab",
        slug="tls",
        title="TLS Certificate Lab",
        summary="You inspected a certificate and saw a hostname mismatch warning.",
        suggested_commands=("nsc ask \"why does hostname mismatch matter?\"",),
    )
    path = save_recent_context(context, home=home)
    assert path == get_recent_context_path(home)

    loaded = load_recent_context(home=home)
    assert loaded is not None
    assert loaded.kind == "lab"
    assert loaded.slug == "tls"
    assert loaded.title == "TLS Certificate Lab"
    assert "hostname mismatch" in loaded.summary
    assert loaded.suggested_commands == ("nsc ask \"why does hostname mismatch matter?\"",)

    for child in sorted(home.rglob("*"), reverse=True):
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            child.rmdir()


def test_load_recent_context_returns_none_when_missing():
    home = Path("tests") / "_tmp_home_missing_memory"
    if home.exists():
        for child in sorted(home.rglob("*"), reverse=True):
            if child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
        home.rmdir()

    assert load_recent_context(home=home) is None
