import json

from network_security_classroom.ask import (
    AskConfig,
    HuggingFaceAskProvider,
    OpenAIAskProvider,
    _build_remote_prompt,
    get_ask_provider,
    render_ask_response,
)
from network_security_classroom.memory import create_recent_context


def test_local_ask_provider_answers_metadata_question():
    provider = get_ask_provider(AskConfig(provider="local"))
    response = provider.answer("why does metadata matter?")
    assert response.source == "local"
    assert "metadata" in response.answer.casefold()
    assert "nsc lesson show tls-metadata" in response.suggested_commands


def test_local_ask_provider_answers_zero_day_question():
    provider = get_ask_provider(AskConfig(provider="local"))
    response = provider.answer("what is a zero-day?")
    assert "zero-day" in response.answer.casefold()
    assert "detection" in response.related_topics


def test_remote_provider_requires_key():
    try:
        get_ask_provider(AskConfig(provider="openai"))
    except RuntimeError as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:
        raise AssertionError("Expected RuntimeError")


def test_render_ask_response_includes_source_and_related_topics():
    provider = get_ask_provider(AskConfig(provider="local"))
    response = provider.answer("what is a host?")
    text = render_ask_response(response)
    assert "Source: local" in text
    assert "Related topics:" in text


def test_local_ask_provider_falls_back_for_unknown_question():
    provider = get_ask_provider(AskConfig(provider="local"))
    response = provider.answer("tell me something weird and unrelated")
    assert "could not map that cleanly" in response.answer
    assert "nsc explore topics" in response.suggested_commands


def test_unknown_provider_raises_value_error():
    try:
        get_ask_provider(AskConfig(provider="mystery"))
    except ValueError as exc:
        assert "Unknown ask provider" in str(exc)
    else:
        raise AssertionError("Expected ValueError")


def test_build_remote_prompt_includes_project_context():
    prompt = _build_remote_prompt("why does tls matter?")
    assert "Project context:" in prompt
    assert "TLS, Encryption, and Metadata" in prompt


def test_build_remote_prompt_includes_recent_context():
    recent_context = create_recent_context(
        kind="lab",
        slug="tcp",
        title="TCP Handshake Lab",
        summary="You tested 192.168.1.1:443 and observed an open handshake state.",
    )
    prompt = _build_remote_prompt("what does that mean?", recent_context=recent_context)
    assert "Recent learner context:" in prompt
    assert "TCP Handshake Lab" in prompt


def test_local_ask_provider_uses_recent_context_for_follow_up():
    provider = get_ask_provider(AskConfig(provider="local"))
    recent_context = create_recent_context(
        kind="lab",
        slug="tcp",
        title="TCP Handshake Lab",
        summary="You tested 192.168.1.1:443 and observed a filtered handshake state.",
    )
    response = provider.answer("what does that mean?", recent_context=recent_context)
    assert "Recent context:" in response.answer
    assert "TCP Handshake Lab" in response.answer
    assert response.recent_context_note


def test_render_ask_response_includes_recent_context_note():
    provider = get_ask_provider(AskConfig(provider="local"))
    recent_context = create_recent_context(
        kind="explore",
        slug="metadata",
        title="Metadata and Visibility",
        summary="You explored how metadata can reveal intent around encrypted traffic.",
    )
    response = provider.answer("tell me more", recent_context=recent_context)
    text = render_ask_response(response)
    assert "Recent context used:" in text
    assert "Metadata and Visibility" in text


def test_openai_provider_uses_mocked_response(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {"choices": [{"message": {"content": "Short answer: mocked openai response"}}]}
            ).encode("utf-8")

    monkeypatch.setattr("network_security_classroom.ask.request.urlopen", lambda *args, **kwargs: FakeResponse())
    provider = OpenAIAskProvider(api_key="key-1", model="demo-openai")
    response = provider.answer("what is metadata?")
    assert response.source == "openai:demo-openai"
    assert "mocked openai response" in response.answer


def test_huggingface_provider_uses_mocked_response(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps([{"generated_text": "Mocked hugging face response"}]).encode("utf-8")

    monkeypatch.setattr("network_security_classroom.ask.request.urlopen", lambda *args, **kwargs: FakeResponse())
    provider = HuggingFaceAskProvider(api_key="hf-1", model="demo-hf")
    response = provider.answer("what is dns metadata?")
    assert response.source == "huggingface:demo-hf"
    assert "Mocked hugging face response" in response.answer
