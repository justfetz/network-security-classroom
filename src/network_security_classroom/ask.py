"""Ask mode for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass
import json
from urllib import request

from .config import AskConfig
from .explore import get_topic, render_topic_summary
from .lessons import get_lesson
from .memory import RecentContext


@dataclass(frozen=True)
class AskResponse:
    answer: str
    source: str
    related_topics: tuple[str, ...]
    suggested_commands: tuple[str, ...]
    recent_context_note: str = ""


class AskProvider:
    def answer(self, question: str, recent_context: RecentContext | None = None) -> AskResponse:  # pragma: no cover - interface only
        raise NotImplementedError


class LocalAskProvider(AskProvider):
    def answer(self, question: str, recent_context: RecentContext | None = None) -> AskResponse:
        prompt = question.strip().casefold()
        lesson_slug, topic_slug = _resolve_local_targets(prompt)

        lesson = get_lesson(lesson_slug) if lesson_slug else None
        topic = get_topic(topic_slug) if topic_slug else None

        fragments = []
        related_topics: tuple[str, ...] = ()
        suggested_commands: tuple[str, ...] = ()
        recent_context_note = ""

        if lesson:
            fragments.append(f"Short answer:\n{lesson.summary}")
            fragments.append(f"Deeper view:\n{lesson.body}")
        if topic:
            fragments.append(f"Why it matters:\n{topic.why_it_matters}")
            related_topics = topic.related
            suggested_commands = topic.suggested_commands
        if not fragments:
            fragments.append(
                "Short answer:\nI could not map that cleanly to one topic yet. Try exploring hosts, handshake, "
                "metadata, tls, zero-day, or detection."
            )
            related_topics = ("hosts", "handshake", "metadata")
            suggested_commands = ("nsc explore topics", "nsc lesson list")
        if recent_context and _should_reference_recent_context(prompt, lesson_slug, topic_slug, recent_context):
            recent_context_note = _render_recent_context_note(recent_context)
            fragments.insert(0, f"Recent context:\n{recent_context_note}")
            if not suggested_commands:
                suggested_commands = recent_context.suggested_commands

        return AskResponse(
            answer="\n\n".join(fragments),
            source="local",
            related_topics=related_topics,
            suggested_commands=suggested_commands,
            recent_context_note=recent_context_note,
        )


class OpenAIAskProvider(AskProvider):
    def __init__(self, api_key: str, model: str = "") -> None:
        if not api_key:
            raise RuntimeError("OpenAI provider selected but OPENAI_API_KEY is not configured.")
        self.api_key = api_key
        self.model = model or "gpt-4.1-mini"

    def answer(self, question: str, recent_context: RecentContext | None = None) -> AskResponse:
        prompt = _build_remote_prompt(question, recent_context=recent_context)
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_INSTRUCTIONS},
                {"role": "user", "content": prompt},
            ],
        }
        response = _post_json(
            "https://api.openai.com/v1/chat/completions",
            payload,
            {"Authorization": f"Bearer {self.api_key}"},
        )
        text = response["choices"][0]["message"]["content"]
        return AskResponse(
            answer=text.strip(),
            source=f"openai:{self.model}",
            related_topics=(),
            suggested_commands=("nsc explore topics",),
            recent_context_note=_render_recent_context_note(recent_context) if recent_context else "",
        )


class HuggingFaceAskProvider(AskProvider):
    def __init__(self, api_key: str, model: str = "") -> None:
        if not api_key:
            raise RuntimeError("Hugging Face provider selected but HF_TOKEN is not configured.")
        self.api_key = api_key
        self.model = model or "meta-llama/Meta-Llama-3.1-8B-Instruct"

    def answer(self, question: str, recent_context: RecentContext | None = None) -> AskResponse:
        prompt = _build_remote_prompt(question, recent_context=recent_context)
        payload = {"inputs": prompt}
        response = _post_json(
            f"https://api-inference.huggingface.co/models/{self.model}",
            payload,
            {"Authorization": f"Bearer {self.api_key}"},
        )
        if isinstance(response, list) and response and "generated_text" in response[0]:
            text = response[0]["generated_text"]
        else:
            text = str(response)
        return AskResponse(
            answer=text.strip(),
            source=f"huggingface:{self.model}",
            related_topics=(),
            suggested_commands=("nsc explore topics",),
            recent_context_note=_render_recent_context_note(recent_context) if recent_context else "",
        )


def get_ask_provider(config: AskConfig) -> AskProvider:
    if config.provider == "local":
        return LocalAskProvider()
    if config.provider == "openai":
        return OpenAIAskProvider(api_key=config.openai_api_key, model=config.model)
    if config.provider == "huggingface":
        return HuggingFaceAskProvider(api_key=config.hf_api_key, model=config.model)
    raise ValueError(f"Unknown ask provider: {config.provider}")


def render_ask_response(response: AskResponse) -> str:
    lines = [response.answer, "", f"Source: {response.source}"]
    if response.recent_context_note:
        lines.extend(["", f"Recent context used: {response.recent_context_note}"])
    if response.related_topics:
        lines.extend(["", "Related topics:", *(f"- {topic}" for topic in response.related_topics)])
    if response.suggested_commands:
        lines.extend(["", "Try next:", *(f"- {cmd}" for cmd in response.suggested_commands)])
    return "\n".join(lines)


SYSTEM_INSTRUCTIONS = (
    "You are a defensive security mentor inside a terminal learning tool. "
    "Explain concepts clearly, avoid unsafe procedural attack instructions, "
    "and help the user connect ideas like networking, metadata, encryption, and detection."
)


def _resolve_local_targets(prompt: str) -> tuple[str | None, str | None]:
    if any(
        word in prompt
        for word in (
            "attacker mindset",
            "attacker-mindset",
            "what attackers look for",
            "what are attackers looking for",
            "exposure",
            "exploit chain",
            "misconfiguration",
        )
    ):
        return "attacker-mindset", "attacker-mindset"
    if any(word in prompt for word in ("zero-day", "zero day", "n-day", "patch")):
        return "zero-day", "zero-day"
    if any(word in prompt for word in ("metadata", "privacy", "visible", "dns")):
        return "tls-metadata", "metadata"
    if any(word in prompt for word in ("tls", "https", "encryption", "certificate")):
        return "tls-metadata", "tls"
    if any(word in prompt for word in ("handshake", "filtered", "closed", "open port")):
        return "handshake", "handshake"
    if any(word in prompt for word in ("host", "device", "reachable")):
        return "host", "hosts"
    if any(word in prompt for word in ("detect", "logging", "response")):
        return None, "detection"
    return None, None


def _build_remote_prompt(question: str, recent_context: RecentContext | None = None) -> str:
    context_parts = []
    for slug in ("attacker-mindset", "host", "handshake", "tls-metadata", "zero-day"):
        lesson = get_lesson(slug)
        if lesson:
            context_parts.append(f"{lesson.title}: {lesson.summary}")
    for slug in ("attacker-mindset", "metadata", "tls", "detection"):
        topic = get_topic(slug)
        if topic:
            context_parts.append(render_topic_summary(topic))
    context = "\n\n".join(context_parts)
    recent_context_block = ""
    if recent_context:
        recent_context_block = (
            "Recent learner context:\n"
            f"- kind: {recent_context.kind}\n"
            f"- slug: {recent_context.slug}\n"
            f"- title: {recent_context.title}\n"
            f"- summary: {recent_context.summary}\n"
            f"- suggested_commands: {', '.join(recent_context.suggested_commands)}\n\n"
        )
    return f"Project context:\n{context}\n\n{recent_context_block}User question:\n{question}"


def _should_reference_recent_context(
    prompt: str,
    lesson_slug: str | None,
    topic_slug: str | None,
    recent_context: RecentContext,
) -> bool:
    follow_up_markers = ("this", "that", "these", "those", "recent", "last", "just", "again")
    if any(marker in prompt for marker in follow_up_markers):
        return True
    if not lesson_slug and not topic_slug:
        return True
    return recent_context.slug in {lesson_slug, topic_slug}


def _render_recent_context_note(recent_context: RecentContext) -> str:
    return f"You recently explored {recent_context.title}. {recent_context.summary}"


def _post_json(url: str, payload: dict, extra_headers: dict[str, str]) -> dict | list:
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", **extra_headers},
    )
    with request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))
