"""Exploration mode for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass

from .content import load_markdown_documents, split_csv


@dataclass(frozen=True)
class ExploreTopic:
    slug: str
    title: str
    summary: str
    why_it_matters: str
    related: tuple[str, ...]
    suggested_commands: tuple[str, ...]


def list_topics() -> list[ExploreTopic]:
    return [TOPICS[key] for key in sorted(TOPICS)]


def get_topic(slug: str) -> ExploreTopic | None:
    return TOPICS.get(slug)


def render_topic_summary(topic: ExploreTopic) -> str:
    related = ", ".join(topic.related)
    commands = "\n".join(f"- {command}" for command in topic.suggested_commands)
    return (
        f"{topic.title}\n\n"
        f"{topic.summary}\n\n"
        f"Why it matters: {topic.why_it_matters}\n\n"
        f"Related topics: {related}\n\n"
        f"Try this next:\n{commands}"
    )


def suggest_next(slug: str) -> list[str]:
    topic = get_topic(slug)
    if not topic:
        raise ValueError(f"Unknown exploration topic: {slug}")
    return list(topic.related)


def render_welcome() -> str:
    return (
        "Network Security Classroom\n\n"
        "A defensive CLI for learning security in a curious, forgiving way.\n\n"
        "Start here:\n"
        "- nsc explore topics\n"
        "- nsc ask \"why does metadata matter?\"\n"
        "- nsc lesson list\n"
        "- nsc lab arp --range 192.168.1.0/24\n"
        "- nsc lab tcp --target 192.168.1.1 --port 443\n"
        "- nsc lab dns --demo-domain example.com\n\n"
        "You do not need to know the perfect question yet. Explore first."
    )


def _load_topics() -> dict[str, ExploreTopic]:
    topics = {}
    for document in load_markdown_documents("topics"):
        topic = ExploreTopic(
            slug=document.metadata["slug"],
            title=document.metadata["title"],
            summary=document.metadata["summary"],
            why_it_matters=document.metadata["why_it_matters"],
            related=split_csv(document.metadata.get("related", "")),
            suggested_commands=split_csv(document.metadata.get("commands", "")),
        )
        topics[topic.slug] = topic
    return topics


TOPICS = _load_topics()
