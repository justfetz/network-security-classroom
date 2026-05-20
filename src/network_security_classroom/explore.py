"""Exploration mode for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExploreTopic:
    slug: str
    title: str
    summary: str
    why_it_matters: str
    related: tuple[str, ...]
    suggested_commands: tuple[str, ...]


TOPICS = {
    "hosts": ExploreTopic(
        slug="hosts",
        title="Hosts and Reachability",
        summary="Understand what devices exist on a network and why reachability is the first question in security.",
        why_it_matters="Security starts with knowing what is actually there and whether it can be reached.",
        related=("handshake", "firewalls", "metadata"),
        suggested_commands=("nsc lesson show host", "nsc lab arp --range 192.168.1.0/24"),
    ),
    "handshake": ExploreTopic(
        slug="handshake",
        title="TCP Handshakes",
        summary="See how systems agree to talk and what open, closed, or filtered really mean.",
        why_it_matters="Handshake behavior helps you reason about service exposure, filtering, and basic troubleshooting.",
        related=("hosts", "firewalls", "services"),
        suggested_commands=("nsc lesson show handshake", "nsc lab tcp --target 192.168.1.1 --port 443"),
    ),
    "metadata": ExploreTopic(
        slug="metadata",
        title="Metadata and Visibility",
        summary="Learn how observers can infer intent even when content is encrypted.",
        why_it_matters="A lot of real-world security and privacy risk comes from what traffic reveals around the content.",
        related=("dns", "tls", "zero-day"),
        suggested_commands=("nsc lab dns --demo-domain example.com", "nsc lesson show tls-metadata"),
    ),
    "dns": ExploreTopic(
        slug="dns",
        title="DNS Lookups",
        summary="Study how domain lookups expose destinations and user intent.",
        why_it_matters="DNS is often the first breadcrumb that reveals where a device is trying to go.",
        related=("metadata", "tls", "hosts"),
        suggested_commands=("nsc lab dns --demo-domain openai.com",),
    ),
    "firewalls": ExploreTopic(
        slug="firewalls",
        title="Filtering and Firewalls",
        summary="Understand how traffic gets allowed, rejected, or silently dropped.",
        why_it_matters="A lot of security behavior only makes sense when you can distinguish open, closed, and filtered paths.",
        related=("handshake", "services", "hosts"),
        suggested_commands=("nsc lab tcp --target 192.168.1.1 --port 443 --demo-state filtered",),
    ),
    "tls": ExploreTopic(
        slug="tls",
        title="TLS and Encryption",
        summary="Understand what encryption protects and what it does not protect.",
        why_it_matters="People often assume encryption hides everything. In practice, metadata still matters a lot.",
        related=("metadata", "dns", "zero-day"),
        suggested_commands=("nsc lesson show tls-metadata", "nsc explore topic metadata"),
    ),
    "zero-day": ExploreTopic(
        slug="zero-day",
        title="Zero-Days and Exposure",
        summary="Break down what zero-days mean without treating them like magic.",
        why_it_matters="Modern security is often about reducing blast radius and understanding chains, not just patching one bug.",
        related=("tls", "metadata", "detection"),
        suggested_commands=("nsc lesson show zero-day",),
    ),
    "services": ExploreTopic(
        slug="services",
        title="Ports and Services",
        summary="Connect port behavior to the real applications that may or may not be listening.",
        why_it_matters="Ports are not interesting by themselves; they matter because services and protocols live behind them.",
        related=("handshake", "firewalls", "hosts"),
        suggested_commands=("nsc lab tcp --target 192.168.1.1 --port 443 --demo-state open",),
    ),
    "detection": ExploreTopic(
        slug="detection",
        title="Detection and Response",
        summary="Start thinking like a defender who notices patterns, logs, and strange behavior.",
        why_it_matters="Security is not just about preventing bad things. It is also about seeing them quickly and responding well.",
        related=("zero-day", "metadata", "dns"),
        suggested_commands=("nsc explore next zero-day",),
    ),
}


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
        "- nsc lesson list\n"
        "- nsc lab arp --range 192.168.1.0/24\n"
        "- nsc lab tcp --target 192.168.1.1 --port 443\n"
        "- nsc lab dns --demo-domain example.com\n\n"
        "You do not need to know the perfect question yet. Explore first."
    )
