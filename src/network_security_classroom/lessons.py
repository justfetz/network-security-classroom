"""Lesson registry for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Lesson:
    slug: str
    title: str
    summary: str
    body: str


LESSONS = {
    "host": Lesson(
        slug="host",
        title="What Is a Host?",
        summary="Understand what a host is and why it matters in networking and security.",
        body=(
            "A host is any device on a network that has an address and can send or receive traffic. "
            "That can be a laptop, phone, server, printer, switch management interface, or cloud VM.\n\n"
            "In security, hosts matter because they are the concrete systems that expose services, store "
            "data, and create logs. When someone says an attacker discovered a host, they usually mean "
            "the attacker found a real reachable system worth studying further."
        ),
    ),
    "handshake": Lesson(
        slug="handshake",
        title="What Is a TCP Handshake?",
        summary="Learn how two systems agree to talk before application data moves.",
        body=(
            "A TCP handshake is the opening agreement between two systems before a reliable connection starts. "
            "The common shorthand is SYN, SYN-ACK, ACK.\n\n"
            "That sequence matters because it tells you a lot. If you get a SYN-ACK back, something is listening. "
            "If you get a reset, the path may be open but nothing is listening on that port. If you get silence, "
            "a firewall or filter may be dropping the traffic.\n\n"
            "Security engineers use handshake behavior to reason about exposure, filtering, and service state."
        ),
    ),
    "zero-day": Lesson(
        slug="zero-day",
        title="What Is a Zero-Day?",
        summary="Break down what zero-day means without treating it like magic.",
        body=(
            "A zero-day is a vulnerability that is not yet publicly known or not yet patched when attackers start "
            "using it. The term does not mean unstoppable. It means defenders have little or no patch lead time.\n\n"
            "What matters in practice is not just the bug, but the whole situation around it: who can reach the system, "
            "what privileges the vulnerable component has, what monitoring exists, and how quickly the organization can "
            "contain blast radius.\n\n"
            "A mature security mindset treats zero-days as one part of a chain. Good isolation, least privilege, logging, "
            "and fast response still matter even when a patch does not exist yet."
        ),
    ),
    "tls-metadata": Lesson(
        slug="tls-metadata",
        title="TLS, Encryption, and Metadata",
        summary="Understand what TLS protects and what it still leaves visible to observers.",
        body=(
            "TLS is designed to protect the content of communication in transit. It helps keep passwords, page contents, "
            "tokens, and application data private from casual interception.\n\n"
            "But TLS does not hide everything. Observers can often still see who is talking, when they talk, how often they "
            "talk, and other surrounding details such as DNS lookups, destination IPs, timing, and traffic volume.\n\n"
            "That difference between content and metadata is one of the most important ideas in modern security. Encryption "
            "is powerful, but it is not the same thing as invisibility."
        ),
    ),
}


def list_lessons() -> list[Lesson]:
    return [LESSONS[key] for key in sorted(LESSONS)]


def get_lesson(slug: str) -> Lesson | None:
    return LESSONS.get(slug)
