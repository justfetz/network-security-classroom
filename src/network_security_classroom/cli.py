"""CLI entrypoint for Network Security Classroom."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .explore import get_topic, list_topics, render_topic_summary, render_welcome, suggest_next
from .labs import (
    render_arp_summary,
    render_dns_summary,
    render_tcp_summary,
    run_arp_discovery,
    run_dns_observation,
    run_tcp_handshake,
)
from .lessons import get_lesson, list_lessons
from .notes import (
    export_arp_markdown,
    export_dns_markdown,
    export_lesson_markdown,
    export_tcp_markdown,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nsc",
        description="A defensive CLI for learning networking and modern security concepts.",
    )
    subparsers = parser.add_subparsers(dest="command")

    lesson_parser = subparsers.add_parser("lesson", help="List or show lessons")
    lesson_subparsers = lesson_parser.add_subparsers(dest="lesson_command")

    lesson_subparsers.add_parser("list", help="List available lessons")

    show_parser = lesson_subparsers.add_parser("show", help="Show one lesson")
    show_parser.add_argument("slug", help="Lesson slug to display")

    notes_parser = subparsers.add_parser("notes", help="Export lesson notes")
    notes_subparsers = notes_parser.add_subparsers(dest="notes_command")

    export_parser = notes_subparsers.add_parser("export", help="Export one lesson as Markdown")
    export_parser.add_argument("--lesson", required=True, help="Lesson slug to export")
    export_parser.add_argument("--output", help="Optional output path")

    lab_parser = subparsers.add_parser("lab", help="Run safe lab exercises")
    lab_subparsers = lab_parser.add_subparsers(dest="lab_command")

    arp_parser = lab_subparsers.add_parser("arp", help="Run a safe ARP discovery exercise")
    arp_parser.add_argument("--range", required=True, dest="network_range", help="Subnet range to scan")
    arp_parser.add_argument(
        "--backend",
        default="demo",
        choices=["demo", "live"],
        help="ARP backend to use. Default is the safe deterministic demo backend.",
    )
    arp_parser.add_argument("--output", help="Optional Markdown output path")

    tcp_parser = lab_subparsers.add_parser("tcp", help="Run a safe TCP handshake exercise")
    tcp_parser.add_argument("--target", required=True, help="Target host or IP address")
    tcp_parser.add_argument("--port", required=True, help="Target TCP port")
    tcp_parser.add_argument(
        "--backend",
        default="demo",
        choices=["demo", "live"],
        help="TCP backend to use. Default is the safe deterministic demo backend.",
    )
    tcp_parser.add_argument(
        "--demo-state",
        default="open",
        choices=["open", "closed", "filtered"],
        help="State to simulate when using the demo backend.",
    )
    tcp_parser.add_argument("--output", help="Optional Markdown output path")

    dns_parser = lab_subparsers.add_parser("dns", help="Run a safe DNS metadata exercise")
    dns_parser.add_argument(
        "--backend",
        default="demo",
        choices=["demo", "live"],
        help="DNS backend to use. Default is the safe deterministic demo backend.",
    )
    dns_parser.add_argument(
        "--demo-domain",
        default="example.com",
        help="Domain to simulate when using the demo backend.",
    )
    dns_parser.add_argument("--output", help="Optional Markdown output path")

    explore_parser = subparsers.add_parser("explore", help="Browse topics and next-step suggestions")
    explore_subparsers = explore_parser.add_subparsers(dest="explore_command")

    explore_subparsers.add_parser("topics", help="List exploration topics")

    topic_parser = explore_subparsers.add_parser("topic", help="Show one exploration topic")
    topic_parser.add_argument("slug", help="Topic slug to display")

    next_parser = explore_subparsers.add_parser("next", help="Suggest related next topics")
    next_parser.add_argument("slug", help="Topic slug to branch from")

    return parser


def run(argv: list[str] | None = None) -> int:
    if not argv:
        print(render_welcome())
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "lesson" and args.lesson_command == "list":
        for lesson in list_lessons():
            print(f"{lesson.slug:<12} {lesson.title}")
        return 0

    if args.command == "lesson" and args.lesson_command == "show":
        lesson = get_lesson(args.slug)
        if not lesson:
            print(f"Unknown lesson: {args.slug}", file=sys.stderr)
            return 1
        print(lesson.title)
        print()
        print(lesson.summary)
        print()
        print(lesson.body)
        return 0

    if args.command == "notes" and args.notes_command == "export":
        lesson = get_lesson(args.lesson)
        if not lesson:
            print(f"Unknown lesson: {args.lesson}", file=sys.stderr)
            return 1
        path = export_lesson_markdown(lesson, args.output)
        print(f"Exported notes to {Path(path).resolve()}")
        return 0

    if args.command == "lab" and args.lab_command == "arp":
        try:
            result = run_arp_discovery(args.network_range, backend_name=args.backend)
        except (ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"ARP backend: {args.backend}")
        print()
        print(render_arp_summary(result))
        if args.output:
            path = export_arp_markdown(result, args.output)
            print()
            print(f"Exported notes to {Path(path).resolve()}")
        return 0

    if args.command == "lab" and args.lab_command == "tcp":
        try:
            result = run_tcp_handshake(
                args.target,
                args.port,
                backend_name=args.backend,
                demo_state=args.demo_state,
            )
        except (ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"TCP backend: {args.backend}")
        print()
        print(render_tcp_summary(result))
        if args.output:
            path = export_tcp_markdown(result, args.output)
            print()
            print(f"Exported notes to {Path(path).resolve()}")
        return 0

    if args.command == "lab" and args.lab_command == "dns":
        try:
            result = run_dns_observation(
                backend_name=args.backend,
                demo_domain=args.demo_domain,
            )
        except (ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"DNS backend: {args.backend}")
        print()
        print(render_dns_summary(result))
        if args.output:
            path = export_dns_markdown(result, args.output)
            print()
            print(f"Exported notes to {Path(path).resolve()}")
        return 0

    if args.command == "explore" and args.explore_command == "topics":
        for topic in list_topics():
            print(f"{topic.slug:<12} {topic.title}")
        return 0

    if args.command == "explore" and args.explore_command == "topic":
        topic = get_topic(args.slug)
        if not topic:
            print(f"Unknown exploration topic: {args.slug}", file=sys.stderr)
            return 1
        print(render_topic_summary(topic))
        return 0

    if args.command == "explore" and args.explore_command == "next":
        try:
            topics = suggest_next(args.slug)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(f"If {args.slug} interests you, explore these next:")
        print()
        for topic in topics:
            print(f"- {topic}")
        return 0

    parser.print_help()
    return 1


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
