"""CLI entrypoint for Network Security Classroom."""

from __future__ import annotations

import argparse
from collections.abc import Callable
from pathlib import Path
import ssl
import sys
from typing import Any

from .ask import get_ask_provider, render_ask_response
from .config import AskConfig, get_config_path, load_ask_config, save_ask_config
from .explore import get_topic, list_topics, render_topic_summary, render_welcome, suggest_next
from .labs import (
    render_arp_summary,
    render_dns_summary,
    render_http_summary,
    render_tls_summary,
    render_tcp_summary,
    run_arp_discovery,
    run_dns_observation,
    run_http_inspection,
    run_tls_inspection,
    run_tcp_handshake,
)
from .lessons import get_lesson, list_lessons
from .memory import create_recent_context, get_recent_context_path, load_recent_context, save_recent_context
from .notes import (
    export_arp_markdown,
    export_dns_markdown,
    export_http_markdown,
    export_lesson_markdown,
    export_tls_markdown,
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

    tls_parser = lab_subparsers.add_parser("tls", help="Inspect a TLS certificate in a safe learning flow")
    tls_parser.add_argument("--target", required=True, help="Target host or IP address")
    tls_parser.add_argument("--port", required=True, help="Target TLS port")
    tls_parser.add_argument(
        "--backend",
        default="demo",
        choices=["demo", "live"],
        help="TLS backend to use. Default is the safe deterministic demo backend.",
    )
    tls_parser.add_argument(
        "--demo-trust-state",
        default="valid",
        choices=["valid", "hostname-mismatch", "expired", "self-signed"],
        help="Trust scenario to simulate when using the demo backend.",
    )
    tls_parser.add_argument("--output", help="Optional Markdown output path")

    http_parser = lab_subparsers.add_parser("http", help="Inspect HTTP security headers")
    http_parser.add_argument("--url", required=True, help="Target URL to inspect")
    http_parser.add_argument(
        "--backend",
        default="demo",
        choices=["demo", "live"],
        help="HTTP backend to use. Default is the safe deterministic demo backend.",
    )
    http_parser.add_argument("--output", help="Optional Markdown output path")

    explore_parser = subparsers.add_parser("explore", help="Browse topics and next-step suggestions")
    explore_subparsers = explore_parser.add_subparsers(dest="explore_command")

    explore_subparsers.add_parser("topics", help="List exploration topics")

    topic_parser = explore_subparsers.add_parser("topic", help="Show one exploration topic")
    topic_parser.add_argument("slug", help="Topic slug to display")

    next_parser = explore_subparsers.add_parser("next", help="Suggest related next topics")
    next_parser.add_argument("slug", help="Topic slug to branch from")

    ask_parser = subparsers.add_parser("ask", help="Ask a security question in plain English")
    ask_parser.add_argument("question", nargs="?", help="Plain-English question to ask")
    ask_parser.add_argument(
        "--setup",
        action="store_true",
        help="Configure an optional remote ask provider",
    )
    ask_parser.add_argument(
        "--status",
        action="store_true",
        help="Show current ask provider status",
    )
    ask_parser.add_argument(
        "--provider",
        choices=["local", "openai", "huggingface"],
        help="Provider override used with --setup",
    )

    return parser


def run(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print(render_welcome())
        return 0

    parser = build_parser()
    args = parser.parse_args(argv)
    handler = _dispatch_table().get(_command_key(args))
    if handler:
        return handler(args)

    parser.print_help()
    return 1


CommandHandler = Callable[[argparse.Namespace], int]


def _command_key(args: argparse.Namespace) -> tuple[str | None, str | None]:
    subcommand = None
    for name in ("lesson_command", "notes_command", "lab_command", "explore_command"):
        value = getattr(args, name, None)
        if value:
            subcommand = value
            break
    return args.command, subcommand


def _dispatch_table() -> dict[tuple[str | None, str | None], CommandHandler]:
    return {
        ("lesson", "list"): _handle_lesson_list,
        ("lesson", "show"): _handle_lesson_show,
        ("notes", "export"): _handle_notes_export,
        ("lab", "arp"): _handle_lab_arp,
        ("lab", "tcp"): _handle_lab_tcp,
        ("lab", "dns"): _handle_lab_dns,
        ("lab", "tls"): _handle_lab_tls,
        ("lab", "http"): _handle_lab_http,
        ("explore", "topics"): _handle_explore_topics,
        ("explore", "topic"): _handle_explore_topic,
        ("explore", "next"): _handle_explore_next,
        ("ask", None): _handle_ask,
    }


def _handle_lesson_list(args: argparse.Namespace) -> int:
    del args
    for lesson in list_lessons():
        print(f"{lesson.slug:<18} {lesson.title}")
    return 0


def _handle_lesson_show(args: argparse.Namespace) -> int:
    lesson = get_lesson(args.slug)
    if not lesson:
        print(f"Unknown lesson: {args.slug}", file=sys.stderr)
        return 1
    print(lesson.title)
    print()
    print(lesson.summary)
    print()
    print(lesson.body)
    _remember_recent_context(
        create_recent_context(
            kind="lesson",
            slug=lesson.slug,
            title=lesson.title,
            summary=lesson.summary,
            suggested_commands=(f"nsc notes export --lesson {lesson.slug}", 'nsc ask "why does this matter?"'),
        )
    )
    return 0


def _handle_notes_export(args: argparse.Namespace) -> int:
    lesson = get_lesson(args.lesson)
    if not lesson:
        print(f"Unknown lesson: {args.lesson}", file=sys.stderr)
        return 1
    path = export_lesson_markdown(lesson, args.output)
    print(f"Exported notes to {Path(path).resolve()}")
    return 0


def _handle_lab_arp(args: argparse.Namespace) -> int:
    try:
        result = run_arp_discovery(args.network_range, backend_name=args.backend)
    except (ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"ARP backend: {args.backend}")
    print()
    print(render_arp_summary(result))
    _remember_recent_context(
        create_recent_context(
            kind="lab",
            slug="arp",
            title="ARP Discovery Lab",
            summary=f"You scanned {result.network} and found {len(result.devices)} responding host(s).",
            suggested_commands=("nsc explore topic hosts", 'nsc ask "what does arp actually tell me?"'),
        )
    )
    _export_if_requested(args.output, export_arp_markdown, result)
    return 0


def _handle_lab_tcp(args: argparse.Namespace) -> int:
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
    _remember_recent_context(
        create_recent_context(
            kind="lab",
            slug="tcp",
            title="TCP Handshake Lab",
            summary=f"You tested {result.target}:{result.port} and observed a {result.state} handshake state.",
            suggested_commands=(
                f"nsc lab tcp --target {result.target} --port {result.port} --demo-state filtered",
                'nsc ask "what does this state mean?"',
            ),
        )
    )
    _export_if_requested(args.output, export_tcp_markdown, result)
    return 0


def _handle_lab_dns(args: argparse.Namespace) -> int:
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
    _remember_recent_context(
        create_recent_context(
            kind="lab",
            slug="dns",
            title="DNS Metadata Lab",
            summary=f"You observed a DNS lookup for {result.queried_domain} over {result.transport}.",
            suggested_commands=("nsc explore topic metadata", 'nsc ask "why does dns still matter if traffic is encrypted?"'),
        )
    )
    _export_if_requested(args.output, export_dns_markdown, result)
    return 0


def _handle_lab_tls(args: argparse.Namespace) -> int:
    try:
        result = run_tls_inspection(
            args.target,
            args.port,
            backend_name=args.backend,
            demo_trust_state=args.demo_trust_state,
        )
    except (ValueError, RuntimeError, OSError, ssl.SSLError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"TLS backend: {args.backend}")
    print()
    print(render_tls_summary(result))
    _remember_recent_context(
        create_recent_context(
            kind="lab",
            slug="tls",
            title="TLS Certificate Lab",
            summary=f"You inspected {result.target}:{result.port} and saw a {result.trust_state} trust interpretation.",
            suggested_commands=(
                f"nsc lab tls --target {result.target} --port {result.port} --demo-trust-state hostname-mismatch",
                'nsc ask "why would a client distrust this certificate?"',
            ),
        )
    )
    _export_if_requested(args.output, export_tls_markdown, result)
    return 0


def _handle_lab_http(args: argparse.Namespace) -> int:
    try:
        result = run_http_inspection(args.url, backend_name=args.backend)
    except (ValueError, RuntimeError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"HTTP backend: {args.backend}")
    print()
    print(render_http_summary(result))
    _remember_recent_context(
        create_recent_context(
            kind="lab",
            slug="http",
            title="HTTP Security Headers Lab",
            summary=f"You inspected {result.url} and reviewed security-relevant response headers.",
            suggested_commands=("nsc explore topic detection", 'nsc ask "which missing headers matter most?"'),
        )
    )
    _export_if_requested(args.output, export_http_markdown, result)
    return 0


def _handle_explore_topics(args: argparse.Namespace) -> int:
    del args
    for topic in list_topics():
        print(f"{topic.slug:<18} {topic.title}")
    _remember_recent_context(
        create_recent_context(
            kind="explore",
            slug="topics",
            title="Exploration Topic Map",
            summary="You browsed the high-level topic map for the classroom.",
            suggested_commands=("nsc explore topic metadata", 'nsc ask "where should i start?"'),
        )
    )
    return 0


def _handle_explore_topic(args: argparse.Namespace) -> int:
    topic = get_topic(args.slug)
    if not topic:
        print(f"Unknown exploration topic: {args.slug}", file=sys.stderr)
        return 1
    print(render_topic_summary(topic))
    _remember_recent_context(
        create_recent_context(
            kind="explore",
            slug=topic.slug,
            title=topic.title,
            summary=topic.summary,
            suggested_commands=topic.suggested_commands,
        )
    )
    return 0


def _handle_explore_next(args: argparse.Namespace) -> int:
    try:
        topics = suggest_next(args.slug)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"If {args.slug} interests you, explore these next:")
    print()
    for topic in topics:
        print(f"- {topic}")
    _remember_recent_context(
        create_recent_context(
            kind="explore",
            slug=args.slug,
            title=f"Next topics after {args.slug}",
            summary=f"You asked for follow-up topics after {args.slug}: {', '.join(topics)}.",
            suggested_commands=tuple(f"nsc explore topic {topic}" for topic in topics[:2]),
        )
    )
    return 0


def _handle_ask(args: argparse.Namespace) -> int:
    if args.setup:
        path = run_ask_setup(provider_override=args.provider)
        print(f"Saved ask configuration to {path}")
        return 0
    if args.status:
        config = load_ask_config()
        recent_context = load_recent_context()
        print(f"Provider: {config.provider}")
        print(f"Model: {config.model or '(default)'}")
        print(f"Config path: {get_config_path()}")
        print(f"Recent context path: {get_recent_context_path()}")
        print(f"Recent context configured: {'yes' if recent_context else 'no'}")
        if recent_context:
            print(f"Recent context title: {recent_context.title}")
        print(f"OpenAI key configured: {'yes' if bool(config.openai_api_key) else 'no'}")
        print(f"Hugging Face key configured: {'yes' if bool(config.hf_api_key) else 'no'}")
        return 0
    if args.question:
        try:
            config = load_ask_config()
            recent_context = load_recent_context()
            provider = get_ask_provider(config)
            response = provider.answer(args.question, recent_context=recent_context)
        except (ValueError, RuntimeError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(render_ask_response(response))
        return 0
    print("Usage: nsc ask \"your question here\"  |  nsc ask --setup  |  nsc ask --status")
    return 1


def _export_if_requested(output: str | None, exporter: Callable[[Any, str], Path], result: Any) -> None:
    if output:
        path = exporter(result, output)
        print()
        print(f"Exported notes to {Path(path).resolve()}")


def main() -> None:
    raise SystemExit(run())


def run_ask_setup(provider_override: str | None = None):
    provider = provider_override or input("Ask provider [local/openai/huggingface]: ").strip().casefold() or "local"
    if provider not in {"local", "openai", "huggingface"}:
        raise ValueError(f"Unknown ask provider: {provider}")

    model = ""
    openai_api_key = ""
    hf_api_key = ""

    if provider == "openai":
        print("API keys are stored in plaintext in your user-local .nsc config file.")
        model = input("OpenAI model [gpt-4.1-mini]: ").strip() or "gpt-4.1-mini"
        openai_api_key = input("OpenAI API key: ").strip()
    elif provider == "huggingface":
        print("API tokens are stored in plaintext in your user-local .nsc config file.")
        model = input("Hugging Face model [meta-llama/Meta-Llama-3.1-8B-Instruct]: ").strip() or (
            "meta-llama/Meta-Llama-3.1-8B-Instruct"
        )
        hf_api_key = input("Hugging Face token: ").strip()

    return save_ask_config(
        provider=provider,
        model=model,
        openai_api_key=openai_api_key,
        hf_api_key=hf_api_key,
    )


def _remember_recent_context(context) -> None:
    try:
        save_recent_context(context)
    except OSError:
        pass


if __name__ == "__main__":
    main()
