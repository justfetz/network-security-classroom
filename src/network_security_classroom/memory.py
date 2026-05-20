"""Recent-context memory helpers for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path

from .config import get_config_dir


DEFAULT_RECENT_CONTEXT_FILENAME = "recent_context.json"


@dataclass(frozen=True)
class RecentContext:
    kind: str
    slug: str
    title: str
    summary: str
    suggested_commands: tuple[str, ...] = ()
    recorded_at: str = ""


def create_recent_context(
    kind: str,
    slug: str,
    title: str,
    summary: str,
    suggested_commands: tuple[str, ...] = (),
) -> RecentContext:
    return RecentContext(
        kind=kind,
        slug=slug,
        title=title,
        summary=summary,
        suggested_commands=suggested_commands,
        recorded_at=_now_iso(),
    )


def get_recent_context_path(home: Path | None = None) -> Path:
    return get_config_dir(home) / DEFAULT_RECENT_CONTEXT_FILENAME


def save_recent_context(context: RecentContext, home: Path | None = None) -> Path:
    path = get_recent_context_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "kind": context.kind,
        "slug": context.slug,
        "title": context.title,
        "summary": context.summary,
        "suggested_commands": list(context.suggested_commands),
        "recorded_at": context.recorded_at,
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def load_recent_context(home: Path | None = None) -> RecentContext | None:
    path = get_recent_context_path(home)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    return RecentContext(
        kind=str(data.get("kind", "")).strip(),
        slug=str(data.get("slug", "")).strip(),
        title=str(data.get("title", "")).strip(),
        summary=str(data.get("summary", "")).strip(),
        suggested_commands=tuple(data.get("suggested_commands", []) or ()),
        recorded_at=str(data.get("recorded_at", "")).strip(),
    )


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
