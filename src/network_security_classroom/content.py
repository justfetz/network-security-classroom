"""Packaged Markdown content loading."""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources


@dataclass(frozen=True)
class ContentDocument:
    metadata: dict[str, str]
    body: str


def load_markdown_documents(folder: str) -> list[ContentDocument]:
    base = resources.files("network_security_classroom").joinpath("content", folder)
    documents = []
    for path in sorted(base.iterdir(), key=lambda item: item.name):
        if path.name.endswith(".md"):
            documents.append(parse_markdown_document(path.read_text(encoding="utf-8")))
    return documents


def parse_markdown_document(text: str) -> ContentDocument:
    normalized = text.strip()
    if not normalized.startswith("---\n"):
        raise ValueError("Content documents must start with front matter.")

    _, front_matter, body = normalized.split("---", 2)
    metadata = _parse_front_matter(front_matter)
    return ContentDocument(metadata=metadata, body=body.strip())


def split_csv(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in value.split(",") if part.strip())


def _parse_front_matter(front_matter: str) -> dict[str, str]:
    data = {}
    for raw_line in front_matter.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Invalid front matter line: {raw_line}")
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip()
    return data
