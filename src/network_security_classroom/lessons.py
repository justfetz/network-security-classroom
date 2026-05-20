"""Lesson registry for Network Security Classroom."""

from __future__ import annotations

from dataclasses import dataclass

from .content import load_markdown_documents


@dataclass(frozen=True)
class Lesson:
    slug: str
    title: str
    summary: str
    body: str


def list_lessons() -> list[Lesson]:
    return [LESSONS[key] for key in sorted(LESSONS)]


def get_lesson(slug: str) -> Lesson | None:
    return LESSONS.get(slug)


def _load_lessons() -> dict[str, Lesson]:
    lessons = {}
    for document in load_markdown_documents("lessons"):
        lesson = Lesson(
            slug=document.metadata["slug"],
            title=document.metadata["title"],
            summary=document.metadata["summary"],
            body=document.body,
        )
        lessons[lesson.slug] = lesson
    return lessons


LESSONS = _load_lessons()
