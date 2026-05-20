from network_security_classroom.lessons import get_lesson, list_lessons


def test_list_lessons_returns_expected_slugs():
    slugs = [lesson.slug for lesson in list_lessons()]
    assert slugs == ["attacker-mindset", "handshake", "host", "tls-metadata", "zero-day"]


def test_get_lesson_returns_none_for_unknown_slug():
    assert get_lesson("not-real") is None


def test_attacker_mindset_lesson_exists():
    lesson = get_lesson("attacker-mindset")
    assert lesson is not None
    assert "defenders" in lesson.title.casefold()
    assert "exposed services" in lesson.body.casefold()
