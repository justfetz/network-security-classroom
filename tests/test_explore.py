from network_security_classroom.explore import (
    get_topic,
    list_topics,
    render_topic_summary,
    render_welcome,
    suggest_next,
)


def test_list_topics_contains_metadata():
    slugs = [topic.slug for topic in list_topics()]
    assert "metadata" in slugs
    assert "attacker-mindset" in slugs


def test_get_topic_returns_none_for_unknown_slug():
    assert get_topic("missing") is None


def test_render_topic_summary_contains_related_topics():
    topic = get_topic("metadata")
    text = render_topic_summary(topic)
    assert "Related topics:" in text
    assert "dns" in text
    assert "nsc lesson show tls-metadata" in text


def test_suggest_next_returns_related_topics():
    related = suggest_next("zero-day")
    assert "detection" in related
    assert "attacker-mindset" in related


def test_render_welcome_invites_exploration():
    text = render_welcome()
    assert "Network Security Classroom" in text
    assert "nsc explore topics" in text
