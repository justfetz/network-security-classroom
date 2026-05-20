# Contributing

Network Security Classroom is meant to be easy to extend without turning every contribution into a Python refactor.

## Add a Lesson

Lessons live in:

```text
src/network_security_classroom/content/lessons/
```

Create a Markdown file with this shape:

```markdown
---
slug: example-topic
title: Example Topic
summary: One sentence explaining what the learner will understand.
---
Write the lesson body here in plain English.
```

Keep lessons defensive, practical, and clear. Offensive concepts are allowed when they help people defend systems, but avoid procedural attack steps, stealth guidance, or social engineering playbooks.

## Add an Exploration Topic

Topics live in:

```text
src/network_security_classroom/content/topics/
```

Create a Markdown file with this shape:

```markdown
---
slug: example-topic
title: Example Topic
summary: One sentence summary.
why_it_matters: Why this matters to a learner or defender.
related: metadata, detection
commands: nsc lesson show example-topic, nsc ask "why does this matter?"
---
```

The `related` and `commands` fields are comma-separated lists.

## Add a Lab

Labs still require Python code because they validate input, produce structured results, render terminal summaries, and export Markdown notes.

When adding a lab:

- add a spec in `specs/`
- add result models and backend functions in `src/network_security_classroom/labs.py`
- add CLI handling in `src/network_security_classroom/cli.py`
- add Markdown export support in `src/network_security_classroom/notes.py`
- add tests for validation, rendering, CLI behavior, and notes

## Quality Gates

Run these before opening a pull request:

```powershell
python -m pyright
python -m pytest
```

The default test run includes coverage through `pytest-cov`.
