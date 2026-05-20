# Network Security Classroom

Network Security Classroom is a defensive CLI that teaches networking and modern security concepts through plain-English lessons and generated study notes.

## Start Here

If you want to open the project in a terminal and start learning right away, use this flow:

```powershell
git clone https://github.com/justfetz/network-security-classroom.git
cd network-security-classroom
pip install -e .[dev]
nsc
```

That will:

- install the CLI locally in editable mode
- install the test and coverage tools
- make the `nsc` command available in your shell

If you do not want to install it yet, you can run it directly like this:

```powershell
cd path\to\network-security-classroom
$env:PYTHONPATH='src'
python -m network_security_classroom.cli
```

If you already cloned or downloaded the repo, the shortest setup is:

```powershell
cd path\to\network-security-classroom
pip install -e .[dev]
nsc
```

The important part is that one of these must be true before `python -m network_security_classroom.cli` works:

- you already ran `pip install -e .[dev]`, or
- you set `PYTHONPATH=src` for the current shell

## Why this exists

There are a lot of security tools that assume you already understand the basics. This project is for people who want to build that understanding deliberately, from networking foundations to more advanced topics like zero-days, exploit chains, and defensive reasoning.

This is not an offensive tool. It is a learning tool.

## Current scope

The first slice focuses on:

- a lesson registry
- plain-English concept lessons
- Markdown note export

The next slice adds:

- safe ARP discovery for a lab subnet
- Markdown export for observed hosts
- optional live backend selection for ARP discovery
- TCP handshake learning for one host and port
- DNS metadata learning with safe demo output
- exploration mode with a topic map and next-step suggestions
- ask mode with local answers first, recent-context memory, and optional BYO-key LLM providers
- TLS certificate inspection as an intermediate lab
- HTTP headers and security posture inspection

The first shipped lessons are:

- `host`
- `handshake`
- `tls-metadata`
- `zero-day`

## First Learning Session

After install, this is the simplest “feel the project” path:

```powershell
nsc
nsc explore topics
nsc explore topic metadata
nsc lesson show tls-metadata
nsc lab tcp --target 192.168.1.1 --port 443
nsc lab dns --demo-domain example.com
nsc ask "why does metadata matter?"
```

What each step does:

- `nsc`
  - opens the welcome screen
- `nsc explore topics`
  - shows the topic map
- `nsc explore topic metadata`
  - explains why metadata matters and what to try next
- `nsc lesson show tls-metadata`
  - gives the plain-English content vs metadata lesson
- `nsc lab tcp ...`
  - shows what open, closed, or filtered means
- `nsc lab dns ...`
  - shows why DNS can reveal intent
- `nsc ask ...`
  - lets the user ask a plain-English question
  - remembers the last lesson, lab, or topic they explored so follow-up questions feel grounded

## Command Reference

After editable install, these all work:

```powershell
nsc
nsc ask "why does metadata matter?"
nsc ask --status
nsc ask --setup
nsc explore topics
nsc explore topic metadata
nsc explore next zero-day
nsc lesson list
nsc lesson show tls-metadata
nsc lesson show host
nsc notes export --lesson zero-day
nsc lab arp --range 192.168.1.0/24
nsc lab arp --range 192.168.1.0/24 --backend live
nsc lab tcp --target 192.168.1.1 --port 443
nsc lab dns --demo-domain example.com
nsc lab tls --target example.com --port 443
nsc lab http --url https://example.com
```

If you prefer not to install the command, run directly from the repo:

```powershell
$env:PYTHONPATH='src'
python -m network_security_classroom.cli
python -m network_security_classroom.cli ask "what is a zero-day?"
python -m network_security_classroom.cli explore topics
python -m network_security_classroom.cli lesson list
python -m network_security_classroom.cli lesson show tls-metadata
python -m network_security_classroom.cli lesson show handshake
python -m network_security_classroom.cli lab arp --range 192.168.1.0/24
python -m network_security_classroom.cli lab tcp --target 192.168.1.1 --port 443
python -m network_security_classroom.cli lab dns --demo-domain example.com
python -m network_security_classroom.cli lab tls --target example.com --port 443
python -m network_security_classroom.cli lab http --url https://example.com
```

`demo` mode is the default. `live` mode is optional and intended for a home lab or hotspot box where packet capture tooling is installed and explicitly allowed.

`ask` mode works with a local provider by default. It also remembers the learner's most recent lesson, lab, or exploration topic. Users can optionally configure their own OpenAI or Hugging Face key through `nsc ask --setup`.

## Ask Mode

The project does not use the author's API keys.

By default:

- `nsc ask "..."` uses a local knowledge-backed provider
- no remote model is required
- no API key is required
- the tool remembers the last lesson, lab, or exploration topic you ran and can use that context in follow-up answers

If a user wants remote model support, they can bring their own key:

```powershell
nsc ask --setup
nsc ask --status
```

Supported provider pattern:

- `local`
- `openai`
- `huggingface`

## Development

```powershell
pip install -e .[dev]
pytest
```

`pip install -e .[dev]` means:

- `-e`: install in editable mode, so code changes are picked up without reinstalling
- `.`: install the current project
- `[dev]`: also install the optional development dependency group defined in `pyproject.toml`

## Project shape

- `specs/`
  - spec-driven implementation notes
- `src/network_security_classroom/`
  - CLI, lesson registry, labs, and exploration mode
- `tests/`
  - unit tests for command behavior and note generation

## Current Scope

Current lessons:

- `host`
- `handshake`
- `tls-metadata`
- `zero-day`

Current labs:

- `arp`
- `tcp`
- `dns`
- `tls`
- `http`

Current exploration features:

- topic map
- related-topic suggestions
- local-first ask mode
