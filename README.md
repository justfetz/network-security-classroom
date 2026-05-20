# Network Security Classroom

Network Security Classroom is a defensive CLI that teaches networking and modern security concepts through plain-English lessons and generated study notes.

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
- ask mode with local answers first and optional BYO-key LLM providers

The first shipped lessons are:

- `host`
- `handshake`
- `tls-metadata`
- `zero-day`

## Usage

After editable install:

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
```

Or run directly:

```powershell
python -m network_security_classroom.cli
python -m network_security_classroom.cli ask "what is a zero-day?"
python -m network_security_classroom.cli explore topics
python -m network_security_classroom.cli lesson list
python -m network_security_classroom.cli lesson show tls-metadata
python -m network_security_classroom.cli lesson show handshake
python -m network_security_classroom.cli lab arp --range 192.168.1.0/24
python -m network_security_classroom.cli lab tcp --target 192.168.1.1 --port 443
python -m network_security_classroom.cli lab dns --demo-domain example.com
```

`demo` mode is the default. `live` mode is optional and intended for a home lab or hotspot box where packet capture tooling is installed and explicitly allowed.

`ask` mode works with a local provider by default. Users can optionally configure their own OpenAI or Hugging Face key through `nsc ask --setup`.

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
