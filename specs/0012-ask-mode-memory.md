# Spec 0012: Ask Mode Memory

## Status

Accepted

## Problem

Ask mode currently answers questions in isolation. That works, but it misses an important part of the learning experience: a curious user often asks follow-up questions right after running a lesson, lab, or topic exploration. The tool should remember that recent context so the answer feels more like a mentor conversation than a detached glossary lookup.

## Goals

- store a lightweight recent-context record in user-local state
- update recent context automatically when a learner runs a lesson, lab, or exploration command
- let ask mode reference that recent context in local and remote responses
- keep the memory model simple, transparent, and easy to test

## Non-Goals

- full chat history
- cloud-synced memory
- multi-turn transcript storage
- opaque personalization or behavioral profiling

## User Stories

- As a learner, I want ask mode to notice the last concept or lab I explored.
- As a learner, I want follow-up answers to connect back to the command I just ran.
- As a learner, I want to inspect whether recent context exists without guessing.

## Command Surface

- `nsc ask "what does filtered mean?"`
- `nsc ask --status`
- `nsc lesson show handshake`
- `nsc explore topic metadata`
- `nsc lab tls --target example.com --port 443`

## Acceptance Criteria

- a recent-context record is stored in user-local state
- lesson, lab, and exploration commands update recent context automatically
- ask mode can mention recent context when it is relevant
- `nsc ask --status` shows whether recent context exists
- tests cover storage, CLI updates, and ask-mode rendering

## Why This Slice Matters

This is the piece that makes ask mode feel less like a lookup utility and more like a forgiving terminal mentor. A little memory goes a long way when the goal is to keep users curious and oriented.
