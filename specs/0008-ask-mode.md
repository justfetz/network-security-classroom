# Spec 0008: Ask Mode

## Status

Accepted

## Problem

Lessons, labs, and exploration mode are useful, but users will eventually want to ask natural questions in their own words. The tool needs a forgiving `ask` layer without collapsing into an unbounded chatbot.

## Goals

- add `ask` mode to the CLI
- answer from local project knowledge first
- support optional remote providers through user-owned API keys
- provide an interactive setup path for configuring providers
- keep the output structured and educational

## Non-Goals

- shipping the author's API keys
- making remote LLM usage mandatory
- answering unsafe offensive questions with procedural instructions

## User Stories

- As a learner, I want to ask a plain-English security question and get a grounded answer.
- As a learner, I want this to work even if I have no API key configured.
- As a learner, I want an easy way to add my own provider key later.

## Command Surface

- `nsc ask "why does metadata matter?"`
- `nsc ask "what is a zero-day?"`
- `nsc ask setup`
- `nsc ask status`

## Acceptance Criteria

- the local provider works with no configuration
- `ask setup` writes a user-local config file
- `ask status` shows the active provider and whether a key is configured
- remote provider selection is optional and explicit

## Why This Slice Matters

This is the slice that starts to make the terminal feel like a forgiving mentor instead of only a command surface.
