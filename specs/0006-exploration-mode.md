# Spec 0006: Exploration Mode

## Status

Accepted

## Problem

Lessons and labs are useful, but a learning playground should also feel open-ended. Users should be able to browse topics, follow related ideas, and get suggestions about where to go next without already knowing the exact command they need.

## Goals

- add an `explore` mode
- provide a topic map users can browse
- connect lessons and labs through related concepts
- make the default CLI experience feel welcoming and exploratory

## Non-Goals

- a full chatbot in this slice
- unbounded freeform question answering
- unsafe offensive guidance

## User Stories

- As a learner, I want to open the CLI and immediately understand how to start.
- As a learner, I want to browse topics instead of memorizing commands.
- As a learner, I want suggestions for what to explore next.

## Command Surface

- `nsc`
- `nsc explore topics`
- `nsc explore topic metadata`
- `nsc explore next zero-day`

## Acceptance Criteria

- running `nsc` with no arguments prints a welcoming starter screen
- users can list exploration topics
- users can inspect a topic and see related ideas
- users can ask for recommended next steps from a topic

## Why This Slice Matters

This is the first slice focused on product feel instead of just feature count. It makes the CLI feel like a forgiving security playground instead of a list of subcommands.
