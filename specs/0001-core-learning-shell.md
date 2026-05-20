# Spec 0001: Core Learning Shell

## Status

Accepted

## Problem

People who are interested in security often jump between beginner labs and advanced terminology without a clear bridge. They hear terms like:

- host
- handshake
- firewall
- zero-day
- exploit chain

but do not have a simple tool that explains those ideas in a structured, reusable way.

## Goals

- provide a lesson-driven CLI
- explain concepts in plain English
- let users export notes for later study
- keep the tool clearly defensive and educational

## Non-Goals

- packet capture in this first slice
- exploit execution
- stealth scanning
- attack simulation

## User Stories

- As a learner, I want to list available lessons so I know what I can study.
- As a learner, I want to read one lesson in plain English without searching multiple sites.
- As a learner, I want to export notes as Markdown so I can keep a study log.

## Command Surface

- `nsc lesson list`
- `nsc lesson show <slug>`
- `nsc notes export --lesson <slug> [--output path]`

## Acceptance Criteria

- the CLI lists the lesson slugs and titles
- a user can show a lesson by slug
- a user can export a Markdown note for a lesson
- an unknown lesson returns a readable error

## Initial Lessons

- `host`
- `handshake`
- `zero-day`

## Why This Slice Matters

This slice proves the project shape before we add lab commands. It gives us:

- a stable CLI
- a lesson registry
- a note export format
- a safe educational foundation
