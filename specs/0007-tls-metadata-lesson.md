# Spec 0007: TLS and Metadata

## Status

Accepted

## Problem

The DNS metadata lab introduces the idea that encryption does not hide everything. The next step is to make that lesson explicit: what TLS protects, what it does not protect, and why metadata still matters.

## Goals

- add a dedicated TLS/metadata lesson
- connect that lesson to the DNS metadata lab and exploration mode
- export notes for the lesson just like the others

## Non-Goals

- packet capture in this slice
- certificate parsing
- live TLS inspection workflows

## User Stories

- As a learner, I want a clear explanation of what encryption hides and what it leaves visible.
- As a learner, I want to connect DNS and TLS into one mental model.
- As a learner, I want to export that explanation as part of my notes.

## Acceptance Criteria

- `tls-metadata` appears in the lesson list
- the lesson can be shown and exported
- exploration mode includes TLS and metadata as related concepts

## Why This Slice Matters

This is one of the most important ideas in modern security literacy. People often assume HTTPS hides everything. This slice helps correct that misunderstanding in a plain-English way.
