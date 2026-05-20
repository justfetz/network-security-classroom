# Spec 0010: HTTP Headers and Security Posture Lab

## Status

Accepted

## Problem

After TLS certificate inspection, the next natural step is learning how application-layer security posture shows up in HTTP response headers. This helps users connect transport security to browser-facing protections and real-world web hardening.

## Goals

- add a `lab http` command
- inspect a small set of security-relevant response headers
- provide a plain-English interpretation of what is present and what is missing
- keep demo mode as the default
- provide an optional live backend for real HTTP responses
- support Markdown export for the observation

## Non-Goals

- full browser simulation
- vulnerability scanning
- crawling websites
- cookie analysis beyond a simple educational mention

## User Stories

- As a learner, I want to see which security headers a site returns.
- As a learner, I want to understand why those headers matter.
- As a learner, I want to export notes from the inspection.

## Command Surface

- `nsc lab http --url https://example.com`
- `nsc lab http --url https://example.com --backend demo`
- `nsc lab http --url https://example.com --backend live`

## Acceptance Criteria

- demo backend is the default
- live backend is explicit
- output includes a readable summary of key security headers
- Markdown export works

## Why This Slice Matters

This moves the project deeper into practical web security posture without abandoning the learning-first format.
