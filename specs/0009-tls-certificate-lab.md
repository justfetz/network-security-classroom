# Spec 0009: TLS Certificate Lab

## Status

Accepted

## Problem

After the TLS and metadata lesson, learners should be able to inspect the shape of a certificate and understand what it tells them. This helps move the project from pure conceptual learning toward more practical network/security inspection.

## Goals

- add a `lab tls` command
- show the learner key certificate facts in plain English
- keep demo mode as the default
- provide an optional live backend that can fetch certificate metadata from a target host
- support Markdown export for the observation

## Non-Goals

- full TLS handshake analysis
- deep cipher negotiation analysis
- packet capture in this slice

## User Stories

- As a learner, I want to inspect a certificate and understand what it says.
- As a learner, I want to connect host, port, TLS, and identity into one mental model.
- As a learner, I want to export notes from the inspection.

## Command Surface

- `nsc lab tls --target example.com --port 443`
- `nsc lab tls --target example.com --port 443 --backend demo`
- `nsc lab tls --target example.com --port 443 --backend live`

## Acceptance Criteria

- demo backend is the default
- live backend is explicit
- output includes subject, issuer, validity, and a plain-English interpretation
- Markdown export works

## Why This Slice Matters

This is a natural bridge into intermediate networking/security work because it turns TLS from a vague concept into an inspectable object.
