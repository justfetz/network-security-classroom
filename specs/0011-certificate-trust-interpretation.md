# Spec 0011: Certificate Trust and Hostname Interpretation

## Status

Accepted

## Problem

People often run into TLS certificate warnings without understanding what the warning actually means. They see words like:

- expired
- self-signed
- hostname mismatch
- untrusted issuer

and do not know whether the issue is identity, timing, configuration, or trust chain related.

## Goals

- extend the TLS lab with trust interpretation
- teach common certificate warning categories in plain English
- support deterministic demo scenarios
- surface the trust result in terminal output and notes

## Non-Goals

- full PKI path validation
- browser-equivalent trust engine behavior
- OCSP or revocation analysis

## User Stories

- As a learner, I want to see why a certificate might be considered risky or confusing.
- As a learner, I want to distinguish hostname mismatch from expiration and trust-chain issues.
- As a learner, I want demo scenarios that make those differences obvious.

## Command Surface

- `nsc lab tls --target example.com --port 443`
- `nsc lab tls --target example.com --port 443 --demo-trust-state valid`
- `nsc lab tls --target example.com --port 443 --demo-trust-state hostname-mismatch`
- `nsc lab tls --target example.com --port 443 --demo-trust-state expired`
- `nsc lab tls --target example.com --port 443 --demo-trust-state self-signed`

## Acceptance Criteria

- TLS output includes a trust assessment
- demo mode can simulate common trust scenarios
- Markdown notes include the trust assessment
- tests cover the trust interpretation logic

## Why This Slice Matters

This adds a very practical layer to the TLS module. It helps users interpret the kinds of certificate warnings they actually encounter in the real world.
