# Spec 0005: DNS Metadata Lab

## Status

Accepted

## Problem

After ARP discovery and TCP handshake basics, learners need to understand that encryption does not hide everything. DNS is a strong next lesson because it shows how metadata can still reveal user activity even when application traffic is encrypted.

## Goals

- add a `lab dns` command
- explain what metadata is visible in DNS lookups
- keep demo mode as the default
- allow an optional live backend later through Scapy
- support Markdown export for the observation

## Non-Goals

- packet replay
- passive capture by default
- enterprise surveillance workflows
- deep protocol dissection in this slice

## User Stories

- As a learner, I want to see what a DNS lookup reveals.
- As a learner, I want a plain-English explanation of why this matters for privacy and security.
- As a learner, I want to export notes about the observation.

## Command Surface

- `nsc lab dns`
- `nsc lab dns --backend demo`
- `nsc lab dns --backend live`
- `nsc lab dns --demo-domain example.com`

## Acceptance Criteria

- demo backend is the default
- demo output shows source host and queried domain
- live backend errors clearly if Scapy is not installed
- output includes plain-English interpretation of metadata visibility

## Why This Slice Matters

This is the first lab that makes the “content vs metadata” lesson tangible, which is one of the most important mental models in modern security.
