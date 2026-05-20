# Spec 0004: TCP Handshake Lab

## Status

Accepted

## Problem

After ARP discovery, the next foundational network-security lesson is the TCP handshake. Learners need a safe way to understand what open, closed, and filtered really mean without jumping into broad scanning.

## Goals

- add a `lab tcp` command
- explain `open`, `closed`, and `filtered` in plain English
- keep demo mode as the default
- allow an optional live backend later through Scapy
- support Markdown export for the observation

## Non-Goals

- multi-target scanning
- stealth scan variations
- malformed packets
- general offensive workflow automation

## User Stories

- As a learner, I want to test one host and port so I can see what handshake behavior means.
- As a learner, I want the result translated into plain English.
- As a learner, I want to export a note for later study.

## Command Surface

- `nsc lab tcp --target 192.168.1.1 --port 443`
- `nsc lab tcp --target 192.168.1.1 --port 443 --backend demo`
- `nsc lab tcp --target 192.168.1.1 --port 443 --backend live`
- `nsc lab tcp --target 192.168.1.1 --port 443 --demo-state open`

## Acceptance Criteria

- demo backend is the default
- demo backend can simulate `open`, `closed`, or `filtered`
- live backend errors clearly if Scapy is not installed
- output includes both technical state and plain-English interpretation

## Why This Slice Matters

This is the first lab that directly ties packet behavior to security reasoning about services, filtering, and exposure.
