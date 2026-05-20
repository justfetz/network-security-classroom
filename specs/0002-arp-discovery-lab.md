# Spec 0002: ARP Discovery Lab

## Status

Accepted

## Problem

After the core learning shell, the project needs its first real lab feature. ARP discovery is a strong first step because it teaches:

- what a host is
- the difference between IP and MAC addresses
- how local discovery works on a subnet

It is also safer and more bounded than jumping straight into general port scanning.

## Goals

- add a `lab arp` command
- validate the user-provided subnet range
- keep packet interaction behind a backend interface
- support Markdown note export for the observed devices

## Non-Goals

- stealth discovery
- enterprise-targeted scanning logic
- advanced fingerprinting
- passive sniffing in this slice

## User Stories

- As a learner, I want to scan a local lab subnet so I can see which devices respond.
- As a learner, I want the output explained in plain English, not just dumped as raw tuples.
- As a learner, I want to export the findings as Markdown notes.

## Command Surface

- `nsc lab arp --range 192.168.1.0/24`
- `nsc lab arp --range 192.168.1.0/24 --output arp-notes.md`

## Acceptance Criteria

- invalid ranges fail with a readable error
- valid ranges produce readable device output
- Markdown export includes the range and discovered devices
- command logic remains testable without a live network

## Design Notes

- use Python `ipaddress` for subnet validation
- keep the backend swappable so later slices can use Scapy
- default implementation may return a clear “backend unavailable” error when live packet tooling is not installed

## Why This Slice Matters

This slice proves that the project can move from concept lessons into safe observational labs without losing the defensive, educational posture.
