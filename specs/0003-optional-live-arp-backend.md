# Spec 0003: Optional Live ARP Backend

## Status

Accepted

## Problem

The demo backend is useful for tests and safe onboarding, but the project also needs a path to real local-network observation. That path should be explicit, optional, and dependency-aware.

## Goals

- add a backend selection model for ARP discovery
- keep demo mode as the default
- support an optional live backend using Scapy when available
- fail clearly when a user requests live mode without the dependency

## Non-Goals

- making live packet tooling mandatory
- silently switching users into live network behavior
- hiding the difference between simulated and live observations

## Command Surface

- `nsc lab arp --range 192.168.1.0/24`
- `nsc lab arp --range 192.168.1.0/24 --backend demo`
- `nsc lab arp --range 192.168.1.0/24 --backend live`

## Acceptance Criteria

- demo remains the default
- live backend can be requested explicitly
- requesting live mode without Scapy returns a readable error
- backend choice is visible in the command output

## Why This Slice Matters

This proves the project can grow into real observation tooling without losing safety, testability, or clarity about what is actually happening on the machine.
