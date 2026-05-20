# Spec 0013: Attacker Mindset

## Status

Accepted

## Problem

People often hear security terms like exploit, exposure, misconfiguration, or zero-day without understanding what defenders are actually trying to notice. If the project only teaches protocols and trust surfaces without explaining what attackers tend to look for, learners can miss the reason these details matter.

## Goals

- add a defensive deep dive on attacker mindset
- explain what attackers commonly look for in systems and networks without teaching exploitation steps
- connect offensive concepts back to defensive priorities like visibility, patching, isolation, and least privilege
- make the project's defensive posture explicit

## Non-Goals

- exploit tutorials
- stealth or evasion guidance
- social engineering playbooks
- procedural attack execution

## User Stories

- As a learner, I want to understand why defenders study attacker behavior.
- As a learner, I want a safe explanation of what attackers notice first.
- As a learner, I want offensive concepts translated into defensive action items.

## Command Surface

- `nsc lesson show attacker-mindset`
- `nsc explore topic attacker-mindset`
- `nsc ask "what are attackers looking for?"`

## Acceptance Criteria

- a new lesson exists for attacker mindset
- a new exploration topic connects attacker mindset to existing topics like metadata, zero-day, and detection
- ask mode can map high-level attacker-mindset questions to the new content
- tests cover the new lesson and topic

## Why This Slice Matters

This gives the project a clearer bridge between curiosity about offense and commitment to defense. Learners can study what attackers notice without the tool drifting into “how to hack” territory.
