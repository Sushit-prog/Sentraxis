# ADR-007: Blast-radius gating and human-in-the-loop containment

## Context
The problem statement requires orchestrating containment actions autonomously
while remaining operator-safe. Two failure classes dominate: an autonomous
action that is wrong and irreversible, and an approval workflow so slow it is
never used.

## Options
- Full autonomy: fastest response; unacceptable blast radius on false positives.
- Manual-only: safe; reintroduces the minutes-to-hours response gap the system
  exists to eliminate.
- Tiered autonomy keyed to blast radius with policy thresholds.

## Decision
Every playbook carries a blast radius. `low` actions auto-execute when the
policy matches (confidence + source rules); `high` actions enter
`pending_approval` and require an authenticated approver (RBAC role gate).
Approvals expire after a configurable timeout rather than queueing forever.
Every transition — creation, decision, execution, expiry, failure — appends to
a hash-chained audit ledger in the same transaction as the state change, so
tampering is detectable and no action can bypass its audit record.

## Trade-offs
High-blast response latency now includes human think-time by design.
Simulated effectors keep the platform self-contained; real EDR/firewall APIs
slot into the effector registry without touching policy or state machine code.
