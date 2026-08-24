# Security model & review status (M6)

## Enforced controls (each covered by automated tests)

| Threat | Control | Test |
| --- | --- | --- |
| Credential stuffing / weak auth | Argon2id hashes; constant-verify; disabled accounts excluded | `test_login_wrong_password_401` |
| Token forgery / alg confusion | HS256 with pinned algorithm list; signature+expiry verified server-side | `test_tampered_token_rejected`, `test_garbage_scheme_rejected` |
| Privilege escalation on containment | Approval endpoints gated to approver/admin via dependency injection; analysts receive 403 before handler logic runs | `test_analyst_cannot_approve_actions` |
| Duplicate/replayed decisions | Unique idempotency keys return recorded outcomes; state-machine CAS prevents double execution | live verification + `test_duplicate_action_suppressed_across_ticks` |
| SQL injection via filters/params | SQLAlchemy parameterization everywhere; adversarial filter strings asserted safe | `test_status_filter_injection_is_safe` |
| Resource abuse via pagination | Ge/Le bounds on limit/offset → 422 outside range | `test_limit_parameter_clamped`, `test_negative_offset_rejected` |
| Autonomous overreach | Blast-radius policy gates: high-impact actions cannot execute without an approval record; expiry reverts stale approvals to a terminal state | orchestrator integration matrix |
| Audit tampering | Hash-chained ledger, verified walk detects forged payloads and deletions | `test_tampered_history_is_detected`, `test_deletion_gap_breaks_verification` |
| Secret leakage in VCS | `.env` gitignored + pre-push secret scan (`gsk_` pattern grep) part of release checklist | manual step, documented here |
| Prompt injection into correlation | Model receives only typed numeric projections; output schema + ATT&CK allowlist reject instruction-shaped payloads | golden-set injection case |

## Known limitations (honest)

- No rate limiting on `/auth/token` yet (planned: Redis-backed sliding window).
- JWT revocation is absent — short expiry is the only mitigation; add a
  denylist when multi-user operation becomes real.
- Metrics endpoint requires auth but is not scoped per-role; scrape accounts
  should use a dedicated read-only principal.
- Effectors are simulated. The moment real EDR/firewall APIs are registered,
  their credentials become the highest-value secret and must move to a proper
  secret manager.
