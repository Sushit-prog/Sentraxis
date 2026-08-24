# ADR-006: LLM correlation behind enforced contracts; allowlist over STIX RAG

## Context
Incident enrichment needs MITRE ATT&CK technique mapping from an LLM running
on free-tier providers (Groq / OpenRouter / Mistral). Two risks dominate:
hallucinated technique IDs/evidence and provider unreliability or rate limits.

## Options
- Full STIX bundle RAG before validation: complete coverage of ATT&CK; heavy
  dependency (embedding pipeline) before any value is proven.
- Curated allowlist (~18 network-relevant techniques) as a validation seam:
  zero infra, deterministic rejection of unknown/misnamed techniques.
- No validation, prompt-only discipline: unacceptable — silent hallucinations
  become "intelligence".

## Decision
The agent's output is validated against a strict pydantic schema whose context
includes (a) the bundled ATT&CK allowlist (id + exact-name match) and (b) the
incident's real detection ids (evidence-citation check). One repair round feeds
exact violations back; failure at any point returns None and the incident stays
in deterministic rules mode. The gateway adds provider fallback, pacing, a daily
budget circuit breaker in Redis, response caching keyed on the prompt hash
(cache-busted deliberately for repair rounds), and full call-ledger rows
(`llm_calls`) for cost/outcome evaluation.

## Trade-offs
Technique coverage is intentionally narrow until M4 introduces retrieval over
the full STIX corpus; `correlation/attack_reference.py` is the single seam for
that upgrade. Correlation quality is therefore measurable now instead of
theoretical later.
