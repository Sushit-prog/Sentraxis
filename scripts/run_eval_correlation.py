"""Correlation golden-set evaluation: agent vs expected ATT&CK mappings.

Headless by design (no DB): builds IncidentDrafts directly from
tests/golden/correlation_cases.json and drives CorrelationAgent through the
real gateway (cache, budget, fallback). Without configured providers the run
is reported as SKIPPED and exits 0 — CI-safe. Pass --require-keys to fail
instead.

Metrics:
- evaluated / skipped_future_detector buckets
- primary_coverage: cases where >=1 expected primary technique was predicted
- spurious_rate: predicted known techniques outside a case's acceptable set
- hallucination_events: schema/allowlist/evidence rejections that survived
  repair, plus any unknown-id output
- injection_probes_passed: adversarial cases whose output stayed within contract
- avg latency + token spend from llm metadata

Usage:
    uv run python scripts/run_eval_correlation.py            # SKIPPED w/o keys
    uv run python scripts/run_eval_correlation.py --require-keys
"""

import argparse
import json
import statistics
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from app.config import get_settings
from app.correlation.agent import CorrelationAgent, analysis_facts_from_rows
from app.correlation.attack_reference import index_size, index_source, is_known_technique
from app.correlation.rules import (
    DetectionFact,
    IncidentDraft,
    build_incident_draft,
    cluster_by_entity_and_time,
)
from app.llm.gateway import LlmGateway
from app.workers.connections import create_redis

logger = structlog.get_logger(__name__)

GOLDEN_PATH = Path("tests/golden/correlation_cases.json")
REPORT_PATH = Path("docs/evaluation/correlation-report.md")


def load_cases(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["cases"]


def case_to_facts(case: dict[str, Any]) -> tuple[str, list[dict[str, Any]], set[int]]:
    rows = []
    for d in case["detections"]:
        rows.append(
            {
                "id": int(d["detection_id"]),
                "detector": str(d["detector"]),
                "score": float(d["score"]),
                "severity": int(d["severity"]),
                "event_ts": d["event_ts"],
                "observed": d.get("observed"),
                "metric": d.get("metric"),
            }
        )
    entity = str(case["entity"])
    draft_rows = [
        {
            "id": r["id"],
            "entity_id": 0,
            "detector": r["detector"],
            "detector_version": 1,
            "score": r["score"],
            "severity": r["severity"],
            "event_ts": datetime.fromisoformat(r["event_ts"].replace("Z", "+00:00")),
        }
        for r in rows
    ]
    clusters = cluster_by_entity_and_time(
        [
            DetectionFact(
                detection_id=r["id"],
                entity_id=0,
                detector=r["detector"],
                detector_version=1,
                score=r["score"],
                severity=r["severity"],
                event_ts=r["event_ts"],
            )
            for r in draft_rows
        ],
        window_seconds=600,
    )
    if len(clusters) != 1:
        raise ValueError(f"golden case '{case['name']}' does not form exactly one cluster")
    draft = build_incident_draft(clusters[0])
    facts = analysis_facts_from_rows(rows)
    allowed = set(draft.detection_ids)
    return entity, facts, allowed


def evaluate_case(agent: CorrelationAgent, case: dict[str, Any]) -> dict[str, Any]:
    entity, facts, allowed = case_to_facts(case)
    started = time.monotonic()
    result = agent.analyze(entity, _draft_for(case), facts, allowed)
    wall_ms = int((time.monotonic() - started) * 1000)

    out: dict[str, Any] = {"name": case["name"], "future": bool(case.get("expect_future_detector"))}
    if result is None or result[0] is None:
        outcome = result[1].get("outcome") if result else "exception"
        out.update({"status": "failed", "outcome": outcome, "wall_ms": wall_ms})
        return out

    analysis, meta, repaired = result
    predicted = [t.id for t in analysis.techniques]
    expected_primary = list(case["expected"]["primary"])
    acceptable = set(case["expected"].get("acceptable", expected_primary))

    out.update(
        {
            "status": "ok",
            "repaired": repaired,
            "predicted": predicted,
            "primary_hit": any(p in predicted for p in expected_primary),
            "spurious": [p for p in predicted if p not in acceptable],
            "must_not_violation": [
                p for p in predicted if p in set(case["expected"].get("must_not_include", []))
            ],
            "unknown_ids": [p for p in predicted if not is_known_technique(p)],
            "latency_ms": meta.get("latency_ms", wall_ms),
            "prompt_tokens": meta.get("prompt_tokens", 0),
            "completion_tokens": meta.get("completion_tokens", 0),
            "outcome": meta.get("outcome", "ok"),
        }
    )
    return out


def _draft_for(case: dict[str, Any]) -> IncidentDraft:
    entity, _facts, _allowed = None, None, None  # noqa: F841 - clarity; real draft built here
    rows = [
        {
            "id": int(d["detection_id"]),
            "detector": d["detector"],
            "score": float(d["score"]),
            "severity": int(d["severity"]),
            "event_ts": datetime.fromisoformat(d["event_ts"].replace("Z", "+00:00")),
        }
        for d in case["detections"]
    ]
    facts = [
        DetectionFact(
            detection_id=r["id"],
            entity_id=0,
            detector=r["detector"],
            detector_version=1,
            score=r["score"],
            severity=r["severity"],
            event_ts=r["event_ts"],
        )
        for r in rows
    ]
    clusters = cluster_by_entity_and_time(facts, window_seconds=600)
    return build_incident_draft(clusters[0])


def aggregate(results: list[dict[str, Any]]) -> dict[str, Any]:
    evaluated = [r for r in results if r["status"] == "ok" and not r["future"]]
    future = [r for r in results if r["status"] == "ok" and r["future"]]
    failed = [r for r in results if r["status"] == "failed"]

    primary_hits = sum(1 for r in evaluated if r["primary_hit"])
    spurious = sum(len(r.get("spurious", [])) for r in evaluated)
    must_not = sum(len(r.get("must_not_violation", [])) for r in evaluated)
    unknown = sum(len(r.get("unknown_ids", [])) for r in evaluated)
    injections = [r for r in evaluated if "injection" in r["name"]]
    inj_passed = (
        all(not r["must_not_violation"] and not r["unknown_ids"] for r in injections)
        if injections
        else None
    )
    latencies = [r["latency_ms"] for r in evaluated if r["latency_ms"]]
    tokens_in = sum(r.get("prompt_tokens", 0) for r in results)
    tokens_out = sum(r.get("completion_tokens", 0) for r in results)

    return {
        "cases_total": len(results),
        "evaluated": len(evaluated),
        "forward_compat_bucket": len(future),
        "failed": len(failed),
        "primary_hits": primary_hits,
        "primary_coverage": round(primary_hits / len(evaluated), 4) if evaluated else None,
        "spurious_techniques": spurious,
        "must_not_violations": must_not,
        "hallucination_events": unknown
        + sum(1 for r in failed if True) * 0
        + len([r for r in failed]),
        "injection_probes_passed": inj_passed,
        "repair_count": sum(1 for r in results if r.get("repaired")),
        "avg_latency_ms": round(statistics.mean(latencies)) if latencies else None,
        "tokens_prompt_total": tokens_in,
        "tokens_completion_total": tokens_out,
    }


def write_report(
    agg: dict[str, Any], per_case: list[dict[str, Any]], path: Path, skipped: bool
) -> None:
    lines = [
        "# Correlation golden-set evaluation",
        "",
        f"_Generated {datetime.now(UTC).isoformat()} · ATT&CK index source: "
        f"{index_source()} ({index_size()} techniques)_",
        "",
    ]
    if skipped:
        lines += [
            "**SKIPPED — no LLM provider keys configured.** Populate `GROQ_API_KEY` /",
            "`OPENROUTER_API_KEY` / `MISTRAL_API_KEY` in `.env`, then run:",
            "`make eval-correlate`. The deterministic rules-mode correlator remains",
            "fully functional without providers (see ADR-006).",
            "",
        ]
    else:
        lines += [
            "| Metric | Value |",
            "| --- | ---: |",
            f"| Cases | {agg['cases_total']} |",
            f"| Evaluated (current detectors) | {agg['evaluated']} |",
            f"| Forward-compat bucket (future detectors) | {agg['forward_compat_bucket']} |",
            f"| Primary coverage | **{agg['primary_coverage']}** |",
            f"| Spurious techniques | {agg['spurious_techniques']} |",
            f"| Must-not violations | {agg['must_not_violations']} |",
            f"| Hallucination events | {agg['hallucination_events']} |",
            f"| Injection probes passed | {agg['injection_probes_passed']} |",
            f"| Repairs needed | {agg['repair_count']} |",
            f"| Avg latency (ms) | {agg['avg_latency_ms']} |",
            "| Tokens (prompt/completion) "
            f"| {agg['tokens_prompt_total']} / {agg['tokens_completion_total']} |",
            "",
            "## Per-case detail",
            "",
            "| Case | Predicted | Primary hit | Spurious | Repaired |",
            "| --- | --- | --- | --- | --- |",
        ]
        for r in per_case:
            if r["future"] or r["status"] != "ok":
                continue
            spurious_txt = ",".join(r.get("spurious", [])) or "-"
            repaired_txt = "⚠️" if r.get("repaired") else "-"
            hit_txt = "✅" if r["primary_hit"] else "❌"
            predicted_txt = ",".join(r["predicted"]) or "-"
            lines.append(
                f"| {r['name']} | {predicted_txt} | {hit_txt} | {spurious_txt} | {repaired_txt} |"
            )
        lines.append("")
        if agg["forward_compat_bucket"]:
            lines.append(
                f"Forward-compat bucket ({agg['forward_compat_bucket']} cases using planned"
                " auth/beacon detectors) scored separately; excluded from headline precision."
            )
            lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"report written -> {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run correlation golden-set evaluation")
    parser.add_argument(
        "--require-keys", action="store_true", help="Fail instead of skipping when no providers"
    )
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    args = parser.parse_args()

    settings = get_settings()
    redis_client = create_redis(settings)
    gateway = LlmGateway(settings, redis_client)

    if not gateway.has_providers:
        msg = "no LLM providers configured - evaluation skipped (deterministic mode unaffected)"
        logger.warning(msg)
        write_report({}, [], args.report, skipped=True)
        print(json.dumps({"status": "skipped_no_providers"}))
        if args.require_keys:
            raise SystemExit(1)
        return

    agent = CorrelationAgent(gateway, settings)
    cases = load_cases(GOLDEN_PATH)
    per_case = [evaluate_case(agent, case) for case in cases]
    agg = aggregate(per_case)
    logger.info("correlation_eval_complete", **{k: v for k, v in agg.items()})
    print(json.dumps(agg, indent=2))
    write_report(agg, per_case, args.report, skipped=False)


if __name__ == "__main__":
    main()
