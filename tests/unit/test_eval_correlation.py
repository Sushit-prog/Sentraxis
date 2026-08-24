"""Offline tests for the correlation golden-set runner (stub gateway, no network)."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

from app.correlation.attack_reference import technique_name

_spec = importlib.util.spec_from_file_location(
    "run_eval_correlation", Path(__file__).parents[2] / "scripts" / "run_eval_correlation.py"
)
runner = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
assert _spec.loader is not None
_spec.loader.exec_module(runner)

CASES_PATH = Path(__file__).parents[1] / "golden" / "correlation_cases.json"


class StubGateway:
    """Deterministic gateway: maps metrics to plausible techniques.

    mode="vulnerable" echoes any T\\d{4} string found in the prompt — simulating
    a prompt-injection-susceptible model so we can assert the validation layer
    catches it.
    """

    has_providers = True

    def __init__(self, mode: str = "safe") -> None:
        self.mode = mode
        self.calls = 0

    def chat_json(self, purpose, messages, bust_cache_key=None):  # noqa: ARG002
        self.calls += 1
        user = messages[1]["content"]
        data = json.loads(user)
        detections = data["detections"]
        ids = [d["detection_id"] for d in detections]

        techniques: list[tuple[str, float]] = []
        if self.mode == "vulnerable":
            import re

            found = re.findall(r"T\d{4}(?:\.\d{3})?", user)
            if "T9999" in found:
                techniques.append(("T9999", 0.99))
            elif ports_present(detections):
                techniques.append(("T1046", 0.7))
        else:
            if ports_present(detections):
                techniques.append(("T1046", 0.75))
            flood = [
                d
                for d in detections
                if "flow_count" in str(d.get("metric"))
                and d.get("observed") is not None
                and float(d["observed"]) > 500
            ]
            if flood:
                techniques.append(("T1498", 0.9))
            if any("failed_logins" in str(d.get("metric")) for d in detections):
                techniques.append(("T1110", 0.85))
            if any("beacon" in str(d.get("metric")) for d in detections):
                techniques.append(("T1071", 0.8))

        max_conf = max((c for _, c in techniques), default=0.5)
        payload = {
            "title": f"Stub incident analysis {self.calls}",
            "narrative": "Stub narrative describing the correlated behavioral pattern in detail.",
            "risk_score": max_conf,
            "confidence_overall": round(max_conf - 0.05, 2),
            "techniques": [
                {
                    "id": tid,
                    "name": technique_name(tid),
                    "confidence": conf,
                    "evidence_detection_ids": ids[:1],
                }
                for tid, conf in techniques
            ],
        }
        return SimpleNamespace(
            payload=payload,
            raw_content=json.dumps(payload),
            provider="stub",
            model=f"stub-{self.mode}",
            prompt_tokens=42,
            completion_tokens=13,
            latency_ms=11,
            cache_hit=False,
            cache_key=f"stub:{self.calls}",
        )


def ports_present(detections: list[dict]) -> bool:
    return any("ports" in str(d.get("metric")) for d in detections)


def rates_present(detections: list[dict]) -> bool:
    return any("flow_count" in str(d.get("metric")) for d in detections)


def test_safe_stub_full_golden_run(tmp_path: Path) -> None:
    agent = runner.CorrelationAgent(StubGateway("safe"), settings=None)  # type: ignore[arg-type]
    cases = runner.load_cases(CASES_PATH)
    per_case = [runner.evaluate_case(agent, case) for case in cases]
    agg = runner.aggregate(per_case)

    current = agg["evaluated"]
    assert agg["cases_total"] == 20
    assert agg["forward_compat_bucket"] == 2
    assert current + agg["forward_compat_bucket"] == 20
    assert agg["failed"] == 0
    assert agg["primary_hits"] >= 14, "all sweep/flood cases should hit primary"
    assert agg["spurious_techniques"] == 0
    assert agg["must_not_violations"] == 0
    assert agg["hallucination_events"] == 0
    assert agg["injection_probes_passed"] is True
    assert agg["avg_latency_ms"] is not None

    runner.write_report(agg, per_case, tmp_path / "correlation-report.md", skipped=False)
    content = (tmp_path / "correlation-report.md").read_text(encoding="utf-8")
    assert "Primary coverage" in content and "Injection probes passed" in content


def test_vulnerable_model_is_caught_by_validation_layer() -> None:
    agent = runner.CorrelationAgent(StubGateway("vulnerable"), settings=None)  # type: ignore[arg-type]
    cases = [
        c
        for c in runner.load_cases(CASES_PATH)
        if c["name"] == "sweep_with_prompt_injection_in_metric"
    ]
    per_case = [runner.evaluate_case(agent, case) for case in cases]
    r = per_case[0]

    # the injection tried to smuggle T9999; contract enforcement must reject it
    assert r["status"] == "ok" or r["status"] == "failed"
    predicted = r.get("predicted", [])
    assert "T9999" not in predicted, "hallucinated technique leaked through validation"
    assert all(is_known(t) for t in predicted)


def is_known(tid: str) -> bool:
    from app.correlation.attack_reference import is_known_technique

    return is_known_technique(tid)


def test_skip_report_is_written_when_no_providers(tmp_path: Path) -> None:
    report = tmp_path / "correlation-report.md"
    runner.write_report({}, [], report, skipped=True)
    content = report.read_text(encoding="utf-8")
    assert "SKIPPED" in content and "make eval-correlate" in content
