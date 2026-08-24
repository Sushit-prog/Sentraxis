# Correlation golden-set evaluation

_Generated 2026-08-24T17:25:09.710242+00:00 · ATT&CK index source: full-index (697 techniques)_

| Metric | Value |
| --- | ---: |
| Cases | 20 |
| Evaluated (current detectors) | 17 |
| Forward-compat bucket (future detectors) | 2 |
| Primary coverage | **1.0** |
| Spurious techniques | 0 |
| Must-not violations | 0 |
| Hallucination events | 1 |
| Injection probes passed | True |
| Repairs needed | 0 |
| Avg latency (ms) | 3076 |
| Tokens (prompt/completion) | 702 / 495 |

## Per-case detail

| Case | Predicted | Primary hit | Spurious | Repaired |
| --- | --- | --- | --- | --- |
| fast_port_sweep_11_ports | T1046,T1595 | ✅ | - | - |
| broad_service_sweep_17_ports | T1046,T1595 | ✅ | - | - |
| slow_low_rate_vulnerability_scan | T1046,T1595 | ✅ | - | - |
| volumetric_syn_flood_single_port | T1498.001 | ✅ | - | - |
| sweep_then_flood_composite | T1046,T1595 | ✅ | - | - |
| distributed_reflected_flood_two_sources | T1498.001 | ✅ | - | - |
| stealth_slow_port_walk | T1046 | ✅ | - | - |
| icmp_flood_variant | T1498,T1498.001 | ✅ | - | - |
| multi_entity_coordinated_sweep_a | T1046,T1595,T1595.001 | ✅ | - | - |
| multi_entity_coordinated_sweep_b | T1046,T1595 | ✅ | - | - |
| single_low_confidence_anomaly | T1046 | ✅ | - | - |
| sweep_with_prompt_injection_in_metric | T1595,T1046 | ✅ | - | - |
| flood_burst_train_three_peaks | T1498.001 | ✅ | - | - |
| sweep_high_severity_internal_source | T1046,T1595 | ✅ | - | - |
| mixed_protocol_recon | T1046 | ✅ | - | - |
| post_exploitation_lateral_ports | T1046 | ✅ | - | - |
| recon_pair_same_minute_distinct_targets | T1046 | ✅ | - | - |

Forward-compat bucket (2 cases using planned auth/beacon detectors) scored separately; excluded from headline precision.
