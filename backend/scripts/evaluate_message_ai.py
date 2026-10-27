"""Evaluate rules locally or run an explicitly opt-in OpenRouter benchmark."""

from __future__ import annotations

import argparse
import asyncio
import json
import time
from pathlib import Path

from app.core.config import settings
from app.services.openrouter_messages import _request_assessment
from app.services.risk_engine import analyze_message


CASES_PATH = Path(__file__).resolve().parents[1] / "data" / "message_fraud_eval.json"


def _metrics(rows: list[tuple[bool, bool]]) -> dict[str, float | int]:
    tp = sum(expected and predicted for expected, predicted in rows)
    tn = sum(not expected and not predicted for expected, predicted in rows)
    fp = sum(not expected and predicted for expected, predicted in rows)
    fn = sum(expected and not predicted for expected, predicted in rows)
    return {
        "n": len(rows),
        "accuracy": round((tp + tn) / len(rows), 4) if rows else 0.0,
        "precision": round(tp / (tp + fp), 4) if tp + fp else 0.0,
        "recall": round(tp / (tp + fn), 4) if tp + fn else 0.0,
        "specificity": round(tn / (tn + fp), 4) if tn + fp else 0.0,
        "true_positive": tp,
        "true_negative": tn,
        "false_positive": fp,
        "false_negative": fn,
    }


def _percentile(values: list[int], percentile: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return ordered[index]


async def _run_live(cases: list[dict]) -> dict:
    if not settings.openrouter_api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not configured in the backend environment.")
    rows: list[tuple[bool, bool]] = []
    latencies: list[int] = []
    failures = 0
    for case in cases:
        result = await _request_assessment(case["message"])
        if result.assessment is None:
            failures += 1
            continue
        rows.append((case["label"] == "malicious", result.assessment.risk_score >= 30))
        if result.latency_ms is not None:
            latencies.append(result.latency_ms)
    return {
        "mode": "live_openrouter",
        "model": settings.openrouter_model,
        "attempted": len(cases),
        "completed": len(rows),
        "provider_failures": failures,
        "classification": _metrics(rows),
        "latency_ms_p50": _percentile(latencies, 0.50),
        "latency_ms_p95": _percentile(latencies, 0.95),
    }


def _run_rules(cases: list[dict]) -> dict:
    rows: list[tuple[bool, bool]] = []
    timings: list[int] = []
    for case in cases:
        started = time.perf_counter()
        analysis = analyze_message(case["message"])
        timings.append(round((time.perf_counter() - started) * 1000))
        rows.append((case["label"] == "malicious", analysis.risk_score >= 30))
    return {
        "mode": "rules_only_local",
        "attempted": len(cases),
        "classification": _metrics(rows),
        "latency_ms_p50": _percentile(timings, 0.50),
        "latency_ms_p95": _percentile(timings, 0.95),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--rules-only", action="store_true", help="Run the deterministic baseline without network access.")
    mode.add_argument("--live", action="store_true", help="Make one billable OpenRouter call for each evaluation case.")
    parser.add_argument("--limit", type=int, default=20, help="Number of synthetic cases, 1-20 (default: 20).")
    args = parser.parse_args()
    if not 1 <= args.limit <= 20:
        parser.error("--limit must be between 1 and 20")
    cases = json.loads(CASES_PATH.read_text(encoding="utf-8"))[:args.limit]
    if args.live:
        result = asyncio.run(_run_live(cases))
    else:
        result = _run_rules(cases)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
