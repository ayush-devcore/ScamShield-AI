# Message AI evaluation snapshot

Measured during the local OpenRouter integration work on 2026-10-28 using `backend/data/message_fraud_eval.json`, a small, hand-authored synthetic set of 20 messages (12 labeled malicious, 8 benign). This is an implementation smoke/evaluation set, not a representative production sample or calibrated benchmark. The messages include prize/click bait, cash rewards without a literal URL, verification and credential theft, financial pressure, impersonation, ordinary promotions, and quoted warnings.

## Observed results

| Mode | Completed | Accuracy | Precision | Recall | Specificity | False negatives | False positives | p50 latency | p95 latency |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Deterministic rules only | 20/20 | 85.0% | 90.9% | 83.3% | 87.5% | 2 | 1 | 0 ms | 2 ms |
| OpenRouter + Gemini 3.1 Flash Lite | 20/20 | 100.0% | 100.0% | 100.0% | 100.0% | 0 | 0 | 2,102 ms | 2,949 ms |

The local live run had zero provider failures. Latency is measured around the HTTP request and response parsing for serial requests from one local machine. Model routing, network conditions, account privacy settings, and provider availability can change these results. The synthetic set is too small to support real-world accuracy claims.

## Reproduce

Run the deterministic evaluation without network access:

```powershell
cd backend
.\.venv\Scripts\python.exe -m scripts.evaluate_message_ai --rules-only
```

The live command sends one billable call per case (up to 20), sends only the synthetic message text, and prints aggregate metrics without raw messages or credentials:

```powershell
.\.venv\Scripts\python.exe -m scripts.evaluate_message_ai --live --limit 20
```

Ordinary tests mock OpenRouter and never spend provider credits. A separate single-request integration smoke test is opt-in with `RUN_OPENROUTER_INTEGRATION=1`.
