"""Small explainable rules over sanitized browser observations."""


RULESET_VERSION = "sandbox-url-1"


def analyze_observations(observations: dict) -> dict:
    findings = []
    score = 0
    navigation = observations.get("navigation") or {}
    final_origin = observations.get("final_origin") or ""

    if final_origin.startswith("http://"):
        score += 25
        findings.append({
            "id": "sandbox_http_transport",
            "rule": "HTTP_TRANSPORT_NO_ENCRYPTION",
            "severity": "medium",
            "title": "The final page used unencrypted HTTP.",
            "observation_refs": ["final_origin"],
        })

    page_origin = final_origin or observations.get("initial_origin")
    external_forms = [
        form for form in observations.get("forms", [])
        if form.get("action_origin") not in (page_origin, "[invalid origin]", "[non-http origin]")
    ]
    if external_forms:
        score += min(55, 35 + 5 * (len(external_forms) - 1))
        findings.append({
            "id": "sandbox_cross_origin_form",
            "rule": "CROSS_ORIGIN_FORM_SUBMISSION",
            "severity": "high" if score >= 60 else "medium",
            "title": "A form submits to a different origin.",
            "observation_refs": ["forms"],
            "count": len(external_forms),
        })

    downloads = int(observations.get("download_attempt_count") or 0)
    if downloads:
        score += min(15, downloads * 5)
        findings.append({
            "id": "sandbox_download_attempt",
            "rule": "DOWNLOAD_ATTEMPT_OBSERVED",
            "severity": "low",
            "title": "The page attempted a download; the file was not saved or opened.",
            "observation_refs": ["download_attempt_count"],
            "count": downloads,
        })

    score = min(100, score)
    classification = "high" if score >= 60 else "medium" if score >= 30 else "safe"
    return {
        "classification": classification,
        "risk_score": score,
        "findings": findings,
        "method": {"name": "ScamShield sandbox URL heuristics", "ruleset_version": RULESET_VERSION},
        "conclusion": (
            "Risk is based only on the listed browser observations and named rules."
            if findings else "No configured high-risk behavior was observed during this limited navigation."
        ),
        "limitations": [
            "No threat-intelligence or reputation service was queried.",
            "Page forms were observed but never submitted.",
            "Downloads were not saved or opened.",
            "Page text, cookies, authorization headers, and screenshots were not retained.",
        ],
        "navigation_http_status": navigation.get("http_status"),
    }
