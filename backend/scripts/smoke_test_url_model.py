from __future__ import annotations

import hashlib
import json
from pathlib import Path

import joblib
import numpy as np
from train_url_model import build_feature_frame


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "models" / "candidates"
ARTIFACT = MODEL_DIR / "url_model_sgd_multichannel_candidate.joblib"
METADATA = MODEL_DIR / "url_model_sgd_multichannel_candidate_metadata.json"

# These are offline sanity targets, not a substitute for a validated external test set.
SAMPLES = [
    ("https://example.com", "benign"),
    ("https://www.google.com", "benign"),
    ("https://www.microsoft.com", "benign"),
    ("https://www.wikipedia.org", "benign"),
    ("https://www.python.org", "benign"),
    ("https://github.com", "benign"),
    ("http://192.168.1.10/login/verify-account?session=urgent", "phishing"),
    ("http://secure-account-login-verify.test/update-password", "phishing"),
    ("signin.eby.de.zukruygxctzmmqi.civpro.co.za", "phishing"),
]


def main() -> None:
    if not ARTIFACT.is_file():
        raise FileNotFoundError(f"Model artifact not found: {ARTIFACT}")
    if not METADATA.is_file():
        raise FileNotFoundError(f"Model metadata not found: {METADATA}")

    metadata = json.loads(METADATA.read_text(encoding="utf-8"))
    actual_hash = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    expected_hash = metadata.get("artifact_sha256")
    if not expected_hash or actual_hash.lower() != str(expected_hash).lower():
        raise RuntimeError("Artifact SHA-256 mismatch; refusing to load this candidate.")

    model = joblib.load(ARTIFACT)
    if not isinstance(model, dict) or "pipeline" not in model:
        raise TypeError("Unexpected artifact format; expected a preprocessing/classifier pipeline.")

    pipeline = model["pipeline"]
    classifier = pipeline.named_steps["classifier"]
    labels = [str(label) for label in classifier.classes_]

    print("=" * 72)
    print("SCAMSHIELD AI — MULTICHANNEL URL MODEL SMOKE TEST")
    print("=" * 72)
    print("Model:", metadata.get("model_name", "Unknown"))
    print("Version:", metadata.get("model_version", "Unknown"))
    print("Artifact SHA-256: VERIFIED")
    print("Features: typed URL structure + separate hostname/path/query/fragment character TF-IDF")
    print("Model scores are NOT calibrated confidence.")
    print("Offline only: no URLs will be visited.")
    print("=" * 72)

    passed = 0
    for raw_url, expected_label in SAMPLES:
        features = build_feature_frame([raw_url])
        scores = pipeline.predict_proba(features)[0]
        ranking = np.argsort(scores)[::-1]
        predicted = labels[int(ranking[0])]
        correct = predicted == expected_label
        passed += int(correct)

        print("\n" + "-" * 72)
        print("Input URL:       ", raw_url)
        print("Parsed features: ", json.dumps(features.iloc[0].to_dict(), sort_keys=True))
        print("Sanity target:   ", expected_label)
        print("Prediction:      ", predicted)
        print("Sanity result:   ", "PASS" if correct else "REVIEW")
        print("Model scores (not calibrated confidence):")
        for index in ranking:
            print(f"  {labels[int(index)]:<14} {float(scores[index]):.4f}")

    print("\n" + "=" * 72)
    print(f"SANITY TARGETS MATCHED: {passed}/{len(SAMPLES)}")
    print("These small samples do not establish real-world accuracy.")
    print("Candidate only — not connected to the live scanner.")
    print("No URLs were visited.")
    print("=" * 72)


if __name__ == "__main__":
    main()
