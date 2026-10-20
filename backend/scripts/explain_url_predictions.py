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

SAMPLES = [
    "https://example.com",
    "https://www.google.com",
    "https://www.microsoft.com",
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://github.com",
    "http://192.168.1.10/login/verify-account?session=urgent",
    "http://secure-account-login-verify.test/update-password",
    "signin.eby.de.zukruygxctzmmqi.civpro.co.za",
]


def main() -> None:
    if not ARTIFACT.is_file() or not METADATA.is_file():
        raise FileNotFoundError(
            "Structural candidate artifact/metadata not found. Train the candidate first."
        )

    metadata = json.loads(METADATA.read_text(encoding="utf-8"))
    actual_hash = hashlib.sha256(ARTIFACT.read_bytes()).hexdigest()
    expected_hash = metadata.get("artifact_sha256")
    if not expected_hash or actual_hash.lower() != str(expected_hash).lower():
        raise RuntimeError("Artifact SHA-256 mismatch; refusing to load this candidate.")

    model = joblib.load(ARTIFACT)
    if not isinstance(model, dict) or "pipeline" not in model:
        raise TypeError("Unexpected artifact format; expected a preprocessing/classifier pipeline.")

    pipeline = model["pipeline"]
    feature_transformer = pipeline.named_steps["features"]
    classifier = pipeline.named_steps["classifier"]
    feature_names = feature_transformer.get_feature_names_out()
    labels = [str(label) for label in classifier.classes_]

    print("MODEL:", metadata.get("model_name", "Unknown"))
    print("VERSION:", metadata.get("model_version", "Unknown"))
    print("SHA-256: VERIFIED")
    print("Offline explanations only; no URLs will be visited.")
    print(
        "Explanation values are linear class-score contributions, "
        "not causal evidence or calibrated confidence."
    )

    for raw_url in SAMPLES:
        features = build_feature_frame([raw_url])
        row = feature_transformer.transform(features)
        scores = pipeline.predict_proba(features)[0]
        ranking = np.argsort(scores)[::-1]

        print("\n" + "=" * 72)
        print("URL:", raw_url)
        print("Parsed features:", json.dumps(features.iloc[0].to_dict(), sort_keys=True))
        print("Prediction:", labels[int(ranking[0])])
        print("Model scores (NOT calibrated confidence):")
        for index in ranking:
            print(f"  {labels[int(index)]:<14} {float(scores[index]):.4f}")

        if row.nnz == 0:
            print("No known character n-gram features matched this input.")
            continue

        for target in ("phishing", "benign"):
            if target not in labels:
                continue

            class_index = labels.index(target)
            contributions = row.data * classifier.coef_[class_index, row.indices]
            positive_order = np.argsort(contributions)[::-1]
            negative_order = np.argsort(contributions)
            positive = [int(i) for i in positive_order if contributions[i] > 0][:10]
            negative = [int(i) for i in negative_order if contributions[i] < 0][:10]

            print(f"\nStrongest positive linear contributions for '{target}':")
            if not positive:
                print("  None")
            for position in positive:
                feature_index = int(row.indices[position])
                print(
                    f"  {str(feature_names[feature_index])!r}: "
                    f"{float(contributions[position]):+.5f}"
                )

            print(f"Strongest negative linear contributions for '{target}':")
            if not negative:
                print("  None")
            for position in negative:
                feature_index = int(row.indices[position])
                print(
                    f"  {str(feature_names[feature_index])!r}: "
                    f"{float(contributions[position]):+.5f}"
                )

    print("\nComplete. No network requests were made.")


if __name__ == "__main__":
    main()
