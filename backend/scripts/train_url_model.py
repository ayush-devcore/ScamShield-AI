from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler


# -----------------------------------------------------------------------------
# Paths and model identity
# -----------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "urls" / "cleaned_urls.csv"
MODEL_DIR = ROOT / "models" / "candidates"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

ARTIFACT_PATH = MODEL_DIR / "url_model_sgd_multichannel_candidate.joblib"
METADATA_PATH = MODEL_DIR / "url_model_sgd_multichannel_candidate_metadata.json"
EVALUATION_PATH = MODEL_DIR / "url_model_sgd_multichannel_candidate_evaluation.json"
EXPLANATIONS_PATH = MODEL_DIR / "url_model_sgd_multichannel_candidate_global_explanations.json"

MODEL_NAME = "scamshield-url-tfidf-sgd-multichannel"
MODEL_VERSION = "0.4.0-sgd-multichannel-candidate"
NORMALIZATION_DESCRIPTION = (
    "parsed numeric and one-hot hostname/URL structure; separate character TF-IDF "
    "channels for hostname, path, query, and fragment; leading scheme excluded"
)
RANDOM_STATE = 42
TEST_SIZE = 0.14
VALIDATION_FRACTION_OF_TRAIN_VALIDATION = 0.167
MIN_DOCUMENT_FREQUENCY = 2

NUMERIC_FEATURES = [
    "host_is_ip", "host_label_count", "host_subdomain_depth", "host_length",
    "host_hyphen_count", "host_underscore_count", "host_digit_count",
    "host_digit_ratio", "host_punycode", "host_longest_label", "host_tld_length",
    "host_numeric_tld", "host_port_present", "path_depth", "path_length",
    "path_extension_present", "path_percent_encoding", "query_present", "query_length",
    "query_parameter_count", "query_percent_encoding", "fragment_present", "fragment_length",
]
CATEGORICAL_FEATURES = [
    "host_length_bucket", "host_digit_ratio_bucket", "host_tld_length_bucket",
]
TEXT_FEATURES = ["hostname_text", "path_text", "query_text", "fragment_text"]


# -----------------------------------------------------------------------------
# Parsing is shared by training, smoke tests, and explanations. It performs no
# DNS lookup and no network request.
# -----------------------------------------------------------------------------
def length_bucket(number: int) -> str:
    if number <= 12:
        return "short"
    if number <= 30:
        return "medium"
    if number <= 60:
        return "long"
    return "very_long"


def ratio_bucket(ratio: float) -> str:
    if ratio == 0:
        return "none"
    if ratio < 0.15:
        return "low"
    if ratio < 0.35:
        return "medium"
    return "high"


def parse_url_features(value: str) -> dict[str, int | float | str]:
    raw = str(value).strip().lower()
    raw = re.sub(
        r"^[a-z][a-z0-9+.-]*://",
        "",
        raw,
        count=1,
        flags=re.IGNORECASE,
    )
    raw = raw.lstrip("/")

    try:
        parsed = urlsplit("//" + raw)
        host = (parsed.hostname or "").lower().strip(".")
        path = parsed.path or "/"
        query = parsed.query
        fragment = parsed.fragment
        try:
            port = parsed.port
        except ValueError:
            port = None
    except ValueError:
        host = ""
        path = "/" + raw
        query = ""
        fragment = ""
        port = None

    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False

    labels = host.split(".") if host and not is_ip else []
    digits = sum(character.isdigit() for character in host)
    digit_ratio = digits / max(len(host), 1)
    longest_label = max((len(label) for label in labels), default=0)
    tld = labels[-1] if labels else ""
    path_segments = [segment for segment in path.split("/") if segment]
    query_params = [part for part in query.split("&") if part]

    return {
        "host_is_ip": int(is_ip),
        "host_label_count": min(len(labels), 5),
        "host_subdomain_depth": min(max(len(labels) - 2, 0), 5),
        "host_length": len(host),
        "host_hyphen_count": host.count("-"),
        "host_underscore_count": host.count("_"),
        "host_digit_count": digits,
        "host_digit_ratio": digit_ratio,
        "host_punycode": int("xn--" in host),
        "host_longest_label": longest_label,
        "host_tld_length": len(tld),
        "host_numeric_tld": int(bool(tld) and tld.isdigit()),
        "host_port_present": int(port is not None),
        "host_length_bucket": length_bucket(len(host)),
        "host_digit_ratio_bucket": ratio_bucket(digit_ratio),
        "host_tld_length_bucket": length_bucket(len(tld)),
        "path_depth": min(len(path_segments), 5),
        "path_length": len(path),
        "path_extension_present": int(bool(path_segments) and "." in path_segments[-1]),
        "path_percent_encoding": int("%" in path),
        "query_present": int(bool(query)),
        "query_length": len(query),
        "query_parameter_count": min(len(query_params), 5),
        "query_percent_encoding": int("%" in query),
        "fragment_present": int(bool(fragment)),
        "fragment_length": len(fragment),
        "hostname_text": host,
        "path_text": path,
        "query_text": query,
        "fragment_text": fragment,
    }


def build_feature_frame(urls: list[str] | np.ndarray) -> pd.DataFrame:
    return pd.DataFrame([parse_url_features(value) for value in urls])


def build_feature_transformer() -> ColumnTransformer:
    text_transformers = [
        (
            "hostname_text",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(2, 5),
                min_df=3,
                max_features=50_000,
                sublinear_tf=True,
                dtype=np.float32,
                lowercase=False,
            ),
            "hostname_text",
        )
    ]
    for column, max_features in (("path", 100_000), ("query", 40_000), ("fragment", 20_000)):
        text_transformers.append(
            (
                f"{column}_text",
                TfidfVectorizer(
                    analyzer="char",
                    ngram_range=(3, 5),
                    min_df=MIN_DOCUMENT_FREQUENCY,
                    max_features=max_features,
                    sublinear_tf=True,
                    dtype=np.float32,
                    lowercase=False,
                ),
                f"{column}_text",
            )
        )

    return ColumnTransformer(
        transformers=[
            ("numeric", StandardScaler(with_mean=False), NUMERIC_FEATURES),
            ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
            *text_transformers,
        ],
        sparse_threshold=1.0,
        verbose_feature_names_out=True,
    )


def assert_no_group_overlap(
    train_groups: np.ndarray,
    validation_groups: np.ndarray,
    test_groups: np.ndarray,
) -> None:
    train_set = set(train_groups)
    validation_set = set(validation_groups)
    test_set = set(test_groups)
    if train_set & validation_set:
        raise RuntimeError("Hostname group leakage between train and validation splits.")
    if train_set & test_set:
        raise RuntimeError("Hostname group leakage between train and test splits.")
    if validation_set & test_set:
        raise RuntimeError("Hostname group leakage between validation and test splits.")


def get_report(y_true: np.ndarray, y_pred: np.ndarray, labels: list[str]) -> dict:
    report = classification_report(
        y_true,
        y_pred,
        labels=labels,
        target_names=labels,
        output_dict=True,
        zero_division=0,
    )
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "macro_recall": float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0)),
        "per_class": report,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "label_order": labels,
    }


def build_global_explanations(model: Pipeline, top_n: int = 40) -> dict:
    classifier = model.named_steps["classifier"]
    feature_names = model.named_steps["features"].get_feature_names_out()
    output: dict[str, dict[str, list[dict[str, float | str]]]] = {}

    for class_index, label in enumerate(classifier.classes_):
        coefficients = classifier.coef_[class_index]
        positive_indices = np.argsort(coefficients)[-top_n:][::-1]
        negative_indices = np.argsort(coefficients)[:top_n]

        output[str(label)] = {
            "strongest_positive": [
                {"feature": str(feature_names[i]), "coefficient": float(coefficients[i])}
                for i in positive_indices
            ],
            "strongest_negative": [
                {"feature": str(feature_names[i]), "coefficient": float(coefficients[i])}
                for i in negative_indices
            ],
        }

    return {
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "interpretation": "Linear classifier coefficients, not causal evidence or calibrated confidence.",
        "features": output,
    }


def main() -> None:
    started = time.time()
    output_paths = (ARTIFACT_PATH, METADATA_PATH, EVALUATION_PATH, EXPLANATIONS_PATH)
    existing_outputs = [str(path) for path in output_paths if path.exists()]
    if existing_outputs:
        raise FileExistsError(
            "Refusing to overwrite existing candidate outputs: "
            + ", ".join(existing_outputs)
        )

    print("Loading cleaned URL dataset...")
    if not DATA_PATH.is_file():
        raise FileNotFoundError(
            f"Cleaned dataset not found: {DATA_PATH}\n"
            "Expected columns: url,type,host_group. Prepare the dataset first."
        )

    frame = pd.read_csv(DATA_PATH, dtype={"url": "string", "type": "string", "host_group": "string"})
    required_columns = {"url", "type", "host_group"}
    missing_columns = required_columns - set(frame.columns)
    if missing_columns:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing_columns)}")

    frame = frame.dropna(subset=["url", "type", "host_group"]).copy()
    frame["url"] = frame["url"].astype(str).str.strip()
    frame["type"] = frame["type"].astype(str).str.strip().str.lower()
    frame["host_group"] = frame["host_group"].astype(str).str.strip().str.lower()
    frame = frame[(frame["url"] != "") & (frame["type"] != "") & (frame["host_group"] != "")]
    if frame.empty:
        raise ValueError("The cleaned URL dataset has no usable rows.")

    label_counts = frame["type"].value_counts().sort_index().to_dict()
    if len(label_counts) < 2:
        raise ValueError("At least two distinct classes are required for model training.")

    print(f"Rows: {len(frame):,}")
    print(f"Unique host groups: {frame['host_group'].nunique():,}")
    print(f"Labels: {label_counts}")
    print("Creating hostname-grouped splits...")

    y = frame["type"].to_numpy(dtype=str)
    groups = frame["host_group"].to_numpy(dtype=str)
    indices = np.arange(len(frame))

    outer_split = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    train_validation_indices, test_indices = next(outer_split.split(indices, y, groups))

    inner_split = GroupShuffleSplit(
        n_splits=1,
        test_size=VALIDATION_FRACTION_OF_TRAIN_VALIDATION,
        random_state=RANDOM_STATE + 1,
    )
    train_sub_indices, validation_sub_indices = next(
        inner_split.split(
            train_validation_indices,
            y[train_validation_indices],
            groups[train_validation_indices],
        )
    )
    train_indices = train_validation_indices[train_sub_indices]
    validation_indices = train_validation_indices[validation_sub_indices]

    assert_no_group_overlap(
        groups[train_indices], groups[validation_indices], groups[test_indices]
    )

    print(
        "Split sizes — train: {:,}, validation: {:,}, test: {:,}".format(
            len(train_indices), len(validation_indices), len(test_indices)
        )
    )
    print("Parsing structural fields and separate text channels...")
    raw_urls = frame["url"].astype(str).to_numpy()
    feature_frame = build_feature_frame(raw_urls)
    model = Pipeline(
        steps=[
            ("features", build_feature_transformer()),
            (
                "classifier",
                SGDClassifier(
                    loss="log_loss",
                    alpha=1e-5,
                    max_iter=30,
                    tol=1e-3,
                    random_state=RANDOM_STATE,
                    class_weight="balanced",
                    average=True,
                    n_jobs=1,
                    verbose=0,
                ),
            ),
        ]
    )

    print("Fitting preprocessing and classifier on training split only...")
    model.fit(feature_frame.iloc[train_indices], y[train_indices])
    feature_count = len(model.named_steps["features"].get_feature_names_out())
    print(f"Training rows: {len(train_indices):,}; fitted features: {feature_count:,}")
    classifier = model.named_steps["classifier"]
    labels = [str(label) for label in classifier.classes_]

    print("Evaluating validation data...")
    validation_predictions = model.predict(feature_frame.iloc[validation_indices])
    validation_metrics = get_report(y[validation_indices], validation_predictions, labels)

    print("Evaluating held-out test data...")
    test_predictions = model.predict(feature_frame.iloc[test_indices])
    test_metrics = get_report(y[test_indices], test_predictions, labels)

    print("Building global feature explanations...")
    global_explanations = build_global_explanations(model)
    EXPLANATIONS_PATH.write_text(
        json.dumps(global_explanations, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print("Saving candidate artifact...")
    artifact_bundle = {
        "pipeline": model,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "normalization": NORMALIZATION_DESCRIPTION,
    }
    joblib.dump(artifact_bundle, ARTIFACT_PATH, compress=3)
    artifact_hash = hashlib.sha256(ARTIFACT_PATH.read_bytes()).hexdigest()

    split_sizes = {
        "train_rows": int(len(train_indices)),
        "validation_rows": int(len(validation_indices)),
        "test_rows": int(len(test_indices)),
        "train_host_groups": int(len(set(groups[train_indices]))),
        "validation_host_groups": int(len(set(groups[validation_indices]))),
        "test_host_groups": int(len(set(groups[test_indices]))),
        "hostname_group_overlap": False,
    }

    evaluation = {
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "dataset_path": str(DATA_PATH),
        "dataset_rows_used": int(len(frame)),
        "label_counts": {str(key): int(value) for key, value in label_counts.items()},
        "split_sizes": split_sizes,
        "validation": validation_metrics,
        "test": test_metrics,
        "normalization": NORMALIZATION_DESCRIPTION,
        "candidate_only": True,
        "live_scanner_connected": False,
        "urls_visited": False,
    }
    EVALUATION_PATH.write_text(
        json.dumps(evaluation, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    metadata = {
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "artifact_filename": ARTIFACT_PATH.name,
        "artifact_sha256": artifact_hash,
        "dataset_filename": DATA_PATH.name,
        "dataset_rows_used": int(len(frame)),
        "class_labels": labels,
        "normalization": NORMALIZATION_DESCRIPTION,
        "feature_method": (
            "Standard-scaled numeric structure, one-hot categorical structure, and separate "
            "character TF-IDF channels for hostname, path, query, and fragment"
        ),
        "raw_hostname_text_used": True,
        "hostname_text_channel": "character TF-IDF, min_df=3; evaluated with hostname-grouped splits",
        "leading_scheme_used_as_text_feature": False,
        "feature_channels": {
            "numeric": NUMERIC_FEATURES,
            "categorical": CATEGORICAL_FEATURES,
            "text": TEXT_FEATURES,
        },
        "classifier": {
            "type": "SGDClassifier",
            "loss": "log_loss",
            "alpha": 1e-5,
            "max_iter": 30,
            "class_weight": "balanced",
            "average": True,
        },
        "random_state": RANDOM_STATE,
        "split_sizes": split_sizes,
        "validation_macro_f1": validation_metrics["macro_f1"],
        "test_macro_f1": test_metrics["macro_f1"],
        "test_macro_recall": test_metrics["macro_recall"],
        "test_accuracy": test_metrics["accuracy"],
        "validation_group_overlap_verified": True,
        "converged_or_stopped_by_sklearn": True,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "training_duration_seconds": round(time.time() - started, 2),
        "evaluation_filename": EVALUATION_PATH.name,
        "global_explanations_filename": EXPLANATIONS_PATH.name,
        "candidate_only": True,
        "live_scanner_connected": False,
        "probabilities_calibrated": False,
        "urls_visited": False,
    }
    METADATA_PATH.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    print("\n=== MULTICHANNEL URL MODEL TRAINING COMPLETE ===")
    print(f"Artifact: {ARTIFACT_PATH}")
    print(f"Evaluation: {EVALUATION_PATH}")
    print(f"Metadata: {METADATA_PATH}")
    print(f"Global explanations: {EXPLANATIONS_PATH}")
    print(f"Artifact SHA-256: {artifact_hash}")
    print(f"VALIDATION MACRO F1: {validation_metrics['macro_f1']:.4f}")
    print(f"TEST MACRO F1: {test_metrics['macro_f1']:.4f}")
    print(f"TEST MACRO RECALL: {test_metrics['macro_recall']:.4f}")
    print(f"TEST ACCURACY: {test_metrics['accuracy']:.4f}")
    print("\nPer-class test results:")
    for label in labels:
        item = test_metrics["per_class"][label]
        print(
            f"  {label}: precision={item['precision']:.4f}, "
            f"recall={item['recall']:.4f}, f1={item['f1-score']:.4f}"
        )
    print("\nConfusion matrix (rows=true, columns=predicted):")
    print(f"Label order: {labels}")
    for row in test_metrics["confusion_matrix"]:
        print(row)
    print("\nCandidate only — not connected to the live scanner.")
    print("No URLs were visited.")


if __name__ == "__main__":
    main()
