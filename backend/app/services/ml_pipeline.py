import hashlib
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split

from app.services.risk_engine import ThreatSignal, analyze_message

MODEL_DIR = Path(__file__).resolve().parents[2] / "models"
MODEL_PATH = MODEL_DIR / "message_model.joblib"
MODEL_META_PATH = MODEL_DIR / "message_model_metadata.json"


def _safe_model_path(path: str | Path) -> Path:
    candidate = Path(path).resolve()
    allowed_root = MODEL_DIR.resolve()
    if allowed_root not in candidate.parents and candidate != allowed_root:
        raise ValueError("Model path is outside the approved models directory.")
    return candidate


def _load_model_metadata() -> dict:
    if not MODEL_META_PATH.exists():
        return {}
    try:
        return json.loads(MODEL_META_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def load_trained_message_model() -> tuple[TfidfVectorizer, LogisticRegression] | None:
    if not MODEL_PATH.exists():
        return None

    artifact = joblib.load(_safe_model_path(MODEL_PATH))
    if not isinstance(artifact, dict):
        raise ValueError("Unsupported model artifact format.")
    if "vectorizer" not in artifact or "classifier" not in artifact:
        raise ValueError("Model artifact is missing required components.")
    return artifact["vectorizer"], artifact["classifier"]


def train_message_model(dataset_path: str | None = None) -> dict:
    dataset_file = Path(dataset_path) if dataset_path else None
    if dataset_file is None or not dataset_file.exists():
        return {
            "status": "fallback_only",
            "message": "No training dataset is available; rules-based analysis remains active.",
            "model_name": "scamshield-rules-baseline",
            "model_version": "1.0.0",
        }

    import pandas as pd

    df = pd.read_csv(dataset_file)
    required = {"text", "label"}
    if not required.issubset(df.columns):
        raise ValueError("Training dataset must have 'text' and 'label' columns.")

    X = df["text"].fillna("").astype(str)
    y = df["label"].astype(str)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1, 2))
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    classifier = LogisticRegression(max_iter=1000, class_weight="balanced")
    classifier.fit(X_train_tfidf, y_train)

    predictions = classifier.predict(X_test_tfidf)
    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "f1_score": float(f1_score(y_test, predictions, average="weighted")),
        "classification_report": classification_report(y_test, predictions, output_dict=True),
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    artifact = {"vectorizer": vectorizer, "classifier": classifier}
    joblib.dump(artifact, MODEL_PATH)

    metadata = {
        "model_name": "scamshield-message-tfidf-logreg",
        "model_version": "1.0.0",
        "training_data": str(dataset_file),
        "metrics": metrics,
        "created_by": "ScamShield AI",
        "artifact_hash": hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest(),
    }
    MODEL_META_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def predict_message_with_ml(text: str) -> dict:
    model = load_trained_message_model()
    if model is None:
        base = analyze_message(text)
        return {
            "used_ml": False,
            "model_name": base.model_name,
            "model_version": base.model_version,
            "source": "baseline_rules",
            "score": base.risk_score,
            "threat_type": base.threat_type,
            "confidence": base.confidence,
            "recommendations": base.recommendations,
            "signals": [
                {"indicator_type": s.indicator_type, "description": s.description, "severity": s.severity, "evidence": s.evidence}
                for s in base.signals
            ],
        }

    vectorizer, classifier = model
    tfidf = vectorizer.transform([text])
    probabilities = classifier.predict_proba(tfidf)[0]
    prediction_label = classifier.predict(tfidf)[0]
    probability = float(max(probabilities))

    metadata = _load_model_metadata()
    return {
        "used_ml": True,
        "model_name": metadata.get("model_name", "scamshield-message-tfidf-logreg"),
        "model_version": metadata.get("model_version", "1.0.0"),
        "source": "trained_ml",
        "score": int(round(min(100, max(0, probability * 100)))),
        "threat_type": "ML Prediction" if prediction_label == "spam" else "Suspicious Message",
        "confidence": round(float(min(95.0, probability * 100)), 2),
        "recommendations": [
            "Do not act under time pressure. Verify through an official app or site.",
            "Never share OTPs, passwords, or PINs from unexpected requests.",
        ],
        "signals": [],
    }
