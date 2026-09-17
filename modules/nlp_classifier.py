"""
NLP Classifier Module
TF-IDF + Logistic Regression phishing email classifier.
Trains automatically from data/emails.csv if model doesn't exist.
"""

import os
import pickle
import re
import logging
from pathlib import Path
from typing import Tuple, Optional

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

logger = logging.getLogger(__name__)

# Suspicious terms for explainability (NOT used in ML decision)
SUSPICIOUS_TERMS = [
    "urgent", "verify", "password", "suspended", "account", "login",
    "payment", "click here", "reset", "security alert", "confirm",
    "winner", "reward", "congratulations", "limited", "expire",
    "immediately", "suspended", "unauthorized", "suspicious",
    "update", "validate", "compromise", "breach", "locked",
    "free", "claim", "prize", "selected", "chosen", "alert",
    "warning", "danger", "critical", "action required", "final notice",
]

# Classification thresholds
THRESHOLD_PHISHING = 0.65
THRESHOLD_SUSPICIOUS = 0.40

MODEL_PATH = Path(__file__).parent.parent / "models" / "phishing_model.pkl"
DATA_PATH = Path(__file__).parent.parent / "data" / "emails.csv"


def preprocess_text(text: str) -> str:
    """Basic text preprocessing for TF-IDF."""
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r"http\S+|www\S+", " urltoken ", text)
    text = re.sub(r"\S+@\S+", " emailtoken ", text)
    text = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", " iptoken ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_pipeline() -> Pipeline:
    """Build the TF-IDF + Logistic Regression pipeline."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            preprocessor=preprocess_text,
            ngram_range=(1, 2),
            max_features=3000,
            min_df=1,
            sublinear_tf=True,
        )),
        ("clf", LogisticRegression(
            solver="liblinear",   # fastest for small datasets
            max_iter=200,
            C=1.0,
            random_state=42,
            class_weight="balanced",
        )),
    ])


def train_model() -> Pipeline:
    """Train model on emails.csv and save to models/phishing_model.pkl."""
    logger.info("Training phishing classifier...")

    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Training data not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH)
    df = df.dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)

    X = df["text"].tolist()
    y = df["label"].tolist()

    # Train on all data for prototype (small dataset)
    pipeline = build_pipeline()

    if len(X) > 10:
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            pipeline.fit(X_train, y_train)
            y_pred = pipeline.predict(X_test)
            acc = accuracy_score(y_test, y_pred)
            logger.info(f"Model accuracy on test split: {acc:.2%}")
        except Exception:
            pipeline.fit(X, y)
    else:
        pipeline.fit(X, y)

    # Save model
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(pipeline, f)

    logger.info(f"Model saved to {MODEL_PATH}")
    return pipeline


def load_or_train_model() -> Pipeline:
    """Load existing model or train a new one."""
    if MODEL_PATH.exists():
        try:
            with open(MODEL_PATH, "rb") as f:
                pipeline = pickle.load(f)
            logger.info("Model loaded from disk.")
            return pipeline
        except Exception as e:
            logger.warning(f"Failed to load model: {e}. Retraining...")

    return train_model()


# Module-level model instance (lazy loaded)
_model: Optional[Pipeline] = None


def get_model() -> Pipeline:
    """Get the global model instance, loading/training if needed."""
    global _model
    if _model is None:
        _model = load_or_train_model()
    return _model


def classify_email(text: str) -> dict:
    """
    Classify email text as Phishing / Suspicious / Benign.

    Returns
    -------
    dict with keys:
        classification: str
        threat_probability: float (0-1)
        phishing_probability: float (0-1)
        benign_probability: float (0-1)
        suspicious_terms_found: list[str]
        model_name: str
        error: str | None
    """
    result = {
        "classification": "Unknown",
        "threat_probability": 0.0,
        "phishing_probability": 0.0,
        "benign_probability": 0.0,
        "suspicious_terms_found": [],
        "model_name": "TF-IDF + Logistic Regression",
        "error": None,
    }

    if not text or not text.strip():
        result["classification"] = "Unknown"
        result["error"] = "No text provided for classification"
        return result

    try:
        model = get_model()
        proba = model.predict_proba([text])[0]

        # classes_ may be [0,1] or [1,0] depending on training order
        classes = list(model.classes_)
        phishing_idx = classes.index(1) if 1 in classes else 1
        benign_idx = classes.index(0) if 0 in classes else 0

        phishing_prob = float(proba[phishing_idx])
        benign_prob = float(proba[benign_idx])

        result["phishing_probability"] = phishing_prob
        result["benign_probability"] = benign_prob
        result["threat_probability"] = phishing_prob

        if phishing_prob >= THRESHOLD_PHISHING:
            result["classification"] = "Phishing"
        elif phishing_prob >= THRESHOLD_SUSPICIOUS:
            result["classification"] = "Suspicious"
        else:
            result["classification"] = "Benign"

        # Find suspicious terms for explainability
        text_lower = text.lower()
        found = [term for term in SUSPICIOUS_TERMS if term in text_lower]
        result["suspicious_terms_found"] = found

    except Exception as e:
        result["error"] = str(e)
        result["classification"] = "Unknown"
        logger.error(f"Classification error: {e}")

    return result


def force_retrain() -> dict:
    """Force retrain the model and reload it."""
    global _model
    try:
        _model = train_model()
        return {"success": True, "message": "Model retrained successfully."}
    except Exception as e:
        return {"success": False, "message": str(e)}
