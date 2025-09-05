"""
Offline prediction script for Device Type Classifier.
Loads /ml/model.pkl and predicts device type (with confidence) from raw scan JSON/dict.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd

from features import extract_features

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "model.pkl"


def load_model(path: Path = DEFAULT_MODEL_PATH):
    return joblib.load(path)


def predict_one(scan: Dict[str, Any], model) -> Dict[str, Any]:
    feats = extract_features(scan)
    proba = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(feats)[0]
        classes = list(model.classes_)
        top_idx = int(np.argmax(proba))
        return {
            "device": str(classes[top_idx]),
            "confidence": float(proba[top_idx]),
            "probas": {str(c): float(p) for c, p in zip(classes, proba)},
        }
    else:
        pred = model.predict(feats)[0]
        return {"device": str(pred), "confidence": None, "probas": None}


def main():
    ap = argparse.ArgumentParser(description="Predict device type from scan JSON")
    ap.add_argument("--model", type=str, default=str(DEFAULT_MODEL_PATH), help="Path to model.pkl")
    ap.add_argument("--json", type=str, required=False, help="Raw scan JSON string or path to JSON file")
    args = ap.parse_args()

    # Load input JSON (string or file path). If missing, read from stdin.
    if args.json:
        input_str = args.json
        p = Path(input_str)
        if p.exists():
            scan = json.loads(Path(p).read_text(encoding="utf-8"))
        else:
            scan = json.loads(input_str)
    else:
        import sys
        scan = json.load(sys.stdin)

    model = load_model(Path(args.model))
    result = predict_one(scan, model)

    # Pretty-print
    device = result["device"]
    conf = result["confidence"]
    print(f"Device: {device}")
    if conf is not None:
        print(f"Confidence: {conf:.2f}")


if __name__ == "__main__":
    main()
