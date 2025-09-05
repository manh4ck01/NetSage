"""
Train a device type classifier from a CSV dataset of features OR raw scans.
Saves a full sklearn Pipeline (preprocessing + model) to /ml/model.pkl.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

# Optional XGBoost (falls back to RandomForest if unavailable)
try:
    from xgboost import XGBClassifier  # type: ignore
    HAVE_XGB = True
except Exception:
    HAVE_XGB = False

from features import get_feature_columns, extract_features

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent / "model.pkl"


def _prepare_dataframe(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Return (X, y). If df contains a 'raw_scan' column, expand it via extract_features()."""
    assert "device_type" in df.columns, "Dataset must include a 'device_type' label column."

    if "raw_scan" in df.columns:
        # Expand raw JSON scans into features
        feats = []
        for raw in df["raw_scan"].tolist():
            if isinstance(raw, str):
                try:
                    js = json.loads(raw)
                except Exception:
                    js = {}
            else:
                js = raw if isinstance(raw, dict) else {}
            feats.append(extract_features(js))
        feat_df = pd.concat(feats, ignore_index=True)
    else:
        # Assume columns are already extracted features
        feat_cols = [c for c in df.columns if c != "device_type"]
        feat_df = df[feat_cols].copy()

    y = df["device_type"].astype(str)
    X = feat_df
    return X, y


def build_pipeline(X: pd.DataFrame):
    """Build a sklearn Pipeline that preprocesses columns to match X and trains a classifier."""
    # Separate numeric and categorical columns by dtype
    numeric_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    categorical_cols = [c for c in X.columns if c not in numeric_cols]

    pre = ColumnTransformer(
        transformers=[
            ("num", SimpleImputer(strategy="median"), numeric_cols),
            ("cat", Pipeline(steps=[
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("ohe", OneHotEncoder(handle_unknown="ignore"))
            ]), categorical_cols)
        ]
    )

    if HAVE_XGB:
        model = XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            reg_lambda=1.0,
            random_state=42,
            n_jobs=0,
            tree_method="hist",
        )
    else:
        model = RandomForestClassifier(
            n_estimators=300, max_depth=None, random_state=42, n_jobs=0, class_weight=None
        )

    pipe = Pipeline(steps=[("pre", pre), ("model", model)])
    return pipe


def main():
    ap = argparse.ArgumentParser(description="Train Device Type Classifier")
    ap.add_argument("--csv", type=str, default=str(Path(__file__).with_name("sample_dataset.csv")),
                    help="Path to training CSV. Must include device_type column. Can optionally include raw_scan JSON column.")
    ap.add_argument("--out", type=str, default=str(DEFAULT_MODEL_PATH), help="Output path for model.pkl")
    args = ap.parse_args()

    csv_path = Path(args.csv)
    out_path = Path(args.out)

    df = pd.read_csv(csv_path)
    X, y = _prepare_dataframe(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipe = build_pipeline(X_train)
    pipe.fit(X_train, y_train)

    # Evaluate
    y_pred = pipe.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {acc:.3f}\n")
    print("Classification Report:")
    print(classification_report(y_test, y_pred))

    # Feature importance (best-effort): works for tree-based models
    try:
        # Get feature names after preprocessing
        pre = pipe.named_steps["pre"]
        num_features = pre.transformers_[0][2]
        cat_features = pre.transformers_[1][1].named_steps["ohe"].get_feature_names_out(pre.transformers_[1][2])
        feature_names = list(num_features) + list(cat_features)
        model = pipe.named_steps["model"]
        if hasattr(model, "feature_importances_"):
            importances = model.feature_importances_
            imp_df = pd.DataFrame({"feature": feature_names, "importance": importances})
            imp_df = imp_df.sort_values("importance", ascending=False).head(20)
            print("\nTop 20 Feature Importances:")
            for _, row in imp_df.iterrows():
                print(f"{row['feature']}: {row['importance']:.4f}")
        else:
            print("\nModel does not expose feature_importances_. Skipping.")
    except Exception as e:
        print(f"\nCould not compute feature importances: {e}")

    # Save pipeline
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, out_path)
    print(f"\nSaved model to: {out_path}")


if __name__ == "__main__":
    main()
