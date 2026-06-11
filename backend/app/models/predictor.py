import numpy as np
import pandas as pd
from datetime import datetime
from app.models.loader import get_model
from app.api.schemas import FEATURE_COLS


def align_dict(data: dict) -> np.ndarray:
    """Build (1, 77) array from any dict — missing cols default to 0."""
    row = [float(data.get(col, 0.0)) for col in FEATURE_COLS]
    return np.array([row])


def align_df(df: pd.DataFrame) -> pd.DataFrame:
    """Align a DataFrame to FEATURE_COLS, fill missing cols with 0."""
    out = pd.DataFrame(columns=FEATURE_COLS)
    for col in FEATURE_COLS:
        out[col] = df[col].values if col in df.columns else 0
    return out.fillna(0).astype(float)


def _run(X: np.ndarray, model_key: str) -> dict:
    scaler = get_model("scaler")
    model  = get_model(model_key)
    if model is None:
        raise ValueError(f"Model '{model_key}' not loaded.")
    Xs   = scaler.transform(X) if scaler else X
    pred = int(model.predict(Xs)[0])
    if hasattr(model, "predict_proba"):
        conf = float(max(model.predict_proba(Xs)[0]))
    elif hasattr(model, "decision_function"):
        margin = model.decision_function(Xs)[0]
        conf   = float(1 / (1 + np.exp(-abs(float(margin)))))
    else:
        conf = 1.0
    return {"label": pred, "confidence": round(conf, 4)}


def predict_from_dict(data: dict, model_key: str) -> dict:
    X   = align_dict(data)
    res = _run(X, model_key)
    return {
        "prediction": "DDoS" if res["label"] == 1 else "BENIGN",
        "label":      res["label"],
        "confidence": res["confidence"],
        "model_used": model_key.upper(),
        "timestamp":  datetime.utcnow(),
    }


def predict_from_df_row(X: np.ndarray, model_key: str) -> dict:
    res = _run(X, model_key)
    return {
        "prediction": "DDoS" if res["label"] == 1 else "BENIGN",
        "label":      res["label"],
        "confidence": res["confidence"],
        "model_used": model_key.upper(),
        "timestamp":  datetime.utcnow(),
    }