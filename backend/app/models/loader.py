import pickle
import os
from pathlib import Path
import joblib

# Resolve paths relative to this file
MODELS_DIR = Path(__file__).parent

_models = {}


def load_models():
    """Load all pkl models into memory. Called once at API startup."""
    global _models
    model_files = {
        "rf": "rf_model.pkl",
        "svm": "svm_model.pkl",
        "scaler": "scaler.pkl",
    }
    for key, filename in model_files.items():
        path = MODELS_DIR / filename
        if path.exists():
            with open(path, "rb") as f:
                _models[key] = model = joblib.load(f)
            print(f"[loader] Loaded {filename}")
        else:
            print(f"[loader] WARNING: {filename} not found at {path}")
            _models[key] = None


def get_model(name: str):
    """Return a loaded model by key: 'rf', 'svm', or 'scaler'."""
    if not _models:
        load_models()
    return _models.get(name)


def models_status() -> dict:
    """Return loading status of each model (for health check)."""
    return {k: (v is not None) for k, v in _models.items()}
