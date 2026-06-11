"""
api_client.py — drop this into your frontend/ folder.

Usage in ddos_dashboard.py:
    from api_client import DDoSApiClient

    client = DDoSApiClient()
    result = client.predict(features_dict)
    stats  = client.get_stats()
"""

import requests
from typing import Optional

API_BASE = "http://localhost:8000/api/v1"


class DDoSApiClient:
    def __init__(self, base_url: str = API_BASE, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ── Health ────────────────────────────────────────────────────────────────

    def health(self) -> dict:
        r = requests.get(f"{self.base_url}/health", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ── Single prediction ─────────────────────────────────────────────────────

    def predict(self, features: dict, model: str = "rf") -> dict:
        """
        Send one traffic sample for classification.

        Args:
            features: dict matching TrafficFeatures schema
            model: "rf" or "svm"

        Returns:
            {"prediction": "ddos"|"normal", "confidence": float,
             "model_used": str, "timestamp": str}
        """
        r = requests.post(
            f"{self.base_url}/predict",
            json=features,
            params={"model": model},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    # ── Batch prediction ──────────────────────────────────────────────────────

    def predict_batch(self, samples: list, model: str = "rf") -> dict:
        """Send multiple samples in one request."""
        payload = {"samples": samples, "model": model}
        r = requests.post(
            f"{self.base_url}/predict/batch",
            json=payload,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Fetch cumulative detection statistics."""
        r = requests.get(f"{self.base_url}/stats", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ── History ───────────────────────────────────────────────────────────────

    def get_history(self, limit: int = 50) -> dict:
        """Fetch the last N detection results."""
        r = requests.get(
            f"{self.base_url}/history",
            params={"limit": limit},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()


# ── Quick smoke-test (run directly: python api_client.py) ─────────────────────

if __name__ == "__main__":
    client = DDoSApiClient()

    print("Health:", client.health())
    print("Stats:", client.get_stats())

    sample = {
        "duration": 0.0,
        "protocol_type": 1,
        "src_bytes": 491.0,
        "dst_bytes": 0.0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "num_compromised": 0,
        "count": 2.0,
        "srv_count": 2.0,
        "serror_rate": 0.0,
        "rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
    }
    print("Prediction:", client.predict(sample, model="rf"))
