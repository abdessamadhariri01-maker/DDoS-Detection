import io
import pandas as pd
from datetime import datetime
from collections import deque
from fastapi import APIRouter, HTTPException, UploadFile, File, Form

from app.api.schemas import (
    ManualInput, RowInput,
    PredictionResult, BatchPredictionResponse,
    StatsResponse, HealthResponse, FEATURE_COLS,
)
from app.models.loader import get_model, load_models, models_status
from app.models.predictor import predict_from_dict, predict_from_df_row, align_df

# ── NO prefix here — main.py already adds /api/v1 ────────────────────────────
router = APIRouter()

_history: deque = deque(maxlen=2000)
_stats = {"total": 0, "ddos": 0, "normal": 0}


def _record(label: int):
    _stats["total"] += 1
    if label == 1:
        _stats["ddos"] += 1
    else:
        _stats["normal"] += 1


@router.on_event("startup")
async def startup_event():
    load_models()


# ── Health ────────────────────────────────────────────────────────────────────

@router.get("/health", response_model=HealthResponse, tags=["system"])
def health_check():
    return HealthResponse(status="ok", models_loaded=models_status())


@router.get("/features", tags=["system"])
def feature_list():
    return {"columns": FEATURE_COLS, "count": len(FEATURE_COLS)}


# ── Manual input (5 key features) ────────────────────────────────────────────

@router.post("/predict/manual", response_model=PredictionResult, tags=["predict"])
def predict_manual(body: ManualInput):
    """5 features typed by the user — the other 72 default to 0."""
    model_key = "rf" if body.model.lower() in ("rf", "random forest") else "svm"
    data = {
        "Destination Port":  body.destination_port,
        "Flow Duration":     body.flow_duration,
        "Total Fwd Packets": body.total_fwd_packets,
        "Flow Packets/s":    body.flow_packets_s,
        "Flow Bytes/s":      body.flow_bytes_s,
    }
    try:
        out = predict_from_dict(data, model_key)
    except ValueError as e:
        raise HTTPException(503, str(e))
    _record(out["label"])
    _history.append(out)
    return out


# ── Full row prediction (used by Live Simulation) ─────────────────────────────

@router.post("/predict/row", response_model=PredictionResult, tags=["predict"])
def predict_row(body: RowInput):
    """Dict of any/all 77 features — missing keys default to 0."""
    model_key = "rf" if body.model.lower() in ("rf", "random forest") else "svm"
    try:
        out = predict_from_dict(body.features, model_key)
    except ValueError as e:
        raise HTTPException(503, str(e))
    _record(out["label"])
    _history.append(out)
    return out


# ── CSV upload ────────────────────────────────────────────────────────────────

@router.post("/predict/csv", response_model=BatchPredictionResponse, tags=["predict"])
async def predict_csv(
    file:  UploadFile = File(...),
    model: str        = Form("rf"),
    limit: int        = Form(500),
):
    """Upload a CSV — each row classified as BENIGN or DDoS."""
    model_key = "rf" if model.lower() in ("rf", "random forest") else "svm"
    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(400, f"Cannot parse CSV: {e}")

    df_aligned = align_df(df).head(limit)
    results, errors = [], 0

    for i in range(len(df_aligned)):
        try:
            X   = df_aligned.iloc[[i]].values
            out = predict_from_df_row(X, model_key)
            out["row_index"] = i
            results.append(out)
            _record(out["label"])
            _history.append(out)
        except Exception:
            errors += 1

    ddos_count = sum(1 for r in results if r["label"] == 1)
    return BatchPredictionResponse(
        total=len(results),
        ddos_count=ddos_count,
        benign_count=len(results) - ddos_count,
        errors=errors,
        results=results,
    )


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=StatsResponse, tags=["monitor"])
def get_stats():
    total = _stats["total"] or 1
    return StatsResponse(
        total_requests=_stats["total"],
        ddos_detected=_stats["ddos"],
        normal_traffic=_stats["normal"],
        detection_rate=round(_stats["ddos"] / total, 4),
        last_updated=datetime.utcnow(),
    )


# ── History ───────────────────────────────────────────────────────────────────

@router.get("/history", tags=["monitor"])
def get_history(limit: int = 100):
    items = list(_history)[-min(limit, 2000):]
    return {"count": len(items), "results": items}