from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime

# ── Real 77 CIC-DDoS2019 feature columns ──────────────────────────────────────
FEATURE_COLS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets',
    'Total Backward Packets', 'Total Length of Fwd Packets',
    'Total Length of Bwd Packets', 'Fwd Packet Length Max',
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
    'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags',
    'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
    'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
    'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
    'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]

class ManualInput(BaseModel):
    """5 key features typed by the user — the other 72 default to 0."""
    destination_port:  float = 443.0
    flow_duration:     float = 85000.0
    total_fwd_packets: float = 2.0
    flow_packets_s:    float = 19736.84
    flow_bytes_s:      float = 118421.05
    model: str = "rf"

class RowInput(BaseModel):
    """Any/all of the 77 features as a dict — missing keys default to 0."""
    features: Dict[str, Any]
    model: str = "rf"

class PredictionResult(BaseModel):
    prediction: str    # "BENIGN" or "DDoS"
    label: int         # 0 or 1
    confidence: float
    model_used: str
    timestamp: datetime

class BatchPredictionResponse(BaseModel):
    total: int
    ddos_count: int
    benign_count: int
    errors: int
    results: List[dict]

class StatsResponse(BaseModel):
    total_requests: int
    ddos_detected: int
    normal_traffic: int
    detection_rate: float
    last_updated: datetime

class HealthResponse(BaseModel):
    status: str
    models_loaded: dict