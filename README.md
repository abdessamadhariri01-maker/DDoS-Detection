# DDoS Detection System

Real-time DDoS attack detection using Random Forest and SVM classifiers trained on the CIC-DDoS2019 dataset. The system exposes a FastAPI backend for model inference and a Streamlit dashboard for interactive traffic analysis.

## Architecture

The application follows a client-server architecture with a clear separation between ML inference and presentation:

```
Streamlit Dashboard (frontend/)
    │
    ├── Manual Input    → 5 key features → API → aligned to 77 → prediction
    ├── CSV Upload      → batch rows     → API → aligned to 77 → predictions
    └── Live Simulation → auto-generated → API → aligned to 77 → predictions
                                   │
                            FastAPI (backend/)
                                   │
                         ┌─────────┴──────────┐
                    rf_model.pkl          svm_model.pkl
                    scaler.pkl
```

The backend loads pre-trained models at startup and serves predictions through a REST API. The frontend communicates with the API through a thin client wrapper.

## Project Structure

```
DDoS-Detection/
├── backend/
│   └── app/
│       ├── main.py              # FastAPI entry point, CORS, startup/shutdown
│       ├── api/
│       │   ├── routes.py        # 6 REST endpoints
│       │   └── schemas.py       # Pydantic models + 77 CIC-DDoS2019 column names
│       └── models/
│           ├── predictor.py     # Feature alignment, prediction, confidence scoring
│           ├── loader.py        # Load .pkl models with joblib
│           ├── rf_model.pkl     # Trained Random Forest
│           ├── svm_model.pkl    # Trained SVM
│           └── scaler.pkl       # Fitted StandardScaler
├── frontend/
│   ├── ddos_dashboard.py        # Streamlit dashboard (3 detection modes)
│   └── api_client.py            # API client wrapper
├── training/
│   ├── ddos.csv                 # CIC-DDoS2019 training data
│   └── pythonproject (3).ipynb  # Model training & evaluation notebook
├── tests/
│   ├── only_ddos.csv
│   ├── test DDOS.csv
│   └── test benign.csv
├── requirements.txt
└── README.md
```

## How Prediction Works

1. **Input** — The API accepts either 5 key features (simplified mode) or a full 77-feature vector
2. **Feature Alignment** — In simplified mode, the predictor maps the 5 inputs to the full 77-column schema used during training. Missing columns are set to 0.
3. **Scaling** — The StandardScaler (fitted on training data) normalizes the input
4. **Classification** — The selected model (RF or SVM) outputs a binary label: `0` (BENIGN) or `1` (DDoS)
5. **Confidence** — RF uses `predict_proba` directly; SVM applies a sigmoid function to `decision_function` scores since it doesn't natively support probability estimates

## API Endpoints

| Endpoint | Method | Description |
|:---|:---|:---|
| `/api/v1/health` | GET | API status and loaded model info |
| `/api/v1/features` | GET | Return the 77 CIC-DDoS2019 feature column names |
| `/api/v1/predict/manual` | POST | Predict from 5 key features |
| `/api/v1/predict/row` | POST | Predict from a full 77-feature dictionary |
| `/api/v1/predict/csv` | POST | Batch prediction from uploaded CSV (up to 500 rows) |
| `/api/v1/stats` | GET | Cumulative detection statistics |
| `/api/v1/history` | GET | Last N detection events |

Interactive API documentation is available at `/docs` (Swagger UI) when the server is running.

## Setup

```bash
git clone https://github.com/abdessamadhariri01-maker/DDoS-Detection.git
cd DDoS-Detection
pip install -r requirements.txt
```

**Start the backend:**
```bash
cd backend
python -m app.main
# → http://localhost:8000
# → API docs: http://localhost:8000/docs
```

**Start the dashboard:**
```bash
cd frontend
streamlit run ddos_dashboard.py
# → http://localhost:8501
```

## Tech Stack

| Component | Technology |
|:---|:---|
| Backend framework | FastAPI + Uvicorn |
| ML models | Scikit-learn (RandomForestClassifier, SVC) |
| Feature scaling | StandardScaler (joblib) |
| Frontend | Streamlit |
| Data visualization | Plotly |
| Input validation | Pydantic |
| Dataset | CIC-DDoS2019 — 77 network flow features |

## Authors

- [Abdessamad Hariri](https://www.linkedin.com/in/abdessamad-hariri)
- Achraf Choukroun
- Abdellah Amjoud

Module: Advanced Python — Faculté Polydisciplinaire de Béni Mellal (USMS)
