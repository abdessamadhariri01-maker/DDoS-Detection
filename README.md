<div align="center">

# DDoS Detection System

### ML-Powered DDoS Attack Detection using Random Forest & SVM

<img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white" />
<img src="https://img.shields.io/badge/StreamLit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white" />
<img src="https://img.shields.io/badge/Scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" />
<img src="https://img.shields.io/badge/CIC--DDoS2019-77_Features-blue?style=for-the-badge" />

**Real-time network traffic classification as BENIGN or DDoS with an interactive cybersecurity dashboard.**

</div>

---

## Overview

This project implements a complete **DDoS detection system** using Machine Learning. It features a **FastAPI backend** serving pre-trained Random Forest and SVM models, and a **Streamlit frontend** with a real-time cybersecurity-themed dashboard.

The models are trained on the **CIC-DDoS2019** dataset with **77 network flow features**, enabling accurate binary classification of network traffic.

---

## Architecture

```
ddos-detection/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application entry point
│   │   ├── api/
│   │   │   ├── routes.py        # REST API endpoints (6 routes)
│   │   │   └── schemas.py       # Pydantic models & 77 feature columns
│   │   └── models/
│   │       ├── predictor.py     # Prediction logic (align, predict, confidence)
│   │       ├── loader.py        # Model loading with joblib
│   │       ├── rf_model.pkl     # Trained Random Forest model
│   │       ├── svm_model.pkl    # Trained SVM model
│   │       └── scaler.pkl       # StandardScaler for feature normalization
├── frontend/
│   ├── ddos_dashboard.py        # Streamlit interactive dashboard
│   └── api_client.py            # Python API client wrapper
├── training/
│   ├── ddos.csv                 # Training dataset
│   └── pythonproject (3).ipynb  # Jupyter notebook (model training & evaluation)
├── tests/
│   ├── only_ddos.csv            # DDoS-only test samples
│   ├── test DDOS.csv            # Mixed test samples
│   └── test benign.csv          # Benign traffic test samples
├── requirements.txt
└── .gitignore
```

---

## Features

### 3 Detection Modes
- **Manual Input** — Enter 5 key network features for instant classification
- **CSV Upload** — Batch analyze up to 500 rows from a CSV file
- **Live Simulation** — Real-time traffic simulation with auto-injection

### ML Models
- **Random Forest (RF)** — Ensemble classifier with probability-based confidence scoring
- **Support Vector Machine (SVM)** — Margin-based classifier with sigmoid confidence mapping

### Dashboard
- Real-time traffic graphs (packets/sec, bytes/sec) with Plotly
- DDoS alert banners with animated pulse effects
- Detection statistics and event history table
- Export predictions, events, and full 77-feature vectors to CSV

### API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/health` | GET | Check API and model status |
| `/api/v1/features` | GET | List all 77 feature columns |
| `/api/v1/predict/manual` | POST | Predict from 5 key features |
| `/api/v1/predict/row` | POST | Predict from full 77-feature dict |
| `/api/v1/predict/csv` | POST | Batch prediction from CSV upload |
| `/api/v1/stats` | GET | Cumulative detection statistics |
| `/api/v1/history` | GET | Last N detection results |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | FastAPI + Uvicorn |
| ML Models | Scikit-learn (RandomForestClassifier, SVC) |
| Feature Scaling | StandardScaler |
| Frontend | Streamlit |
| Data Viz | Plotly |
| Serialization | Joblib / Pickle |
| Validation | Pydantic |
| Dataset | CIC-DDoS2019 (77 features) |

---

## Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/abdessamadhariri01-maker/DDoS-Detection.git
cd DDoS-Detection

# Install dependencies
pip install -r requirements.txt
```

### Run the Backend

```bash
cd backend
python -m app.main
# Server running at http://localhost:8000
# Interactive docs at http://localhost:8000/docs
```

### Run the Dashboard

```bash
cd frontend
streamlit run ddos_dashboard.py
# Dashboard opens at http://localhost:8501
```

---

## How It Works

1. **Feature Extraction** — Network traffic is described by 77 features from CIC-DDoS2019 (Destination Port, Flow Duration, Packet Lengths, IAT stats, TCP Flags, etc.)
2. **Preprocessing** — Features are aligned to the 77-column schema; missing columns default to 0. The StandardScaler normalizes input data.
3. **Prediction** — The selected model (RF or SVM) classifies the traffic as `BENIGN` (0) or `DDoS` (1)
4. **Confidence Scoring** — RF uses `predict_proba`; SVM uses sigmoid mapping on `decision_function`
5. **Visualization** — Results are displayed on the dashboard with real-time charts and alerts

---

## Authors

- **[Abdessamad Hariri](https://www.linkedin.com/in/abdessamad-hariri)** — Data Science & ML
- **Achraf Choukroun** — Data Science & ML
- **Abdellah Amjoud** — Data Science & ML

---

## Acknowledgments

- **CIC-DDoS2019 Dataset** — Canadian Institute for Cybersecurity
- **Module**: Advanced Python — Faculty of Polydisciplinary, Beni Mellal (USMS)

</div>