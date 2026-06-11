import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import requests
import time
import random
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# CONFIG
# ============================================================
API_BASE = "http://127.0.0.1:8000/api/v1"

st.set_page_config(
    page_title="Systeme de Detection DDoS",
    page_icon="",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CSS  (identical to your original)
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap');
* { font-family: 'Exo 2', sans-serif; }
.stApp { background: #030712; color: #e2e8f0; }
section[data-testid="stSidebar"] { background: #0f172a !important; border-right: 1px solid #1e3a5f; }
[data-testid="metric-container"] { background: linear-gradient(135deg,#0f172a,#1e293b); border: 1px solid #1e3a5f; border-radius: 12px; padding: 16px; }
.alert-box { background: linear-gradient(135deg,#450a0a,#7f1d1d); border: 1px solid #ef4444; border-left: 4px solid #ef4444; border-radius: 8px; padding: 16px 20px; margin: 8px 0; font-family: 'Share Tech Mono',monospace; font-size: 15px; color: #fca5a5; animation: pulse 2s infinite; text-align: center; }
.normal-box { background: linear-gradient(135deg,#052e16,#14532d); border: 1px solid #22c55e; border-left: 4px solid #22c55e; border-radius: 8px; padding: 16px 20px; margin: 8px 0; font-family: 'Share Tech Mono',monospace; font-size: 15px; color: #86efac; text-align: center; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.75} }
.header-title { font-family: 'Share Tech Mono',monospace; font-size: 28px; font-weight: 700; color: #38bdf8; text-shadow: 0 0 20px rgba(56,189,248,0.4); letter-spacing: 2px; }
.section-title { font-family: 'Share Tech Mono',monospace; color: #38bdf8; font-size: 14px; letter-spacing: 3px; text-transform: uppercase; border-bottom: 1px solid #1e3a5f; padding-bottom: 8px; margin-bottom: 16px; }
.model-badge { display: inline-block; background: linear-gradient(135deg,#0369a1,#0ea5e9); color: white; padding: 4px 12px; border-radius: 20px; font-family: 'Share Tech Mono',monospace; font-size: 12px; letter-spacing: 1px; }
.status-online { display: inline-block; width: 8px; height: 8px; background: #22c55e; border-radius: 50%; margin-right: 6px; box-shadow: 0 0 8px #22c55e; animation: blink 1.5s infinite; }
.status-offline { display: inline-block; width: 8px; height: 8px; background: #ef4444; border-radius: 50%; margin-right: 6px; }
@keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
.stButton > button { background: linear-gradient(135deg,#0369a1,#0ea5e9); color: white; border: none; border-radius: 8px; font-family: 'Share Tech Mono',monospace; letter-spacing: 1px; font-weight: 600; padding: 10px 24px; transition: all 0.2s; }
.stButton > button:hover { background: linear-gradient(135deg,#0ea5e9,#38bdf8); box-shadow: 0 0 20px rgba(56,189,248,0.3); transform: translateY(-1px); }
.api-tag { display: inline-block; background: rgba(56,189,248,0.1); border: 1px solid #1e3a5f; color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-family: 'Share Tech Mono',monospace; font-size: 11px; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# API HELPERS
# ============================================================

def api_health() -> dict:
    try:
        r = requests.get(f"{API_BASE}/health", timeout=3)
        return r.json()
    except Exception:
        return {"status": "unreachable", "models": {}}


def api_predict_manual(dst_port, flow_dur, fwd_pkts, flow_pkt_s, flow_byt_s, model_key) -> dict | None:
    try:
        r = requests.post(f"{API_BASE}/predict/manual", json={
            "destination_port":  dst_port,
            "flow_duration":     flow_dur,
            "total_fwd_packets": fwd_pkts,
            "flow_packets_s":    flow_pkt_s,
            "flow_bytes_s":      flow_byt_s,
            "model":             model_key,
        }, timeout=10)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f" API error: {e}")
        return None


def api_predict_csv(file_bytes, filename, model_key, limit) -> dict | None:
    try:
        r = requests.post(
            f"{API_BASE}/predict/csv",
            files={"file": (filename, file_bytes, "text/csv")},
            data={"model": model_key, "limit": str(limit)},
            timeout=60,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f" API error: {e}")
        return None


def api_predict_row(features: dict, model_key: str) -> dict | None:
    """Used internally by live simulation."""
    try:
        r = requests.post(
            f"{API_BASE}/predict/row",
            json={"features": features, "model": model_key},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f" API error: {e}")
        return None

def api_stats() -> dict:
    try:
        r = requests.get(f"{API_BASE}/stats", timeout=5)
        return r.json()
    except Exception:
        return {"total_analyzed": 0, "total_attacks": 0, "attack_rate": 0.0}


# ============================================================
# FEATURE COLUMNS — 77 cols
# ============================================================
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


def generate_sample(is_attack=False) -> dict:
    if is_attack:
        vals = [
            80,1293792,3,7,26,11607,20,0,8.666666667,10.26320288,
            5840,0,1658.142857,2137.29708,8991.398927,7.72921768,
            143754.6667,430865.8067,1292730,2,
            1292730,646365,913621.5,1292730,2,
            0,0,0,0,0,0,0,0,0,32,32,2.317,5.412,
            0,5840,835.5714,1923.5,3700000,
            0,1,0,0,1,0,0,0,0,835.5714,8.6666,1658.14,
            0,0,0,0,0,0,3,26,7,11607,255,255,3,20,
            0,0,0,0,0,0,0,0
        ]
    else:
        vals = [
            443,85000,2,1,12,6,6,6,6.0,0.0,6,6,6.0,0.0,118421.05,19736.84,
            45.0,0.0,45.0,45.0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,20,20,
            9868.42,9868.42,6,6,6.0,0.0,0,0,1,0,0,1,0,0,0,1,8,6,6,
            20,0,0,0,0,0,0,1,6,1,6,255,255,0,20,0,0,0,0,0,0,0,0
        ]
    n    = len(FEATURE_COLS)
    vals = vals[:n] if len(vals) >= n else vals + [0] * (n - len(vals))
    return dict(zip(FEATURE_COLS, vals))


def simulate_traffic(is_attack=False) -> dict:
    if is_attack:
        return {'packets': random.uniform(8000, 25000),
                'bytes':   random.uniform(500000, 2000000)}
    return {'packets': random.uniform(50, 500),
            'bytes':   random.uniform(5000, 80000)}


# ============================================================
# SESSION STATE
# ============================================================
for key, default in [
    ('traffic_history', []), ('events', []),
    ('features_history', []),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown('<div class="header-title">Detection DDoS<br></div>', unsafe_allow_html=True)
    st.markdown('<div class="header-title"><br></div>', unsafe_allow_html=True)


    # ── API status ────────────────────────────────────────────
    health = api_health()
    api_ok = health.get("status") == "ok"
    models_ok = all(health.get("models", {}).values())

    if api_ok and models_ok:
        st.success(" API et Modèles fonctionnels")
    elif api_ok:
        st.warning(" API OK — modèles manquants")
    else:
        st.error(" API non joignable\n\n`python main.py` dans /backend")

    st.markdown('<div class="section-title">Choisir le Modèle</div>', unsafe_allow_html=True)
    model_choice = st.radio(
        "Modèle de classification :",
        [" Random Forest", " SVM"],
        index=0
    )
    model_key = "rf" if "Forest" in model_choice else "svm"

    if model_key == "rf":
        st.success(" Random Forest sélectionné")
    else:
        st.info(" SVM sélectionné")

    st.markdown("---")
    st.markdown('<div class="section-title"> Mode</div>', unsafe_allow_html=True)
    monitor_mode = st.selectbox("Mode", [
        " Live Simulation",
        " Analyse Fichier CSV",
        " Saisie Manuelle",
    ])

    st.markdown("---")
    st.markdown('<div class="section-title"> Statistiques API</div>', unsafe_allow_html=True)
    

    st.markdown("---")
    if st.button(" Reset session"):
        st.session_state.traffic_history  = []
        st.session_state.events           = []
        st.session_state.features_history = []
        st.rerun()

# ============================================================
# HEADER
# ============================================================
ch1, ch2, ch3 = st.columns([3, 1, 1])
with ch1:
    st.markdown('<div class="header-title"> Detection DDoS</div>', unsafe_allow_html=True)
    dot = '<span class="status-online"></span>' if api_ok else '<span class="status-offline"></span>'
    st.markdown(
        f'{dot}<span style="color:#64748b;font-size:12px;font-family:Share Tech Mono;">'
        f'{"SYSTEM ONLINE" if api_ok else "API OFFLINE"} — {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</span>',
        unsafe_allow_html=True
    )
with ch2:
    st.markdown('<br>', unsafe_allow_html=True)
    
with ch3:
    st.markdown('<br>', unsafe_allow_html=True)
    st.info(" Random Forest Actif" if model_key == "rf" else " SVM actif")

st.markdown("---")


# ============================================================
# MODE 1 — LIVE SIMULATION
# ============================================================
if monitor_mode == " Live Simulation":

    st.markdown('<div class="section-title"> Simulation Trafic Réseau</div>', unsafe_allow_html=True)
    
    st.markdown("<br>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1: inject_attack = st.button("Injecter Attaque DDoS")
    with col2: inject_normal = st.button(" Injecter Trafic Normal")
    with col3: auto_sim      = st.checkbox(" Simulation Auto")

    def process(is_atk: bool):
        features = generate_sample(is_attack=is_atk)
        result   = api_predict_row(features, model_key)
        if result is None:
            return
        detected = result["label"] == 1
        traffic  = simulate_traffic(is_attack=is_atk)
        ts       = datetime.now()

        st.session_state.features_history.append({
            'timestamp':  ts,
            'is_attack':  is_atk,
            'prediction': result["label"],
            'confidence': result["confidence"],
            'features':   pd.DataFrame([features]),
            'model':      model_key.upper(),
        })
        st.session_state.traffic_history.append({
            'time':      ts,
            'packets':   traffic['packets'],
            'bytes':     traffic['bytes'],
            'is_attack': detected,
        })
        st.session_state.events.append({
            'Timestamp':  ts.strftime("%H:%M:%S"),
            'Modèle':     model_key.upper(),
            'Résultat':   " DDoS" if detected else " BENIGN",
            'Confiance':  f"{result['confidence']*100:.1f}%",
            'Statut':     " ATTAQUE" if detected else " NORMAL",
        })

    if inject_attack: process(True)
    if inject_normal: process(False)
    if auto_sim:
        process(random.random() < 0.3)
        time.sleep(0.5)
        st.rerun()

    # Alert banner
    if st.session_state.events:
        last = st.session_state.events[-1]
        if "ATTAQUE" in last['Statut']:
            st.markdown(f'<div class="alert-box"> ALERTE [{last["Timestamp"]}] — Attaque DDoS détectée par {last["Modèle"]} ! (confiance {last["Confiance"]})</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="normal-box"> NORMAL [{last["Timestamp"]}] — Trafic légitime ({last["Modèle"]}) — confiance {last["Confiance"]}</div>', unsafe_allow_html=True)

    # Charts
    st.markdown('<div class="section-title"> Graphique du Trafic</div>', unsafe_allow_html=True)
    if st.session_state.traffic_history:
        df_hist = pd.DataFrame(st.session_state.traffic_history)

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_hist['time'], y=df_hist['packets'],
            mode='lines+markers', name='Paquets/sec',
            line=dict(color='#38bdf8', width=2),
            marker=dict(
                color=['#ef4444' if a else '#22c55e' for a in df_hist['is_attack']],
                size=10, line=dict(color='white', width=1)
            ),
            fill='tozeroy', fillcolor='rgba(56,189,248,0.05)'
        ))
        atk_df = df_hist[df_hist['is_attack']]
        if len(atk_df):
            fig.add_trace(go.Scatter(
                x=atk_df['time'], y=atk_df['packets'], mode='markers',
                name=' Attaque',
                marker=dict(color='#ef4444', size=16, symbol='x',
                            line=dict(color='white', width=2))
            ))
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.8)',
            font=dict(color='#94a3b8', family='Share Tech Mono'),
            xaxis=dict(gridcolor='#1e3a5f', title='Temps'),
            yaxis=dict(gridcolor='#1e3a5f', title='Paquets/sec'),
            legend=dict(bgcolor='rgba(15,23,42,0.8)', bordercolor='#1e3a5f'),
            height=320, margin=dict(l=0,r=0,t=10,b=0)
        )
        st.plotly_chart(fig, use_container_width=True)

        fig2 = go.Figure()
        fig2.add_trace(go.Bar(
            x=df_hist['time'], y=df_hist['bytes'],
            marker_color=['#ef4444' if a else '#0ea5e9' for a in df_hist['is_attack']]
        ))
        fig2.update_layout(
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(15,23,42,0.8)',
            font=dict(color='#94a3b8', family='Share Tech Mono'),
            xaxis=dict(gridcolor='#1e3a5f'),
            yaxis=dict(gridcolor='#1e3a5f', title='Bytes/sec'),
            height=220, margin=dict(l=0,r=0,t=10,b=0), showlegend=False
        )
        st.plotly_chart(fig2, use_container_width=True)

        # Export 77 features
        if st.session_state.features_history:
            st.markdown("---")
            st.markdown('<div class="section-title"> Exporter les 77 colonnes</div>', unsafe_allow_html=True)
            fh = st.session_state.features_history
            st.info(f"{len(fh)} injection(s) disponible(s)")

            opts = []
            for idx, item in enumerate(fh):
                atype    = " DDoS" if item['is_attack'] else "BENIGN"
                correct  = item['is_attack'] == (item['prediction'] == 1)
                opts.append(f"{idx+1}: {atype} | {item['timestamp'].strftime('%H:%M:%S')} | {item['model']} | {'' if correct else ''}")

            sel_idx  = st.selectbox("Injection à exporter :", range(len(opts)), format_func=lambda x: opts[x])
            selected = fh[sel_idx]

            ci1, ci2, ci3 = st.columns(3)
            ci1.metric("Type réel",    " ATTAQUE" if selected['is_attack'] else "NORMAL")
            ci2.metric("Prédiction",   " DDoS"    if selected['prediction'] == 1 else " BENIGN")
            ci3.metric("Confiance",    f"{selected['confidence']*100:.1f}%")

            cb1, cb2 = st.columns(2)
            with cb1:
                st.download_button(
                    " Télécharger cette injection (CSV)",
                    selected['features'].to_csv(index=False),
                    f"injection_{sel_idx+1}.csv", "text/csv",
                    use_container_width=True
                )
            with cb2:
                if len(fh) > 1:
                    all_dfs = []
                    for idx, item in enumerate(fh):
                        tmp = item['features'].copy()
                        tmp.insert(0, 'injection_id', idx+1)
                        tmp.insert(1, 'timestamp', item['timestamp'].strftime('%Y-%m-%d %H:%M:%S'))
                        tmp.insert(2, 'actual_type', 'DDoS' if item['is_attack'] else 'BENIGN')
                        tmp.insert(3, 'prediction',  'DDoS' if item['prediction'] == 1 else 'BENIGN')
                        tmp.insert(4, 'confidence',  item['confidence'])
                        tmp.insert(5, 'model', item['model'])
                        all_dfs.append(tmp)
                    all_csv = pd.concat(all_dfs, ignore_index=True).to_csv(index=False)
                    st.download_button(
                        f"Toutes les {len(fh)} injections (CSV)",
                        all_csv,
                        f"all_injections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        "text/csv",
                        use_container_width=True
                    )

            with st.expander(" Aperçu des 77 colonnes"):
                st.dataframe(selected['features'], use_container_width=True)
    else:
        st.info(" En attente de trafic...")


# ============================================================
# MODE 2 — ANALYSE FICHIER CSV
# ============================================================
elif monitor_mode == " Analyse Fichier CSV":

    st.markdown('<div class="section-title"> Analyse d\'un Fichier CSV</div>', unsafe_allow_html=True)
    st.markdown(
        f'Modèle actif : <span class="model-badge">{model_choice}</span> &nbsp; ',
       
        unsafe_allow_html=True
    )
    st.markdown("<br>", unsafe_allow_html=True)

    if not api_ok:
        st.error(" API non joignable — lancez `python main.py` dans /backend")
        st.stop()

    st.info("Chargez un CSV avec  50+ features pour Meilleur resultats, Les colonnes manquantes seront remplacées par 0.")

    uploaded = st.file_uploader("Importer CSV", type=['csv'])

    if uploaded:
        # Quick preview without sending to API yet
        df_preview = pd.read_csv(uploaded)
        uploaded.seek(0)   # reset for API call

        st.success(f" {df_preview.shape[0]} lignes, {df_preview.shape[1]} colonnes")

        cols_present = [c for c in FEATURE_COLS if c in df_preview.columns]
        cols_missing = [c for c in FEATURE_COLS if c not in df_preview.columns]

        cv1, cv2 = st.columns(2)
        cv1.metric(" Colonnes présentes",  f"{len(cols_present)}/77")
        cv2.metric(" Colonnes manquantes", len(cols_missing))

        if cols_missing:
            with st.expander(f" {len(cols_missing)} colonnes manquantes → 0"):
                st.write(cols_missing)
            st.warning(" Colonnes manquantes remplacées par 0")
        else:
            st.success(" Toutes les 77 colonnes présentes !")

        n_sample = st.slider("Lignes à analyser", 10, min(500, len(df_preview)), 50)

        if st.button(" Lancer l'Analyse"):
            with st.spinner("Envoi au backend..."):
                file_bytes = uploaded.read()
                response   = api_predict_csv(file_bytes, uploaded.name, model_key, n_sample)

            if response is None:
                st.stop()

            results    = response["results"]
            n_attacks  = response["ddos_count"]
            n_normal   = response["benign_count"]
            n_errors   = response.get("errors", 0)

            if n_errors:
                st.warning(f" {n_errors} lignes ignorées")

            cr1, cr2, cr3 = st.columns(3)
            cr1.metric("Total analysé",    len(results))
            cr2.metric(" Attaques DDoS", n_attacks)
            cr3.metric(" Trafic Normal",  n_normal)

            # Pie chart
            fig_pie = go.Figure(go.Pie(
                labels=['BENIGN', 'DDoS'],
                values=[n_normal, n_attacks],
                hole=0.5,
                marker_colors=['#22c55e', '#ef4444']
            ))
            fig_pie.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#94a3b8', family='Share Tech Mono'),
                height=300, margin=dict(l=0,r=0,t=10,b=0)
            )
            st.plotly_chart(fig_pie, use_container_width=True)

            # Results table
            df_results = pd.DataFrame([{
                'Index':     r.get('row_index', i),
                'Modèle':    r['model_used'],
                'Résultat':  " DDoS" if r['label'] == 1 else  "BENIGN",
                'Confiance': f"{r['confidence']*100:.1f}%",
                'Classifié': " ATTAQUE" if r['label'] == 1 else "NORMAL",
            } for i, r in enumerate(results)])

            st.dataframe(df_results, use_container_width=True)

            st.download_button(
                "⬇️ Exporter résultats (CSV)",
                df_results.to_csv(index=False).encode('utf-8'),
                "resultats.csv", "text/csv"
            )


# ============================================================
# MODE 3 — SAISIE MANUELLE
# ==============
elif monitor_mode == " Saisie Manuelle":

    st.markdown('<div class="section-title">Saisie Manuelle</div>', unsafe_allow_html=True)
    st.markdown(
        f'Modèle actif : <span class="model-badge">{model_choice}</span> &nbsp; ',
        
        unsafe_allow_html=True
    )
    st.markdown("<br>", unsafe_allow_html=True)

    if not api_ok:
        st.error(" API non joignable — lancez `python main.py` dans /backend")
        st.stop()

    st.info(" Remplis les **5 features clés** — les 72 autres seront à 0 automatiquement.")

    c1, c2, c3 = st.columns(3)
    with c1:
        dst_port   = st.number_input("Destination Port",   value=443.0,     format="%.0f",  help="Port destination (443=HTTPS, 80=HTTP)")
        flow_dur   = st.number_input(" Flow Duration (µs)", value=85000.0,   format="%.2f",  help="Durée du flux en microsecondes")
    with c2:
        fwd_pkts   = st.number_input("Total Fwd Packets",  value=2.0,       format="%.0f",  help="Nombre total de paquets envoyés")
        flow_pkt_s = st.number_input(" Flow Packets/s",     value=19736.84,  format="%.2f",  help="Paquets par seconde — élevé = suspect !")
    with c3:
        flow_byt_s = st.number_input(" Flow Bytes/s",       value=118421.05, format="%.2f",  help="Bytes par seconde")

    if st.button(" Analyser"):
        with st.spinner("Analyse en cours..."):
            result = api_predict_manual(
                dst_port, flow_dur, fwd_pkts, flow_pkt_s, flow_byt_s, model_key
            )

        if result:
            detected = result["label"] == 1

            st.markdown("###  Résultat")
            cm1, cm2, cm3 = st.columns(3)
            cm1.metric(
                f"{' Random Forest' if model_key == 'rf' else ' SVM'}",
                " DDoS" if detected else " BENIGN"
            )
            cm2.metric(" Verdict Final",  " ATTAQUE" if detected else "NORMAL")
            cm3.metric(" Confiance",      f"{result['confidence']*100:.1f}%")

            if detected:
                st.markdown(
                    '<div class="alert-box"> ATTAQUE DDoS détectée !</div>',
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    '<div class="normal-box"> Trafic Normal — Aucune menace détectée.</div>',
                    unsafe_allow_html=True
                )

            # Export the full 77-feature vector used
            values = {col: 0.0 for col in FEATURE_COLS}
            values['Destination Port']    = dst_port
            values['Flow Duration']       = flow_dur
            values['Total Fwd Packets']   = fwd_pkts
            values['Flow Packets/s']      = flow_pkt_s
            values['Flow Bytes/s']        = flow_byt_s
            df_manual = pd.DataFrame([[values[f] for f in FEATURE_COLS]], columns=FEATURE_COLS)

            st.markdown("---")
            st.markdown('<div class="section-title"> Exporter</div>', unsafe_allow_html=True)
            st.download_button(
                " Télécharger les 77 colonnes (CSV)",
                df_manual.to_csv(index=False),
                f"manual_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "text/csv",
                use_container_width=True
            )


# ============================================================
# EVENTS TABLE
# ============================================================
st.markdown("---")
st.markdown('<div class="section-title">Tableau des Événements</div>', unsafe_allow_html=True)

if st.session_state.events:
    df_ev = pd.DataFrame(st.session_state.events[::-1])
    st.dataframe(df_ev, use_container_width=True, height=280)
    st.download_button(
        " Exporter événements (CSV)",
        df_ev.to_csv(index=False).encode('utf-8'),
        "events.csv", "text/csv"
    )
else:
    st.info(" Aucun événement enregistré.")

# ============================================================
# FOOTER
# ============================================================
