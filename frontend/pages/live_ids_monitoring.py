import time
import pandas as pd
import requests
import streamlit as st
import plotly.express as px
from datetime import datetime

from auth import require_permission, logout_button


import os

API_BASE_URL = os.getenv(
    "API_BASE_URL",
    "http://127.0.0.1:8000"
)

API_URL = f"{API_BASE_URL}/predict-batch" 


st.set_page_config(
    page_title="Live IDS Monitoring",
    page_icon="📡",
    layout="wide"
)

require_permission("live_ids_monitoring")
logout_button()

st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0E1117 0%, #111827 100%);
        color: #FAFAFA;
    }

    h1, h2, h3 {
        color: #00E5FF;
    }

    [data-testid="stMetricValue"] {
        color: #00E5FF;
        font-weight: 700;
    }

    .cyber-card {
        background-color: #161B22;
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #1F2937;
        box-shadow: 0 0 12px rgba(0, 229, 255, 0.12);
        margin-bottom: 16px;
    }

    .alert-card {
        background: linear-gradient(135deg, #2A0F13 0%, #40151C 100%);
        padding: 14px;
        border-radius: 12px;
        border: 1px solid #7F1D1D;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)


def calculate_threat_score(prediction, severity, confidence):
    if prediction == "BENIGN":
        return 0

    base_scores = {
        "LOW": 20,
        "MEDIUM": 55,
        "HIGH": 85,
        "UNKNOWN": 40
    }

    if confidence is None:
        confidence = 0.5

    return round(min(base_scores.get(severity, 40) * float(confidence), 100), 2)


def clean_dataframe(df):
    df = df.copy()
    df.columns = df.columns.str.strip()
    df = df.replace([float("inf"), float("-inf")], 0)
    df = df.fillna(0)

    for col in ["Label", "label"]:
        if col in df.columns:
            df = df.drop(columns=[col])

    return df


def predict_batch(batch_df):
    records = batch_df.to_dict(orient="records")

    response = requests.post(
        API_URL,
        json={"records": records},
        timeout=60
    )

    if response.status_code != 200:
        raise RuntimeError(response.text)

    return response.json()["results"]


st.markdown("""
<div class="cyber-card">
    <h1>📡 Live Network Monitoring</h1>
    <p>Real-time IDS simulation using streamed network flow records.</p>
</div>
""", unsafe_allow_html=True)


uploaded_file = st.file_uploader(
    "Качи CIC-IDS2017 CSV файл за live monitoring simulation",
    type=["csv"]
)


col_a, col_b, col_c = st.columns(3)

batch_size = col_a.slider(
    "Flow records per cycle",
    min_value=10,
    max_value=1000,
    value=100,
    step=10
)

delay = col_b.slider(
    "Delay между циклите",
    min_value=0.1,
    max_value=5.0,
    value=1.0,
    step=0.1
)

max_cycles = col_c.slider(
    "Брой live цикли",
    min_value=1,
    max_value=100,
    value=20,
    step=1
)


if "live_results" not in st.session_state:
    st.session_state.live_results = pd.DataFrame()

if "alert_log" not in st.session_state:
    st.session_state.alert_log = []


if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
    df.columns = df.columns.str.strip()

    st.subheader("📄 Преглед на входните flow данни")
    st.dataframe(df.head(10), width="stretch")

    df_for_prediction = clean_dataframe(df)

    start_button = st.button("▶️ Стартирай Live Monitoring")

    if start_button:
        st.session_state.live_results = pd.DataFrame()
        st.session_state.alert_log = []

        metrics_placeholder = st.empty()
        alerts_placeholder = st.empty()
        table_placeholder = st.empty()
        chart_placeholder = st.empty()

        total_rows = len(df_for_prediction)

        for cycle in range(max_cycles):
            start_index = cycle * batch_size
            end_index = start_index + batch_size

            if start_index >= total_rows:
                break

            batch_df = df_for_prediction.iloc[start_index:end_index].copy()

            predictions = predict_batch(batch_df)

            batch_output = batch_df.copy()
            batch_output["prediction"] = [
                item["prediction"] for item in predictions
            ]
            batch_output["confidence"] = [
                item["confidence"] for item in predictions
            ]
            batch_output["severity"] = [
                item["severity"] for item in predictions
            ]

            batch_output["threat_score"] = batch_output.apply(
                lambda row: calculate_threat_score(
                    row["prediction"],
                    row["severity"],
                    row["confidence"]
                ),
                axis=1
            )

            batch_output["timestamp"] = datetime.now().strftime("%H:%M:%S")

            st.session_state.live_results = pd.concat(
                [st.session_state.live_results, batch_output],
                ignore_index=True
            )

            attacks = batch_output[batch_output["prediction"] != "BENIGN"]

            for _, row in attacks.iterrows():
                st.session_state.alert_log.insert(0, {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "severity": row["severity"],
                    "attack": row["prediction"],
                    "confidence": row["confidence"],
                    "threat_score": row["threat_score"]
                })

            live_df = st.session_state.live_results

            total_analyzed = len(live_df)
            total_attacks = (live_df["prediction"] != "BENIGN").sum()
            normal_traffic = (live_df["prediction"] == "BENIGN").sum()
            avg_threat = live_df["threat_score"].mean()

            with metrics_placeholder.container():
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("📡 Анализирани flow записи", total_analyzed)
                c2.metric("✅ Нормален трафик", int(normal_traffic))
                c3.metric("🚨 Атаки", int(total_attacks))
                c4.metric("🔥 Avg Threat Score", f"{avg_threat:.2f}/100")

            with alerts_placeholder.container():
                st.subheader("🚨 Live Alert Panel")

                if not st.session_state.alert_log:
                    st.success("✅ Няма активни alert-и.")
                else:
                    alerts_df = pd.DataFrame(
                        st.session_state.alert_log[:15]
                    )
                    st.dataframe(alerts_df, width="stretch")

            with table_placeholder.container():
                st.subheader("📊 Последни анализирани записи")
                st.dataframe(
                    live_df.tail(20),
                    width="stretch"
                )

            with chart_placeholder.container():
                st.subheader("📈 Live Attack Distribution")

                prediction_counts = live_df["prediction"].value_counts().reset_index()
                prediction_counts.columns = ["Traffic Type", "Count"]

                fig = px.bar(
                    prediction_counts,
                    x="Traffic Type",
                    y="Count",
                    text="Count",
                    title="Live traffic classification"
                )

                st.plotly_chart(fig, width="stretch")

            time.sleep(delay)

        st.success("✅ Live monitoring simulation finished.")
else:
    st.info("📂 Качи CSV файл, за да стартираш live monitoring.")