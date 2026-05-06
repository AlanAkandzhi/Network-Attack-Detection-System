import pandas as pd
import requests
import streamlit as st
import plotly.express as px
from datetime import datetime

from auth import require_permission, logout_button

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))

from database import init_db, save_alerts_bulk

init_db()

import os

API_BASE_URL = os.getenv(
    "API_BASE_URL",
    "http://127.0.0.1:8000"
)

API_URL = f"{API_BASE_URL}/predict-batch"


st.set_page_config(
    page_title="Network Attack Detection System",
    page_icon="🛡️",
    layout="wide"
)

require_permission("dashboard_analysis")
logout_button()


if "dashboard_output_df" not in st.session_state:
    st.session_state.dashboard_output_df = None


def calculate_threat_score(prediction, severity, confidence):
    if prediction == "BENIGN":
        return 0

    severity_base_scores = {
        "LOW": 20,
        "MEDIUM": 55,
        "HIGH": 85,
        "UNKNOWN": 40
    }

    base_score = severity_base_scores.get(severity, 40)

    if confidence is None:
        confidence = 0.5

    threat_score = base_score * float(confidence)

    return round(min(threat_score, 100), 2)


def get_alert_icon(severity):
    if severity == "HIGH":
        return "🔴"
    if severity == "MEDIUM":
        return "🟠"
    if severity == "LOW":
        return "🟢"
    return "⚪"


def build_live_alerts(output_df, max_alerts=15):
    attacks_df = output_df[output_df["prediction"] != "BENIGN"].copy()

    if attacks_df.empty:
        return pd.DataFrame(
            columns=["Time", "Severity", "Threat Score", "Attack Type", "Confidence"]
        )

    attacks_df = attacks_df.sort_values(
        by=["threat_score", "confidence"],
        ascending=False
    )

    alerts = []

    for _, row in attacks_df.head(max_alerts).iterrows():
        severity = row["severity"]
        icon = get_alert_icon(severity)

        alerts.append({
            "Time": datetime.now().strftime("%H:%M:%S"),
            "Severity": f"{icon} {severity}",
            "Threat Score": row["threat_score"],
            "Attack Type": row["prediction"],
            "Confidence": f"{row['confidence'] * 100:.2f}%"
        })

    return pd.DataFrame(alerts)


st.sidebar.title("🛡️ IDS Dashboard")

st.sidebar.markdown("""
### Информация

Система за анализ и класификация на мрежов трафик чрез методи за машинно обучение.

### Технологии
- Python
- FastAPI
- Streamlit
- Random Forest
- Scikit-learn
- CIC-IDS2017
- SQLite
""")

st.sidebar.success("System Status: ONLINE")


st.markdown("""
<style>
    .stApp {
        background: linear-gradient(135deg, #0E1117 0%, #111827 100%);
    }

    h1, h2, h3 {
        color: #00E5FF;
    }

    [data-testid="stSidebar"] {
        background-color: #0B0F14;
        border-right: 1px solid #1F2937;
    }

    [data-testid="stMetricValue"] {
        color: #00E5FF;
        font-weight: 700;
    }

    [data-testid="stMetricLabel"] {
        color: #E5E7EB;
    }

    div.stButton > button {
        background: linear-gradient(90deg, #00E5FF, #2563EB);
        color: white;
        border: none;
        border-radius: 10px;
        padding: 0.6rem 1.2rem;
        font-weight: 700;
    }

    div.stButton > button:hover {
        background: linear-gradient(90deg, #2563EB, #00E5FF);
        color: white;
        border: none;
    }

    .cyber-card {
        background-color: #161B22;
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #1F2937;
        box-shadow: 0 0 12px rgba(0, 229, 255, 0.08);
        margin-bottom: 16px;
    }

    .soc-card {
        background: linear-gradient(135deg, #111827 0%, #172033 100%);
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #243244;
        box-shadow: 0 0 16px rgba(0, 229, 255, 0.10);
        margin-bottom: 16px;
    }

    .danger-card {
        background: linear-gradient(135deg, #2A0F13 0%, #40151C 100%);
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #7F1D1D;
        box-shadow: 0 0 16px rgba(239, 68, 68, 0.18);
        margin-bottom: 16px;
    }

    .warning-card {
        background: linear-gradient(135deg, #2A1D0F 0%, #3F2D14 100%);
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #92400E;
        box-shadow: 0 0 16px rgba(245, 158, 11, 0.18);
        margin-bottom: 16px;
    }

    .database-card {
        background: linear-gradient(135deg, #071A24 0%, #102A3A 100%);
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #00E5FF;
        box-shadow: 0 0 18px rgba(0, 229, 255, 0.16);
        margin-bottom: 16px;
    }
</style>
""", unsafe_allow_html=True)


st.markdown("""
<div class="cyber-card">
    <h1>🛡️ Network Attack Detection System</h1>
    <p>AI-powered Intrusion Detection Dashboard for network traffic analysis.</p>
</div>
""", unsafe_allow_html=True)

st.markdown("""
Система за анализ и класификация на мрежов трафик чрез методи за машинно обучение.
""")


uploaded_file = st.file_uploader(
    "Качи CSV файл с мрежови характеристики",
    type=["csv"]
)


if uploaded_file is not None:

    df = pd.read_csv(uploaded_file)

    df.columns = df.columns.str.strip()
    df = df.replace([float("inf"), float("-inf")], 0)
    df = df.fillna(0)

    st.subheader("📄 Преглед на качените данни")

    st.dataframe(
        df.head(10),
        width="stretch"
    )

    df_for_prediction = df.copy()

    for col in ["Label", "label"]:
        if col in df_for_prediction.columns:
            df_for_prediction = df_for_prediction.drop(columns=[col])

    if st.button("🚀 Стартирай анализ"):

        records = df_for_prediction.to_dict(orient="records")

        try:
            response = requests.post(
                API_URL,
                json={"records": records},
                timeout=90
            )

            if response.status_code == 200:

                result = response.json()
                predictions = result["results"]

                output_df = df.copy()

                output_df["prediction"] = [
                    item["prediction"]
                    for item in predictions
                ]

                output_df["confidence"] = [
                    item["confidence"]
                    for item in predictions
                ]

                output_df["severity"] = [
                    item["severity"]
                    for item in predictions
                ]

                output_df["threat_score"] = output_df.apply(
                    lambda row: calculate_threat_score(
                        row["prediction"],
                        row["severity"],
                        row["confidence"]
                    ),
                    axis=1
                )

                st.session_state.dashboard_output_df = output_df

            else:
                st.error(f"API error: {response.status_code}")
                st.text(response.text)

        except requests.exceptions.RequestException as e:
            st.error("❌ Неуспешна връзка с backend API.")
            st.text(str(e))


if st.session_state.dashboard_output_df is not None:

    output_df = st.session_state.dashboard_output_df

    st.subheader("📊 Резултати от анализа")

    st.dataframe(
        output_df.head(50),
        width="stretch"
    )

    prediction_counts = output_df["prediction"].value_counts()
    severity_counts = output_df["severity"].value_counts()

    normal_count = prediction_counts.get("BENIGN", 0)
    attack_count = len(output_df) - normal_count
    total_records = len(output_df)

    avg_confidence = output_df["confidence"].mean()
    avg_threat_score = output_df["threat_score"].mean()
    max_threat_score = output_df["threat_score"].max()

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("📁 Общо записи", total_records)
    col2.metric("✅ Нормален трафик", int(normal_count))
    col3.metric("🚨 Открити атаки", int(attack_count))
    col4.metric("🎯 Средна увереност", f"{avg_confidence * 100:.2f}%")
    col5.metric("🔥 Threat Score", f"{avg_threat_score:.2f}/100")

    high_risk_count = severity_counts.get("HIGH", 0)
    medium_risk_count = severity_counts.get("MEDIUM", 0)

    if high_risk_count > 0:
        st.markdown(f"""
        <div class="danger-card">
            <h3>🔴 Critical SOC Summary</h3>
            <p><b>HIGH risk detections:</b> {int(high_risk_count)}</p>
            <p><b>Maximum threat score:</b> {max_threat_score:.2f}/100</p>
            <p>Системата засече високорискови мрежови събития, които изискват внимание.</p>
        </div>
        """, unsafe_allow_html=True)

    elif medium_risk_count > 0:
        st.markdown(f"""
        <div class="warning-card">
            <h3>🟠 SOC Summary</h3>
            <p><b>MEDIUM risk detections:</b> {int(medium_risk_count)}</p>
            <p><b>Maximum threat score:</b> {max_threat_score:.2f}/100</p>
            <p>Системата засече подозрителна активност със среден риск.</p>
        </div>
        """, unsafe_allow_html=True)

    else:
        st.markdown("""
        <div class="soc-card">
            <h3>🟢 SOC Summary</h3>
            <p>Не са засечени високорискови мрежови събития.</p>
        </div>
        """, unsafe_allow_html=True)

    st.subheader("📡 Live Alert Panel")

    alerts_df = build_live_alerts(output_df)

    if alerts_df.empty:
        st.success("✅ Няма активни alert-и.")
    else:
        st.dataframe(
            alerts_df,
            width="stretch"
        )

    st.markdown("""
    <div class="database-card">
        <h3>🗄️ SQLite Alert Storage</h3>
        <p>Save detected attack alerts into the local IDS database for future Alert History and reporting.</p>
    </div>
    """, unsafe_allow_html=True)

    if st.button("💾 Save Detected Alerts to Database", use_container_width=True):

        alerts_to_save = []

        for _, row in output_df.iterrows():

            attack_type = str(row.get("prediction", "Unknown"))

            if attack_type.upper() not in ["BENIGN", "NORMAL"]:

                alerts_to_save.append({
                    "module_source": "Dashboard Analysis",
                    "attack_type": attack_type,
                    "severity": row.get("severity", "UNKNOWN"),
                    "confidence": float(row.get("confidence", 0)),
                    "threat_score": float(row.get("threat_score", 0)),
                    "details": "Saved from uploaded CIC-IDS2017 CSV analysis"
                })

        if alerts_to_save:
            save_alerts_bulk(alerts_to_save)

            st.success(
                f"✅ Saved {len(alerts_to_save)} alerts to SQLite database."
            )

        else:
            st.info("No attack alerts found to save.")

    attack_types = prediction_counts.drop(
        labels=["BENIGN"],
        errors="ignore"
    )

    if not attack_types.empty:
        st.subheader("🚨 Видове открити атаки")

        attack_types_df = attack_types.reset_index()
        attack_types_df.columns = ["Attack Type", "Count"]

        st.dataframe(
            attack_types_df,
            width="stretch"
        )

        fig_attack_bar = px.bar(
            attack_types_df,
            x="Attack Type",
            y="Count",
            title="Брой открити атаки по тип",
            text="Count"
        )

        st.plotly_chart(
            fig_attack_bar,
            width="stretch"
        )

    chart_data = prediction_counts.reset_index()
    chart_data.columns = ["Traffic Type", "Count"]

    fig = px.pie(
        chart_data,
        names="Traffic Type",
        values="Count",
        title="Разпределение на мрежовия трафик"
    )

    st.plotly_chart(
        fig,
        width="stretch"
    )

    st.subheader("⚠️ Разпределение по ниво на риск")

    severity_df = severity_counts.reset_index()
    severity_df.columns = ["Severity", "Count"]

    st.dataframe(
        severity_df,
        width="stretch"
    )

    fig_severity = px.bar(
        severity_df,
        x="Severity",
        y="Count",
        title="Разпределение по ниво на риск",
        text="Count"
    )

    st.plotly_chart(
        fig_severity,
        width="stretch"
    )

    st.subheader("🔥 Разпределение на Threat Score")

    fig_threat = px.histogram(
        output_df,
        x="threat_score",
        nbins=20,
        title="Threat Score Distribution"
    )

    st.plotly_chart(
        fig_threat,
        width="stretch"
    )

    st.subheader("🎯 Разпределение на увереността на модела")

    fig_confidence = px.histogram(
        output_df,
        x="confidence",
        nbins=20,
        title="Confidence Score Distribution"
    )

    st.plotly_chart(
        fig_confidence,
        width="stretch"
    )

    if attack_count > 0:

        attack_message = ", ".join(
            [
                f"{attack}: {count}"
                for attack, count in attack_types.items()
            ]
        )

        if high_risk_count > 0:
            st.error(
                f"🔴 HIGH риск: {int(high_risk_count)} записа. Засечени атаки: {attack_message}"
            )

        elif medium_risk_count > 0:
            st.warning(
                f"🟠 MEDIUM риск: {int(medium_risk_count)} записа. Засечени атаки: {attack_message}"
            )

        else:
            st.warning(
                f"⚠️ Засечени са потенциални атаки: {attack_message}"
            )

    else:
        st.success(
            "✅ Не са открити атаки."
        )

    csv = output_df.to_csv(index=False)

    st.download_button(
        label="⬇️ Изтегли резултатите",
        data=csv,
        file_name="analysis_results.csv",
        mime="text/csv"
    )

else:
    st.info("📂 Качи CSV файл, за да започнеш анализ.")