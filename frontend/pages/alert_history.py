import pandas as pd
import streamlit as st
import plotly.express as px

from auth import require_permission, logout_button

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"

if str(BACKEND_DIR) not in sys.path:
    sys.path.append(str(BACKEND_DIR))

from database import init_db, get_all_alerts, get_alert_count

from report_generator import generate_alert_history_pdf

init_db()


# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(
    page_title="Alert History | IDS Platform",
    page_icon="🗄️",
    layout="wide"
)


# ---------------------------------------------------
# AUTH
# ---------------------------------------------------

require_permission("alert_history")
logout_button()


# ---------------------------------------------------
# DARK CYBER UI
# ---------------------------------------------------

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

    .soc-card {
        background: linear-gradient(135deg, #111827 0%, #172033 100%);
        padding: 18px;
        border-radius: 14px;
        border: 1px solid #243244;
        box-shadow: 0 0 16px rgba(0, 229, 255, 0.10);
        margin-bottom: 16px;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------
# SIDEBAR
# ---------------------------------------------------

st.sidebar.title("🗄️ Alert History")

st.sidebar.markdown("""
### SOC Storage

This page displays stored IDS alerts from the SQLite database.

### Data Source
- SQLite
- Dashboard Analysis
- Live IDS Monitoring
- Real-Time Packet IDS
""")

st.sidebar.success("Database Status: ONLINE")


# ---------------------------------------------------
# MAIN TITLE
# ---------------------------------------------------

st.markdown("""
<div class="cyber-card">
    <h1>🗄️ SOC Alert History</h1>
    <p>Persistent IDS alert storage, investigation history, and threat analytics.</p>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------
# LOAD ALERTS
# ---------------------------------------------------

alerts = get_all_alerts(limit=1000)
total_alerts = get_alert_count()

if not alerts:
    st.info("No alerts saved yet. Go to Dashboard Analysis and save detected alerts first.")
    st.stop()

alerts_df = pd.DataFrame(alerts)

alerts_df["timestamp"] = pd.to_datetime(
    alerts_df["timestamp"],
    errors="coerce"
)

alerts_df["confidence"] = pd.to_numeric(
    alerts_df["confidence"],
    errors="coerce"
).fillna(0)

alerts_df["threat_score"] = pd.to_numeric(
    alerts_df["threat_score"],
    errors="coerce"
).fillna(0)


# ---------------------------------------------------
# METRICS
# ---------------------------------------------------

high_count = len(alerts_df[alerts_df["severity"] == "HIGH"])
medium_count = len(alerts_df[alerts_df["severity"] == "MEDIUM"])
low_count = len(alerts_df[alerts_df["severity"] == "LOW"])
avg_threat_score = alerts_df["threat_score"].mean()
max_threat_score = alerts_df["threat_score"].max()

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("🗄️ Total Alerts", total_alerts)
col2.metric("🔴 HIGH", high_count)
col3.metric("🟠 MEDIUM", medium_count)
col4.metric("🟢 LOW", low_count)
col5.metric("🔥 Avg Threat", f"{avg_threat_score:.2f}/100")


# ---------------------------------------------------
# SOC SUMMARY
# ---------------------------------------------------

if high_count > 0:
    st.markdown(f"""
    <div class="danger-card">
        <h3>🔴 Critical Alert History</h3>
        <p><b>HIGH severity alerts stored:</b> {high_count}</p>
        <p><b>Maximum threat score:</b> {max_threat_score:.2f}/100</p>
        <p>The database contains critical IDS alerts requiring analyst review.</p>
    </div>
    """, unsafe_allow_html=True)

elif medium_count > 0:
    st.markdown(f"""
    <div class="warning-card">
        <h3>🟠 Suspicious Alert History</h3>
        <p><b>MEDIUM severity alerts stored:</b> {medium_count}</p>
        <p><b>Maximum threat score:</b> {max_threat_score:.2f}/100</p>
        <p>The database contains suspicious network activity records.</p>
    </div>
    """, unsafe_allow_html=True)

else:
    st.markdown("""
    <div class="soc-card">
        <h3>🟢 Stable Alert History</h3>
        <p>No high-risk alerts are currently stored in the database.</p>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------
# FILTERS
# ---------------------------------------------------

st.subheader("🔎 Alert Filters")

filter_col1, filter_col2, filter_col3 = st.columns(3)

with filter_col1:
    severity_options = ["ALL"] + sorted(alerts_df["severity"].dropna().unique().tolist())
    selected_severity = st.selectbox("Filter by Severity", severity_options)

with filter_col2:
    module_options = ["ALL"] + sorted(alerts_df["module_source"].dropna().unique().tolist())
    selected_module = st.selectbox("Filter by Module Source", module_options)

with filter_col3:
    attack_options = ["ALL"] + sorted(alerts_df["attack_type"].dropna().unique().tolist())
    selected_attack = st.selectbox("Filter by Attack Type", attack_options)


filtered_df = alerts_df.copy()

if selected_severity != "ALL":
    filtered_df = filtered_df[filtered_df["severity"] == selected_severity]

if selected_module != "ALL":
    filtered_df = filtered_df[filtered_df["module_source"] == selected_module]

if selected_attack != "ALL":
    filtered_df = filtered_df[filtered_df["attack_type"] == selected_attack]


# ---------------------------------------------------
# FILTERED ALERT TABLE
# ---------------------------------------------------

st.subheader("📋 Stored Alert Records")

display_columns = [
    "id",
    "timestamp",
    "module_source",
    "attack_type",
    "severity",
    "confidence",
    "threat_score",
    "src_ip",
    "dst_ip",
    "protocol",
    "details"
]

available_columns = [
    col for col in display_columns
    if col in filtered_df.columns
]

st.dataframe(
    filtered_df[available_columns],
    width="stretch"
)


# ---------------------------------------------------
# CHARTS
# ---------------------------------------------------

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.subheader("🚨 Attack Type Distribution")

    attack_counts = filtered_df["attack_type"].value_counts().reset_index()
    attack_counts.columns = ["Attack Type", "Count"]

    fig_attack = px.bar(
        attack_counts,
        x="Attack Type",
        y="Count",
        text="Count",
        title="Stored Alerts by Attack Type"
    )

    st.plotly_chart(fig_attack, width="stretch")

with chart_col2:
    st.subheader("⚠️ Severity Distribution")

    severity_counts = filtered_df["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]

    fig_severity = px.pie(
        severity_counts,
        names="Severity",
        values="Count",
        title="Stored Alerts by Severity"
    )

    st.plotly_chart(fig_severity, width="stretch")


st.subheader("🔥 Threat Score Distribution")

fig_threat = px.histogram(
    filtered_df,
    x="threat_score",
    nbins=20,
    title="Historical Threat Score Distribution"
)

st.plotly_chart(fig_threat, width="stretch")


# ---------------------------------------------------
# TIMELINE
# ---------------------------------------------------

st.subheader("📈 Alert Timeline")

timeline_df = filtered_df.copy()
timeline_df["date"] = timeline_df["timestamp"].dt.date

timeline_counts = timeline_df.groupby("date").size().reset_index(name="Alert Count")

fig_timeline = px.line(
    timeline_counts,
    x="date",
    y="Alert Count",
    markers=True,
    title="Alerts Over Time"
)

st.plotly_chart(fig_timeline, width="stretch")


# ---------------------------------------------------
# EXPORT
# ---------------------------------------------------

st.subheader("⬇️ Export Alert History")

csv = filtered_df.to_csv(index=False)

st.download_button(
    label="⬇️ Download Filtered Alert History",
    data=csv,
    file_name="ids_alert_history.csv",
    mime="text/csv",
    use_container_width=True
)

# ---------------------------------------------------
# PDF REPORT EXPORT
# ---------------------------------------------------

st.subheader("📄 PDF SOC Report")

pdf_data = generate_alert_history_pdf(filtered_df)

st.download_button(
    label="📄 Download SOC PDF Report",
    data=pdf_data,
    file_name="ids_soc_alert_report.pdf",
    mime="application/pdf",
    use_container_width=True
)