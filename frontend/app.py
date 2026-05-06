import streamlit as st

from auth import (
    login_required,
    logout_button,
    has_permission
)


st.set_page_config(
    page_title="Network Attack Detection System",
    page_icon="🛡️",
    layout="wide"
)

login_required()
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

    [data-testid="stSidebar"] {
        background-color: #0B0F14;
        border-right: 1px solid #1F2937;
    }

    .cyber-card {
        background-color: #161B22;
        padding: 22px;
        border-radius: 16px;
        border: 1px solid #1F2937;
        box-shadow: 0 0 14px rgba(0, 229, 255, 0.10);
        margin-bottom: 18px;
    }

    .module-card {
        background: linear-gradient(135deg, #111827 0%, #172033 100%);
        padding: 22px;
        border-radius: 16px;
        border: 1px solid #243244;
        box-shadow: 0 0 16px rgba(0, 229, 255, 0.08);
        min-height: 210px;
    }

    .module-title {
        font-size: 24px;
        font-weight: 800;
        color: #00E5FF;
        margin-bottom: 10px;
    }

    .module-text {
        font-size: 15px;
        color: #E5E7EB;
        line-height: 1.6;
    }

    .status-online {
        color: #22C55E;
        font-weight: 700;
    }
</style>
""", unsafe_allow_html=True)


st.sidebar.title("🛡️ IDS Platform")

st.sidebar.markdown("""
### Navigation

Използвай менюто вляво, за да отвориш модулите:

- 📊 Dashboard Analysis
- 📡 Live IDS Monitoring
- 🛰️ Real-Time Packet IDS
""")

st.sidebar.success("System Status: ONLINE")


st.markdown("""
<div class="cyber-card">
    <h1>🛡️ Network Attack Detection System</h1>
    <p>
        AI-powered Intrusion Detection Platform for network traffic analysis,
        threat scoring, live monitoring and packet-level inspection.
    </p>
</div>
""", unsafe_allow_html=True)


col1, col2, col3 = st.columns(3)

if has_permission("dashboard_analysis"):

 with col1:
    st.markdown("""
    <div class="module-card">
        <div class="module-title">📊 Dashboard Analysis</div>
        <div class="module-text">
            Анализира CIC-IDS2017 CSV файлове, класифицира трафика чрез ML модел,
            показва attack types, severity нива, confidence score и threat score.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.page_link(
    "pages/dashboard_analysis.py",
        label="Отвори Dashboard Analysis",
        icon="📊"
    )

if has_permission("live_ids_monitoring"):

 with col2:
    st.markdown("""
    <div class="module-card">
        <div class="module-title">📡 Live IDS Monitoring</div>
        <div class="module-text">
            Симулира real-time IDS чрез streaming на network flow записи от CSV.
            Показва live alerts, live metrics и attack distribution.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.page_link(
    "pages/live_ids_monitoring.py",
        label="Отвори Live IDS Monitoring",
        icon="📡"
    )

if has_permission("realtime_packet_ids"):

    with col3:
        st.markdown("""
        <div class="module-card">
            <div class="module-title">🛰️ Real-Time Packet IDS</div>
            <div class="module-text">
                Извършва live packet sniffing от реалната мрежа чрез Scapy/Npcap,
            показва IP адреси, портове, протоколи и heuristic threat alerts.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.page_link(
    "pages/realtime_packet_ids.py",
        label="Отвори Real-Time Packet IDS",
        icon="🛰️"
    )


st.markdown("<br>", unsafe_allow_html=True)

col4 = st.columns(1)[0]

if has_permission("alert_history"):

   with col4:
 
    st.markdown("""
    <div class="module-card">
        <div class="module-title">🗄️ Alert History</div>
        <div class="module-text">
            SOC-style historical alert storage using SQLite database.
            View saved IDS alerts, threat history, severity analytics,
            attack timelines, filtering, and downloadable reports.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.page_link(
        "pages/alert_history.py",
        label="Отвори Alert History",
        icon="🗄️"
    )

st.markdown("---")

st.markdown("""
### ✅ Project Modules

Тази система включва:
- ML-based multi-class intrusion detection
- FastAPI backend
- Streamlit cybersecurity dashboard
- CIC-IDS2017 dataset integration
- Threat Score Engine
- Live Alert Panel
- Real-time packet monitoring
- CSV result export
""")