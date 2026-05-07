import os
import sys
import time
import random
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st
import plotly.express as px

from auth import require_permission, logout_button


# ---------------------------------------------------
# BACKEND DATABASE IMPORTS
# ---------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.append(str(PROJECT_ROOT))

from backend.database import init_db, save_alert

init_db()


# ---------------------------------------------------
# OPTIONAL SCAPY IMPORT
# ---------------------------------------------------

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False


# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(
    page_title="Real-Time Packet IDS",
    page_icon="🛰️",
    layout="wide"
)


# ---------------------------------------------------
# AUTH / RBAC
# ---------------------------------------------------

require_permission("realtime_packet_ids")
logout_button()


# ---------------------------------------------------
# SESSION STATE
# ---------------------------------------------------

if "packet_feed" not in st.session_state:
    st.session_state.packet_feed = []

if "packet_alerts" not in st.session_state:
    st.session_state.packet_alerts = []

if "sniffing_active" not in st.session_state:
    st.session_state.sniffing_active = False


# ---------------------------------------------------
# CLOUD DETECTION
# ---------------------------------------------------

def is_cloud_environment():
    cloud_indicators = [
        "STREAMLIT_SHARING",
        "STREAMLIT_CLOUD",
        "RENDER",
        "DYNO",
        "SPACE_ID"
    ]

    for indicator in cloud_indicators:
        if os.getenv(indicator):
            return True

    return os.name != "nt"


CLOUD_MODE = is_cloud_environment()


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
# HELPER FUNCTIONS
# ---------------------------------------------------

def calculate_packet_threat_score(protocol, dst_port, packet_size):
    threat_score = 0
    severity = "LOW"
    alert_reason = "Normal packet activity"

    suspicious_ports = {
        21: "FTP connection attempt",
        22: "SSH connection attempt",
        23: "Telnet connection attempt",
        25: "SMTP connection attempt",
        53: "DNS traffic",
        80: "HTTP traffic",
        135: "RPC service access",
        139: "NetBIOS service access",
        443: "HTTPS traffic",
        445: "SMB service access",
        3389: "RDP connection attempt",
        4444: "Suspicious reverse shell style port",
        8080: "Alternative web service port"
    }

    if protocol in ["TCP", "UDP"]:
        threat_score += 15

    if dst_port in suspicious_ports:
        threat_score += 35
        alert_reason = suspicious_ports[dst_port]

    if packet_size > 1000:
        threat_score += 20
        alert_reason += " | Large packet size"

    if dst_port in [23, 135, 139, 445, 3389, 4444]:
        threat_score += 30

    if threat_score >= 70:
        severity = "HIGH"
    elif threat_score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return min(threat_score, 100), severity, alert_reason


def generate_demo_packet():
    protocols = ["TCP", "UDP", "ICMP"]
    src_ips = [
        "192.168.1.10",
        "192.168.1.24",
        "10.0.0.8",
        "172.16.0.12",
        "203.0.113.44",
        "198.51.100.22"
    ]
    dst_ips = [
        "192.168.1.1",
        "10.0.0.1",
        "8.8.8.8",
        "1.1.1.1",
        "203.0.113.10"
    ]

    common_ports = [53, 80, 443, 22, 21, 25, 445, 3389, 8080, 4444, 135, 139]
    protocol = random.choice(protocols)

    if protocol == "ICMP":
        src_port = None
        dst_port = None
    else:
        src_port = random.randint(1024, 65535)
        dst_port = random.choice(common_ports)

    packet_size = random.randint(64, 1500)

    threat_score, severity, reason = calculate_packet_threat_score(
        protocol,
        dst_port,
        packet_size
    )

    packet = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "src_ip": random.choice(src_ips),
        "dst_ip": random.choice(dst_ips),
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": packet_size,
        "severity": severity,
        "threat_score": threat_score,
        "reason": reason
    }

    return packet


def process_real_packet(packet):
    src_ip = "Unknown"
    dst_ip = "Unknown"
    protocol = "OTHER"
    src_port = None
    dst_port = None
    packet_size = len(packet)

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    elif ICMP in packet:
        protocol = "ICMP"

    threat_score, severity, reason = calculate_packet_threat_score(
        protocol,
        dst_port,
        packet_size
    )

    packet_record = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": packet_size,
        "severity": severity,
        "threat_score": threat_score,
        "reason": reason
    }

    st.session_state.packet_feed.insert(0, packet_record)
    st.session_state.packet_feed = st.session_state.packet_feed[:100]

    if severity in ["MEDIUM", "HIGH"]:
        st.session_state.packet_alerts.insert(0, packet_record)
        st.session_state.packet_alerts = st.session_state.packet_alerts[:50]

        save_alert(
            module_source="Real-Time Packet IDS",
            attack_type="Suspicious Packet Activity",
            severity=severity,
            confidence=None,
            threat_score=threat_score,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol,
            details=reason
        )


def add_demo_packets(count=5):
    for _ in range(count):
        packet = generate_demo_packet()

        st.session_state.packet_feed.insert(0, packet)
        st.session_state.packet_feed = st.session_state.packet_feed[:100]

        if packet["severity"] in ["MEDIUM", "HIGH"]:
            st.session_state.packet_alerts.insert(0, packet)
            st.session_state.packet_alerts = st.session_state.packet_alerts[:50]

            save_alert(
                module_source="Real-Time Packet IDS - Cloud Demo",
                attack_type="Simulated Suspicious Packet Activity",
                severity=packet["severity"],
                confidence=None,
                threat_score=packet["threat_score"],
                src_ip=packet["src_ip"],
                dst_ip=packet["dst_ip"],
                protocol=packet["protocol"],
                details=packet["reason"]
            )


# ---------------------------------------------------
# SIDEBAR
# ---------------------------------------------------

st.sidebar.title("🛰️ Packet IDS")

st.sidebar.markdown("""
### Module Info

Real-time packet inspection module.

### Modes
- Local Mode: Scapy + Npcap real sniffing
- Cloud Demo Mode: simulated packet stream

### Note
Cloud platforms cannot sniff your local network traffic.
""")

st.sidebar.success("Module Status: ONLINE")


# ---------------------------------------------------
# MAIN TITLE
# ---------------------------------------------------

st.markdown("""
<div class="cyber-card">
    <h1>🛰️ Real-Time Packet IDS</h1>
    <p>Live packet sniffing, heuristic packet analysis, and packet-level threat detection.</p>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------
# CLOUD / LOCAL MODE MESSAGE
# ---------------------------------------------------

if CLOUD_MODE:
    st.markdown("""
    <div class="warning-card">
        <h3>☁️ Cloud Demo Mode Enabled</h3>
        <p>This app is running in a cloud environment. Real packet sniffing is disabled because cloud containers cannot access your personal network interface.</p>
        <p>The module below simulates packet traffic so the online demo remains functional and professional.</p>
        <p><b>For real packet sniffing:</b> run the project locally on Windows with Npcap installed.</p>
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown("""
    <div class="soc-card">
        <h3>🖥️ Local Real Packet Sniffing Mode</h3>
        <p>Scapy/Npcap packet capture is available on this machine.</p>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------
# CONTROLS
# ---------------------------------------------------

control_col1, control_col2, control_col3 = st.columns(3)

with control_col1:
    if st.button("▶️ Start Monitoring", use_container_width=True):
        st.session_state.sniffing_active = True

        if CLOUD_MODE:
            add_demo_packets(count=10)
            st.success("Cloud demo monitoring started. Demo packet batch generated.")

with control_col2:
    if st.button("⏹️ Stop Monitoring", use_container_width=True):
        st.session_state.sniffing_active = False
        st.warning("Sniffing stop requested.")

with control_col3:
    if st.button("🧹 Clear Feed", use_container_width=True):
        st.session_state.packet_feed = []
        st.session_state.packet_alerts = []
        st.success("Packet feed cleared.")


if CLOUD_MODE and st.session_state.sniffing_active:
    if st.button("➕ Generate More Demo Traffic", use_container_width=True):
        add_demo_packets(count=10)
        st.success("New simulated packet batch generated.")


# ---------------------------------------------------
# MONITORING LOGIC
# ---------------------------------------------------

if st.session_state.sniffing_active:

    if CLOUD_MODE:
        st.info(
            "☁️ Cloud Demo Mode is active. Click 'Generate More Demo Traffic' to simulate additional packet activity."
        )

    else:
        if not SCAPY_AVAILABLE:
            st.error("Scapy is not available. Install it with: pip install scapy")
        else:
            st.info("Real packet sniffing active. Capturing packets...")
            sniff(
                prn=process_real_packet,
                store=False,
                count=10,
                timeout=3
            )
            st.rerun()


# ---------------------------------------------------
# DATAFRAMES
# ---------------------------------------------------

packet_df = pd.DataFrame(st.session_state.packet_feed)
alerts_df = pd.DataFrame(st.session_state.packet_alerts)


# ---------------------------------------------------
# METRICS
# ---------------------------------------------------

total_packets = len(packet_df)
total_alerts = len(alerts_df)

if not packet_df.empty:
    avg_threat = packet_df["threat_score"].mean()
    high_count = len(packet_df[packet_df["severity"] == "HIGH"])
    medium_count = len(packet_df[packet_df["severity"] == "MEDIUM"])
else:
    avg_threat = 0
    high_count = 0
    medium_count = 0

metric_col1, metric_col2, metric_col3, metric_col4 = st.columns(4)

metric_col1.metric("📦 Packets Captured", total_packets)
metric_col2.metric("🚨 Alerts", total_alerts)
metric_col3.metric("🔴 HIGH Risk", high_count)
metric_col4.metric("🔥 Avg Threat", f"{avg_threat:.2f}/100")


# ---------------------------------------------------
# ALERT SUMMARY
# ---------------------------------------------------

if high_count > 0:
    st.markdown(f"""
    <div class="danger-card">
        <h3>🔴 Critical Packet Activity Detected</h3>
        <p><b>HIGH severity packets:</b> {high_count}</p>
        <p>Packet-level activity contains high-risk network indicators.</p>
    </div>
    """, unsafe_allow_html=True)

elif medium_count > 0:
    st.markdown(f"""
    <div class="warning-card">
        <h3>🟠 Suspicious Packet Activity Detected</h3>
        <p><b>MEDIUM severity packets:</b> {medium_count}</p>
        <p>Suspicious packet behavior was identified by heuristic rules.</p>
    </div>
    """, unsafe_allow_html=True)

else:
    st.markdown("""
    <div class="soc-card">
        <h3>🟢 Packet Activity Stable</h3>
        <p>No high-risk packet behavior detected yet.</p>
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------
# CHARTS
# ---------------------------------------------------

if not packet_df.empty:

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("📡 Protocol Distribution")

        protocol_counts = packet_df["protocol"].value_counts().reset_index()
        protocol_counts.columns = ["Protocol", "Count"]

        fig_protocol = px.pie(
            protocol_counts,
            names="Protocol",
            values="Count",
            title="Captured Packets by Protocol"
        )

        st.plotly_chart(
            fig_protocol,
            width="stretch",
            key="packet_protocol_chart"
        )

    with chart_col2:
        st.subheader("⚠️ Severity Distribution")

        severity_counts = packet_df["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]

        fig_severity = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            text="Count",
            title="Packet Severity Distribution"
        )

        st.plotly_chart(
            fig_severity,
            width="stretch",
            key="packet_severity_chart"
        )

    st.subheader("🔥 Packet Threat Score Distribution")

    fig_threat = px.histogram(
        packet_df,
        x="threat_score",
        nbins=20,
        title="Packet Threat Score Distribution"
    )

    st.plotly_chart(
        fig_threat,
        width="stretch",
        key="packet_threat_score_chart"
    )


# ---------------------------------------------------
# LIVE ALERT PANEL
# ---------------------------------------------------

st.subheader("🚨 Live Packet Alert Panel")

if alerts_df.empty:
    st.success("✅ No active packet alerts.")
else:
    st.dataframe(
        alerts_df.head(25),
        width="stretch"
    )


# ---------------------------------------------------
# LIVE PACKET FEED
# ---------------------------------------------------

st.subheader("📦 Live Packet Feed")

if packet_df.empty:
    st.info("Click Start Monitoring to begin packet analysis.")
else:
    st.dataframe(
        packet_df.head(50),
        width="stretch"
    )


# ---------------------------------------------------
# EXPORT
# ---------------------------------------------------

if not packet_df.empty:
    csv = packet_df.to_csv(index=False)

    st.download_button(
        label="⬇️ Download Packet Feed CSV",
        data=csv,
        file_name="packet_ids_feed.csv",
        mime="text/csv",
        use_container_width=True
    )