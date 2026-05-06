import time
import queue
import threading
from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from auth import require_permission, logout_button

# ---------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------

st.set_page_config(
    page_title="Real-Time Packet IDS",
    page_icon="📡",
    layout="wide"
)

require_permission("realtime_packet_ids")
logout_button()


# ---------------------------------------------------
# DARK UI
# ---------------------------------------------------

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

    .critical-alert {
        background: linear-gradient(135deg, #2A0F13 0%, #40151C 100%);
        border: 1px solid #991B1B;
        padding: 16px;
        border-radius: 12px;
        margin-bottom: 16px;
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------
# SESSION STATE
# ---------------------------------------------------

if "packets" not in st.session_state:
    st.session_state.packets = []

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "sniffing" not in st.session_state:
    st.session_state.sniffing = False


packet_queue = queue.Queue()


# ---------------------------------------------------
# THREAT ENGINE
# ---------------------------------------------------

def calculate_threat(packet_size, dst_port, protocol):
    score = 0
    severity = "LOW"

    suspicious_ports = [
        21, 22, 23, 53, 80, 135,
        139, 443, 445, 3389
    ]

    if packet_size > 1400:
        score += 25

    if dst_port in suspicious_ports:
        score += 35

    if protocol == "TCP":
        score += 20

    if protocol == "UDP":
        score += 10

    if score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"

    return score, severity


# ---------------------------------------------------
# PACKET PROCESSING
# ---------------------------------------------------

def process_packet(packet):

    if IP not in packet:
        return

    protocol = "OTHER"
    src_port = None
    dst_port = None

    if TCP in packet:
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif UDP in packet:
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    packet_size = len(packet)

    threat_score, severity = calculate_threat(
        packet_size,
        dst_port,
        protocol
    )

    packet_data = {
        "time": datetime.now().strftime("%H:%M:%S"),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": packet_size,
        "threat_score": threat_score,
        "severity": severity
    }

    packet_queue.put(packet_data)


# ---------------------------------------------------
# SNIFFER THREAD
# ---------------------------------------------------

def start_sniffing():
    sniff(
        prn=process_packet,
        store=False
    )


# ---------------------------------------------------
# UI HEADER
# ---------------------------------------------------

st.markdown("""
<div class="cyber-card">
    <h1>📡 Real-Time Packet IDS</h1>
    <p>Live packet sniffing and threat monitoring.</p>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------
# CONTROLS
# ---------------------------------------------------

col1, col2 = st.columns(2)

start_button = col1.button("▶️ Start Sniffing")
stop_button = col2.button("⏹ Stop")


# ---------------------------------------------------
# START SNIFFING
# ---------------------------------------------------

if start_button and not st.session_state.sniffing:

    st.session_state.sniffing = True

    sniff_thread = threading.Thread(
        target=start_sniffing,
        daemon=True
    )

    sniff_thread.start()

    st.success("✅ Packet sniffing started.")


if stop_button:
    st.session_state.sniffing = False
    st.warning("⏹ Sniffing stop requested.")


# ---------------------------------------------------
# LIVE DASHBOARD
# ---------------------------------------------------

metrics_placeholder = st.empty()
alerts_placeholder = st.empty()
table_placeholder = st.empty()
chart_placeholder = st.empty()


while st.session_state.sniffing:

 while not packet_queue.empty():
    packet_data = packet_queue.get()
    st.session_state.packets.append(packet_data)

    if packet_data["severity"] in ["HIGH", "MEDIUM"]:
        st.session_state.alerts.insert(0, packet_data)

    packets_df = pd.DataFrame(st.session_state.packets)

    if not packets_df.empty:

        total_packets = len(packets_df)

        high_alerts = len(
            packets_df[
                packets_df["severity"] == "HIGH"
            ]
        )

        medium_alerts = len(
            packets_df[
                packets_df["severity"] == "MEDIUM"
            ]
        )

        avg_threat = packets_df["threat_score"].mean()

        with metrics_placeholder.container():

            c1, c2, c3, c4 = st.columns(4)

            c1.metric(
                "📦 Captured Packets",
                total_packets
            )

            c2.metric(
                "🔴 HIGH Alerts",
                high_alerts
            )

            c3.metric(
                "🟠 MEDIUM Alerts",
                medium_alerts
            )

            c4.metric(
                "🔥 Avg Threat Score",
                f"{avg_threat:.2f}"
            )

        with alerts_placeholder.container():

            st.subheader("🚨 Live Alert Panel")

            alerts_df = pd.DataFrame(
                st.session_state.alerts[:20]
            )

            if not alerts_df.empty:
                st.dataframe(
                    alerts_df,
                    width="stretch"
                )

        with table_placeholder.container():

            st.subheader("📊 Live Packet Feed")

            st.dataframe(
                packets_df.tail(30),
                width="stretch"
            )

        with chart_placeholder.container():

            st.subheader("📈 Protocol Distribution")

            protocol_counts = (
                packets_df["protocol"]
                .value_counts()
                .reset_index()
            )

            protocol_counts.columns = [
                "Protocol",
                "Count"
            ]

            fig = px.pie(
                protocol_counts,
                names="Protocol",
                values="Count",
                title="Captured Protocols"
            )

            st.plotly_chart(
              fig,
              width="stretch",
              key=f"protocol_chart_{time.time()}"
)

    time.sleep(1)