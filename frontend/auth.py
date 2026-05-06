import streamlit as st


USERS = {
    "admin": {
        "password": "admin123",
        "role": "Administrator",
        "permissions": [
            "dashboard_analysis",
            "live_ids_monitoring",
            "realtime_packet_ids",
            "alert_history",
            "pdf_reports",
            "admin_panel"
        ]
    },
    "analyst": {
        "password": "analyst123",
        "role": "Security Analyst",
        "permissions": [
            "dashboard_analysis",
            "live_ids_monitoring",
            "alert_history",
            "pdf_reports"
        ]
    }
}


def login_required():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "username" not in st.session_state:
        st.session_state.username = None

    if "role" not in st.session_state:
        st.session_state.role = None

    if "permissions" not in st.session_state:
        st.session_state.permissions = []

    if not st.session_state.logged_in:
        st.markdown("""
        <style>
            .stApp {
                background: linear-gradient(135deg, #0E1117 0%, #111827 100%);
            }

            h1, h2, h3 {
                color: #00E5FF;
            }

            div.stButton > button {
                background: linear-gradient(90deg, #00E5FF, #2563EB);
                color: white;
                border: none;
                border-radius: 10px;
                padding: 0.6rem 1.2rem;
                font-weight: 700;
            }
        </style>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style="
            background-color: #161B22;
            padding: 24px;
            border-radius: 16px;
            border: 1px solid #1F2937;
            box-shadow: 0 0 18px rgba(0, 229, 255, 0.12);
            margin-bottom: 20px;
        ">
            <h1>🛡️ Network Attack Detection System</h1>
            <p>Secure SOC Dashboard Login</p>
        </div>
        """, unsafe_allow_html=True)

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login", use_container_width=True):
            if username in USERS and USERS[username]["password"] == password:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.role = USERS[username]["role"]
                st.session_state.permissions = USERS[username]["permissions"]
                st.success("Login successful.")
                st.rerun()
            else:
                st.error("Invalid username or password.")

        st.stop()


def logout_button():
    with st.sidebar:
        st.markdown("---")
        st.markdown(f"👤 **User:** `{st.session_state.username}`")
        st.markdown(f"🛡️ **Role:** `{st.session_state.role}`")

        if st.button("Logout", use_container_width=True):
            st.session_state.logged_in = False
            st.session_state.username = None
            st.session_state.role = None
            st.session_state.permissions = []
            st.rerun()


def has_permission(permission_name):
    return permission_name in st.session_state.get("permissions", [])


def require_permission(permission_name):
    login_required()

    if not has_permission(permission_name):
        st.error("⛔ Access denied. Your role does not have permission to view this page.")
        st.info(f"Current role: {st.session_state.get('role', 'Unknown')}")
        st.stop()


def is_admin():
    return st.session_state.get("role") == "Administrator"