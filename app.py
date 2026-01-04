import streamlit as st
import pandas as pd
from datetime import datetime
import random

from src.feature_extractor import extract_features
from src.train_model import train_model
from src.ml_detector import detect_anomalies

st.set_page_config(page_title="Credential Stuffing Detector", layout="wide")

st.title("🔐 AI Credential Stuffing Detection — Interactive UI")
st.caption("Human vs Bot simulation + anomaly detection using Isolation Forest.")

# -----------------------
# Helpers
# -----------------------
def add_event(df, user_id, ip, success, source):
    new_row = {
        "user_id": user_id,
        "ip_address": ip,
        "timestamp": datetime.now(),
        "success": success,
        "source": source
    }
    return pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)

def explain_row(row):
    reasons = []
    if row["attempts"] >= 15:
        reasons.append(f"high_attempts={int(row['attempts'])}")
    if row["failure_rate"] >= 0.80:
        reasons.append(f"high_failure_rate={row['failure_rate']:.2f}")
    if row["unique_users"] >= 5:
        reasons.append(f"many_users_targeted={int(row['unique_users'])}")
    if row["burst_ratio"] >= 3:
        reasons.append(f"burst_ratio={row['burst_ratio']:.2f}")
    return ", ".join(reasons) if reasons else "anomalous_pattern"

# -----------------------
# Session State
# -----------------------
if "events" not in st.session_state:
    st.session_state.events = pd.DataFrame(
        columns=["user_id", "ip_address", "timestamp", "success", "source"]
    )

# -----------------------
# Sidebar Controls
# -----------------------
st.sidebar.header("Controls")

mode = st.sidebar.radio("Mode", ["Human (manual)", "Bot (simulate)"], index=0)

if mode == "Human (manual)":
    st.sidebar.subheader("Submit a login attempt")
    user_id = st.sidebar.text_input("user_id", value="user_1")
    ip = st.sidebar.text_input("ip_address", value="192.168.1.10")
    success = st.sidebar.selectbox("success", [True, False], index=0)

    if st.sidebar.button("➕ Add attempt"):
        st.session_state.events = add_event(st.session_state.events, user_id, ip, success, "human")
        st.sidebar.success("Added.")

else:
    st.sidebar.subheader("Simulate bot burst")
    attack_ip = st.sidebar.text_input("bot ip_address", value="10.0.0.99")
    attempts = st.sidebar.slider("attempts", 10, 500, 150)
    user_pool = st.sidebar.slider("unique users targeted", 5, 200, 50)

    if st.sidebar.button("🤖 Run bot attack"):
        df = st.session_state.events
        for _ in range(attempts):
            df = add_event(
                df,
                user_id=f"user_{random.randint(1, user_pool)}",
                ip=attack_ip,
                success=False,
                source="bot"
            )
        st.session_state.events = df
        st.sidebar.warning(f"Generated {attempts} failed attempts from {attack_ip}")

st.sidebar.divider()

if st.sidebar.button("🧹 Clear all events"):
    st.session_state.events = pd.DataFrame(
        columns=["user_id", "ip_address", "timestamp", "success", "source"]
    )
    st.sidebar.info("Cleared.")

# -----------------------
# Main Layout
# -----------------------
left, right = st.columns([1.3, 1])

with left:
    st.subheader("📄 Live Login Events")
    st.dataframe(st.session_state.events, use_container_width=True, height=420)

with right:
    st.subheader("🧠 Detection Panel")

    if len(st.session_state.events) < 5:
        st.info("Add a few events first (human or bot), then run detection.")
    else:
        if st.button("🚨 Train + Detect"):
            df = st.session_state.events.copy()

            # 1) extract features per IP per time window
            feature_df = extract_features(df)

            # 2) train model
            train_model(feature_df)

            # 3) detect
            preds, risk, _ = detect_anomalies(feature_df)

            feature_df = feature_df.copy()
            feature_df["pred"] = preds
            feature_df["risk"] = risk
            feature_df["reason"] = feature_df.apply(explain_row, axis=1)

            st.session_state.features = feature_df

            suspicious = feature_df[feature_df["pred"] == -1]
            st.metric("Suspicious windows", len(suspicious))
            st.metric("Total windows analyzed", len(feature_df))

            if len(suspicious) > 0:
                st.error("⚠️ Suspicious behavior detected (anomalies found).")
            else:
                st.success("✅ No suspicious behavior detected.")

st.divider()

# -----------------------
# Feature view + Alerts
# -----------------------
if "features" in st.session_state:
    st.subheader("📊 What the model evaluated (IP windows)")
    st.dataframe(
        st.session_state.features.sort_values("risk", ascending=False),
        use_container_width=True,
        height=320
    )

    st.subheader("🚨 Top Alerts (highest risk)")
    top = st.session_state.features.sort_values("risk", ascending=False).head(10)
    st.table(top[[
        "ip_address", "time_window", "attempts", "failure_rate",
        "unique_users", "burst_ratio", "risk", "pred", "reason"
    ]])

