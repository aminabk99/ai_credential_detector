import pandas as pd

def extract_features(df, window="1min"):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # failure as 1/0 for easy aggregation
    df["failure"] = df["success"].apply(lambda x: 0 if x else 1)

    # bucket events into a time window (e.g., per minute)
    df["time_window"] = df["timestamp"].dt.floor(window)

    # IP-level window features (best for credential stuffing)
    ip_window = df.groupby(["ip_address", "time_window"]).agg(
        attempts=("success", "count"),
        failures=("failure", "sum"),
        unique_users=("user_id", "nunique"),
    ).reset_index()

    ip_window["failure_rate"] = ip_window["failures"] / ip_window["attempts"]

    # baseline attempts per IP across all windows (for burstiness)
    ip_baseline = (
        ip_window.groupby("ip_address")["attempts"]
        .mean()
        .rename("ip_avg_attempts")
        .reset_index()
    )

    ip_window = ip_window.merge(ip_baseline, on="ip_address", how="left")
    ip_window["burst_ratio"] = ip_window["attempts"] / (ip_window["ip_avg_attempts"] + 1e-6)

    # keep context cols for logging + UI later
    return ip_window[[
        "ip_address",
        "time_window",
        "attempts",
        "failure_rate",
        "unique_users",
        "burst_ratio"
    ]]
