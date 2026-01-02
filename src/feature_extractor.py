import pandas as pd

def extract_features(df):
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    features = df.groupby(["user_id", "ip_address"]).agg(
        login_attempts=("success", "count"),
        failure_rate=("success", lambda x: 1 - x.mean()),
        unique_users=("user_id", "nunique")
    ).reset_index()

    return features[["login_attempts", "failure_rate", "unique_users"]]

