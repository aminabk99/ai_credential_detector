import joblib

def detect_anomalies(feature_df):
    model = joblib.load("models/credential_model.pkl")
    X = feature_df[["attempts", "failure_rate", "unique_users", "burst_ratio"]]

    # 1 = normal, -1 = anomaly
    preds = model.predict(X)

    # lower score_samples => more anomalous
    raw_scores = model.score_samples(X)

    # convert to 0-100 risk score (higher = riskier)
    inv = -raw_scores
    risk = 100 * (inv - inv.min()) / (inv.max() - inv.min() + 1e-9)

    return preds, risk, raw_scores
