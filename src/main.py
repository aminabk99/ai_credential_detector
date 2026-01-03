from auth_simulator import generate_login_events
from feature_extractor import extract_features
from train_model import train_model
from ml_detector import detect_anomalies
from datetime import datetime

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

def run_pipeline():
    # 1) generate simulated auth logs
    df = generate_login_events()

    # 2) extract windowed IP features
    feature_df = extract_features(df)

    # 3) train model
    train_model(feature_df)

    # 4) detect anomalies + risk
    preds, risk, _ = detect_anomalies(feature_df)

    feature_df = feature_df.copy()
    feature_df["pred"] = preds
    feature_df["risk"] = risk

    # 5) write SOC-style alerts
    alerts_written = 0
    with open("logs/alerts.log", "a") as log:
        for _, row in feature_df.iterrows():
            if row["pred"] == -1:
                reason = explain_row(row)
                log.write(
                    f"{datetime.now().isoformat()} | ALERT | "
                    f"ip={row['ip_address']} | window={row['time_window']} | "
                    f"risk={row['risk']:.0f} | {reason}\n"
                )
                alerts_written += 1

    print(f"Detection complete. Alerts written: {alerts_written}. Check logs/alerts.log")

if __name__ == "__main__":
    run_pipeline()
