from auth_simulator import generate_login_events
from feature_extractor import extract_features
from train_model import train_model
from ml_detector import detect_anomalies
from datetime import datetime

def run_pipeline():
    df = generate_login_events()
    features = extract_features(df)

    train_model(features)
    results = detect_anomalies(features)

    with open("logs/alerts.log", "a") as log:
        for idx, result in enumerate(results):
            if result == -1:
                log.write(
                    f"{datetime.now()} | ALERT | Suspicious login behavior detected\n"
                )

    print("Detection complete. Check logs/alerts.log")

if __name__ == "__main__":
    run_pipeline()

