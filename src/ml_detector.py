import joblib

def detect_anomalies(features):
    model = joblib.load("models/credential_model.pkl")
    scores = model.predict(features)
    return scores

