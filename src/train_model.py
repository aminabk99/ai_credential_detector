from sklearn.ensemble import IsolationForest
import joblib

def train_model(features):
    model = IsolationForest(
        n_estimators=100,
        contamination=0.1,
        random_state=42
    )
    model.fit(features)

    joblib.dump(model, "models/credential_model.pkl")
    return model

