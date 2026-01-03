from sklearn.ensemble import IsolationForest
import joblib

def train_model(feature_df):
    X = feature_df[["attempts", "failure_rate", "unique_users", "burst_ratio"]]

    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42
    )
    model.fit(X)

    joblib.dump(model, "models/credential_model.pkl")
    return model
