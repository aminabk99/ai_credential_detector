<div align="center">

# 🤖 AI Credential Stuffing Detector
### Distinguishing Human Logins from Bot Attacks Using Machine Learning

A Python-based anomaly detection system that analyzes login traffic per IP address and classifies attempts as **human or bot** using an **Isolation Forest** model — with both a Streamlit web UI and a Tkinter desktop app.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-IsolationForest-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-UI-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
![Tkinter](https://img.shields.io/badge/Tkinter-Desktop_App-3776AB?style=for-the-badge&logo=python&logoColor=white)

</div>

---

## How It Works

1. Login events are simulated or submitted — each with a `user_id`, `ip_address`, `timestamp`, and `success` flag
2. Events are bucketed into **1-minute time windows per IP** and four features are extracted: `attempts`, `failure_rate`, `unique_users`, `burst_ratio`
3. An **Isolation Forest** model is trained on a normal baseline and scores each window as normal or anomalous
4. Windows flagged as anomalous are written to `logs/alerts.log` with a human-readable reason
5. The verdict — **HUMAN** or **AI** — is displayed instantly in the UI

**Detection signals:** 🔢 High attempt count · ❌ High failure rate · 👥 Many targeted users · ⚡ Burst behavior

---

## Setup

**Requirements:** Python 3.11+ · pip

**1. Clone & install**
```bash
git clone https://github.com/aminabk99/ai_credential_detector
cd ai_credential_detector
python -m venv venv && source venv/Scripts/activate  # Windows
pip install pandas scikit-learn joblib streamlit
```

**2. Run the Streamlit web UI**
```bash
streamlit run app.py
```

**3. Run the desktop app**
```bash
python desktop_app.py
```

**4. Run the pipeline directly**
```bash
python src/main.py
```
Check `logs/alerts.log` for output.

---

## Project Structure

ai_credential_detector/
├── src/
│   ├── auth_simulator.py     # Generates simulated human + bot login events
│   ├── feature_extractor.py  # Extracts windowed IP-level features
│   ├── train_model.py        # Trains and saves the Isolation Forest model
│   ├── ml_detector.py        # Loads model, runs predictions, scores risk
│   └── main.py               # End-to-end pipeline runner
├── app.py                    # Streamlit interactive web UI
├── desktop_app.py            # Tkinter offline desktop UI
├── models/                   # Saved model (.pkl)
├── logs/                     # Alert output
└── data/                     # Login event CSVs

---

## Hardest Part
**Tuning the Isolation Forest contamination parameter** — setting it too low missed real attacks, too high flooded the alerts log with false positives. Getting the burst ratio feature right was the key to separating human pauses from machine-speed requests.

## Most Interesting
**The same IP address looks completely different depending on the time window.** A human logging in twice a minute apart is normal; a bot doing 150 attempts in 30 seconds from the same IP is unmistakable — and the model learns to see exactly that boundary.

---

## Future Improvements
- Live log ingestion instead of simulation
- Per-user behavioral baselines (not just per-IP)
- Severity tiers with email or Slack alerting
- Model retraining on flagged data over time

---

<div align="center">
  <sub>Built by <a href="https://github.com/aminabk99">Amina Bilal</a> · <a href="https://linkedin.com/in/amina-bilal-926340382">LinkedIn</a></sub>
</div>
