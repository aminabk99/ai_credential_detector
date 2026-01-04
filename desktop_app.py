import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta
import random
import pandas as pd

# Make sure imports work even when Visual Studio runs from a different working directory
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.feature_extractor import extract_features
from src.train_model import train_model
from src.ml_detector import detect_anomalies


def _ensure_dirs():
    os.makedirs("models", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs("data", exist_ok=True)


def _now():
    return datetime.now()


def _fmt_dt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _make_human_session() -> pd.DataFrame:
    """
    A small, realistic human login session:
    - Few attempts
    - Same user and IP
    - Mostly success
    """
    t0 = _now()
    user = f"user_{random.randint(1, 50)}"
    ip = f"192.168.1.{random.randint(2, 200)}"

    # 1–3 attempts, usually success
    attempts = random.randint(1, 3)
    rows = []
    for i in range(attempts):
        ts = t0 + timedelta(seconds=i * random.randint(8, 20))  # human-like pauses
        success = True if i == attempts - 1 else (random.random() < 0.4)  # may fail once, then succeed
        rows.append({
            "user_id": user,
            "ip_address": ip,
            "timestamp": ts,
            "success": success,
            "source": "human"
        })
    return pd.DataFrame(rows)


def _make_ai_attack_session() -> pd.DataFrame:
    """
    A realistic credential-stuffing style burst:
    - Many attempts
    - Same IP
    - Many different users
    - Mostly failures
    """
    t0 = _now()
    ip = "10.0.0.99"
    attempts = random.randint(80, 180)
    unique_users = random.randint(25, 80)

    rows = []
    for i in range(attempts):
        ts = t0 + timedelta(seconds=i * random.randint(0, 1))  # very fast
        user = f"user_{random.randint(1, unique_users)}"
        success = (random.random() < 0.03)  # rare success
        rows.append({
            "user_id": user,
            "ip_address": ip,
            "timestamp": ts,
            "success": success,
            "source": "bot"
        })
    return pd.DataFrame(rows)


def _simple_reason(window_row: dict) -> str:
    """
    Simple, human-readable reasons.
    """
    reasons = []
    attempts = int(window_row.get("attempts", 0))
    fail_rate = float(window_row.get("failure_rate", 0))
    unique_users = int(window_row.get("unique_users", 0))
    burst = float(window_row.get("burst_ratio", 0))

    if attempts >= 15:
        reasons.append("Too many login attempts in a short time")
    if fail_rate >= 0.80:
        reasons.append("Most attempts failed (very suspicious)")
    if unique_users >= 5:
        reasons.append("Many different accounts targeted from one IP")
    if burst >= 3:
        reasons.append("Burst behavior (machine-like rapid pattern)")

    return " • " + "\n • ".join(reasons) if reasons else " • Looks like normal human behavior"


class SimpleDetectorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        _ensure_dirs()

        self.title("AI Credential Stuffing Detector (Simple Offline Demo)")
        self.geometry("900x520")
        self.minsize(860, 480)

        self.model_path = os.path.join("models", "credential_model.pkl")

        # If model doesn't exist yet, we will train once using a normal baseline
        self._ensure_model_ready()

        self._build_ui()

    def _build_ui(self):
        # Top description (short)
        header = ttk.Frame(self, padding=(14, 10))
        header.pack(fill="x")

        title = ttk.Label(header, text="Credential Stuffing Detector", font=("Segoe UI", 14, "bold"))
        title.pack(anchor="w")

        subtitle = ttk.Label(
            header,
            text="Click Human Login or AI Attack. The system analyzes the pattern and tells you what it looks like.",
            font=("Segoe UI", 10)
        )
        subtitle.pack(anchor="w", pady=(4, 0))

        # Buttons row
        controls = ttk.Frame(self, padding=(14, 6))
        controls.pack(fill="x")

        ttk.Button(controls, text="Try Human Login", command=self.try_human).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Try AI Attack", command=self.try_ai).pack(side="left", padx=(0, 10))
        ttk.Button(controls, text="Clear", command=self.clear).pack(side="left")

        self.write_logs = tk.BooleanVar(value=True)
        ttk.Checkbutton(controls, text="Write alerts to logs/alerts.log", variable=self.write_logs).pack(
            side="right"
        )

        # One findings box only
        box = ttk.LabelFrame(self, text="Findings (What the system observed)", padding=(12, 10))
        box.pack(fill="both", expand=True, padx=14, pady=10)

        self.findings = tk.Text(box, height=12, wrap="word")
        self.findings.pack(fill="both", expand=True)
        self.findings.configure(state="disabled")

        # Bottom big label result
        bottom = ttk.Frame(self, padding=(14, 10))
        bottom.pack(fill="x")

        self.result_label = ttk.Label(
            bottom,
            text="This looks like: —",
            font=("Segoe UI", 14, "bold")
        )
        self.result_label.pack(anchor="w")

        self.hint_label = ttk.Label(
            bottom,
            text="Tip: Human = few attempts + pauses. AI = many fast attempts + many users + many failures.",
            font=("Segoe UI", 9)
        )
        self.hint_label.pack(anchor="w", pady=(4, 0))

    def _set_findings(self, text: str):
        self.findings.configure(state="normal")
        self.findings.delete("1.0", "end")
        self.findings.insert("1.0", text)
        self.findings.configure(state="disabled")

    def clear(self):
        self._set_findings("")
        self.result_label.config(text="This looks like: —")

    def _ensure_model_ready(self):
        """
        If model doesn't exist, train it once on a normal baseline.
        This makes the demo work immediately.
        """
        if os.path.exists(self.model_path):
            return

        # Build a normal baseline dataset
        baseline_rows = []
        base_time = _now() - timedelta(minutes=10)

        for u in range(1, 35):  # 34 normal users
            user = f"user_{u}"
            ip = f"192.168.1.{random.randint(2, 200)}"
            attempts = random.randint(1, 5)

            for i in range(attempts):
                baseline_rows.append({
                    "user_id": user,
                    "ip_address": ip,
                    "timestamp": base_time + timedelta(seconds=random.randint(0, 600)),
                    "success": random.random() < 0.85,
                    "source": "baseline"
                })

        baseline_df = pd.DataFrame(baseline_rows)
        feat = extract_features(baseline_df)
        train_model(feat)

    def _classify_session(self, df: pd.DataFrame, label: str):
        """
        Runs feature extraction + anomaly detection and displays a simple explanation.
        """
        try:
            feat = extract_features(df)

            preds, risk_scores, _ = detect_anomalies(feat)

            # Use the single "window row" (usually 1 row) for explanation
            feat = feat.copy()
            feat["pred"] = preds
            feat["risk"] = risk_scores

            row = feat.iloc[0].to_dict()

            attempts = int(row.get("attempts", 0))
            fail_rate = float(row.get("failure_rate", 0))
            unique_users = int(row.get("unique_users", 0))
            burst = float(row.get("burst_ratio", 0))
            risk = float(row.get("risk", 0))
            pred = int(row.get("pred", 1))

            # Simple decision:
            # - model says anomaly (-1) OR clearly bot-like thresholds
            looks_ai = (
                pred == -1
                or attempts >= 15
                or fail_rate >= 0.80
                or unique_users >= 5
            )

            verdict = "AI" if looks_ai else "HUMAN"

            # Build simple findings text (no tables)
            findings_text = (
                f"Scenario you chose: {label}\n"
                f"Time: {_fmt_dt(_now())}\n\n"
                f"What we measured:\n"
                f" • Attempts in short window: {attempts}\n"
                f" • Failure rate: {fail_rate:.2f}\n"
                f" • Unique users targeted: {unique_users}\n"
                f" • Burst score: {burst:.2f}\n"
                f" • Risk score: {risk:.0f}\n\n"
                f"Why it decided this:\n"
                f"{_simple_reason(row)}\n"
            )

            self._set_findings(findings_text)
            self.result_label.config(text=f"This looks like: {verdict}")

            # optional alert logging
            if self.write_logs.get() and looks_ai:
                with open("logs/alerts.log", "a", encoding="utf-8") as log:
                    log.write(
                        f"{_now().isoformat()} | ALERT | verdict={verdict} | "
                        f"attempts={attempts} | fail_rate={fail_rate:.2f} | "
                        f"unique_users={unique_users} | risk={risk:.0f}\n"
                    )

        except Exception as e:
            messagebox.showerror("Error", f"Could not analyze session:\n{e}")

    def try_human(self):
        df = _make_human_session()
        self._classify_session(df, "Human Login")

    def try_ai(self):
        df = _make_ai_attack_session()
        self._classify_session(df, "AI Attack (Credential Stuffing)")



if __name__ == "__main__":
    app = SimpleDetectorApp()
    app.mainloop()
