import pandas as pd
import random
from datetime import datetime, timedelta

def generate_login_events(num_users=50, days=3):
    events = []
    base_time = datetime.now() - timedelta(days=days)

    # Normal user behavior (human)
    for user_id in range(num_users):
        ip = f"192.168.1.{random.randint(1, 50)}"
        attempts = random.randint(2, 6)

        for _ in range(attempts):
            events.append({
                "user_id": f"user_{user_id}",
                "ip_address": ip,
                "timestamp": base_time + timedelta(minutes=random.randint(1, 4000)),
                "success": random.choice([True, True, True, False]),
                "source": "human"
            })

    # Simulated credential stuffing attack (bot)
    attack_ip = "10.0.0.99"
    for _ in range(150):
        events.append({
            "user_id": f"user_{random.randint(1, num_users)}",
            "ip_address": attack_ip,
            "timestamp": base_time + timedelta(minutes=random.randint(1, 30)),  # concentrated burst
            "success": False,
            "source": "bot"
        })

    return pd.DataFrame(events)
