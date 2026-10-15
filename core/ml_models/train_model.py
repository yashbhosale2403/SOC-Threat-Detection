"""
Module: Machine Learning Model Trainer (Isolation Forest)
Author: CyberSentinel SOC Project
Purpose: Generates a baseline dataset of typical benign enterprise traffic,
         trains an Isolation Forest unsupervised anomaly detector, and saves
         the model artifact using Joblib for real-time SOC inference.

Features in behavioral vector:
  [0] failed_login_count (recent window)
  [1] requests_per_minute
  [2] unique_ports_accessed
  [3] data_transferred_kb
  [4] is_external_ip (0 = internal, 1 = external)
  [5] is_admin_access_attempt (0 = no, 1 = yes)
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "feature_scaler.pkl")


def generate_synthetic_training_data(n_samples: int = 1500) -> np.ndarray:
    """
    Creates synthetic behavioral baseline for normal SOC traffic:
    - Failed logins: mostly 0-1, rarely 2
    - Requests/min: 5 to 35
    - Unique ports: 1 to 2 (e.g. 80, 443, 22)
    - Data transfer: 50 KB to 1500 KB
    - External IP: ~30%
    - Admin access attempt: ~5%
    """
    np.random.seed(42)

    # 1. Normal traffic (96% of data)
    n_normal = int(n_samples * 0.96)
    failed_logins = np.random.poisson(lam=0.3, size=n_normal)
    requests_pm = np.random.normal(loc=18.0, scale=6.0, size=n_normal).clip(1, 45)
    unique_ports = np.random.choice([1, 2, 3], size=n_normal, p=[0.75, 0.20, 0.05])
    data_kb = np.random.normal(loc=400.0, scale=180.0, size=n_normal).clip(20, 2500)
    external_ip = np.random.choice([0, 1], size=n_normal, p=[0.70, 0.30])
    admin_access = np.random.choice([0, 1], size=n_normal, p=[0.97, 0.03])

    normal_data = np.column_stack([
        failed_logins,
        requests_pm,
        unique_ports,
        data_kb,
        external_ip,
        admin_access
    ])

    # 2. Sparse anomalies (4% of data for diversity)
    n_anomaly = n_samples - n_normal
    ano_failed = np.random.randint(6, 25, size=n_anomaly)
    ano_reqs = np.random.randint(250, 1200, size=n_anomaly)
    ano_ports = np.random.randint(10, 60, size=n_anomaly)
    ano_data = np.random.randint(20000, 150000, size=n_anomaly)  # data exfiltration
    ano_external = np.ones(n_anomaly)
    ano_admin = np.random.choice([0, 1], size=n_anomaly, p=[0.2, 0.8])

    anomaly_data = np.column_stack([
        ano_failed,
        ano_reqs,
        ano_ports,
        ano_data,
        ano_external,
        ano_admin
    ])

    dataset = np.vstack([normal_data, anomaly_data])
    np.random.shuffle(dataset)
    return dataset


def train_and_save_model():
    """
    Trains the Isolation Forest model and writes pkl artifacts.
    """
    print("[*] Generating baseline dataset for SOC anomaly detection...")
    X = generate_synthetic_training_data(2000)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("[*] Training IsolationForest (n_estimators=100, contamination=0.05)...")
    # Contamination set to 0.05 assumes roughly 5% anomalies
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        max_samples='auto',
        random_state=42
    )
    model.fit(X_scaled)

    # Save to disk
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"[+] Model saved successfully at: {MODEL_PATH}")
    print(f"[+] Scaler saved successfully at: {SCALER_PATH}")
    return model, scaler


if __name__ == "__main__":
    train_and_save_model()
