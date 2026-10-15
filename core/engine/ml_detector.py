"""
Module: Machine Learning Anomaly Detection Engine
Author: CyberSentinel SOC Project
Purpose: Extracts real-time behavioral features from security events,
         applies the pre-trained Isolation Forest model, and calculates
         an anomaly score (0.00 to 1.00) to flag unexpected operational deviations.
"""

import os
import joblib
import numpy as np

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "ml_models", "isolation_forest.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "ml_models", "feature_scaler.pkl")

_model = None
_scaler = None


def load_ml_pipeline():
    """
    Lazy loads the Isolation Forest model and feature scaler.
    """
    global _model, _scaler
    if _model is None or _scaler is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            _model = joblib.load(MODEL_PATH)
            _scaler = joblib.load(SCALER_PATH)
        else:
            # Fallback auto-train if files not found
            from core.ml_models.train_model import train_and_save_model
            _model, _scaler = train_and_save_model()
    return _model, _scaler


class MLAnomalyDetector:
    """
    Evaluates behavioral features using Isolation Forest.
    """

    @classmethod
    def extract_features(cls, event_data: dict, ip_history: dict = None) -> list:
        """
        Constructs a 6-dimensional feature vector:
        [
          failed_login_count,
          requests_per_min,
          unique_ports_accessed,
          data_transferred_kb,
          is_external_ip,
          is_admin_attempt
        ]
        """
        ip_history = ip_history or {}
        source_ip = event_data.get('source_ip', '127.0.0.1')

        # 1. Failed login count
        failed_count = ip_history.get('failed_logins', 0)
        if event_data.get('event_type') in ('login_failed', 'web_login_failed'):
            failed_count += 1

        # 2. Requests per minute
        requests_pm = ip_history.get('requests_pm', 15.0)

        # 3. Unique ports accessed
        ports_count = ip_history.get('unique_ports', 1)

        # 4. Data transfer in KB
        data_kb = ip_history.get('data_kb', 250.0)

        # 5. External IP? (Non-private RFC1918)
        is_external = 0
        if not (source_ip.startswith('192.168.') or source_ip.startswith('10.') or source_ip.startswith('172.16.') or source_ip == '127.0.0.1'):
            is_external = 1

        # 6. Admin access / sensitive action attempt
        target = str(event_data.get('target', '')).lower()
        user = str(event_data.get('user', '')).lower()
        event_type = str(event_data.get('event_type', '')).lower()
        is_admin = 1 if ('admin' in target or 'root' in user or 'sudo' in event_type or 'admin' in user) else 0

        return [failed_count, requests_pm, ports_count, data_kb, is_external, is_admin]

    @classmethod
    def predict_anomaly(cls, feature_vector: list) -> dict:
        """
        Runs the Isolation Forest inference on the feature vector.
        Isolation forest score: lower score means more anomalous.
        Decision function outputs negative values for anomalies, positive for normal.
        We transform this into an intuitive 0.00 - 1.00 Anomaly Score.
        """
        model, scaler = load_ml_pipeline()

        X = np.array([feature_vector])
        X_scaled = scaler.transform(X)

        # decision_function gives signed distance to separating hyperplane
        # typical range ~ [-0.5, +0.5]
        score_raw = model.decision_function(X_scaled)[0]

        # Normalize score into [0.0, 1.0] where 1.0 = highly anomalous
        # Sigmoidal mapping centered around 0
        norm_score = 1.0 / (1.0 + np.exp(score_raw * 5.0))
        norm_score = round(float(np.clip(norm_score, 0.01, 0.99)), 3)

        # Classification flag
        is_anomaly = bool(norm_score >= 0.60)

        if norm_score >= 0.80:
            confidence_label = "Highly Abnormal (Critical Anomaly)"
        elif norm_score >= 0.60:
            confidence_label = "Suspicious Deviation"
        elif norm_score >= 0.35:
            confidence_label = "Slightly Unusual"
        else:
            confidence_label = "Normal Behavioral Pattern"

        return {
            "anomaly_score": norm_score,
            "is_anomaly": is_anomaly,
            "confidence_label": confidence_label,
            "features_analyzed": {
                "failed_logins": feature_vector[0],
                "requests_per_min": feature_vector[1],
                "unique_ports": feature_vector[2],
                "data_transferred_kb": feature_vector[3],
                "is_external_ip": bool(feature_vector[4]),
                "is_admin_attempt": bool(feature_vector[5]),
            }
        }
