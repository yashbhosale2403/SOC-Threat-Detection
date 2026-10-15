"""
Module: Composite Risk Scoring Engine
Author: CyberSentinel SOC Project
Purpose: Calculates a unified 0-100 Risk Score by combining:
         1. Rule Detection Confidence (Weight: 35)
         2. Machine Learning Anomaly Score (Weight: 35)
         3. Threat Intelligence IOC Hit (Weight: 15)
         4. Target Asset Criticality (Weight: 15)
"""


class RiskScoringEngine:
    """
    Computes objective risk ratings for prioritized alert triaging.
    """

    # Criticality weight mapping for enterprise assets
    ASSET_CRITICALITY_MAP = {
        "Domain-Controller": 15,
        "Database-Server": 15,
        "SSH-Server": 12,
        "Web-Portal": 10,
        "Core-Network": 10,
        "Endpoint-PC": 6,
    }

    @classmethod
    def calculate_risk(
        cls,
        rule_weight: int,
        ml_anomaly_score: float,
        threat_intel_match: bool,
        target_asset: str = "SSH-Server"
    ) -> dict:
        """
        Combines individual risk vectors into an overall score (0 - 100).
        """
        # 1. Rule component (0 to 35 pts)
        score_rule = min(int(rule_weight), 35)

        # 2. ML anomaly component (0 to 35 pts)
        score_ml = int(round(ml_anomaly_score * 35.0))

        # 3. Threat intel component (0 or 15 pts)
        score_ti = 15 if threat_intel_match else 0

        # 4. Asset criticality component (0 to 15 pts)
        score_asset = cls.ASSET_CRITICALITY_MAP.get(target_asset, 8)

        total_score = min(score_rule + score_ml + score_ti + score_asset, 100)

        # Map to severity level
        if total_score >= 76:
            severity = "CRITICAL"
        elif total_score >= 51:
            severity = "HIGH"
        elif total_score >= 26:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": total_score,
            "severity": severity,
            "breakdown": {
                "rule_component": score_rule,
                "ml_component": score_ml,
                "threat_intel_component": score_ti,
                "asset_criticality_component": score_asset,
            }
        }
