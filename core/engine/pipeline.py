"""
Module: SOC Core Pipeline Orchestrator
Author: CyberSentinel SOC Project
Purpose: Executes the end-to-end security pipeline:
         COLLECT -> NORMALIZE -> DETECT (Rule + ML) -> CORRELATE -> RISK SCORE -> ALERT -> INCIDENT
"""

import uuid
from core.models import LogEvent, Alert
from core.engine.collector import LogNormalizer
from core.engine.rules import RuleDetectionEngine
from core.engine.ml_detector import MLAnomalyDetector
from core.engine.threat_intel import check_ioc_match
from core.engine.risk_scorer import RiskScoringEngine
from core.engine.correlation import CorrelationEngine


class SOCPipeline:
    """
    Unified entry point for ingesting and processing events through the SOC intelligence stack.
    """

    @classmethod
    def process_raw_log(cls, raw_line: str, source_type: str = "auto") -> dict:
        """
        Ingests a raw log line, normalizes it, and runs full SOC detection.
        """
        # Step 1: Normalize & Ingest
        log_event = LogNormalizer.ingest_raw(raw_line, source_type)
        return cls.process_log_event(log_event)

    @classmethod
    def process_log_event(cls, log_event: LogEvent) -> dict:
        """
        Runs Rule Engine, ML Anomaly Detector, Risk Scorer, and Correlation.
        """
        source_ip = log_event.source_ip
        event_type = log_event.event_type

        # Step 2: Rule-Based Detection
        triggered_rules = RuleDetectionEngine.run_all_rules(log_event)
        has_rule_trigger = len(triggered_rules) > 0
        primary_rule = triggered_rules[0] if has_rule_trigger else None

        # Step 3: Threat Intelligence IOC Lookup
        ti_result = check_ioc_match(source_ip)
        has_ti_match = ti_result["matched"]

        # Step 4: ML Behavioral Anomaly Detection
        # Build behavioral context
        recent_failures = LogEvent.objects.filter(
            source_ip=source_ip,
            event_type__in=['login_failed', 'web_login_failed']
        ).count()

        features = MLAnomalyDetector.extract_features(
            {
                "source_ip": source_ip,
                "event_type": event_type,
                "target": log_event.target,
                "user": log_event.user,
            },
            ip_history={
                "failed_logins": recent_failures,
                "requests_pm": 65.0 if has_rule_trigger else 18.0,
                "unique_ports": 8 if "port_scan" in event_type else 1,
                "data_kb": 25000.0 if "exfiltrat" in event_type else 450.0,
            }
        )
        ml_prediction = MLAnomalyDetector.predict_anomaly(features)
        anomaly_score = ml_prediction["anomaly_score"]
        is_ml_anomaly = ml_prediction["is_anomaly"]

        # Step 5: Risk Scoring (Rule + ML + Threat Intel + Asset)
        rule_weight = primary_rule.get("rule_weight", 0) if primary_rule else (15 if is_ml_anomaly else 0)
        risk_result = RiskScoringEngine.calculate_risk(
            rule_weight=rule_weight,
            ml_anomaly_score=anomaly_score,
            threat_intel_match=has_ti_match,
            target_asset=log_event.target
        )
        risk_score = risk_result["risk_score"]
        severity = risk_result["severity"]

        created_alert = None
        created_incident = None

        # Step 6: Alert Generation if Rule or High ML Anomaly or TI Match
        if has_rule_trigger or is_ml_anomaly or has_ti_match:
            alert_id = f"ALT-{uuid.uuid4().hex[:6].upper()}"

            if has_rule_trigger and is_ml_anomaly:
                detection_method = "HYBRID"
                title = f"{primary_rule['category'].replace('_', ' ').title()}: {primary_rule['rule_name'].split(':')[-1].strip()}"
            elif has_rule_trigger:
                detection_method = "RULE_BASED"
                title = primary_rule['rule_name'].split(':')[-1].strip()
            elif has_ti_match:
                detection_method = "THREAT_INTEL"
                title = f"Known Malicious Host Communication ({ti_result['threat_name']})"
            else:
                detection_method = "ML_ANOMALY"
                title = f"Behavioral Anomaly: Unusual {event_type} Pattern"

            category = primary_rule["category"] if primary_rule else ("MALICIOUS_IOC" if has_ti_match else "ANOMALOUS_BEHAVIOR")
            rule_name = primary_rule["rule_name"] if primary_rule else ("Threat Intel Match" if has_ti_match else "IsolationForest Outlier")

            desc = (
                f"Detection Triggered: {title}.\n"
                f"Source IP: {source_ip} | Target User: {log_event.user} | Asset: {log_event.target}\n"
                f"ML Anomaly Score: {anomaly_score} ({ml_prediction['confidence_label']})\n"
                f"Composite Risk Score: {risk_score}/100 ({severity})\n"
            )
            if has_ti_match:
                desc += f"Threat Intel Alert: Matched known adversary '{ti_result['threat_actor']}' (Confidence: {ti_result['confidence']}%).\n"

            created_alert = Alert.objects.create(
                alert_id=alert_id,
                title=title,
                category=category,
                source_ip=source_ip,
                target_user=log_event.user,
                target_asset=log_event.target,
                detection_method=detection_method,
                rule_name=rule_name,
                ml_anomaly_score=anomaly_score,
                risk_score=risk_score,
                severity=severity,
                status='OPEN',
                description=desc,
            )
            created_alert.evidence_events.add(log_event)

            # Step 7: Event Correlation into Multi-Stage Incidents
            created_incident = CorrelationEngine.correlate_incident_for_ip(source_ip)

        log_event.is_processed = True
        log_event.save()

        return {
            "log_event_id": log_event.id,
            "source_ip": source_ip,
            "event_type": event_type,
            "rules_triggered": triggered_rules,
            "ml_anomaly_score": anomaly_score,
            "is_anomaly": is_ml_anomaly,
            "threat_intel_match": ti_result,
            "risk_score": risk_score,
            "severity": severity,
            "alert": created_alert.alert_id if created_alert else None,
            "incident": created_incident.incident_id if created_incident else None,
        }
