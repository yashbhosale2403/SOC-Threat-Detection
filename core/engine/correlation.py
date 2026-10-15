"""
Module: Event Correlation Engine
Author: CyberSentinel SOC Project
Purpose: Correlates disparate security alerts across time windows,
         associates IP addresses and users, reconstructs multi-stage attack
         kill-chains, and synthesizes them into actionable Incidents.
"""

from datetime import timedelta
import uuid
from django.utils import timezone
from core.models import Alert, Incident, ResponseAction


class CorrelationEngine:
    """
    Groups atomic alerts into holistic security incidents.
    """

    @classmethod
    def correlate_incident_for_ip(cls, source_ip: str) -> Incident:
        """
        Examines recent alerts from this IP address to discover correlated patterns.
        """
        fifteen_mins_ago = timezone.now() - timedelta(minutes=15)
        recent_alerts = list(Alert.objects.filter(
            source_ip=source_ip,
            created_at__gte=fifteen_mins_ago,
            status='OPEN'
        ))

        if not recent_alerts:
            return None

        categories = set(a.category for a in recent_alerts)

        # Check for Multi-Stage Kill-Chain:
        # e.g., Recon (PORT_SCAN) + Credential Access (BRUTE_FORCE) or SUSPICIOUS_LOGIN + PRIVILEGE_ESCALATION
        is_multi_stage = False
        mitre_tactic = "Defense Evasion / Initial Access"
        title = f"Security Incident: Anomalous Activity from {source_ip}"
        recommendation = f"Block source IP {source_ip} on firewall and audit recent connections."

        if ("BRUTE_FORCE" in categories or "PORT_SCAN" in categories) and ("SUSPICIOUS_LOGIN" in categories or "PRIVILEGE_ESCALATION" in categories):
            is_multi_stage = True
            mitre_tactic = "Reconnaissance -> Credential Access -> Lateral Movement / Privilege Escalation"
            title = f"Multi-Stage Attack: Account Takeover & Privilege Escalation ({source_ip})"
            recommendation = (
                f"1. Immediately block IP {source_ip} on perimeter firewall.\n"
                f"2. Temporarily disable compromised user accounts.\n"
                f"3. Isolate target machine for forensic image capture."
            )
        elif "PRIVILEGE_ESCALATION" in categories:
            mitre_tactic = "Privilege Escalation / Root Access"
            title = f"Privilege Escalation Incident on Internal Asset ({source_ip})"
            recommendation = f"Revoke elevated credentials and terminate active administrative session for {source_ip}."
        elif "BRUTE_FORCE" in categories:
            mitre_tactic = "Credential Access (T1110)"
            title = f"Distributed Brute-Force Campaign ({source_ip})"
            recommendation = f"Blacklist {source_ip} and enforce multi-factor authentication (MFA) lockout."
        elif "PORT_SCAN" in categories:
            mitre_tactic = "Network Reconnaissance (T1046)"
            title = f"Reconnaissance Port Scan Probe ({source_ip})"
            recommendation = f"Add rate-limiting rule and monitor edge firewall logs for {source_ip}."

        # Compute aggregate incident risk score
        max_alert_risk = max([a.risk_score for a in recent_alerts]) if recent_alerts else 50
        incident_risk = min(max_alert_risk + (10 if is_multi_stage else 0), 100)

        severity = "CRITICAL" if incident_risk >= 76 else ("HIGH" if incident_risk >= 51 else "MEDIUM")

        # Find active or most recent incident for this IP
        existing_incident = Incident.objects.filter(source_ip=source_ip).order_by('-created_at').first()

        if existing_incident:
            existing_incident.risk_score = max(existing_incident.risk_score, incident_risk)
            existing_incident.severity = severity
            existing_incident.status = 'OPEN'  # Re-open if new attack activity is detected
            if is_multi_stage:
                existing_incident.title = title
                existing_incident.mitre_tactic = mitre_tactic
                existing_incident.recommended_action = recommendation
            existing_incident.save()
            for alert in recent_alerts:
                existing_incident.alerts.add(alert)
                alert.status = 'ESCALATED'
                alert.save()

            # Ensure a pending response action exists for analyst approval
            if not existing_incident.responses.filter(status='PENDING_APPROVAL').exists():
                action_type = 'ISOLATE_HOST' if 'PRIVILEGE_ESCALATION' in categories else 'BLOCK_IP'
                ResponseAction.objects.create(
                    incident=existing_incident,
                    action_type=action_type,
                    target_entity=source_ip,
                    status='PENDING_APPROVAL',
                    execution_log=f"Recommended containment for {source_ip} awaiting analyst authorization.",
                )
            return existing_incident

        else:
            inc_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
            summary = (
                f"Correlated {len(recent_alerts)} security alerts originating from {source_ip}. "
                f"Alert categories involved: {', '.join(categories)}. "
                f"Automated risk rating assessed at {incident_risk}/100."
            )
            incident = Incident.objects.create(
                incident_id=inc_id,
                title=title,
                severity=severity,
                risk_score=incident_risk,
                source_ip=source_ip,
                affected_asset=recent_alerts[0].target_asset if recent_alerts else "Server-01",
                status='OPEN',
                mitre_tactic=mitre_tactic,
                summary=summary,
                recommended_action=recommendation,
                analyst_notes="Generated by CyberSentinel Correlation Engine.",
            )
            for alert in recent_alerts:
                incident.alerts.add(alert)
                alert.status = 'ESCALATED'
                alert.save()

            # Pre-populate recommended response action pending approval
            ResponseAction.objects.create(
                incident=incident,
                action_type='BLOCK_IP',
                target_entity=source_ip,
                status='PENDING_APPROVAL',
                execution_log="Awaiting analyst verification and approval.",
            )

            return incident
