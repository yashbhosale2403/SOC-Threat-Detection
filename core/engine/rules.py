"""
Module: Rule-Based Threat Detection Engine
Author: CyberSentinel SOC Project
Purpose: Evaluates incoming security logs against deterministic signature rules
         including Brute Force, Port Scanning, Suspicious Login,
         Privilege Escalation, and Excessive Traffic probes.
"""

from datetime import timedelta
from django.utils import timezone
from core.models import LogEvent


class RuleDetectionEngine:
    """
    Implements core cybersecurity detection rules.
    """

    @classmethod
    def evaluate_brute_force(cls, event: LogEvent) -> dict:
        """
        Rule: If failed logins from same source IP > 4 within the last 5 minutes.
        """
        if event.event_type not in ('login_failed', 'web_login_failed'):
            return {"triggered": False}

        five_mins_ago = timezone.now() - timedelta(minutes=5)
        failed_attempts = LogEvent.objects.filter(
            source_ip=event.source_ip,
            event_type__in=['login_failed', 'web_login_failed'],
            timestamp__gte=five_mins_ago
        ).count()

        if failed_attempts >= 4:
            return {
                "triggered": True,
                "rule_name": "RULE-01: Authentication Brute-Force",
                "category": "BRUTE_FORCE",
                "severity": "HIGH",
                "rule_weight": 35,
                "description": f"Observed {failed_attempts} failed authentication attempts from IP {event.source_ip} within 5 minutes.",
            }
        return {"triggered": False}

    @classmethod
    def evaluate_port_scan(cls, event: LogEvent) -> dict:
        """
        Rule: If a single source IP connects to >= 6 distinct destination ports within 5 minutes.
        """
        five_mins_ago = timezone.now() - timedelta(minutes=5)
        recent_events = LogEvent.objects.filter(
            source_ip=event.source_ip,
            destination_port__isnull=False,
            timestamp__gte=five_mins_ago
        )
        unique_ports = recent_events.values_list('destination_port', flat=True).distinct().count()

        if unique_ports >= 6:
            return {
                "triggered": True,
                "rule_name": "RULE-02: Port Scanning Reconnaissance",
                "category": "PORT_SCAN",
                "severity": "HIGH",
                "rule_weight": 30,
                "description": f"Source IP {event.source_ip} connected to {unique_ports} distinct network ports, indicative of Nmap/SYN scanning.",
            }
        return {"triggered": False}

    @classmethod
    def evaluate_suspicious_login(cls, event: LogEvent) -> dict:
        """
        Rule: Login occurred at unusual hours (between 00:00 and 05:00 UTC) or immediately following failed attempts.
        """
        if event.event_type not in ('login_success', 'web_login_success'):
            return {"triggered": False}

        hour = event.timestamp.hour
        # Check if there were prior failed logins for this user or IP in the last 10 minutes
        ten_mins_ago = timezone.now() - timedelta(minutes=10)
        recent_failures = LogEvent.objects.filter(
            source_ip=event.source_ip,
            event_type__in=['login_failed', 'web_login_failed'],
            timestamp__gte=ten_mins_ago
        ).count()

        if recent_failures >= 3:
            return {
                "triggered": True,
                "rule_name": "RULE-03A: Credential Stuffing / Successful Login Post-Failure",
                "category": "SUSPICIOUS_LOGIN",
                "severity": "CRITICAL",
                "rule_weight": 40,
                "description": f"Successful login for user '{event.user}' from {event.source_ip} immediately following {recent_failures} failed attempts.",
            }

        if 0 <= hour <= 5:
            return {
                "triggered": True,
                "rule_name": "RULE-03B: Off-Hours Authentication",
                "category": "SUSPICIOUS_LOGIN",
                "severity": "MEDIUM",
                "rule_weight": 25,
                "description": f"User '{event.user}' authenticated during anomalous off-hours window ({hour:02d}:00 UTC).",
            }

        return {"triggered": False}

    @classmethod
    def evaluate_privilege_escalation(cls, event: LogEvent) -> dict:
        """
        Rule: User executed sudo command, root escalation, or sensitive file access.
        """
        raw = event.raw_log.lower()
        event_lower = event.event_type.lower()
        if "sudo" in event_lower or "sudo:" in raw or "root" in raw or "/etc/shadow" in raw or "useradd" in raw:
            return {
                "triggered": True,
                "rule_name": "RULE-04: Unauthorized Privilege Escalation Attempt",
                "category": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "rule_weight": 40,
                "description": f"Privileged command or sensitive credential access executed by user '{event.user}' on {event.target}.",
            }
        return {"triggered": False}

    @classmethod
    def evaluate_excessive_requests(cls, event: LogEvent) -> dict:
        """
        Rule: Excessive HTTP requests or admin path probing.
        """
        if "probe" in event.event_type or "admin" in event.raw_log.lower():
            return {
                "triggered": True,
                "rule_name": "RULE-05: Web Application Admin Probe / Directory Enumeration",
                "category": "WEB_ATTACK",
                "severity": "MEDIUM",
                "rule_weight": 25,
                "description": f"Automated directory fuzzing / admin portal probe detected from {event.source_ip}.",
            }
        return {"triggered": False}

    @classmethod
    def evaluate_custom_database_rules(cls, event: LogEvent) -> list:
        """
        Evaluates user-configured custom rules stored dynamically in the database.
        """
        from core.models import DetectionRule
        custom_rules = DetectionRule.objects.filter(is_enabled=True, is_builtin=False)
        triggered_custom = []

        for rule in custom_rules:
            is_match = False
            raw_lower = event.raw_log.lower()

            # Condition 1: Keyword pattern match
            if rule.keyword_pattern and rule.keyword_pattern.lower() in raw_lower:
                is_match = True

            # Condition 2: Event type match
            if rule.event_type_match and rule.event_type_match.lower() == event.event_type.lower():
                is_match = True

            if is_match:
                # Check threshold count over time window
                if rule.threshold_count > 1:
                    window_ago = timezone.now() - timedelta(minutes=rule.time_window_minutes)
                    q = LogEvent.objects.filter(source_ip=event.source_ip, timestamp__gte=window_ago)
                    if rule.event_type_match:
                        q = q.filter(event_type=rule.event_type_match)
                    occurrences = q.count()
                    if occurrences < rule.threshold_count:
                        continue  # Threshold not met yet

                triggered_custom.append({
                    "triggered": True,
                    "rule_name": f"{rule.rule_id}: {rule.name}",
                    "category": rule.category,
                    "severity": rule.severity,
                    "rule_weight": rule.risk_weight,
                    "description": f"Custom Rule [{rule.name}] triggered: {rule.description} (Source: {event.source_ip})",
                })

        return triggered_custom

    @classmethod
    def run_all_rules(cls, event: LogEvent) -> list:
        """
        Executes built-in detection rules and dynamic database rules against the incoming event.
        Returns a list of triggered rule results.
        """
        results = []
        checks = [
            cls.evaluate_brute_force(event),
            cls.evaluate_port_scan(event),
            cls.evaluate_suspicious_login(event),
            cls.evaluate_privilege_escalation(event),
            cls.evaluate_excessive_requests(event),
        ]
        for c in checks:
            if c.get("triggered"):
                results.append(c)

        # Append custom database rules
        custom_triggers = cls.evaluate_custom_database_rules(event)
        results.extend(custom_triggers)

        return results


def seed_default_rules():
    """
    Populates standard built-in rules into the DetectionRule table for UI management.
    """
    from core.models import DetectionRule
    defaults = [
        {
            "rule_id": "RULE-01",
            "name": "Authentication Brute-Force",
            "category": "BRUTE_FORCE",
            "severity": "HIGH",
            "event_type_match": "login_failed",
            "threshold_count": 4,
            "time_window_minutes": 5,
            "risk_weight": 35,
            "description": "Detects 4 or more failed authentication attempts from a single IP within 5 minutes.",
            "is_builtin": True,
        },
        {
            "rule_id": "RULE-02",
            "name": "Network Port Scanning / Reconnaissance",
            "category": "PORT_SCAN",
            "severity": "HIGH",
            "event_type_match": "connection_blocked",
            "threshold_count": 6,
            "time_window_minutes": 5,
            "risk_weight": 30,
            "description": "Detects single source IP sweeping >= 6 distinct destination ports within 5 minutes.",
            "is_builtin": True,
        },
        {
            "rule_id": "RULE-03",
            "name": "Credential Stuffing / Suspicious Authentication",
            "category": "SUSPICIOUS_LOGIN",
            "severity": "CRITICAL",
            "event_type_match": "login_success",
            "threshold_count": 1,
            "time_window_minutes": 10,
            "risk_weight": 40,
            "description": "Detects successful login following rapid failed attempts or off-hours authentication.",
            "is_builtin": True,
        },
        {
            "rule_id": "RULE-04",
            "name": "Unauthorized Root Privilege Escalation",
            "category": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "keyword_pattern": "sudo",
            "threshold_count": 1,
            "time_window_minutes": 5,
            "risk_weight": 40,
            "description": "Detects user attempting unauthorized root sudo command or reading /etc/shadow.",
            "is_builtin": True,
        },
        {
            "rule_id": "RULE-05",
            "name": "Web Application Directory Fuzzing / Admin Probe",
            "category": "WEB_ATTACK",
            "severity": "MEDIUM",
            "keyword_pattern": "admin",
            "threshold_count": 1,
            "time_window_minutes": 5,
            "risk_weight": 25,
            "description": "Detects automated URL path fuzzing and administrative portal enumeration.",
            "is_builtin": True,
        },
    ]

    for item in defaults:
        DetectionRule.objects.get_or_create(
            rule_id=item["rule_id"],
            defaults=item
        )

