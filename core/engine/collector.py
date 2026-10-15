"""
Module: Log Normalizer and Ingestion
Author: CyberSentinel SOC Project
Purpose: Ingests raw logs from diverse sources (Linux auth, Apache/Nginx web,
         firewalls, and system events) and normalizes them into a consistent
         JSON schema for downstream rule and ML inspection.
"""

import re
from datetime import datetime
from django.utils import timezone
from core.models import LogEvent


class LogNormalizer:
    """
    Parses heterogeneous text logs into standardized LogEvent records.
    """

    # Common regex patterns for log parsing
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    USER_PATTERN = re.compile(r'\b(?:for|user|by)\s+([a-zA-Z0-9_\-\.]+)', re.IGNORECASE)
    PORT_PATTERN = re.compile(r'\bport\s+(\d+)\b', re.IGNORECASE)

    @classmethod
    def normalize_linux_auth(cls, raw_line: str) -> dict:
        """
        Parses Linux /var/log/auth.log lines (e.g. Failed password, Accepted password, sudo).
        """
        ip_match = cls.IP_PATTERN.search(raw_line)
        user_match = cls.USER_PATTERN.search(raw_line)
        port_match = cls.PORT_PATTERN.search(raw_line)

        source_ip = ip_match.group(0) if ip_match else "127.0.0.1"
        user = user_match.group(1) if user_match else "unknown"
        port = int(port_match.group(1)) if port_match else 22

        lower = raw_line.lower()
        if "failed password" in lower or "authentication failure" in lower:
            event_type = "login_failed"
            severity = "MEDIUM"
        elif "accepted password" in lower or "session opened" in lower:
            event_type = "login_success"
            severity = "LOW"
        elif "sudo:" in lower or "command=" in lower:
            event_type = "sudo_command"
            severity = "HIGH"
        else:
            event_type = "system_auth"
            severity = "INFO"

        return {
            "source": "linux-auth",
            "source_ip": source_ip,
            "destination_ip": "192.168.1.10",
            "destination_port": port,
            "user": user,
            "event_type": event_type,
            "target": "SSH-Server",
            "raw_log": raw_line.strip(),
            "severity": severity,
        }

    @classmethod
    def normalize_web_log(cls, raw_line: str) -> dict:
        """
        Parses Common Log Format / Combined Web logs (e.g. Apache / Nginx).
        Example: 192.168.1.50 - - [15/Oct/2026:12:00:00] "POST /api/login HTTP/1.1" 401 512
        """
        ip_match = cls.IP_PATTERN.search(raw_line)
        source_ip = ip_match.group(0) if ip_match else "127.0.0.1"

        status_code = 200
        status_match = re.search(r'"\s+(\d{3})\s+', raw_line)
        if status_match:
            status_code = int(status_match.group(1))

        if "/login" in raw_line and status_code in (401, 403):
            event_type = "web_login_failed"
            severity = "MEDIUM"
        elif "/admin" in raw_line:
            event_type = "admin_portal_probe"
            severity = "HIGH" if status_code >= 400 else "MEDIUM"
        elif status_code == 404:
            event_type = "http_404_scan"
            severity = "LOW"
        elif status_code == 500:
            event_type = "http_server_error"
            severity = "MEDIUM"
        else:
            event_type = "http_request"
            severity = "INFO"

        return {
            "source": "web-server",
            "source_ip": source_ip,
            "destination_ip": "192.168.1.15",
            "destination_port": 443,
            "user": "web-client",
            "event_type": event_type,
            "target": "Web-Portal",
            "raw_log": raw_line.strip(),
            "severity": severity,
        }

    @classmethod
    def normalize_firewall_log(cls, raw_line: str) -> dict:
        """
        Parses network perimeter firewall logs.
        Example: FIREWALL DROP src=192.168.1.80 dst=192.168.1.10 proto=TCP dport=445
        """
        ips = cls.IP_PATTERN.findall(raw_line)
        source_ip = ips[0] if len(ips) > 0 else "127.0.0.1"
        dest_ip = ips[1] if len(ips) > 1 else "192.168.1.1"

        port_match = re.search(r'dport=(\d+)', raw_line, re.IGNORECASE)
        dest_port = int(port_match.group(1)) if port_match else 80

        action = "blocked" if ("drop" in raw_line.lower() or "block" in raw_line.lower()) else "allowed"
        severity = "MEDIUM" if action == "blocked" else "LOW"

        return {
            "source": "firewall",
            "source_ip": source_ip,
            "destination_ip": dest_ip,
            "destination_port": dest_port,
            "user": "network",
            "event_type": f"connection_{action}",
            "target": f"Port-{dest_port}",
            "raw_log": raw_line.strip(),
            "severity": severity,
        }

    @classmethod
    def ingest_log_dict(cls, data: dict) -> LogEvent:
        """
        Accepts already structured dictionary or normalized data and saves LogEvent in DB.
        """
        event = LogEvent.objects.create(
            timestamp=data.get('timestamp') or timezone.now(),
            source=data.get('source', 'generic'),
            source_ip=data.get('source_ip', '127.0.0.1'),
            destination_ip=data.get('destination_ip', '192.168.1.1'),
            destination_port=data.get('destination_port'),
            user=data.get('user', 'unknown'),
            event_type=data.get('event_type', 'generic_event'),
            target=data.get('target', 'Core-Network'),
            raw_log=data.get('raw_log', str(data)),
            severity=data.get('severity', 'INFO'),
        )
        return event

    @classmethod
    def ingest_raw(cls, raw_line: str, log_source: str = "auto") -> LogEvent:
        """
        Auto-detects source or uses specified type, normalizes, and saves.
        """
        lower = raw_line.lower()
        if log_source == "linux-auth" or "sshd" in lower or "password for" in lower or "sudo:" in lower:
            parsed = cls.normalize_linux_auth(raw_line)
        elif log_source == "web-server" or "get /" in lower or "post /" in lower or "http/" in lower:
            parsed = cls.normalize_web_log(raw_line)
        elif log_source == "firewall" or "firewall" in lower or "dport=" in lower:
            parsed = cls.normalize_firewall_log(raw_line)
        else:
            # Fallback general parser
            ip_match = cls.IP_PATTERN.search(raw_line)
            parsed = {
                "source": "system",
                "source_ip": ip_match.group(0) if ip_match else "127.0.0.1",
                "destination_ip": "192.168.1.1",
                "destination_port": 80,
                "user": "system",
                "event_type": "system_event",
                "target": "Host",
                "raw_log": raw_line.strip(),
                "severity": "INFO",
            }

        return cls.ingest_log_dict(parsed)
