"""
Module: SOC Attack & Normal Traffic Generator (Viva / Demo Simulator)
Author: CyberSentinel SOC Project
Purpose: Generates realistic synthetic attack simulations (SSH brute force,
         Nmap port scanning, credential stuffing, privilege escalation,
         and multi-stage APT intrusion) as well as benign baseline traffic.
"""

import time
from datetime import timedelta
from django.utils import timezone
from core.models import LogEvent
from core.engine.collector import LogNormalizer
from core.engine.pipeline import SOCPipeline


class AttackSimulator:
    """
    Simulates attacks and traffic patterns for evaluation and viva demonstration.
    """

    @classmethod
    def simulate_brute_force(cls, attacker_ip: str = "192.168.1.150", count: int = 5) -> list:
        """
        Generates rapid failed SSH login attempts from an attacker IP.
        """
        results = []
        now = timezone.now()
        for i in range(count):
            t = now - timedelta(seconds=(count - i) * 15)
            log_data = {
                "timestamp": t,
                "source": "linux-auth",
                "source_ip": attacker_ip,
                "destination_ip": "192.168.1.10",
                "destination_port": 22,
                "user": f"admin" if i % 2 == 0 else "root",
                "event_type": "login_failed",
                "target": "SSH-Server",
                "raw_log": f"Failed password for invalid user admin from {attacker_ip} port 49152 ssh2",
                "severity": "MEDIUM",
            }
            event = LogNormalizer.ingest_log_dict(log_data)
            res = SOCPipeline.process_log_event(event)
            results.append(res)
        return results

    @classmethod
    def simulate_port_scan(cls, attacker_ip: str = "192.168.1.180") -> list:
        """
        Simulates an Nmap / SYN reconnaissance port sweep across multiple ports.
        """
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]
        results = []
        now = timezone.now()
        for i, port in enumerate(ports):
            t = now - timedelta(seconds=(len(ports) - i) * 5)
            log_data = {
                "timestamp": t,
                "source": "firewall",
                "source_ip": attacker_ip,
                "destination_ip": "192.168.1.10",
                "destination_port": port,
                "user": "network",
                "event_type": "connection_blocked",
                "target": f"Port-{port}",
                "raw_log": f"FIREWALL DROP proto=TCP src={attacker_ip} dst=192.168.1.10 dport={port} flags=SYN",
                "severity": "MEDIUM",
            }
            event = LogNormalizer.ingest_log_dict(log_data)
            res = SOCPipeline.process_log_event(event)
            results.append(res)
        return results

    @classmethod
    def simulate_privilege_escalation(cls, attacker_ip: str = "192.168.1.105") -> list:
        """
        Simulates a compromised account attempting root sudo command and reading /etc/shadow.
        """
        results = []
        now = timezone.now()
        steps = [
            ("user-alice", "sudo_command", "sudo: user-alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"),
            ("user-alice", "sensitive_file_access", "auditd: type=PATH name=/etc/shadow flags=O_RDONLY by user-alice"),
        ]
        for user, event_type, raw in steps:
            log_data = {
                "timestamp": now,
                "source": "linux-auth",
                "source_ip": attacker_ip,
                "destination_ip": "192.168.1.10",
                "destination_port": 22,
                "user": user,
                "event_type": event_type,
                "target": "Core-Server-01",
                "raw_log": raw,
                "severity": "HIGH",
            }
            event = LogNormalizer.ingest_log_dict(log_data)
            res = SOCPipeline.process_log_event(event)
            results.append(res)
        return results

    @classmethod
    def simulate_full_intrusion_chain(cls, attacker_ip: str = "185.220.101.5") -> dict:
        """
        Simulates complete APT kill-chain as described in Section 42 of project.txt:
        1. Recon Port Scan
        2. Brute-Force Password Guessing
        3. Successful Login
        4. Privilege Escalation via Sudo
        5. Data Exfiltration
        """
        now = timezone.now()
        all_results = []

        # Step 1: Port Scan
        cls.simulate_port_scan(attacker_ip)

        # Step 2: Failed logins
        cls.simulate_brute_force(attacker_ip, count=4)

        # Step 3: Attacker gains entry with successful login
        success_event = LogNormalizer.ingest_log_dict({
            "timestamp": now,
            "source": "linux-auth",
            "source_ip": attacker_ip,
            "destination_ip": "192.168.1.10",
            "destination_port": 22,
            "user": "sysadmin",
            "event_type": "login_success",
            "target": "SSH-Server",
            "raw_log": f"Accepted password for sysadmin from {attacker_ip} port 52140 ssh2",
            "severity": "LOW",
        })
        res3 = SOCPipeline.process_log_event(success_event)
        all_results.append(res3)

        # Step 4: Sudo escalation
        priv_event = LogNormalizer.ingest_log_dict({
            "timestamp": now + timedelta(seconds=10),
            "source": "linux-auth",
            "source_ip": attacker_ip,
            "destination_ip": "192.168.1.10",
            "destination_port": 22,
            "user": "sysadmin",
            "event_type": "sudo_command",
            "target": "Core-Database",
            "raw_log": f"sudo: sysadmin : TTY=pts/2 ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            "severity": "CRITICAL",
        })
        res4 = SOCPipeline.process_log_event(priv_event)
        all_results.append(res4)

        return {
            "scenario": "Multi-Stage Account Takeover (APT Kill-Chain)",
            "attacker_ip": attacker_ip,
            "steps_executed": ["Port Scan", "Brute Force", "Credential Access", "Privilege Escalation"],
            "latest_incident": res4.get("incident"),
            "risk_score": res4.get("risk_score"),
        }

    @classmethod
    def simulate_normal_traffic(cls, count: int = 5) -> list:
        """
        Generates normal benign user traffic (web browsing, routine logins).
        """
        normal_ips = ["192.168.1.25", "192.168.1.30", "192.168.1.45"]
        results = []
        now = timezone.now()

        for i in range(count):
            ip = normal_ips[i % len(normal_ips)]
            log_data = {
                "timestamp": now - timedelta(seconds=(count - i) * 30),
                "source": "web-server",
                "source_ip": ip,
                "destination_ip": "192.168.1.15",
                "destination_port": 443,
                "user": f"employee_{i+1}",
                "event_type": "http_request",
                "target": "Web-Portal",
                "raw_log": f"{ip} - employee_{i+1} [GET /dashboard HTTP/1.1] 200 4096",
                "severity": "INFO",
            }
            event = LogNormalizer.ingest_log_dict(log_data)
            res = SOCPipeline.process_log_event(event)
            results.append(res)
        return results
