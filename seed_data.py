"""
Seed Script: Initial SOC Demonstration Data
Author: CyberSentinel SOC Project
Purpose: Seeds initial baseline traffic, known IOCs, and sample alerts
         so the dashboard looks lively and ready immediately on first run.
"""

import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cybersentinel.settings')
django.setup()

from core.engine.threat_intel import seed_threat_intel
from core.engine.simulator import AttackSimulator


def seed():
    print("[*] Seeding Threat Intelligence IOCs...")
    seed_threat_intel()

    print("[*] Generating benign baseline traffic...")
    AttackSimulator.simulate_normal_traffic(count=8)

    print("[*] Simulating baseline security events...")
    AttackSimulator.simulate_brute_force(attacker_ip="192.168.1.150", count=5)
    AttackSimulator.simulate_port_scan(attacker_ip="192.168.1.180")

    print("[+] Demonstration environment populated successfully!")


if __name__ == "__main__":
    seed()
