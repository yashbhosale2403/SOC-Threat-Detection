"""
Module: Threat Intelligence (IOC Lookup)
Author: CyberSentinel SOC Project
Purpose: Matches observed IP addresses, domains, and hashes against
         Indicators of Compromise (IOC) databases to enhance risk scoring.
"""

from core.models import ThreatIntelIOC

# Seed list of known malicious IPs/ranges for simulation & detection
DEFAULT_IOCS = [
    {"ioc_type": "IP", "value": "185.220.101.5", "threat_name": "Tor Exit Node / Scanner", "threat_actor": "Tor Network", "confidence": 95},
    {"ioc_type": "IP", "value": "198.51.100.23", "threat_name": "Mirai Botnet Command Server", "threat_actor": "Botnet Operator", "confidence": 90},
    {"ioc_type": "IP", "value": "203.0.113.195", "threat_name": "Known SSH Brute-Forcer", "threat_actor": "Masscan Automated", "confidence": 85},
    {"ioc_type": "IP", "value": "45.146.164.110", "threat_name": "Cobalt Strike C2 Beacon", "threat_actor": "APT Group", "confidence": 99},
    {"ioc_type": "IP", "value": "192.168.1.150", "threat_name": "Internal Rogue Attacker (Lab Kali)", "threat_actor": "Red Team Simulation", "confidence": 90},
]


def seed_threat_intel():
    """
    Populates threat intel database with default research signatures if empty.
    """
    for item in DEFAULT_IOCS:
        ThreatIntelIOC.objects.get_or_create(
            value=item["value"],
            defaults={
                "ioc_type": item["ioc_type"],
                "threat_name": item["threat_name"],
                "threat_actor": item["threat_actor"],
                "confidence": item["confidence"],
            }
        )


def check_ioc_match(source_ip: str) -> dict:
    """
    Queries Threat Intelligence table for any hits on the given IP address.
    Returns match details or None.
    """
    match = ThreatIntelIOC.objects.filter(ioc_type='IP', value=source_ip).first()
    if match:
        return {
            "matched": True,
            "threat_name": match.threat_name,
            "threat_actor": match.threat_actor,
            "confidence": match.confidence,
        }
    return {"matched": False, "threat_name": None, "threat_actor": None, "confidence": 0}
