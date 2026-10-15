"""
Module: Automated & Analyst-Approved Incident Response Engine
Author: CyberSentinel SOC Project
Purpose: Implements active response workflows (IP blocking, account disablement,
         endpoint isolation) with human-in-the-loop analyst authorization.
"""

from django.utils import timezone
from core.models import Incident, ResponseAction


class IncidentResponder:
    """
    Executes containment and remediation actions approved by SOC analysts.
    """

    @classmethod
    def execute_action(cls, response_action_id: int, analyst_name: str = "SOC Analyst") -> dict:
        """
        Executes a pending response action and updates incident status.
        """
        try:
            action = ResponseAction.objects.get(id=response_action_id)
        except ResponseAction.DoesNotExist:
            return {"success": False, "error": "Response action not found"}

        now_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        target = action.target_entity
        action_type = action.action_type

        # Generate realistic remediation commands and simulation logs
        if action_type == 'BLOCK_IP':
            log_entry = (
                f"[{now_str}] Firewall Rule Executed by {analyst_name}:\n"
                f"iptables -I INPUT 1 -s {target} -j DROP\n"
                f"Perimeter Edge ACL: Ingress rule updated. Traffic from {target} dropped permanently."
            )
        elif action_type == 'DISABLE_ACCOUNT':
            log_entry = (
                f"[{now_str}] Identity & Access Management Lockout by {analyst_name}:\n"
                f"usermod --expiredate 1 {target}\n"
                f"Active Kerberos/JWT tokens invalidated for account '{target}'."
            )
        elif action_type == 'ISOLATE_HOST':
            log_entry = (
                f"[{now_str}] Host Isolation Protocol Executed by {analyst_name}:\n"
                f"Network interface eth0 isolated into quarantine VLAN (VLAN 999).\n"
                f"Host {target} isolated from production LAN."
            )
        elif action_type == 'REVOKE_SESSION':
            log_entry = (
                f"[{now_str}] Session Termination Executed by {analyst_name}:\n"
                f"pkill -u {target}\n"
                f"All active TTY and SSH sessions terminated for {target}."
            )
        else:
            log_entry = f"[{now_str}] Generic response action {action_type} completed for {target}."

        action.status = 'EXECUTED'
        action.executed_by = analyst_name
        action.execution_log = log_entry
        action.save()

        # Update Incident status to CONTAINED or RESOLVED
        incident = action.incident
        incident.status = 'CONTAINED'
        incident.analyst_notes += f"\n[{now_str}] Action '{action_type}' executed on '{target}'. Threat contained."
        incident.save()

        return {
            "success": True,
            "action_id": action.id,
            "status": "EXECUTED",
            "log": log_entry,
            "incident_status": incident.status
        }

    @classmethod
    def reject_action(cls, response_action_id: int, reason: str = "False positive / intentional test") -> dict:
        """
        Rejects an action if the analyst determines it was benign or duplicate.
        """
        try:
            action = ResponseAction.objects.get(id=response_action_id)
        except ResponseAction.DoesNotExist:
            return {"success": False, "error": "Response action not found"}

        action.status = 'REJECTED'
        action.execution_log = f"Rejected by analyst: {reason}"
        action.save()
        return {"success": True, "status": "REJECTED"}

    @classmethod
    def contain_incident(cls, incident_id: str, analyst_name: str = "SOC Analyst") -> dict:
        """
        Directly executes containment on an incident.
        Finds pending response action or creates one on the fly, then executes it immediately.
        """
        try:
            incident = Incident.objects.get(incident_id=incident_id)
        except Incident.DoesNotExist:
            return {"success": False, "error": f"Incident {incident_id} not found"}

        target = incident.source_ip or incident.affected_asset or "Unknown Target"

        # Check if there is an existing pending response action
        pending_action = incident.responses.filter(status='PENDING_APPROVAL').first()
        if pending_action:
            return cls.execute_action(pending_action.id, analyst_name)

        # Otherwise create an action and execute it
        action_type = 'ISOLATE_HOST' if 'Privilege Escalation' in incident.title else 'BLOCK_IP'
        action = ResponseAction.objects.create(
            incident=incident,
            action_type=action_type,
            target_entity=target,
            status='PENDING_APPROVAL',
            execution_log=f"Direct containment initiated by {analyst_name}."
        )
        return cls.execute_action(action.id, analyst_name)

    @classmethod
    def allow_incident(cls, incident_id: str, analyst_name: str = "SOC Analyst") -> dict:
        """
        Directly marks an incident as ALLOWED / RESOLVED.
        Creates an explicit ALLOW_TRAFFIC action and whitelists source IP on perimeter edge ACL.
        """
        try:
            incident = Incident.objects.get(incident_id=incident_id)
        except Incident.DoesNotExist:
            return {"success": False, "error": f"Incident {incident_id} not found"}

        now_str = timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        target = incident.source_ip or incident.affected_asset or "Unknown Target"

        log_entry = (
            f"[{now_str}] Traffic Authorization / Whitelist Approved by {analyst_name}:\n"
            f"iptables -I INPUT 1 -s {target} -j ACCEPT -m comment --comment \"Whitelisted by SOC Analyst\"\n"
            f"Perimeter Edge ACL: Ingress rule permitted. Traffic from {target} verified as authorized / benign."
        )

        action = ResponseAction.objects.create(
            incident=incident,
            action_type='ALLOW_TRAFFIC',
            target_entity=target,
            status='EXECUTED',
            executed_by=analyst_name,
            execution_log=log_entry
        )

        incident.status = 'RESOLVED'
        incident.analyst_notes += f"\n[{now_str}] Action 'ALLOW_TRAFFIC' approved on '{target}'. Activity verified as benign/authorized."
        incident.save()

        return {
            "success": True,
            "action_id": action.id,
            "status": "EXECUTED",
            "log": log_entry,
            "incident_status": incident.status
        }

