"""
Module: SOC Core Views and REST API Controllers
Author: CyberSentinel SOC Project
Purpose: Handles dashboard page serving, real-time analytics aggregation,
         log ingestion APIs, attack simulation triggers, and analyst actions.
"""

from django.shortcuts import render, get_object_or_404
from django.db.models import Count, Avg
from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from core.models import LogEvent, Alert, Incident, ResponseAction, ThreatIntelIOC, DetectionRule
from core.serializers import (
    LogEventSerializer,
    AlertSerializer,
    IncidentSerializer,
    ResponseActionSerializer,
    ThreatIntelIOCSerializer,
    DetectionRuleSerializer,
)
from core.engine.pipeline import SOCPipeline
from core.engine.simulator import AttackSimulator
from core.engine.responder import IncidentResponder
from core.engine.threat_intel import seed_threat_intel
from core.engine.rules import seed_default_rules
from core.engine.ai_assistant import GeminiAIAssistant


def dashboard_page(request):
    """
    Renders the unified SOC Analyst Command Dashboard.
    """
    # Seed default threat intelligence IOCs and built-in rules on initial load
    seed_threat_intel()
    seed_default_rules()
    return render(request, 'dashboard.html')



class StatsAPIView(APIView):
    """
    Returns summary statistics for the SOC top KPI cards.
    """
    def get(self, request):
        now = timezone.now()
        twenty_four_hours = now - timedelta(hours=24)

        total_logs = LogEvent.objects.count()
        active_alerts = Alert.objects.filter(status='OPEN').count()
        total_incidents = Incident.objects.count()
        critical_incidents = Incident.objects.filter(severity='CRITICAL', status__in=['OPEN', 'INVESTIGATING']).count()
        contained_count = Incident.objects.filter(status__in=['CONTAINED', 'RESOLVED']).count()
        containment_rate = round((contained_count / total_incidents * 100), 1) if total_incidents > 0 else 100.0

        avg_risk = Incident.objects.aggregate(avg_risk=Avg('risk_score'))['avg_risk'] or 0
        avg_anomaly = Alert.objects.aggregate(avg_ano=Avg('ml_anomaly_score'))['avg_ano'] or 0.0

        return Response({
            "total_logs": total_logs,
            "active_alerts": active_alerts,
            "open_incidents": total_incidents,
            "critical_threats": critical_incidents,
            "containment_rate": containment_rate,
            "avg_risk_score": round(avg_risk, 1),
            "avg_ml_anomaly": round(avg_anomaly, 2),
            "soc_status": "MONITORING_ACTIVE",
            "threat_level": "ELEVATED" if critical_incidents > 0 else ("GUARDED" if active_alerts > 0 else "NORMAL"),
        })


class LogEventsAPIView(APIView):
    """
    Retrieves recent normalized logs or supports filtering.
    """
    def get(self, request):
        limit = int(request.GET.get('limit', 50))
        logs = LogEvent.objects.all().order_by('-timestamp')[:limit]
        serializer = LogEventSerializer(logs, many=True)
        return Response(serializer.data)


class IngestLogAPIView(APIView):
    """
    Accepts raw or structured log data via HTTP POST and pushes through the pipeline.
    """
    def post(self, request):
        raw_log = request.data.get('raw_log')
        source_type = request.data.get('source', 'auto')

        if not raw_log:
            return Response({"error": "Field 'raw_log' is required"}, status=status.HTTP_400_BAD_REQUEST)

        result = SOCPipeline.process_raw_log(raw_log, source_type)
        return Response({
            "message": "Log processed through SOC pipeline successfully",
            "result": result
        }, status=status.HTTP_201_CREATED)


class AlertsAPIView(APIView):
    """
    Returns alerts list with optional severity filter.
    """
    def get(self, request):
        limit = int(request.GET.get('limit', 30))
        alerts = Alert.objects.all().order_by('-created_at')[:limit]
        serializer = AlertSerializer(alerts, many=True)
        return Response(serializer.data)


class IncidentsAPIView(APIView):
    """
    Returns incidents list for SOC incident management.
    """
    def get(self, request):
        incidents = Incident.objects.all().order_by('-created_at')
        serializer = IncidentSerializer(incidents, many=True)
        return Response(serializer.data)


class IncidentDetailAPIView(APIView):
    """
    View or update a specific incident status / notes.
    """
    def get(self, request, incident_id):
        inc = get_object_or_404(Incident, incident_id=incident_id)
        serializer = IncidentSerializer(inc)
        return Response(serializer.data)

    def patch(self, request, incident_id):
        inc = get_object_or_404(Incident, incident_id=incident_id)
        new_status = request.data.get('status')
        analyst_notes = request.data.get('analyst_notes')
        assigned_to = request.data.get('assigned_to')

        if new_status in dict(Incident.STATUS_CHOICES):
            inc.status = new_status
        if analyst_notes:
            inc.analyst_notes = analyst_notes
        if assigned_to is not None:
            inc.assigned_to = assigned_to
        inc.save()
        return Response(IncidentSerializer(inc).data)


class IncidentRespondAPIView(APIView):
    """
    Executes or rejects an incident containment action.
    """
    def post(self, request, response_id):
        action_intent = request.data.get('intent', 'approve')
        analyst_name = request.data.get('analyst_name', 'Security Analyst')

        if action_intent == 'approve':
            result = IncidentResponder.execute_action(response_id, analyst_name)
        else:
            reason = request.data.get('reason', 'Analyst marked as benign')
            result = IncidentResponder.reject_action(response_id, reason)

        return Response(result)


class ThreatIntelAPIView(APIView):
    """
    Lists threat indicators or looks up an IP.
    """
    def get(self, request):
        ip_query = request.GET.get('ip')
        if ip_query:
            iocs = ThreatIntelIOC.objects.filter(value=ip_query)
        else:
            iocs = ThreatIntelIOC.objects.all()
        serializer = ThreatIntelIOCSerializer(iocs, many=True)
        return Response(serializer.data)


class SimulateAPIView(APIView):
    """
    Executes live attack simulations for demonstrations and viva presentations.
    """
    def post(self, request):
        scenario = request.data.get('scenario', 'brute_force')
        attacker_ip = request.data.get('attacker_ip')

        if scenario == 'brute_force':
            ip = attacker_ip or "192.168.1.150"
            res = AttackSimulator.simulate_brute_force(ip, count=5)
            msg = f"Simulated SSH Brute-Force from {ip} (5 attempts)"
        elif scenario == 'port_scan':
            ip = attacker_ip or "192.168.1.180"
            res = AttackSimulator.simulate_port_scan(ip)
            msg = f"Simulated Nmap SYN Port Sweep across 12 ports from {ip}"
        elif scenario == 'priv_escalation':
            ip = attacker_ip or "192.168.1.105"
            res = AttackSimulator.simulate_privilege_escalation(ip)
            msg = f"Simulated Unauthorized Root Sudo Privilege Escalation from {ip}"
        elif scenario == 'full_chain':
            ip = attacker_ip or "185.220.101.5"
            res = AttackSimulator.simulate_full_intrusion_chain(ip)
            msg = f"Simulated Full Multi-Stage APT Attack Chain from {ip}"
        elif scenario == 'normal_traffic':
            res = AttackSimulator.simulate_normal_traffic(count=6)
            msg = "Generated 6 benign background web traffic requests"
        else:
            return Response({"error": "Unknown scenario"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({
            "message": msg,
            "scenario": scenario,
            "details": res
        })


class AnalyticsAPIView(APIView):
    """
    Provides aggregated time-series and categorical distribution data for Chart.js.
    """
    def get(self, request):
        # 1. Attack type breakdown from alerts
        category_counts = Alert.objects.values('category').annotate(count=Count('id')).order_by('-count')
        categories = [item['category'].replace('_', ' ').title() for item in category_counts]
        cat_values = [item['count'] for item in category_counts]

        # 2. Top malicious source IPs
        top_ips = Alert.objects.values('source_ip').annotate(count=Count('id')).order_by('-count')[:5]
        ips = [item['source_ip'] for item in top_ips]
        ip_values = [item['count'] for item in top_ips]

        # 3. Detection method split (Rule vs ML vs Hybrid)
        detection_methods = Alert.objects.values('detection_method').annotate(count=Count('id'))
        dm_labels = [item['detection_method'].replace('_', ' ').title() for item in detection_methods]
        dm_values = [item['count'] for item in detection_methods]

        # 4. Severity breakdown
        severity_counts = Alert.objects.values('severity').annotate(count=Count('id'))
        sev_dict = {item['severity']: item['count'] for item in severity_counts}

        return Response({
            "categories": {"labels": categories, "data": cat_values},
            "top_ips": {"labels": ips, "data": ip_values},
            "detection_methods": {"labels": dm_labels, "data": dm_values},
            "severities": {
                "critical": sev_dict.get('CRITICAL', 0),
                "high": sev_dict.get('HIGH', 0),
                "medium": sev_dict.get('MEDIUM', 0),
                "low": sev_dict.get('LOW', 0),
            }
        })


class AIAssistAPIView(APIView):
    """
    Executes live Gemini Generative AI threat analysis and incident recommendations.
    """
    def post(self, request):
        api_key = request.data.get('api_key', '')
        incident_id = request.data.get('incident_id')

        result = GeminiAIAssistant.analyze_soc_state(api_key=api_key, incident_id=incident_id)
        return Response(result)


class RulesAPIView(APIView):
    """
    Lists all detection rules (built-in and custom) or allows adding new custom rules.
    """
    def get(self, request):
        seed_default_rules()
        rules = DetectionRule.objects.all().order_by('-is_builtin', 'rule_id')
        serializer = DetectionRuleSerializer(rules, many=True)
        return Response(serializer.data)

    def post(self, request):
        data = request.data
        name = data.get('name', '').strip()
        if not name:
            return Response({"error": "Rule name is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Generate a unique rule ID
        custom_count = DetectionRule.objects.filter(is_builtin=False).count() + 1
        rule_id = f"RULE-C{custom_count:02d}"

        rule = DetectionRule.objects.create(
            rule_id=rule_id,
            name=name,
            category=data.get('category', 'CUSTOM'),
            severity=data.get('severity', 'HIGH'),
            event_type_match=data.get('event_type_match') or None,
            keyword_pattern=data.get('keyword_pattern') or None,
            threshold_count=int(data.get('threshold_count', 1)),
            time_window_minutes=int(data.get('time_window_minutes', 5)),
            risk_weight=int(data.get('risk_weight', 30)),
            description=data.get('description', f'Custom user rule {name}'),
            is_enabled=True,
            is_builtin=False
        )

        return Response({
            "message": f"Rule {rule.rule_id} created successfully",
            "rule": DetectionRuleSerializer(rule).data
        }, status=status.HTTP_201_CREATED)


class RuleDetailAPIView(APIView):
    """
    Toggles or deletes a detection rule.
    """
    def patch(self, request, rule_id):
        rule = get_object_or_404(DetectionRule, rule_id=rule_id)
        is_enabled = request.data.get('is_enabled')
        if is_enabled is not None:
            rule.is_enabled = bool(is_enabled)
            rule.save()
        return Response(DetectionRuleSerializer(rule).data)

    def delete(self, request, rule_id):
        rule = get_object_or_404(DetectionRule, rule_id=rule_id)
        if rule.is_builtin:
            return Response({"error": "Built-in baseline rules cannot be deleted. You can disable them instead."}, status=status.HTTP_400_BAD_REQUEST)
        rule.delete()
        return Response({"message": f"Rule {rule_id} deleted successfully"})


class IncidentContainDirectAPIView(APIView):
    """
    Directly enforces containment / blocking on an incident.
    """
    def post(self, request, incident_id):
        analyst_name = request.data.get('analyst_name', 'Yash (SOC Analyst)')
        result = IncidentResponder.contain_incident(incident_id, analyst_name)
        return Response(result)


class IncidentAllowDirectAPIView(APIView):
    """
    Directly enforces traffic authorization / whitelist on an incident.
    """
    def post(self, request, incident_id):
        analyst_name = request.data.get('analyst_name', 'Yash (SOC Analyst)')
        result = IncidentResponder.allow_incident(incident_id, analyst_name)
        return Response(result)



class ResetSOCAPIView(APIView):
    """
    Resets the entire SOC platform state to a clean baseline:
    - Clears all response actions, incidents, alerts, and log events (0 traffic)
    - Re-seeds threat intel IOCs and baseline detection rules
    """
    def post(self, request):
        ResponseAction.objects.all().delete()
        Incident.objects.all().delete()
        Alert.objects.all().delete()
        LogEvent.objects.all().delete()

        seed_threat_intel()
        seed_default_rules()

        return Response({
            "success": True,
            "message": "SOC environment reset! All traffic, logs, alerts, and incidents cleared to 0."
        })


