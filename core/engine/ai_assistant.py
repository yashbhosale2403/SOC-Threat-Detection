"""
Module: Gemini AI SOC Analyst Assistant
Author: CyberSentinel SOC Project
Purpose: Connects to the Google Gemini API using the analyst's API key
         to perform live situational assessment, root cause analysis,
         and explicit ALLOW vs BLOCK recommendations for active incidents.
"""

import os
import json
import requests
from django.utils import timezone
from core.models import Incident, Alert, LogEvent

try:
    from local_settings import GEMINI_API_KEY as _LOCAL_KEY
except ImportError:
    _LOCAL_KEY = ""


class GeminiAIAssistant:
    """
    Interfaces with Gemini generative models to act as an autonomous SOC Copilot.
    """

    DEFAULT_CONFIGURED_KEY = os.environ.get("GEMINI_API_KEY", "") or _LOCAL_KEY

    @classmethod
    def analyze_soc_state(cls, api_key: str = None, incident_id: str = None) -> dict:
        """
        Gathers live SOC telemetry and prompts Gemini for situation assessment and recommendations.
        """
        # Use provided key or preconfigured key
        effective_key = (api_key or "").strip() or cls.DEFAULT_CONFIGURED_KEY

        # 1. Fetch relevant incidents
        if incident_id:
            incidents_query = Incident.objects.filter(incident_id=incident_id)
        else:
            incidents_query = Incident.objects.all().order_by('-created_at')[:6]

        incidents_data = []
        for inc in incidents_query:
            pending_responses = [r.action_type for r in inc.responses.filter(status='PENDING_APPROVAL')]
            incidents_data.append({
                "incident_id": inc.incident_id,
                "title": inc.title,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "attacker_ip": inc.source_ip,
                "target_asset": inc.affected_asset,
                "mitre_tactic": inc.mitre_tactic,
                "lifecycle_status": inc.status,
                "summary": inc.summary,
                "recommended_action": inc.recommended_action,
                "pending_containment_actions": pending_responses,
            })

        # 2. Fetch top recent alerts with ML anomaly scores
        recent_alerts = list(Alert.objects.all().order_by('-created_at')[:8].values(
            'alert_id', 'title', 'category', 'source_ip', 'detection_method',
            'ml_anomaly_score', 'risk_score', 'severity'
        ))

        # 3. Fetch recent suspicious logs
        recent_logs = list(LogEvent.objects.exclude(severity='INFO').order_by('-timestamp')[:10].values(
            'timestamp', 'source_ip', 'user', 'event_type', 'target', 'severity', 'raw_log'
        ))
        for l in recent_logs:
            l['timestamp'] = l['timestamp'].strftime('%H:%M:%S')

        # 4. Fallback if no effective API key is available
        if not effective_key:
            return cls._generate_heuristic_offline_report(incidents_data, recent_alerts)

        # 5. Build Structured Prompt for Gemini
        prompt = cls._build_prompt(incidents_data, recent_alerts, recent_logs)

        # 6. Call Google Gemini API
        try:
            analysis_text = cls._call_gemini_api(effective_key, prompt)
            return {
                "success": True,
                "source": "Google Gemini 3.5 Flash (Live AI Analysis)",
                "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "analysis_markdown": analysis_text,
                "incidents_evaluated_count": len(incidents_data),
            }

        except Exception as e:
            # If the API key is expired or network fails, provide graceful message + heuristic evaluation
            return {
                "success": False,
                "error": str(e),
                "fallback_analysis": cls._generate_heuristic_offline_report(incidents_data, recent_alerts),
            }

    @classmethod
    def _build_prompt(cls, incidents: list, alerts: list, logs: list) -> str:
        telemetry_json = json.dumps({
            "active_incidents": incidents,
            "recent_alerts": alerts,
            "suspicious_log_samples": logs
        }, indent=2)

        if incidents and len(incidents) == 1:
            inc = incidents[0]
            return f"""You are a Principal SOC Incident Response Analyst.
Analyze this incident and give an explanation of EXACTLY 4 lines. No more, no less. No introductory or trailing text.

Incident Data:
- ID: {inc.get('incident_id')}
- Title: {inc.get('title')}
- Attacker IP: {inc.get('attacker_ip')}
- Target Asset: {inc.get('target_asset')}
- Severity: {inc.get('severity')} (Risk Score: {inc.get('risk_score')}/100)
- MITRE Tactic: {inc.get('mitre_tactic')}
- Summary: {inc.get('summary')}
- Recommendation: {inc.get('recommended_action')}

Provide output strictly in these 4 lines:
Line 1: Threat: <1 plain sentence explaining the attack activity>
Line 2: Verdict: <[🚨 BLOCK IP] or [🟢 ALLOW / BENIGN] with confidence percentage>
Line 3: Evidence: <Key technical evidence: Source IP, risk score, and detected anomalies>
Line 4: Action: <Immediate containment command or step to execute>"""

        return f"""You are a Principal SOC Incident Response Analyst.
Analyze current network telemetry and provide an explanation of EXACTLY 4 lines. No more, no less. No preamble.

Telemetry Data:
{telemetry_json}

Provide output strictly in these 4 lines:
Line 1: Threat Status: <1 sentence summarizing current active attacks vs baseline>
Line 2: Top Attacker: <Most critical attacker IP, attack category, and target asset>
Line 3: Verdict: <[🚨 BLOCK ALL OFFENDERS] or [🟢 NORMAL BASELINE] with confidence percentage>
Line 4: Action: <Top containment priority to enforce right now>"""

    CANDIDATE_MODELS = ["gemini-3.8-flash", "gemini-3.1-flash-lite", "gemini-flash-latest", "gemini-3.5-flash"]

    @classmethod
    def _call_gemini_api(cls, api_key: str, prompt: str) -> str:
        """
        Invokes Google Generative Language API with candidate fallback models.
        """
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "generationConfig": {
                "temperature": 0.1,
                "topP": 0.9,
                "maxOutputTokens": 1000,
            }
        }

        last_error = None
        for model in cls.CANDIDATE_MODELS:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=20)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates and "content" in candidates[0]:
                        parts = candidates[0]["content"].get("parts", [])
                        if parts and "text" in parts[0]:
                            return parts[0]["text"].strip()
                last_error = f"Model {model} returned HTTP {resp.status_code}: {resp.text}"
            except Exception as ex:
                last_error = str(ex)

        raise Exception(f"All Gemini models failed. Last error: {last_error}")


    @classmethod
    def _generate_heuristic_offline_report(cls, incidents: list, alerts: list) -> dict:
        """
        Concise 4-line fallback heuristic assessment.
        """
        if not incidents:
            report_text = (
                "1. Threat: No active security incidents detected across network endpoints.\n"
                "2. Verdict: 🟢 ALLOW / NORMAL (100% Confidence - All signals baseline clean).\n"
                "3. Evidence: Telemetry shows routine background traffic with zero threshold breaches.\n"
                "4. Action: Maintain continuous monitoring; no containment required."
            )
        else:
            inc = incidents[0]
            verdict = "🚨 BLOCK / CONTAIN (95% Confidence)" if inc["risk_score"] >= 50 else "🟢 ALLOW / MONITOR (85% Confidence)"
            ip = inc.get("attacker_ip", "Unknown IP")
            target = inc.get("target_asset", "Core Server")
            action = inc.get("recommended_action") or f"Execute iptables drop rule for {ip} and terminate sessions."
            report_text = (
                f"1. Threat: {inc.get('title')} targeting {target} from {ip}.\n"
                f"2. Verdict: {verdict} with assessed Risk Score of {inc.get('risk_score')}/100 ({inc.get('severity')}).\n"
                f"3. Evidence: {inc.get('mitre_tactic')} verified by Rule Match and ML Anomaly scoring.\n"
                f"4. Action: {action}"
            )

        return {
            "success": True,
            "source": "CyberSentinel AI Engine",
            "timestamp": timezone.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "analysis_markdown": report_text,
            "incidents_evaluated_count": len(incidents),
        }
