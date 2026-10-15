from django.db import models
from django.utils import timezone


class LogEvent(models.Model):
    """
    Stores normalized security log events ingested from computers, servers,
    web applications, firewalls, and network devices.
    """
    SEVERITY_CHOICES = [
        ('INFO', 'Informational'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    timestamp = models.DateTimeField(default=timezone.now)
    source = models.CharField(max_length=64, help_text="Source type, e.g., auth, ssh, web, firewall")
    source_ip = models.CharField(max_length=45, default="127.0.0.1")
    destination_ip = models.CharField(max_length=45, blank=True, null=True)
    destination_port = models.IntegerField(blank=True, null=True)
    user = models.CharField(max_length=64, default="system")
    event_type = models.CharField(max_length=64, help_text="e.g. login_failed, port_scan, admin_escalation")
    target = models.CharField(max_length=128, default="Localhost")
    raw_log = models.TextField(help_text="Original raw log line prior to normalization")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='INFO')
    is_processed = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.timestamp.strftime('%H:%M:%S')}] {self.source} | {self.event_type} | {self.source_ip}"


class Alert(models.Model):
    """
    Security alerts raised when detection rules trigger or ML flags anomalies.
    """
    DETECTION_METHODS = [
        ('RULE_BASED', 'Rule Engine'),
        ('ML_ANOMALY', 'Machine Learning Anomaly'),
        ('HYBRID', 'Hybrid (Rule + ML)'),
        ('THREAT_INTEL', 'Threat Intelligence Match'),
    ]

    SEVERITY_CHOICES = [
        ('LOW', 'Low (0-25)'),
        ('MEDIUM', 'Medium (26-50)'),
        ('HIGH', 'High (51-75)'),
        ('CRITICAL', 'Critical (76-100)'),
    ]

    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('ACKNOWLEDGED', 'Acknowledged'),
        ('ESCALATED', 'Escalated to Incident'),
        ('DISMISSED', 'Dismissed / False Positive'),
    ]

    alert_id = models.CharField(max_length=32, unique=True)
    title = models.CharField(max_length=128)
    category = models.CharField(max_length=64)
    source_ip = models.CharField(max_length=45)
    target_user = models.CharField(max_length=64, blank=True, null=True)
    target_asset = models.CharField(max_length=128, default="Server-01")
    detection_method = models.CharField(max_length=32, choices=DETECTION_METHODS, default='RULE_BASED')
    rule_name = models.CharField(max_length=128, blank=True, null=True)
    ml_anomaly_score = models.FloatField(default=0.0, help_text="Isolation forest anomaly confidence (0.0 to 1.0)")
    risk_score = models.IntegerField(default=50, help_text="Composite risk rating between 0 and 100")
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='MEDIUM')
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default='OPEN')
    description = models.TextField()
    evidence_events = models.ManyToManyField(LogEvent, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.alert_id} - {self.title} ({self.severity} | Score: {self.risk_score})"


class Incident(models.Model):
    """
    Correlated security incidents requiring investigation and incident response.
    """
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Under Investigation'),
        ('CONTAINED', 'Threat Contained'),
        ('RESOLVED', 'Resolved & Closed'),
    ]

    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    incident_id = models.CharField(max_length=32, unique=True)
    title = models.CharField(max_length=160)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='HIGH')
    risk_score = models.IntegerField(default=75)
    source_ip = models.CharField(max_length=45)
    affected_user = models.CharField(max_length=64, blank=True, null=True)
    affected_asset = models.CharField(max_length=128, default="Core Infrastructure")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='OPEN')
    assigned_to = models.CharField(max_length=64, default="Unassigned", blank=True)
    mitre_tactic = models.CharField(max_length=128, default="Credential Access")
    summary = models.TextField()
    recommended_action = models.TextField(help_text="Automated recommendation from Response Engine")
    analyst_notes = models.TextField(blank=True, default="")
    alerts = models.ManyToManyField(Alert, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.incident_id} - {self.title} [{self.status}]"


class ResponseAction(models.Model):
    """
    Track response actions recommended by the system and approved by the analyst.
    """
    ACTION_TYPES = [
        ('BLOCK_IP', 'Block Source IP on Firewall'),
        ('ALLOW_TRAFFIC', 'Allow / Whitelist Traffic on Firewall'),
        ('DISABLE_ACCOUNT', 'Disable Compromised User Account'),
        ('ISOLATE_HOST', 'Isolate Endpoint / Host Machine'),
        ('REVOKE_SESSION', 'Terminate Active Sessions'),
    ]

    STATUS_CHOICES = [
        ('PENDING_APPROVAL', 'Pending Human Approval'),
        ('EXECUTED', 'Action Executed'),
        ('REJECTED', 'Rejected by Analyst'),
    ]

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='responses')
    action_type = models.CharField(max_length=32, choices=ACTION_TYPES)
    target_entity = models.CharField(max_length=128, help_text="e.g. IP address or username")
    status = models.CharField(max_length=24, choices=STATUS_CHOICES, default='PENDING_APPROVAL')
    executed_by = models.CharField(max_length=64, default="SOC Analyst")
    execution_log = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.get_action_type_display()} on {self.target_entity} ({self.status})"


class ThreatIntelIOC(models.Model):
    """
    Known Indicators of Compromise (IOC) database.
    """
    IOC_TYPES = [
        ('IP', 'IP Address'),
        ('DOMAIN', 'Domain Name'),
        ('HASH', 'File Hash SHA256'),
    ]

    ioc_type = models.CharField(max_length=16, choices=IOC_TYPES)
    value = models.CharField(max_length=128, unique=True)
    threat_name = models.CharField(max_length=128)
    threat_actor = models.CharField(max_length=64, default="Unknown / Cybercrime")
    confidence = models.IntegerField(default=90)
    added_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ioc_type}: {self.value} ({self.threat_name})"


class DetectionRule(models.Model):
    """
    User-configurable threat detection rules allowing SOC analysts
    to create, enable, disable, and tune custom security signatures dynamically.
    """
    CATEGORY_CHOICES = [
        ('BRUTE_FORCE', 'Authentication Brute Force'),
        ('PORT_SCAN', 'Network Port Scanning / Reconnaissance'),
        ('SUSPICIOUS_LOGIN', 'Suspicious / Off-Hours Login'),
        ('PRIVILEGE_ESCALATION', 'Privilege Escalation / Root Access'),
        ('WEB_ATTACK', 'Web Application Attack / Directory Traversal'),
        ('DATA_EXFILTRATION', 'Data Exfiltration / Excessive Transfer'),
        ('MALWARE_BEACON', 'Malware Command & Control Beaconing'),
        ('CUSTOM', 'Custom Analyst Signature'),
    ]

    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    rule_id = models.CharField(max_length=32, unique=True)
    name = models.CharField(max_length=128)
    category = models.CharField(max_length=32, choices=CATEGORY_CHOICES, default='CUSTOM')
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default='HIGH')
    event_type_match = models.CharField(max_length=64, blank=True, null=True, help_text="Matches specific event_type, e.g. login_failed, sudo_command")
    keyword_pattern = models.CharField(max_length=128, blank=True, null=True, help_text="Substring or regex in raw_log, e.g. /etc/shadow, union select, powershell")
    threshold_count = models.IntegerField(default=1, help_text="Number of occurrences required to trigger within time window")
    time_window_minutes = models.IntegerField(default=5, help_text="Time window in minutes")
    risk_weight = models.IntegerField(default=30, help_text="Risk points contributed (10 to 35)")
    description = models.TextField()
    is_enabled = models.BooleanField(default=True)
    is_builtin = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.rule_id} - {self.name} [{self.severity}]"

