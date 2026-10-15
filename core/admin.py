from django.contrib import admin
from core.models import LogEvent, Alert, Incident, ResponseAction, ThreatIntelIOC, DetectionRule



@admin.register(LogEvent)
class LogEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source', 'source_ip', 'user', 'event_type', 'target', 'severity', 'is_processed')
    list_filter = ('source', 'severity', 'is_processed', 'event_type')
    search_fields = ('source_ip', 'user', 'raw_log', 'target')


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('alert_id', 'title', 'category', 'severity', 'risk_score', 'detection_method', 'status', 'created_at')
    list_filter = ('severity', 'detection_method', 'status', 'category')
    search_fields = ('alert_id', 'title', 'source_ip', 'description')


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('incident_id', 'title', 'severity', 'risk_score', 'source_ip', 'status', 'created_at')
    list_filter = ('severity', 'status')
    search_fields = ('incident_id', 'title', 'source_ip', 'summary')


@admin.register(ResponseAction)
class ResponseActionAdmin(admin.ModelAdmin):
    list_display = ('incident', 'action_type', 'target_entity', 'status', 'executed_by', 'created_at')
    list_filter = ('action_type', 'status')


@admin.register(ThreatIntelIOC)
class ThreatIntelIOCAdmin(admin.ModelAdmin):
    list_display = ('value', 'ioc_type', 'threat_name', 'threat_actor', 'confidence', 'added_at')
    list_filter = ('ioc_type',)
    search_fields = ('value', 'threat_name', 'threat_actor')


@admin.register(DetectionRule)
class DetectionRuleAdmin(admin.ModelAdmin):
    list_display = ('rule_id', 'name', 'category', 'severity', 'is_enabled', 'is_builtin', 'threshold_count', 'risk_weight', 'created_at')
    list_filter = ('category', 'severity', 'is_enabled', 'is_builtin')
    search_fields = ('rule_id', 'name', 'keyword_pattern', 'description')

