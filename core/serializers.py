from rest_framework import serializers
from core.models import LogEvent, Alert, Incident, ResponseAction, ThreatIntelIOC, DetectionRule



class LogEventSerializer(serializers.ModelSerializer):
    timestamp_formatted = serializers.SerializerMethodField()

    class Meta:
        model = LogEvent
        fields = '__all__'

    def get_timestamp_formatted(self, obj):
        return obj.timestamp.strftime('%H:%M:%S')


class AlertSerializer(serializers.ModelSerializer):
    created_at_formatted = serializers.SerializerMethodField()

    class Meta:
        model = Alert
        fields = '__all__'

    def get_created_at_formatted(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')


class ResponseActionSerializer(serializers.ModelSerializer):
    action_type_display = serializers.CharField(source='get_action_type_display', read_only=True)

    class Meta:
        model = ResponseAction
        fields = '__all__'


class IncidentSerializer(serializers.ModelSerializer):
    alerts = AlertSerializer(many=True, read_only=True)
    responses = ResponseActionSerializer(many=True, read_only=True)
    created_at_formatted = serializers.SerializerMethodField()

    class Meta:
        model = Incident
        fields = '__all__'

    def get_created_at_formatted(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')


class ThreatIntelIOCSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatIntelIOC
        fields = '__all__'


class DetectionRuleSerializer(serializers.ModelSerializer):
    created_at_formatted = serializers.SerializerMethodField()

    class Meta:
        model = DetectionRule
        fields = '__all__'

    def get_created_at_formatted(self, obj):
        return obj.created_at.strftime('%Y-%m-%d %H:%M:%S')

