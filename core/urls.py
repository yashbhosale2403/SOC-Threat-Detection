from django.urls import path
from core import views

urlpatterns = [
    # SOC Analyst Web Dashboard
    path('', views.dashboard_page, name='dashboard'),

    # REST APIs for Real-Time SOC Interface
    path('api/stats/', views.StatsAPIView.as_view(), name='api-stats'),
    path('api/logs/', views.LogEventsAPIView.as_view(), name='api-logs'),
    path('api/logs/ingest/', views.IngestLogAPIView.as_view(), name='api-log-ingest'),
    path('api/alerts/', views.AlertsAPIView.as_view(), name='api-alerts'),
    path('api/incidents/', views.IncidentsAPIView.as_view(), name='api-incidents'),
    path('api/incidents/<str:incident_id>/', views.IncidentDetailAPIView.as_view(), name='api-incident-detail'),
    path('api/incidents/<str:incident_id>/contain/', views.IncidentContainDirectAPIView.as_view(), name='api-incident-contain-direct'),
    path('api/incidents/<str:incident_id>/allow/', views.IncidentAllowDirectAPIView.as_view(), name='api-incident-allow-direct'),
    path('api/incidents/respond/<int:response_id>/', views.IncidentRespondAPIView.as_view(), name='api-incident-respond'),
    path('api/reset/', views.ResetSOCAPIView.as_view(), name='api-reset'),
    path('api/threat-intel/', views.ThreatIntelAPIView.as_view(), name='api-threat-intel'),
    path('api/simulate/', views.SimulateAPIView.as_view(), name='api-simulate'),
    path('api/analytics/', views.AnalyticsAPIView.as_view(), name='api-analytics'),
    path('api/ai-assist/', views.AIAssistAPIView.as_view(), name='api-ai-assist'),
    path('api/rules/', views.RulesAPIView.as_view(), name='api-rules'),
    path('api/rules/<str:rule_id>/', views.RuleDetailAPIView.as_view(), name='api-rule-detail'),
]


