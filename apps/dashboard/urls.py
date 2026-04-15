from django.urls import path
from . import views
from .stream import stream

urlpatterns = [
    path('summary/',  views.dashboard_summary,  name='dashboard-summary'),
    path('kpi/',      views.kpi_list,            name='dashboard-kpi'),
    path('sensors/',  views.sensor_list,         name='dashboard-sensors'),
    path('devices/',  views.device_list,         name='dashboard-devices'),
    path('alerts/',   views.alert_list,          name='dashboard-alerts'),
    path('activity/', views.activity_waveform,   name='dashboard-activity'),
    path('stream/',   stream,                    name='dashboard-stream'),
]
