from django.urls import path
from . import views

urlpatterns = [
    path('auto/',   views.analytics_auto,   name='analytics-auto'),
    path('week/',   views.analytics_week,   name='analytics-week'),
    path('month/',  views.analytics_month,  name='analytics-month'),
    path('range/',  views.analytics_range,  name='analytics-range'),
    path('ingest/', views.iot_ingest,       name='analytics-ingest'),
]
