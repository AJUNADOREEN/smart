import json
import time
from datetime import date, timedelta
from django.http import StreamingHttpResponse
from django.db.models import Avg, Sum, Max
from django.utils import timezone

from apps.devices.models import Device, DeviceSensorReading
from apps.alerts.models import Alert
from apps.analytics.models import SensorReading


def _collect():
    """Collect all live data into one dict."""
    today     = date.today()
    yesterday = today - timedelta(days=1)

    # ── KPI ──────────────────────────────────────────────────────────────────
    def agg(d):
        return SensorReading.objects.filter(date=d).aggregate(
            soap=Sum('soap_usage'), water=Sum('water_usage'),
            washed=Sum('handwashes'), unwashed=Sum('unwashed'),
        )

    t = agg(today)
    y = agg(yesterday)

    def pct(now, prev):
        if not prev:
            return '+0%'
        diff = ((now or 0) - (prev or 0)) / (prev or 1) * 100
        return f"{'+' if diff >= 0 else ''}{diff:.0f}%"

    latest_ids = (
        DeviceSensorReading.objects
        .values('device')
        .annotate(latest=Max('id'))
        .values_list('latest', flat=True)
    )
    lqs      = DeviceSensorReading.objects.filter(id__in=latest_ids)
    avg_soap  = lqs.aggregate(v=Avg('soap_level'))['v']  or 0
    avg_water = lqs.aggregate(v=Avg('water_level'))['v'] or 0
    avg_temp  = lqs.aggregate(v=Avg('temperature'))['v'] or 0

    handwashes = t['washed']   or 0
    unwashed   = t['unwashed'] or 0
    water_used = t['water']    or 0

    kpi = [
        {'label': 'Handwashes Today', 'value': str(handwashes),     'change': pct(handwashes, y['washed']),  'up': handwashes >= (y['washed'] or 0),  'color': '#10b981'},
        {'label': 'Soap Remaining',   'value': f"{avg_soap:.0f}%",  'change': '-',                           'up': avg_soap > 30,                     'color': '#6366f1'},
        {'label': 'Water Used (L)',   'value': f"{water_used:.0f}", 'change': pct(water_used, y['water']),   'up': True,                              'color': '#0ea5e9'},
        {'label': 'Left Unwashed',    'value': str(unwashed),        'change': pct(unwashed, y['unwashed']),  'up': unwashed <= (y['unwashed'] or 0),  'color': '#ef4444'},
    ]

    # ── Sensors ───────────────────────────────────────────────────────────────
    max_washes = 500
    sensors = [
        {'label': 'Water Level',    'value': f"{avg_water:.0f}%",      'pct': int(avg_water),                                'color': '#0ea5e9'},
        {'label': 'Soap Level',     'value': f"{avg_soap:.0f}%",       'pct': int(avg_soap),                                 'color': '#6366f1'},
        {'label': 'Temperature',    'value': f"{avg_temp:.1f}\u00b0C", 'pct': int(avg_temp / 50 * 100),                      'color': '#f59e0b'},
        {'label': 'Handwash Count', 'value': str(handwashes),          'pct': min(int(handwashes / max_washes * 100), 100),  'color': '#10b981'},
    ]

    # ── Devices ───────────────────────────────────────────────────────────────
    devices = [
        {'id': d.id, 'name': d.name, 'status': d.status,
         'battery': d.battery, 'color': d.color, 'location': d.location, 'icon': d.icon}
        for d in Device.objects.all()[:6]
    ]

    # ── Alerts ────────────────────────────────────────────────────────────────
    alerts = [
        {'id': a.id, 'title': a.title, 'device': a.device,
         'time': a.time.strftime('%I:%M %p'), 'severity': a.severity}
        for a in Alert.objects.filter(dismissed=False).order_by('-time')[:4]
    ]

    # ── Summary ───────────────────────────────────────────────────────────────
    total  = Device.objects.count()
    online = Device.objects.filter(status='Online').count()
    summary = {
        'readable_date': timezone.localtime().strftime('%A, %B %d, %Y'),
        'station':       'Main Entrance Station',
        'status':        'System Operational' if online == total else f'{online}/{total} Devices Online',
        'active_alerts': Alert.objects.filter(severity='High', dismissed=False).count(),
    }

    # ── Activity ──────────────────────────────────────────────────────────────
    now_local    = timezone.localtime()
    buckets      = [0] * 24
    for ts in DeviceSensorReading.objects.filter(timestamp__date=today).values_list('timestamp', flat=True):
        buckets[timezone.localtime(ts).hour] += 1
    ch    = now_local.hour
    activity = {
        'hours':  [f"{h % 12 or 12}{'am' if h < 12 else 'pm'}" for h in range(ch + 1)],
        'values': buckets[:ch + 1],
    }

    return {'kpi': kpi, 'sensors': sensors, 'devices': devices,
            'alerts': alerts, 'summary': summary, 'activity': activity}


def _event(data):
    return f"data: {json.dumps(data)}\n\n"


def stream(request):
    def generator():
        # Send immediately on connect
        try:
            yield _event(_collect())
        except Exception as e:
            yield _event({'error': str(e)})

        # Then every 5 seconds
        while True:
            time.sleep(5)
            try:
                yield _event(_collect())
            except Exception as e:
                yield _event({'error': str(e)})

    response = StreamingHttpResponse(generator(), content_type='text/event-stream')
    response['Cache-Control']     = 'no-cache'
    response['X-Accel-Buffering'] = 'no'   # disable Nginx/Railway buffering
    return response
