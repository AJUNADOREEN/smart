from django.db import models
import random


def random_device_color():
    colors = ['#6366f1', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#84cc16', '#f97316', '#ec4899', '#14b8a6']
    return random.choice(colors)


ICON_CHOICES = [
    ('faPumpSoap',        'Soap Dispenser'),
    ('faDroplet',         'Water Valve'),
    ('faTemperatureHalf', 'Temperature Sensor'),
    ('faHandsWash',       'Handwash Counter'),
    ('faVolumeHigh',      'Speaker System'),
    ('faLightbulb',       'Visual Indicator'),
    ('faBolt',            'Power Device'),
    ('faServer',          'Server'),
    ('faEye',             'IR Proximity Sensor'),
    ('faWater',           'Ultrasonic Sensor'),
    ('faToggleOn',        'Relay Module'),
    ('faDisplay',         'Display Module'),
    ('faMusic',           'MP3 Player Module'),
    ('faSatelliteDish',   'IR Sensor'),
    ('faWaveSquare',      'Ultrasonic Sensor'),
    ('faPlug',            'Submersible Pump'),
    ('faSlidersH',        'Relay Module'),
    ('faBatteryFull',     'Battery'),
    ('faTv',              'OLED Display'),
    ('faVolumeDown',      'Mini Speaker'),
]

STATUS_CHOICES = [
    ('Online',  'Online'),
    ('Offline', 'Offline'),
    ('Warning', 'Warning'),
]


class Device(models.Model):
    name        = models.CharField(max_length=128)
    location    = models.CharField(max_length=128, default='Main Entrance')
    status      = models.CharField(max_length=16, choices=STATUS_CHOICES, default='Online')
    battery     = models.PositiveSmallIntegerField(null=True, blank=True)  # null = wired
    icon        = models.CharField(max_length=64, choices=ICON_CHOICES, default='faServer')
    color       = models.CharField(max_length=16, default=random_device_color)
    last_active = models.DateTimeField(auto_now=True)
    wired       = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.name} ({self.status})"


class DeviceSensorReading(models.Model):
    device      = models.ForeignKey(Device, on_delete=models.CASCADE, related_name='readings')
    timestamp   = models.DateTimeField(auto_now_add=True)
    water_level = models.FloatField(null=True, blank=True)   # percentage 0-100
    soap_level  = models.FloatField(null=True, blank=True)   # percentage 0-100
    temperature = models.FloatField(null=True, blank=True)   # celsius
    value       = models.FloatField(null=True, blank=True)   # generic sensor value

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.device.name} @ {self.timestamp:%Y-%m-%d %H:%M}"
