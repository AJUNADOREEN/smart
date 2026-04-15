from django.db import models


class SensorReading(models.Model):
    date = models.DateField()
    timestamp = models.DateTimeField(null=True, blank=True)
    device = models.CharField(max_length=128, default='IoT-Station-01')
    soap_usage = models.FloatField(default=0.0)    # litres
    water_usage = models.FloatField(default=0.0)   # litres
    handwashes = models.PositiveIntegerField(default=0)
    unwashed = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ['timestamp', 'date']

    def __str__(self):
        return f"{self.device} | {self.date}"
