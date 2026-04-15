from rest_framework import serializers
from .models import SensorReading


class SensorReadingSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(required=False, allow_null=True)
    date = serializers.DateField(required=False)

    class Meta:
        model = SensorReading
        fields = ['id', 'timestamp', 'date', 'device', 'soap_usage', 'water_usage', 'handwashes', 'unwashed']


class AnalyticsSerializer(serializers.Serializer):
    labels = serializers.ListField(child=serializers.CharField())
    soapUsage = serializers.ListField(child=serializers.FloatField())
    waterUsage = serializers.ListField(child=serializers.FloatField())
    handwashes = serializers.ListField(child=serializers.IntegerField())
    unwashed = serializers.ListField(child=serializers.IntegerField())
