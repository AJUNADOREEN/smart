from rest_framework import serializers
from .models import Device, DeviceSensorReading


class DeviceSensorReadingSerializer(serializers.ModelSerializer):
    class Meta:
        model  = DeviceSensorReading
        fields = ['id', 'timestamp', 'water_level', 'soap_level', 'temperature', 'value']


class DeviceSerializer(serializers.ModelSerializer):
    last_active    = serializers.DateTimeField(format='%I:%M %p', read_only=True)
    latest_reading = serializers.SerializerMethodField()
    wifi           = serializers.SerializerMethodField()

    class Meta:
        model  = Device
        fields = ['id', 'name', 'location', 'status', 'battery', 'icon', 'color', 'last_active', 'wired', 'wifi', 'latest_reading']

    def get_wifi(self, obj):
        return getattr(obj, 'wifi', False)

    def get_latest_reading(self, obj):
        r = obj.readings.first()
        if not r:
            return {'water_level': None, 'soap_level': None, 'temperature': None, 'value': None}
        return DeviceSensorReadingSerializer(r).data


class DeviceDetailSerializer(serializers.ModelSerializer):
    last_active    = serializers.DateTimeField(format='%I:%M %p', read_only=True)
    latest_reading = serializers.SerializerMethodField()
    history        = serializers.SerializerMethodField()
    wifi           = serializers.SerializerMethodField()

    class Meta:
        model  = Device
        fields = ['id', 'name', 'location', 'status', 'battery', 'icon', 'color', 'last_active', 'wired', 'wifi', 'latest_reading', 'history']

    def get_wifi(self, obj):
        return getattr(obj, 'wifi', False)

    def get_latest_reading(self, obj):
        r = obj.readings.first()
        if not r:
            return {'water_level': None, 'soap_level': None, 'temperature': None, 'value': None}
        return DeviceSensorReadingSerializer(r).data

    def get_history(self, obj):
        qs = obj.readings.order_by('timestamp')[:10]
        return [r.value for r in qs if r.value is not None]
