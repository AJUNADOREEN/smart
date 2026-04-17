from rest_framework import generics, status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from .models import Device, DeviceSensorReading
from .serializers import DeviceSerializer, DeviceDetailSerializer, DeviceSensorReadingSerializer
from apps.alerts.utils import create_alert
from apps.settings_app.models import SystemSettings


class DeviceList(generics.ListCreateAPIView):
    queryset         = Device.objects.prefetch_related('readings')
    serializer_class = DeviceSerializer


class DeviceDetail(generics.RetrieveAPIView):
    queryset         = Device.objects.prefetch_related('readings')
    serializer_class = DeviceDetailSerializer


@api_view(['POST'])
def iot_ingest(request, device_id):
    try:
        device = Device.objects.get(pk=device_id)
    except Device.DoesNotExist:
        return Response({'error': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

    data = request.data
    water_level = data.get('water_level')
    soap_level  = data.get('soap_level')
    temperature = data.get('temperature')
    new_status  = data.get('status')
    battery     = data.get('battery')

    # Override status when the entire system is offline.
    if not SystemSettings.get().system_online:
      new_status = 'Offline'

    DeviceSensorReading.objects.create(
        device      = device,
        water_level = water_level,
        soap_level  = soap_level,
        temperature = temperature,
        value       = data.get('value'),
    )

    # ── Alert: device came back online or went offline ──
    if new_status and new_status != device.status:
        if new_status == 'Offline':
            create_alert(
                title    = 'Device Went Offline',
                device   = device.name,
                message  = f'{device.name} at {device.location} has gone offline.',
                severity = 'High',
                location = device.location,
            )
        elif new_status == 'Online':
            create_alert(
                title    = 'Device Back Online',
                device   = device.name,
                message  = f'{device.name} at {device.location} is back online.',
                severity = 'Low',
                location = device.location,
                status   = 'resolved',
            )
        device.status = new_status

    # ── Alert: low battery ──
    if battery is not None:
        if battery < 20 and (device.battery is None or device.battery >= 20):
            create_alert(
                title    = 'Critical Battery Level',
                device   = device.name,
                message  = f'{device.name} battery is critically low at {battery}%.',
                severity = 'High',
                location = device.location,
            )
        elif battery < 40 and (device.battery is None or device.battery >= 40):
            create_alert(
                title    = 'Low Battery Warning',
                device   = device.name,
                message  = f'{device.name} battery is low at {battery}%.',
                severity = 'Medium',
                location = device.location,
            )
        device.battery = battery

    # ── Alert: low soap level ──
    if soap_level is not None and soap_level < 20:
        create_alert(
            title    = 'Low Soap Level',
            device   = device.name,
            message  = f'Soap level on {device.name} is critically low at {soap_level}%.',
            severity = 'High',
            location = device.location,
        )

    # ── Alert: low water level ──
    if water_level is not None and water_level < 15:
        create_alert(
            title    = 'Water Tank Empty',
            device   = device.name,
            message  = f'Water level on {device.name} is critically low at {water_level}%.',
            severity = 'High',
            location = device.location,
        )

    # ── Alert: high temperature ──
    if temperature is not None and temperature > 40:
        create_alert(
            title    = 'High Temperature Detected',
            device   = device.name,
            message  = f'Temperature sensor on {device.name} reads {temperature}°C.',
            severity = 'Medium',
            location = device.location,
        )

    device.save()
    return Response({'ok': True}, status=status.HTTP_201_CREATED)


@api_view(['PATCH'])
def update_status(request, device_id):
    try:
        device = Device.objects.get(pk=device_id)
    except Device.DoesNotExist:
        return Response({'error': 'Device not found.'}, status=status.HTTP_404_NOT_FOUND)

    new_status = request.data.get('status', device.status)

    if new_status != device.status:
        if new_status == 'Offline':
            create_alert(
                title    = 'Device Manually Set Offline',
                device   = device.name,
                message  = f'{device.name} was manually set to Offline from the dashboard.',
                severity = 'Medium',
                location = device.location,
            )
        elif new_status == 'Online':
            create_alert(
                title    = 'Device Manually Set Online',
                device   = device.name,
                message  = f'{device.name} was manually set to Online from the dashboard.',
                severity = 'Low',
                location = device.location,
                status   = 'resolved',
            )

    device.status = new_status
    device.save()
    return Response(DeviceSerializer(device).data)
