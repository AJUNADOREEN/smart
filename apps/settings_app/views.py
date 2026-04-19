from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
import json

from .models import SystemSettings
from .serializers import SystemSettingsSerializer
from apps.devices.models import Device
from apps.alerts.utils import create_alert
from django.contrib.auth.models import User


def _resolve_user(request):
    if request.user.is_authenticated:
        return request.user
    try:
        body = json.loads(request.body or '{}')
        username = body.get('requester', '').strip()
        if username:
            return User.objects.filter(username=username, is_active=True).first()
    except Exception:
        pass
    return None


def _device_group(device):
    sensors = {'faEye', 'faWater', 'faTemperatureHalf'}
    boards  = {'faToggleOn', 'faServer', 'faDisplay', 'faMicrochip'}
    if device.icon in sensors:
        return 'sensors'
    if device.icon in boards:
        return 'boards'
    return 'devices'


@api_view(['GET', 'PUT', 'PATCH'])
@authentication_classes([])
@permission_classes([])
def settings_view(request):
    obj = SystemSettings.get()
    if request.method == 'GET':
        return Response(SystemSettingsSerializer(obj).data)
    serializer = SystemSettingsSerializer(obj, data=request.data, partial=request.method == 'PATCH')
    if serializer.is_valid():
        serializer.save()
        create_alert(
            title='System Settings Updated', device='Dashboard',
            message='System settings were saved from the Settings page.',
            severity='Low', location='Dashboard',
        )
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PATCH'])
@authentication_classes([])
@permission_classes([])
def system_power_view(request):
    obj = SystemSettings.get()
    if request.method == 'GET':
        return Response({'system_online': obj.system_online})

    acting = _resolve_user(request)
    if not acting or not acting.is_superuser:
        return Response({'error': 'Only a superadmin can toggle system power.'}, status=status.HTTP_403_FORBIDDEN)

    new_state = request.data.get('system_online')
    if new_state is None:
        return Response({'error': 'system_online required.'}, status=status.HTTP_400_BAD_REQUEST)

    obj.system_online = new_state
    obj.save(update_fields=['system_online'])

    if not new_state:
        Device.objects.all().update(status='Offline')

    create_alert(
        title='System Powered On' if new_state else 'System Powered Off',
        device='Dashboard',
        message=f'System was remotely {"activated" if new_state else "shut down"} from Settings.',
        severity='Low' if new_state else 'High',
        location='Settings',
    )
    return Response({'system_online': obj.system_online})


@api_view(['GET'])
@authentication_classes([])
@permission_classes([])
def power_devices_list(request):
    system_online = SystemSettings.get().system_online
    devices = Device.objects.all()
    return Response([{
        'id': d.id, 'name': d.name, 'group': _device_group(d),
        'status': (d.status == 'Online') if system_online else False,
        'location': d.location,
    } for d in devices])


@api_view(['PATCH'])
@authentication_classes([])
@permission_classes([])
def power_device_toggle(request, pk):
    acting = _resolve_user(request)
    if not acting or not acting.is_staff:
        return Response({'error': 'Only staff users can change device power status.'}, status=status.HTTP_403_FORBIDDEN)
    try:
        device = Device.objects.get(pk=pk)
    except Device.DoesNotExist:
        return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

    new_status = request.data.get('status')
    if new_status is None:
        return Response({'error': 'status required.'}, status=status.HTTP_400_BAD_REQUEST)

    old_status = device.status
    device.status = 'Online' if new_status else 'Offline'
    device.save(update_fields=['status'])

    if device.status != old_status:
        if new_status:
            create_alert(
                title='Device Powered On', device=device.name,
                message=f'{device.name} was powered on from the Settings panel.',
                severity='Low', location=device.location, status='resolved',
            )
        else:
            create_alert(
                title='Device Powered Off', device=device.name,
                message=f'{device.name} was powered off from the Settings panel.',
                severity='Medium', location=device.location,
            )
    return Response({'id': device.id, 'name': device.name, 'group': _device_group(device), 'status': device.status == 'Online'})
