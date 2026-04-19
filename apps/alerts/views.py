from rest_framework import generics, status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from .models import Alert
from .serializers import AlertSerializer


class AlertList(generics.ListCreateAPIView):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer

    def get_queryset(self):
        severity = self.request.query_params.get('severity', None)
        status_param = self.request.query_params.get('status', None)
        if status_param:
            queryset = Alert.objects.filter(status=status_param, dismissed=False)
        else:
            queryset = Alert.objects.filter(status='active', dismissed=False)

        if severity:
            queryset = queryset.filter(severity=severity)
        return queryset


class AlertDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer


@api_view(['PATCH'])
@authentication_classes([])
@permission_classes([])
def mark_read(request, pk):
    try:
        alert = Alert.objects.get(pk=pk)
    except Alert.DoesNotExist:
        return Response({'error': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
    alert.status = 'resolved'
    alert.save(update_fields=['status'])
    return Response({'ok': True})


@api_view(['PATCH'])
@authentication_classes([])
@permission_classes([])
def mark_all_read(request):
    Alert.objects.filter(status='active', dismissed=False).update(status='resolved')
    return Response({'ok': True})


@api_view(['GET'])
@authentication_classes([])
@permission_classes([])
def alert_counts(request):
    high   = Alert.objects.filter(severity='High',   status='active', dismissed=False).count()
    medium = Alert.objects.filter(severity='Medium', status='active', dismissed=False).count()
    low    = Alert.objects.filter(severity='Low',    status='active', dismissed=False).count()
    return Response({'High': high, 'Medium': medium, 'Low': low})
