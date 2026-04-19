from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from .models import ThemePreference
from .serializers import ThemePreferenceSerializer


@csrf_exempt
@api_view(['GET', 'PATCH', 'PUT'])
@authentication_classes([])
@permission_classes([])
def theme_view(request):
    theme_obj = ThemePreference.get()

    if request.method == 'GET':
        return Response(ThemePreferenceSerializer(theme_obj).data)

    serializer = ThemePreferenceSerializer(theme_obj, data=request.data, partial=True)
    if serializer.is_valid():
        serializer.save()
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
