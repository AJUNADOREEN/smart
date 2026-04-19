from datetime import timedelta
import json
import random
import string

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import validate_email
from django.db.models import Q
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import authenticate, login, logout

from .models import OneTimePassword


def _resolve_user(request):
    """Return the acting user from session or 'requester' body field."""
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


@csrf_exempt
def check_availability(request):
    """GET /api/accounts/check/?username=x&email=y"""
    username = request.GET.get('username', '').strip()
    email = request.GET.get('email', '').strip()
    result = {}

    if username:
        result['username_taken'] = User.objects.filter(username=username).exists()

    if email:
        try:
            validate_email(email)
            result['email_valid'] = True
        except ValidationError:
            result['email_valid'] = False
        result['email_taken'] = User.objects.filter(email=email).exists() if result.get('email_valid') else False

    return JsonResponse(result)


@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            full_name = data.get('full_name', '').split(' ', 1)
            first_name = full_name[0] if full_name else ''
            last_name = full_name[1] if len(full_name) > 1 else ''
            email = data.get('email', '').strip()
            username = data.get('username', '').strip()
            password = data.get('password')
            otp_code = data.get('otp_code', '').strip()

            if not username or not password:
                return JsonResponse({'error': 'Username and password are required.'}, status=400)

            if email:
                try:
                    validate_email(email)
                except ValidationError:
                    return JsonResponse({'error': 'Enter a valid email address.'}, status=400)

            otp = None
            if User.objects.exists():
                if not otp_code:
                    return JsonResponse({'error': 'OTP code is required for new account signup.'}, status=401)

                otp = OneTimePassword.objects.filter(
                    code=otp_code,
                    used=False,
                    expires_at__gte=timezone.now(),
                ).first()

                if not otp:
                    return JsonResponse({'error': 'Invalid or expired OTP code.'}, status=401)

                if otp.target_username and otp.target_username != username:
                    return JsonResponse({'error': 'OTP code does not match the provided username.'}, status=401)

                if User.objects.filter(username=username).exists():
                    return JsonResponse({'error': 'Username already exists.'}, status=400)

                if not otp.target_email:
                    return JsonResponse({'error': 'OTP invitation must include an email address.'}, status=400)

                if not otp.target_full_name:
                    return JsonResponse({'error': 'OTP invitation must include a full name.'}, status=400)

                email = otp.target_email
                full_name = otp.target_full_name
                first_name = full_name.split(' ', 1)[0]
                last_name = full_name.split(' ', 1)[1] if ' ' in full_name else ''
                is_staff = otp.target_role in ('admin', 'superadmin')
                is_superuser = otp.target_role == 'superadmin'
            else:
                if User.objects.filter(username=username).exists():
                    return JsonResponse({'error': 'Username already exists'}, status=400)
                if User.objects.filter(email=email).exists():
                    return JsonResponse({'error': 'Email already exists'}, status=400)

                is_staff = True
                is_superuser = True

            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                first_name=first_name,
                last_name=last_name,
                is_staff=is_staff,
                is_superuser=is_superuser,
            )

            if otp:
                otp.used = True
                otp.used_at = timezone.now()
                otp.user = user
                otp.save()

            login(request, user)
            return JsonResponse({
                'message': 'Account created successfully',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'full_name': f"{user.first_name} {user.last_name}".strip(),
                    'email': user.email,
                    'is_superuser': user.is_superuser,
                    'is_staff': user.is_staff,
                }
            }, status=201)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def login_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            user = authenticate(request, username=data.get('username'), password=data.get('password'))
            if user is not None:
                login(request, user)
                return JsonResponse({
                    'message': 'Login successful',
                    'user': {
                        'id': user.id,
                        'username': user.username,
                        'full_name': f"{user.first_name} {user.last_name}".strip(),
                        'email': user.email,
                        'is_superuser': user.is_superuser,
                        'is_staff': user.is_staff,
                    }
                })
            return JsonResponse({'error': 'Invalid username or password'}, status=401)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def generate_otp(request):
    if request.method == 'POST':
        acting = _resolve_user(request)
        if not acting or not acting.is_staff:
            return JsonResponse({'error': 'Only staff users can generate a signup token.'}, status=403)

        try:
            data = json.loads(request.body)
            username  = data.get('username', '').strip()
            email     = data.get('email', '').strip()
            full_name = data.get('full_name', '').strip()
            role      = data.get('role', 'viewer')

            if role not in ['viewer', 'admin', 'superadmin']:
                return JsonResponse({'error': 'Invalid role selected.'}, status=400)
            if acting.is_staff and not acting.is_superuser and role != 'viewer':
                return JsonResponse({'error': 'Only a superadmin can invite admins or superadmins.'}, status=403)

            if not username and not email:
                return JsonResponse({'error': 'Username or email is required to generate an OTP.'}, status=400)
            if not full_name:
                return JsonResponse({'error': 'Full name is required to generate an OTP.'}, status=400)

            target_user = None
            if username:
                target_user = User.objects.filter(username=username).first()
            if not target_user and email:
                target_user = User.objects.filter(email=email).first()

            code = ''.join(random.choices(string.digits, k=6))
            otp = OneTimePassword.objects.create(
                user=target_user,
                target_username=username if not target_user else '',
                target_email=email if not target_user else '',
                target_full_name=full_name,
                target_role=role,
                code=code,
                expires_at=timezone.now() + timedelta(minutes=20)
            )
            return JsonResponse({
                'message': 'One-time password generated successfully',
                'otp_code': otp.code,
                'expires_at': otp.expires_at.isoformat(),
                'target_full_name': otp.target_full_name,
                'target_username': otp.target_username,
                'target_email': otp.target_email,
                'target_role': otp.target_role,
                'username': target_user.username if target_user else None,
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def verify_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username', '').strip()
            otp_code = data.get('otp_code', '').strip()

            if not username or not otp_code:
                return JsonResponse({'error': 'Username and OTP code are required.'}, status=400)

            otp = OneTimePassword.objects.filter(
                code=otp_code,
                used=False,
                expires_at__gte=timezone.now(),
            ).first()
            if not otp:
                return JsonResponse({'error': 'Invalid or expired OTP code.'}, status=401)

            if otp.target_username and otp.target_username != username:
                return JsonResponse({'error': 'OTP code does not match the provided username.'}, status=401)

            if not otp.target_email or not otp.target_full_name:
                return JsonResponse({'error': 'OTP invitation is incomplete.'}, status=400)

            return JsonResponse({
                'username': username,
                'target_email': otp.target_email,
                'target_full_name': otp.target_full_name,
                'target_role': otp.target_role,
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def reset_password_with_otp(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username', '').strip()
            otp_code = data.get('otp_code', '').strip()
            new_password = data.get('new_password')

            if not username or not otp_code or not new_password:
                return JsonResponse({'error': 'Username, OTP code, and new password are required.'}, status=400)

            user = User.objects.filter(username=username).first()
            if not user:
                return JsonResponse({'error': 'Invalid username or token.'}, status=401)

            otp = OneTimePassword.objects.filter(
                user=user,
                code=otp_code,
                used=False,
                expires_at__gte=timezone.now(),
            ).first()
            if not otp:
                return JsonResponse({'error': 'Invalid or expired OTP code.'}, status=401)

            user.set_password(new_password)
            user.save()
            otp.used = True
            otp.used_at = timezone.now()
            otp.save()

            return JsonResponse({'message': 'Password has been reset successfully'})
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def user_list(request):
    acting = _resolve_user(request)
    if not acting or not acting.is_staff:
        return JsonResponse({'error': 'Only staff users can view the user list.'}, status=403)

    if request.method == 'GET':
        users = User.objects.all().order_by('username')
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'username': user.username,
                'full_name': f"{user.first_name} {user.last_name}".strip(),
                'email': user.email,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
                'is_active': user.is_active,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
            })
        return JsonResponse(user_data, safe=False)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def user_detail(request, user_id):
    acting = _resolve_user(request)
    if not acting or not acting.is_staff:
        return JsonResponse({'error': 'Only staff users can manage users.'}, status=403)

    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found.'}, status=404)

    if request.method == 'GET':
        return JsonResponse({
            'id': target_user.id,
            'username': target_user.username,
            'full_name': f"{target_user.first_name} {target_user.last_name}".strip(),
            'email': target_user.email,
            'is_staff': target_user.is_staff,
            'is_superuser': target_user.is_superuser,
            'is_active': target_user.is_active,
            'date_joined': target_user.date_joined.isoformat(),
            'last_login': target_user.last_login.isoformat() if target_user.last_login else None,
        })

    elif request.method == 'PATCH':
        try:
            data = json.loads(request.body)
            # Only superusers can change superuser status
            if 'is_superuser' in data and not acting.is_superuser:
                return JsonResponse({'error': 'Only superusers can change superuser status.'}, status=403)
            # Cannot demote or change yourself
            if target_user.id == acting.id:
                return JsonResponse({'error': 'You cannot modify your own account.'}, status=403)
            # Cannot change superuser if not superuser
            if target_user.is_superuser and not acting.is_superuser:
                return JsonResponse({'error': 'Only superusers can modify other superusers.'}, status=403)

            if 'is_staff' in data:
                target_user.is_staff = data['is_staff']
            if 'is_superuser' in data and acting.is_superuser:
                target_user.is_superuser = data['is_superuser']
                # Superusers are also staff
                if data['is_superuser']:
                    target_user.is_staff = True
            if 'is_active' in data:
                target_user.is_active = data['is_active']

            target_user.save()
            return JsonResponse({
                'id': target_user.id,
                'username': target_user.username,
                'full_name': f"{target_user.first_name} {target_user.last_name}".strip(),
                'email': target_user.email,
                'is_staff': target_user.is_staff,
                'is_superuser': target_user.is_superuser,
                'is_active': target_user.is_active,
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    elif request.method == 'DELETE':
        # Cannot delete yourself
        if target_user.id == acting.id:
            return JsonResponse({'error': 'You cannot delete your own account.'}, status=403)
        # Only superusers can delete other superusers
        if target_user.is_superuser and not acting.is_superuser:
            return JsonResponse({'error': 'Only superusers can delete other superusers.'}, status=403)

        target_user.delete()
        return JsonResponse({'message': 'User deleted successfully'})

    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def user_list(request):
    acting = _resolve_user(request)
    if not acting or not acting.is_staff:
        return JsonResponse({'error': 'Only staff users can view the user list.'}, status=403)

    if request.method == 'GET':
        users = User.objects.all().order_by('username')
        user_data = []
        for user in users:
            user_data.append({
                'id': user.id,
                'username': user.username,
                'full_name': f"{user.first_name} {user.last_name}".strip(),
                'email': user.email,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
                'is_active': user.is_active,
                'date_joined': user.date_joined.isoformat(),
                'last_login': user.last_login.isoformat() if user.last_login else None,
            })
        return JsonResponse(user_data, safe=False)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def user_detail(request, user_id):
    acting = _resolve_user(request)
    if not acting or not acting.is_staff:
        return JsonResponse({'error': 'Only staff users can manage users.'}, status=403)

    try:
        target_user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found.'}, status=404)

    if request.method == 'GET':
        return JsonResponse({
            'id': target_user.id,
            'username': target_user.username,
            'full_name': f"{target_user.first_name} {target_user.last_name}".strip(),
            'email': target_user.email,
            'is_staff': target_user.is_staff,
            'is_superuser': target_user.is_superuser,
            'is_active': target_user.is_active,
            'date_joined': target_user.date_joined.isoformat(),
            'last_login': target_user.last_login.isoformat() if target_user.last_login else None,
        })

    elif request.method == 'PATCH':
        try:
            data = json.loads(request.body)
            # Only superusers can change superuser status
            if 'is_superuser' in data and not acting.is_superuser:
                return JsonResponse({'error': 'Only superusers can change superuser status.'}, status=403)
            # Cannot demote or change yourself
            if target_user.id == acting.id:
                return JsonResponse({'error': 'You cannot modify your own account.'}, status=403)
            # Cannot change superuser if not superuser
            if target_user.is_superuser and not acting.is_superuser:
                return JsonResponse({'error': 'Only superusers can modify other superusers.'}, status=403)

            if 'is_staff' in data:
                target_user.is_staff = data['is_staff']
            if 'is_superuser' in data and acting.is_superuser:
                target_user.is_superuser = data['is_superuser']
                # Superusers are also staff
                if data['is_superuser']:
                    target_user.is_staff = True
            if 'is_active' in data:
                target_user.is_active = data['is_active']

            target_user.save()
            return JsonResponse({
                'id': target_user.id,
                'username': target_user.username,
                'full_name': f"{target_user.first_name} {target_user.last_name}".strip(),
                'email': target_user.email,
                'is_staff': target_user.is_staff,
                'is_superuser': target_user.is_superuser,
                'is_active': target_user.is_active,
            })
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    elif request.method == 'DELETE':
        # Cannot delete yourself
        if target_user.id == acting.id:
            return JsonResponse({'error': 'You cannot delete your own account.'}, status=403)
        # Only superusers can delete other superusers
        if target_user.is_superuser and not acting.is_superuser:
            return JsonResponse({'error': 'Only superusers can delete other superusers.'}, status=403)

        target_user.delete()
        return JsonResponse({'message': 'User deleted successfully'})

    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def user_list(request):
    """GET or POST /api/accounts/users/ — staff (admin + superadmin) only"""
    if request.method not in ('GET', 'POST'):
        return JsonResponse({'error': 'Method not allowed.'}, status=405)
    acting = _resolve_user(request)
    if not acting or not acting.is_staff:
        return JsonResponse({'error': 'Staff access required.'}, status=403)
    users = User.objects.all().order_by('date_joined')
    return JsonResponse({'users': [{
        'id': u.id,
        'username': u.username,
        'full_name': f"{u.first_name} {u.last_name}".strip(),
        'email': u.email,
        'is_superuser': u.is_superuser,
        'is_staff': u.is_staff,
        'role': 'superadmin' if u.is_superuser else 'admin' if u.is_staff else 'viewer',
        'date_joined': u.date_joined.isoformat(),
    } for u in users]})


@csrf_exempt
def user_detail(request, user_id):
    """PATCH (change role) or DELETE a user — superadmin only"""
    acting = _resolve_user(request)
    if not acting or not acting.is_superuser:
        return JsonResponse({'error': 'Superadmin access required.'}, status=403)
    try:
        target = User.objects.get(pk=user_id)
    except User.DoesNotExist:
        return JsonResponse({'error': 'User not found.'}, status=404)

    if request.method == 'DELETE':
        if target == acting:
            return JsonResponse({'error': 'You cannot delete your own account.'}, status=400)
        target.delete()
        return JsonResponse({'message': 'User deleted.'})

    if request.method == 'PATCH':
        data = json.loads(request.body)
        role = data.get('role')
        if role not in ('viewer', 'admin', 'superadmin'):
            return JsonResponse({'error': 'Invalid role.'}, status=400)
        if target == acting and role != 'superadmin':
            return JsonResponse({'error': 'You cannot demote your own account.'}, status=400)
        target.is_staff = role in ('admin', 'superadmin')
        target.is_superuser = role == 'superadmin'
        target.save()
        return JsonResponse({'message': 'Role updated.', 'role': role})

    return JsonResponse({'error': 'Method not allowed.'}, status=405)


@csrf_exempt
def logout_view(request):
    if request.method == 'POST':
        logout(request)
        return JsonResponse({'message': 'Logged out'})
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def me(request):
    if request.user.is_authenticated:
        u = request.user
        return JsonResponse({
            'id': u.id,
            'username': u.username,
            'full_name': f"{u.first_name} {u.last_name}".strip(),
            'email': u.email,
            'is_superuser': u.is_superuser,
            'is_staff': u.is_staff,
        })
    return JsonResponse({'error': 'Not authenticated'}, status=401)
