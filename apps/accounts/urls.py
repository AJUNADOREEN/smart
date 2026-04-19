from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register,            name='register'),
    path('login/',    views.login_view,           name='login'),
    path('logout/',   views.logout_view,          name='logout'),
    path('me/',       views.me,                   name='me'),
    path('check/',    views.check_availability,   name='check'),
    path('otp/verify/', views.verify_otp,         name='verify_otp'),
    path('otp/generate/', views.generate_otp,     name='generate_otp'),
    path('otp/reset/',    views.reset_password_with_otp, name='reset_password_with_otp'),
    path('users/',               views.user_list,   name='user_list'),
    path('users/<int:user_id>/', views.user_detail, name='user_detail'),
]