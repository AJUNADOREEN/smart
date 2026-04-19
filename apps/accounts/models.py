from django.db import models
from django.contrib.auth.models import User

class OneTimePassword(models.Model):
    ROLE_CHOICES = [
        ('viewer', 'Viewer'),
        ('admin', 'Admin'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps', null=True, blank=True)
    target_username = models.CharField(max_length=150, blank=True)
    target_email = models.CharField(max_length=254, blank=True)
    target_full_name = models.CharField(max_length=150, blank=True)
    target_role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='viewer')
    code = models.CharField(max_length=32)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used = models.BooleanField(default=False)
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        target = self.user.username if self.user else self.target_username or self.target_email
        return f"OTP for {target} ({'used' if self.used else 'active'})"
