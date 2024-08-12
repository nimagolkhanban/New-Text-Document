from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.utils import timezone
from django.contrib.auth.hashers import make_password


class MyUserManager(BaseUserManager):
    def create_user(self, phone, password=None):
        if not phone:
            raise ValueError('Users must have an email address')

        user = self.model(
            phone=phone,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_super_user(self, phone, password=None):
        user = self.create_user(
            phone=phone,
            password=password
        )
        user.is_admin = True
        user.save(using=self._db)
        return user
    

class MyUser(AbstractBaseUser):
    phone = models.CharField(max_length=11, unique=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    phone = models.CharField(max_length=15, unique=True)
    email = models.EmailField(blank=True)
    otp = models.CharField(max_length=6, blank=True, null=True)
    otp_expiration = models.DateTimeField(blank=True, null=True) 
    otp_activate = models.BooleanField(default=False, blank=True, null=True)
    failed_login_attempts = models.IntegerField(default=0)
    failed_sms_attempts = models.IntegerField(default=0)
    last_failed_attempt = models.DateTimeField(null=True, blank=True)
    failed_otp_attempts = models.IntegerField(default=0)
    last_failed_otp_attempt = models.DateTimeField(blank=True, null=True)
    otp_blocked_until = models.DateTimeField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_admin = models.BooleanField(default=False)
    
    
    def is_otp_blocked(self):
        if self.otp_blocked_until and timezone.now() < self.otp_blocked_until:
            return True
        return False

    def block_otp(self):
        self.failed_otp_attempts = 0
        self.otp_blocked_until = timezone.now() + timezone.timedelta(hours=1)
        self.save()
        
    objects = MyUserManager()

    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.phone

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True
    
    def set_password(self, raw_password):
        self.password = make_password(raw_password)
   
    
class IPAddress(models.Model):
    ip = models.GenericIPAddressField(unique=True)
    failed_login_attempts = models.IntegerField(default=0)
    failed_signup_attempts = models.IntegerField(default=0)
    sms_request_count = models.IntegerField(default=0)  
    last_failed_attempt = models.DateTimeField(null=True, blank=True)
    last_sms_request = models.DateTimeField(null=True, blank=True) 
    blocked_until = models.DateTimeField(null=True, blank=True) 

    def is_blocked(self):
        if self.blocked_until and timezone.now() < self.blocked_until:
            return True
        if self.failed_login_attempts >= 3 or self.failed_signup_attempts >= 3:
            return (timezone.now() - self.last_failed_attempt).total_seconds() < 3600
        if self.sms_request_count >= 3:
            return (timezone.now() - self.last_sms_request).total_seconds() < 3600
        return False

    def block_ip(self):
        self.failed_login_attempts = 0
        self.failed_signup_attempts = 0
        self.sms_request_count = 0
        self.blocked_until = timezone.now() + timezone.timedelta(hours=1)
        self.save()

    def __str__(self):
        return self.ip