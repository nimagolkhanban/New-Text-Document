from django.urls import path
from .views import SignupView, LoginView, InitialView, ValidateOTPView

urlpatterns = [
    path('', InitialView.as_view(), name='send_otp'),
    path('signup/', SignupView.as_view(), name='signup'),
    path('login/', LoginView.as_view(), name='login'),
    path('validate-otp/', ValidateOTPView.as_view(), name='validate_otp'),
]