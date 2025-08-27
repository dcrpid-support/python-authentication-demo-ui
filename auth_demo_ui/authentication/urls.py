from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='root'),
    path('authenticate/', views.authenticate, name='authenticate'),
    path('request/otp/', views.requestOTP, name='request_otp'),
]