from django.urls import path
from . import views
import autoCheckIn
import threading

urlpatterns = [
    path('', views.showHome),
]

threading.Thread(target=autoCheckIn.startListen).start()
