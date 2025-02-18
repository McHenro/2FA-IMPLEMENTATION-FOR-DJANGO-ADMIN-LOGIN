from django.contrib import admin
from django.urls import path, include


urlpatterns = [
    path('admin/', admin.site.urls),  # Standard admin interface with two-factor enforced
    path("",include(("authentication.urls", "authentication"), namespace="authentication")),
]
