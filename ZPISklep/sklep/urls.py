
from django.urls import path
from . import views
from .views import PasswordsChangeView
from django.contrib.auth import views as auth_views
from . import views

urlpatterns = [
    path('', views.index),
    path('home/', views.index, name="home"),
    path('oNas/', views.oNas),
    path('produkt/', views.produkt),
    path('kontakt/', views.kontakt),
    path('regulamin/', views.regulamin),
    path('platnosc/', views.platnosc),
    path('zwroty/', views.zwroty),
    path('newsletter/', views.newsletter),
    path('logowanie/', views.logowanie),
    path('rejestracja/', views.rejestracja),
    path('wylogowanie/', views.wylogowanie),
    path('zmianaHasla/', PasswordsChangeView.as_view(template_name='zmiana.html')),
    path('zmianaHaslaSuccess/', views.password_success, name="password_success"),
    path('konto/', views.konto),
    path('zapisbrak/', views.zapisbrak),
    path('activate/<uidb64>/<token>', views.activate, name='activate')
]

