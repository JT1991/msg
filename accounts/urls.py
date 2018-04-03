from django.conf.urls import url

from . import views

urlpatterns = [
	#url(r"login/$", views.LoginView.as_view(), name="Login"),
	url(r"logout/$", views.LogoutView.as_view(), name="Logout"),
]