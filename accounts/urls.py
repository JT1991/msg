from django.conf.urls import url

from . import views

app_name = 'accounts'

urlpatterns = [
	#url(r"login/$", views.LoginView.as_view(), name="Login"),
	url(r"logout/$", views.LogoutView.as_view(), name="logout"),
	url(r"signup/$", views.SignUp.as_view(), name="signup"),

]