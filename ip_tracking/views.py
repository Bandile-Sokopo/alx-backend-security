from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from ratelimit.decorators import ratelimit
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings


@csrf_exempt
@ratelimit(key="user_or_ip", rate=settings.RATELIMITS["anonymous"], method="POST", block=True)
def login_view(request):
    """Rate-limited login view — 5/min for anonymous users, 10/min for authenticated."""
    if request.user.is_authenticated:
        # Adjust rate dynamically for authenticated users
        decorator = ratelimit(key="user", rate=settings.RATELIMITS["authenticated"], method="POST", block=True)
        return decorator(_authenticated_login_view)(request)
    return _anonymous_login_view(request)


def _anonymous_login_view(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=400)

    username = request.POST.get("username")
    password = request.POST.get("password")
    user = authenticate(request, username=username, password=password)

    if user is not None:
        login(request, user)
        return JsonResponse({"message": f"Welcome back, {user.username}!"})
    else:
        return JsonResponse({"error": "Invalid credentials"}, status=401)


def _authenticated_login_view(request):
    return JsonResponse({"message": "Already logged in!"})

