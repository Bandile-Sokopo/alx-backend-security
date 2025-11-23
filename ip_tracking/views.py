from django.http import JsonResponse
from ratelimit.decorators import ratelimit
from django.conf import settings


# Utility to choose rate limit per user type
def get_rate_limit(request):
    if request.user.is_authenticated:
        return settings.RATE_LIMIT_AUTHENTICATED
    return settings.RATE_LIMIT_ANONYMOUS


# Sensitive login view (example)
@ratelimit(key='ip', rate=get_rate_limit, block=True)
def sensitive_view(request):
    """
    Example sensitive endpoint that should be rate-limited.
    Replace with your real login logic.
    """
    return JsonResponse({"message": "Request successful"})
