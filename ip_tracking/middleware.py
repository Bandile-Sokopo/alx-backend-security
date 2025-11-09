from django.utils import timezone
from django.http import HttpResponseForbidden
from django.core.cache import cache
from ip_tracking.models import RequestLog, BlockedIP
from ipgeolocation import IpGeolocationAPI


class RequestLoggingMiddleware:
    """Middleware to log requests with geolocation and block blacklisted IPs."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.geo = IpGeolocationAPI()

    def __call__(self, request):
        ip = request.META.get("REMOTE_ADDR", "")
        path = request.path
        timestamp = timezone.now()

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Access denied: your IP is blocked.")

        # --- Geolocation lookup (with caching) ---
        cache_key = f"geo_{ip}"
        geo_data = cache.get(cache_key)

        if not geo_data:
            try:
                geo_info = self.geo.get_geolocation(ip)
                geo_data = {
                    "country": geo_info.get("country_name", "Unknown"),
                    "city": geo_info.get("city", "Unknown"),
                }
                cache.set(cache_key, geo_data, 60 * 60 * 24)  # Cache 24 hours
            except Exception:
                geo_data = {"country": "Unknown", "city": "Unknown"}

        # Log request
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            timestamp=timestamp,
            country=geo_data.get("country"),
            city=geo_data.get("city"),
        )

        return self.get_response(request)
