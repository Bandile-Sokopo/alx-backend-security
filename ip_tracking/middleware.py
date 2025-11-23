import requests
from django.http import HttpResponseForbidden
from django.core.cache import cache
from .models import RequestLog, BlockedIP

GEO_CACHE_TTL = 60 * 60 * 24  # 24 hours


class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Extract IP
        ip = (
            request.META.get("HTTP_X_FORWARDED_FOR").split(",")[0]
            if request.META.get("HTTP_X_FORWARDED_FOR")
            else request.META.get("REMOTE_ADDR")
        )

        # ---- Block IP if blacklisted ----
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP address is blocked.")

        # ---- Try cache first ----
        cache_key = f"geo_ip_{ip}"
        geo = cache.get(cache_key)

        if not geo:
            geo = self.get_geolocation(ip)
            cache.set(cache_key, geo, GEO_CACHE_TTL)

        # ---- Log request ----
        RequestLog.objects.create(
            ip_address=ip,
            path=request.path,
            country=geo.get("country"),
            city=geo.get("city"),
        )

        return self.get_response(request)

    def get_geolocation(self, ip):
        """Fetch geolocation from ipapi.co (free, no key needed)."""
        try:
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=2)
            data = response.json()

            return {
                "country": data.get("country_name"),
                "city": data.get("city"),
            }

        except Exception:
            # If API fails, return null values
            return {"country": None, "city": None}
