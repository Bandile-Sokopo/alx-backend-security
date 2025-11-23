from celery import shared_task
from django.utils import timezone
from datetime import timedelta

from .models import RequestLog, SuspiciousIP


SENSITIVE_PATHS = [
    "/admin",
    "/login",
    "/auth/login",
    "/api/login",
]


@shared_task
def run_anomaly_detection():
    """
    Runs hourly:
    - Flags IPs making >100 requests in the previous hour
    - Flags IPs accessing sensitive paths
    """
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # 1. High traffic detection
    logs_last_hour = RequestLog.objects.filter(timestamp__gte=one_hour_ago)

    ip_counts = (
        logs_last_hour.values("ip_address")
        .annotate(count=models.Count("id"))
        .filter(count__gt=100)
    )

    for entry in ip_counts:
        ip = entry["ip_address"]
        reason = f"Exceeded 100 requests in 1 hour ({entry['count']})"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)

    # 2. Sensitive path monitoring
    sensitive_logs = logs_last_hour.filter(path__in=SENSITIVE_PATHS)

    for log in sensitive_logs:
        reason = f"Accessed sensitive path: {log.path}"
        SuspiciousIP.objects.get_or_create(
            ip_address=log.ip_address,
            reason=reason,
        )
