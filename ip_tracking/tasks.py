from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from ip_tracking.models import SuspiciousIP, RequestLog
from django.db.models import Count

SENSITIVE_PATHS = ["/admin", "/login", "/api/login", "/graphql"]

@shared_task
def detect_suspicious_ips():
    """Detect IPs with high request frequency or sensitive path access."""
    now = timezone.now()
    one_hour_ago = now - timedelta(hours=1)
    suspicious_ips = []

    # 1?? Detect IPs exceeding 100 requests/hour
    heavy_ips = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values("ip_address")
        .annotate(request_count=Count("id"))
        .filter(request_count__gt=100)
    )

    for entry in heavy_ips:
        ip = entry["ip_address"]
        reason = f"Exceeded 100 requests/hour (count={entry['request_count']})"
        suspicious_ips.append((ip, reason))

    # 2?? Detect IPs accessing sensitive paths
    sensitive_logs = RequestLog.objects.filter(
        timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS
    ).values_list("ip_address", flat=True)

    for ip in set(sensitive_logs):
        suspicious_ips.append((ip, "Accessed sensitive paths"))

    # 3?? Save new suspicious IPs (avoid duplicates)
    for ip, reason in suspicious_ips:
        SuspiciousIP.objects.get_or_create(ip_address=ip, defaults={"reason": reason})

    print(f"[Anomaly Detection] {len(suspicious_ips)} suspicious IP(s) flagged.")
