"""
Benign activity generator.
Produces realistic corporate log events with work-hour patterns,
weekday/weekend variance, normal travel, admin tasks, and nightly backups.
"""
import random
from datetime import datetime, timedelta
from typing import Optional
import uuid
import math


def generate_benign_events(
    rng: random.Random,
    entities: dict,
    start_date: datetime,
    num_days: int = 30,
) -> list[dict]:
    """
    Generate a full set of benign log events for num_days.
    Returns a list of log event dicts sorted by timestamp.
    """
    events = []
    users = entities["users"]
    hosts = entities["hosts"]

    for day_offset in range(num_days):
        current_date = start_date + timedelta(days=day_offset)
        is_weekend = current_date.weekday() >= 5  # Saturday=5, Sunday=6

        # --- Regular user activity ---
        for user in users:
            if user.is_service_account:
                continue

            # Weekend: 20% chance of any activity
            if is_weekend and rng.random() > 0.2:
                continue

            # Occasional day off (5%)
            if rng.random() < 0.05:
                continue

            # Generate daily events for this user
            user_events = _generate_user_day(rng, user, current_date, entities, is_weekend)
            events.extend(user_events)

        # --- Service account activity ---
        svc_events = _generate_service_activity(rng, entities, current_date)
        events.extend(svc_events)

        # --- Nightly backups (2-4 AM) ---
        backup_events = _generate_nightly_backup(rng, entities, current_date)
        events.extend(backup_events)

    # Sort by timestamp
    events.sort(key=lambda e: e["timestamp"])
    return events


def _generate_user_day(
    rng: random.Random,
    user,
    date: datetime,
    entities: dict,
    is_weekend: bool,
) -> list[dict]:
    """Generate all events for a single user on a single day."""
    events = []
    hosts = entities["hosts"]

    # Determine work hours with jitter
    start_hour = user.work_start_hour + rng.gauss(0, 0.5)
    end_hour = user.work_end_hour + rng.gauss(0, 0.5)
    if is_weekend:
        start_hour = rng.uniform(10, 14)
        end_hour = start_hour + rng.uniform(1, 3)

    start_hour = max(0, min(23, start_hour))
    end_hour = max(start_hour + 1, min(23.9, end_hour))

    # Pick host for today
    if user.typical_hosts:
        host = rng.choice(user.typical_hosts)
    else:
        wks = [h.hostname for h in hosts if h.host_type == "workstation"]
        host = rng.choice(wks) if wks else "WKS-001"

    host_obj = next((h for h in hosts if h.hostname == host), None)
    src_ip = host_obj.ip if host_obj else "10.0.1.1"
    geo = user.typical_geo

    # --- Login ---
    login_time = _make_time(date, start_hour, rng)
    events.append(_make_event(
        timestamp=login_time, event_type="login_success",
        user=user.username, host=host, src_ip=src_ip,
        geo_country=geo, app="windows_login", status="success",
    ))

    # --- File access (3-15 per day) ---
    num_files = rng.randint(3, 15) if not is_weekend else rng.randint(1, 5)
    normal_files = entities["file_paths_normal"]
    for _ in range(num_files):
        file_time = _make_time(date, rng.uniform(start_hour, end_hour), rng)
        fp = rng.choice(normal_files).replace("{user}", user.username)
        events.append(_make_event(
            timestamp=file_time, event_type="file_access",
            user=user.username, host=host, src_ip=src_ip,
            file_path=fp, app=rng.choice(["excel", "word", "notepad++", "vscode"]),
            bytes_transferred=rng.randint(1000, 500000),
            geo_country=geo,
        ))

    # --- Email (2-10 per day) ---
    num_emails = rng.randint(2, 10) if not is_weekend else rng.randint(0, 2)
    for _ in range(num_emails):
        email_time = _make_time(date, rng.uniform(start_hour, end_hour), rng)
        events.append(_make_event(
            timestamp=email_time, event_type="email_send",
            user=user.username, host=host, src_ip=src_ip,
            dst_ip=rng.choice(entities["external_ips_normal"]),
            app="outlook", bytes_transferred=rng.randint(5000, 2000000),
            geo_country=geo,
        ))

    # --- Web browsing / network connections (5-20) ---
    num_net = rng.randint(5, 20) if not is_weekend else rng.randint(1, 5)
    for _ in range(num_net):
        net_time = _make_time(date, rng.uniform(start_hour, end_hour), rng)
        events.append(_make_event(
            timestamp=net_time, event_type="network_conn",
            user=user.username, host=host, src_ip=src_ip,
            dst_ip=rng.choice(entities["external_ips_normal"]),
            app=rng.choice(["chrome", "firefox", "edge"]),
            bytes_transferred=rng.randint(1000, 5000000),
            geo_country=geo,
        ))

    # --- DNS queries (10-30) ---
    num_dns = rng.randint(10, 30)
    normal_domains = [
        "google.com", "office365.com", "microsoft.com", "github.com",
        "stackoverflow.com", "slack.com", "teams.microsoft.com",
        "cdn.jsdelivr.net", "fonts.googleapis.com", "api.openai.com",
        "aws.amazon.com", "login.microsoftonline.com",
    ]
    for _ in range(num_dns):
        dns_time = _make_time(date, rng.uniform(start_hour, end_hour), rng)
        domain = rng.choice(normal_domains)
        events.append(_make_event(
            timestamp=dns_time, event_type="dns_query",
            user=user.username, host=host, src_ip=src_ip,
            file_path=domain,  # Using file_path for DNS query content
            app="dns_client",
            geo_country=geo,
        ))

    # --- Process starts (2-8) ---
    num_proc = rng.randint(2, 8)
    safe_procs = ["chrome.exe", "outlook.exe", "teams.exe", "excel.exe", "word.exe",
                  "code.exe", "notepad.exe", "explorer.exe", "calc.exe"]
    for _ in range(num_proc):
        proc_time = _make_time(date, rng.uniform(start_hour, end_hour), rng)
        events.append(_make_event(
            timestamp=proc_time, event_type="process_start",
            user=user.username, host=host, src_ip=src_ip,
            app=rng.choice(safe_procs),
            geo_country=geo,
        ))

    # --- Logoff ---
    logoff_time = _make_time(date, end_hour, rng)
    events.append(_make_event(
        timestamp=logoff_time, event_type="logoff",
        user=user.username, host=host, src_ip=src_ip,
        geo_country=geo,
    ))

    # --- Occasional admin tasks for admins ---
    if user.is_admin and rng.random() < 0.3:
        admin_time = _make_time(date, rng.uniform(start_hour, end_hour), rng)
        events.append(_make_event(
            timestamp=admin_time, event_type="privilege_change",
            user=user.username, host=rng.choice(user.typical_hosts) if user.typical_hosts else host,
            src_ip=src_ip, app="active_directory",
            status="granted", geo_country=geo,
        ))

    return events


def _generate_service_activity(rng: random.Random, entities: dict, date: datetime) -> list[dict]:
    """Generate service account activity (monitoring, deployments)."""
    events = []
    svc_users = [u for u in entities["users"] if u.is_service_account]
    servers = [h for h in entities["hosts"] if h.host_type in ("server", "database_server")]

    for svc in svc_users:
        if svc.username == "svc_monitor":
            # Monitoring pings every 5 minutes, 24/7
            for hour in range(24):
                for minute in [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 55]:
                    if rng.random() < 0.95:  # Occasional missed check
                        t = date.replace(hour=hour, minute=minute, second=rng.randint(0, 59))
                        target = rng.choice(servers) if servers else entities["hosts"][0]
                        events.append(_make_event(
                            timestamp=t, event_type="network_conn",
                            user=svc.username, host=target.hostname,
                            src_ip="10.0.0.1", dst_ip=target.ip,
                            app="monitoring_agent",
                            bytes_transferred=rng.randint(100, 1000),
                        ))
        elif svc.username == "svc_deploy" and rng.random() < 0.15:
            # Occasional deployment
            deploy_hour = rng.uniform(10, 16)
            for server in rng.sample(servers, min(3, len(servers))):
                t = _make_time(date, deploy_hour, rng)
                events.append(_make_event(
                    timestamp=t, event_type="process_start",
                    user=svc.username, host=server.hostname,
                    src_ip="10.0.0.2", app="deploy_agent",
                ))
                events.append(_make_event(
                    timestamp=t + timedelta(seconds=rng.randint(30, 300)),
                    event_type="service_start",
                    user=svc.username, host=server.hostname,
                    src_ip="10.0.0.2", app="application_service",
                ))

    return events


def _generate_nightly_backup(rng: random.Random, entities: dict, date: datetime) -> list[dict]:
    """Generate nightly backup events (2-4 AM) by backup service accounts."""
    events = []
    backup_user = "svc_backup"
    servers = [h for h in entities["hosts"] if h.host_type in ("server", "database_server")]

    backup_start = date.replace(hour=2, minute=rng.randint(0, 30), second=0)

    for server in servers:
        t = backup_start + timedelta(minutes=rng.randint(0, 60))

        # Login
        events.append(_make_event(
            timestamp=t, event_type="login_success",
            user=backup_user, host=server.hostname,
            src_ip="10.0.0.5", app="backup_agent",
        ))

        # Many file copies (backup is inherently high-volume)
        num_copies = rng.randint(50, 200)
        for i in range(num_copies):
            copy_time = t + timedelta(seconds=rng.randint(1, 1800))
            events.append(_make_event(
                timestamp=copy_time, event_type="file_copy",
                user=backup_user, host=server.hostname,
                src_ip="10.0.0.5",
                file_path=f"\\\\{server.hostname}\\backup\\{date.strftime('%Y%m%d')}\\file_{i:04d}.bak",
                bytes_transferred=rng.randint(100000, 50000000),
                app="backup_agent",
            ))

        # Large network transfer to backup storage
        events.append(_make_event(
            timestamp=t + timedelta(minutes=rng.randint(30, 90)),
            event_type="network_conn",
            user=backup_user, host=server.hostname,
            src_ip=server.ip, dst_ip="10.0.10.1",  # Backup NAS
            bytes_transferred=rng.randint(500000000, 2000000000),  # 500MB - 2GB
            app="backup_agent",
        ))

    return events


def _make_time(date: datetime, hour_float: float, rng: random.Random) -> datetime:
    """Convert a float hour to a datetime with second-level jitter."""
    hour = int(hour_float) % 24
    minute = int((hour_float % 1) * 60)
    second = rng.randint(0, 59)
    return date.replace(hour=hour, minute=min(minute, 59), second=second, microsecond=0)


def _make_event(
    timestamp: datetime,
    event_type: str,
    user: str = "",
    host: str = "",
    src_ip: str = "",
    dst_ip: str = "",
    app: str = "",
    file_path: str = "",
    bytes_transferred: int = 0,
    geo_country: str = "",
    device_id: str = "",
    status: str = "",
    label: str = "",
) -> dict:
    """Create a log event dict matching the unified schema."""
    event = {
        "id": str(uuid.uuid4()),
        "timestamp": timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_type": event_type,
    }
    if user:
        event["user"] = user
    if host:
        event["host"] = host
    if src_ip:
        event["src_ip"] = src_ip
    if dst_ip:
        event["dst_ip"] = dst_ip
    if app:
        event["app"] = app
    if file_path:
        event["file_path"] = file_path
    if bytes_transferred:
        event["bytes"] = bytes_transferred
    if geo_country:
        event["geo_country"] = geo_country
    if device_id:
        event["device_id"] = device_id
    if status:
        event["status"] = status
    if label:
        event["label"] = label
    return event
