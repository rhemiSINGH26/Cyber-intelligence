"""
Hard negative scenarios that MUST NOT trigger incidents.
These are legitimate activities that look suspicious but are benign.
"""
import random
from datetime import datetime, timedelta
from app.simulation.benign import _make_event


def inject_hard_negatives(
    rng: random.Random,
    entities: dict,
    start_date: datetime,
) -> list[dict]:
    """
    Inject hard negative scenarios that should NOT become incidents.
    Returns benign events that look suspicious.
    """
    events = []

    # 1. Employee travelling — login from different countries on different days
    events.extend(_travelling_employee(rng, entities, start_date))

    # 2. Admin doing bulk file access during a planned migration
    events.extend(_admin_migration(rng, entities, start_date))

    # 3. Nightly backup copying many files (already in benign, but add extra volume)
    events.extend(_extra_backup_volume(rng, entities, start_date))

    # 4. New employee with no baseline — lots of first-time activities
    events.extend(_new_employee(rng, entities, start_date))

    # 5. Forgotten password burst — several failures then success
    events.extend(_forgotten_password(rng, entities, start_date))

    return events


def _travelling_employee(rng: random.Random, entities: dict, start_date: datetime) -> list[dict]:
    """Employee travels to UK, then Germany over 5 days. Should NOT alert."""
    events = []
    # Pick a user who normally works from US
    us_users = [u for u in entities["users"] if u.typical_geo == "US" and not u.is_service_account]
    traveller = rng.choice(us_users[:5])
    host = traveller.typical_hosts[0] if traveller.typical_hosts else "WKS-005"

    travel_schedule = [
        (8, "UK", "82.132.45.67"),   # Day 8: UK
        (9, "UK", "82.132.45.67"),   # Day 9: UK
        (10, "DE", "91.64.112.33"),  # Day 10: Germany
        (11, "DE", "91.64.112.33"),  # Day 11: Germany
        (12, "US", ""),              # Day 12: Back in US
    ]

    for day_off, country, vpn_ip in travel_schedule:
        day = start_date + timedelta(days=day_off)
        src_ip = vpn_ip if vpn_ip else "10.0.1.50"

        # Normal login during business hours
        login_time = day.replace(hour=rng.randint(8, 10), minute=rng.randint(0, 59))
        events.append(_make_event(
            timestamp=login_time, event_type="login_success",
            user=traveller.username, host=host, src_ip=src_ip,
            geo_country=country, app="vpn_client", status="success",
            label="benign_travel",
        ))

        # Normal work activity
        for _ in range(rng.randint(3, 8)):
            t = day.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59))
            events.append(_make_event(
                timestamp=t, event_type="file_access",
                user=traveller.username, host=host, src_ip=src_ip,
                file_path=rng.choice(entities["file_paths_normal"]).replace("{user}", traveller.username),
                app="word", geo_country=country,
                label="benign_travel",
            ))

    return events


def _admin_migration(rng: random.Random, entities: dict, start_date: datetime) -> list[dict]:
    """Admin doing bulk file access during a server migration. Should NOT alert."""
    events = []
    admins = [u for u in entities["users"] if u.is_admin]
    if not admins:
        return events
    admin = rng.choice(admins)
    servers = [h for h in entities["hosts"] if h.host_type == "server"]

    # Migration on day 18, during work hours
    migration_day = start_date + timedelta(days=18)

    for server in rng.sample(servers, min(3, len(servers))):
        # Access 50-100 files per server (migration)
        for i in range(rng.randint(50, 100)):
            t = migration_day.replace(
                hour=rng.randint(10, 16), minute=rng.randint(0, 59), second=rng.randint(0, 59)
            )
            events.append(_make_event(
                timestamp=t, event_type="file_copy",
                user=admin.username, host=server.hostname,
                src_ip=server.ip,
                file_path=f"\\\\{server.hostname}\\migration\\batch_{i:03d}.dat",
                bytes_transferred=rng.randint(100000, 10000000),
                app="robocopy",
                label="benign_migration",
            ))

        # Privilege change (normal for admin during migration)
        t = migration_day.replace(hour=10, minute=rng.randint(0, 30))
        events.append(_make_event(
            timestamp=t, event_type="privilege_change",
            user=admin.username, host=server.hostname,
            src_ip=server.ip, app="active_directory",
            status="granted",
            label="benign_migration",
        ))

    return events


def _extra_backup_volume(rng: random.Random, entities: dict, start_date: datetime) -> list[dict]:
    """Extra-large nightly backup on day 22 (quarterly). Should NOT alert."""
    events = []
    backup_day = start_date + timedelta(days=22)
    servers = [h for h in entities["hosts"] if h.host_type in ("server", "database_server")]

    for server in servers:
        t = backup_day.replace(hour=2, minute=rng.randint(0, 30))
        # Very large transfer
        events.append(_make_event(
            timestamp=t, event_type="file_copy",
            user="svc_backup", host=server.hostname,
            src_ip="10.0.0.5",
            file_path=f"\\\\backup\\quarterly\\{server.hostname}_full.bak",
            bytes_transferred=rng.randint(2000000000, 5000000000),  # 2-5 GB
            app="backup_agent",
            label="benign_backup",
        ))
        events.append(_make_event(
            timestamp=t + timedelta(minutes=rng.randint(30, 90)),
            event_type="network_conn",
            user="svc_backup", host=server.hostname,
            src_ip=server.ip, dst_ip="10.0.10.1",
            bytes_transferred=rng.randint(2000000000, 5000000000),
            app="backup_agent",
            label="benign_backup",
        ))

    return events


def _new_employee(rng: random.Random, entities: dict, start_date: datetime) -> list[dict]:
    """New employee on day 25 — lots of first-time activities. Should NOT alert."""
    events = []
    # Simulate new employee who wasn't in baseline period
    new_user = "tnewman"
    new_host = "WKS-048"
    new_ip = "10.0.4.100"

    for day in range(25, 30):
        work_day = start_date + timedelta(days=day)

        # Login (first-ever logins)
        t = work_day.replace(hour=rng.randint(8, 10), minute=rng.randint(0, 59))
        events.append(_make_event(
            timestamp=t, event_type="login_success",
            user=new_user, host=new_host, src_ip=new_ip,
            geo_country="US", app="windows_login",
            label="benign_new_employee",
        ))

        # Access many files for the first time (onboarding)
        for _ in range(rng.randint(10, 25)):
            ft = work_day.replace(hour=rng.randint(9, 17), minute=rng.randint(0, 59))
            events.append(_make_event(
                timestamp=ft, event_type="file_access",
                user=new_user, host=new_host, src_ip=new_ip,
                file_path=rng.choice(entities["file_paths_normal"]).replace("{user}", new_user),
                app=rng.choice(["word", "excel", "chrome"]),
                geo_country="US",
                label="benign_new_employee",
            ))

        # Account changes (being set up)
        if day == 25:
            events.append(_make_event(
                timestamp=work_day.replace(hour=9, minute=0),
                event_type="account_create",
                user="admin_setup", host="DC-001",
                src_ip="10.0.0.10",
                app="active_directory",
                label="benign_new_employee",
            ))

    return events


def _forgotten_password(rng: random.Random, entities: dict, start_date: datetime) -> list[dict]:
    """User forgets password — 3-4 failures then success. Should NOT alert."""
    events = []
    users = [u for u in entities["users"] if not u.is_service_account]
    user = rng.choice(users[15:25])
    host = user.typical_hosts[0] if user.typical_hosts else "WKS-015"
    host_obj = next((h for h in entities["hosts"] if h.hostname == host), None)
    src_ip = host_obj.ip if host_obj else "10.0.1.100"

    forgot_day = start_date + timedelta(days=14)
    t = forgot_day.replace(hour=rng.randint(8, 9), minute=rng.randint(0, 30))

    # 3-4 failures
    for i in range(rng.randint(3, 4)):
        events.append(_make_event(
            timestamp=t + timedelta(seconds=i * rng.randint(10, 30)),
            event_type="login_failure",
            user=user.username, host=host, src_ip=src_ip,
            app="windows_login", status="failed_password",
            geo_country=user.typical_geo,
            label="benign_forgotten_password",
        ))

    # Success after password reset
    events.append(_make_event(
        timestamp=t + timedelta(minutes=rng.randint(5, 15)),
        event_type="login_success",
        user=user.username, host=host, src_ip=src_ip,
        app="windows_login", status="success",
        geo_country=user.typical_geo,
        label="benign_forgotten_password",
    ))

    return events
