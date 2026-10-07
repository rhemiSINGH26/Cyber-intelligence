"""
Attack scenario injectors.
Each function injects a multi-stage attack into the event stream with ground-truth labels.
Attacks are interleaved with benign events and use realistic entity names.
"""
import random
from datetime import datetime, timedelta
from app.simulation.benign import _make_event, _make_time
import uuid


def inject_insider_data_theft(
    rng: random.Random,
    entities: dict,
    start_date: datetime,
    day_offset: int = 12,
) -> tuple[list[dict], dict]:
    """
    Attack 1: Insider data theft.
    Stages: login from new country at odd hour -> access many sensitive files
    -> USB insert -> bulk file copy to USB.
    """
    # Pick a non-admin user as the insider
    normal_users = [u for u in entities["users"] if not u.is_service_account and not u.is_admin]
    attacker = rng.choice(normal_users[:10])
    host = attacker.typical_hosts[0] if attacker.typical_hosts else "WKS-001"
    host_obj = next((h for h in entities["hosts"] if h.hostname == host), None)
    src_ip = host_obj.ip if host_obj else "10.0.1.50"

    attack_day = start_date + timedelta(days=day_offset)
    events = []
    evidence_stages = {}

    # STAGE 1: Login from unusual country at odd hour (11 PM)
    unusual_geo = rng.choice(entities["suspicious_countries"])
    unusual_ip = rng.choice(entities["external_ips_rare"])
    login_time = attack_day.replace(hour=23, minute=rng.randint(0, 30))

    evt = _make_event(
        timestamp=login_time, event_type="login_success",
        user=attacker.username, host=host, src_ip=unusual_ip,
        geo_country=unusual_geo, app="vpn_client", status="success",
        label="attack_insider_theft",
    )
    events.append(evt)
    evidence_stages["initial_access"] = [evt["id"]]

    # STAGE 2: Access many never-before-seen sensitive files (25+ files in 20 min)
    sensitive_files = entities["file_paths_sensitive"]
    collection_ids = []
    for i in range(rng.randint(25, 40)):
        file_time = login_time + timedelta(minutes=rng.randint(5, 25))
        fp = rng.choice(sensitive_files)
        evt = _make_event(
            timestamp=file_time, event_type="file_access",
            user=attacker.username, host=host, src_ip=unusual_ip,
            file_path=fp, app="explorer.exe",
            bytes_transferred=rng.randint(50000, 5000000),
            geo_country=unusual_geo,
            label="attack_insider_theft",
        )
        events.append(evt)
        collection_ids.append(evt["id"])
    evidence_stages["collection"] = collection_ids

    # STAGE 3: USB insert
    usb_time = login_time + timedelta(minutes=30)
    usb_device = rng.choice(entities["devices"])
    evt = _make_event(
        timestamp=usb_time, event_type="usb_insert",
        user=attacker.username, host=host, src_ip=src_ip,
        device_id=usb_device,
        label="attack_insider_theft",
    )
    events.append(evt)
    evidence_stages["initial_access"].append(evt["id"])

    # STAGE 4: Bulk file copy to USB
    exfil_ids = []
    for i in range(rng.randint(20, 35)):
        copy_time = usb_time + timedelta(minutes=rng.randint(1, 15))
        fp = rng.choice(sensitive_files)
        evt = _make_event(
            timestamp=copy_time, event_type="file_copy",
            user=attacker.username, host=host, src_ip=src_ip,
            file_path=fp, device_id=usb_device,
            bytes_transferred=rng.randint(500000, 10000000),
            label="attack_insider_theft",
        )
        events.append(evt)
        exfil_ids.append(evt["id"])
    evidence_stages["exfiltration"] = exfil_ids

    ground_truth = {
        "attack_id": "insider_data_theft",
        "scenario": "Insider data theft via USB",
        "attacker": attacker.username,
        "hosts": [host],
        "stages": ["initial_access", "collection", "exfiltration"],
        "evidence": evidence_stages,
        "first_event": events[0]["timestamp"],
        "last_event": events[-1]["timestamp"],
        "description": (
            f"User {attacker.username} logged in from {unusual_geo} at an unusual hour, "
            f"accessed {len(collection_ids)} sensitive files, inserted USB {usb_device}, "
            f"and copied {len(exfil_ids)} files to the device."
        ),
    }

    return events, ground_truth


def inject_external_compromise(
    rng: random.Random,
    entities: dict,
    start_date: datetime,
    day_offset: int = 15,
) -> tuple[list[dict], dict]:
    """
    Attack 2: External compromise.
    Stages: brute-force -> success from malicious IP -> priv escalation
    -> lateral movement (RDP/SMB) -> large outbound exfiltration.
    """
    normal_users = [u for u in entities["users"] if not u.is_service_account and not u.is_admin]
    victim = rng.choice(normal_users[10:20])
    malicious_ip = rng.choice(entities["external_ips_malicious"])
    victim_host = victim.typical_hosts[0] if victim.typical_hosts else "WKS-010"
    host_obj = next((h for h in entities["hosts"] if h.hostname == victim_host), None)
    victim_ip = host_obj.ip if host_obj else "10.0.2.50"

    attack_day = start_date + timedelta(days=day_offset)
    events = []
    evidence_stages = {}

    # STAGE 1: Brute-force login failures (15-25 attempts in 5 min)
    bf_start = attack_day.replace(hour=3, minute=rng.randint(0, 30))
    cred_ids = []
    for i in range(rng.randint(15, 25)):
        t = bf_start + timedelta(seconds=rng.randint(1, 300))
        evt = _make_event(
            timestamp=t, event_type="login_failure",
            user=victim.username, host=victim_host, src_ip=malicious_ip,
            app="ssh", status="failed_password",
            geo_country="RU",
            label="attack_external_compromise",
        )
        events.append(evt)
        cred_ids.append(evt["id"])
    evidence_stages["credential_access"] = cred_ids

    # STAGE 2: Successful login from malicious IP
    success_time = bf_start + timedelta(minutes=rng.randint(6, 10))
    evt = _make_event(
        timestamp=success_time, event_type="login_success",
        user=victim.username, host=victim_host, src_ip=malicious_ip,
        app="ssh", status="success",
        geo_country="RU",
        label="attack_external_compromise",
    )
    events.append(evt)
    evidence_stages["initial_access"] = [evt["id"]]

    # STAGE 3: Privilege escalation
    priv_time = success_time + timedelta(minutes=rng.randint(5, 15))
    evt = _make_event(
        timestamp=priv_time, event_type="privilege_change",
        user=victim.username, host=victim_host, src_ip=malicious_ip,
        app="sudo", status="elevated_to_admin",
        label="attack_external_compromise",
    )
    events.append(evt)
    evidence_stages["privilege_escalation"] = [evt["id"]]

    # STAGE 4: Lateral movement to other hosts via RDP/SMB
    servers = [h for h in entities["hosts"] if h.host_type in ("server", "database_server")]
    lateral_targets = rng.sample(servers, min(4, len(servers)))
    lateral_ids = []
    for i, target in enumerate(lateral_targets):
        lat_time = priv_time + timedelta(minutes=rng.randint(10, 60))
        evt = _make_event(
            timestamp=lat_time, event_type="remote_session",
            user=victim.username, host=target.hostname,
            src_ip=victim_ip, dst_ip=target.ip,
            app=rng.choice(["rdp_client", "smb", "psexec"]),
            label="attack_external_compromise",
        )
        events.append(evt)
        lateral_ids.append(evt["id"])

        # Also process start on lateral target
        evt2 = _make_event(
            timestamp=lat_time + timedelta(seconds=30),
            event_type="process_start",
            user=victim.username, host=target.hostname,
            src_ip=victim_ip, app="cmd.exe",
            label="attack_external_compromise",
        )
        events.append(evt2)
        lateral_ids.append(evt2["id"])

    evidence_stages["lateral_movement"] = lateral_ids

    # STAGE 5: Large outbound data transfer
    exfil_time = priv_time + timedelta(hours=rng.randint(1, 3))
    rare_ext_ip = rng.choice(entities["external_ips_rare"])
    evt = _make_event(
        timestamp=exfil_time, event_type="network_conn",
        user=victim.username, host=lateral_targets[0].hostname if lateral_targets else victim_host,
        src_ip=victim_ip, dst_ip=rare_ext_ip,
        bytes_transferred=rng.randint(200000000, 800000000),  # 200MB - 800MB
        app="curl",
        label="attack_external_compromise",
    )
    events.append(evt)
    evidence_stages["exfiltration"] = [evt["id"]]

    ground_truth = {
        "attack_id": "external_compromise",
        "scenario": "External compromise via brute-force",
        "attacker": victim.username,
        "hosts": [victim_host] + [t.hostname for t in lateral_targets],
        "stages": ["credential_access", "initial_access", "privilege_escalation",
                    "lateral_movement", "exfiltration"],
        "evidence": evidence_stages,
        "first_event": events[0]["timestamp"],
        "last_event": events[-1]["timestamp"],
        "description": (
            f"Brute-force attack from {malicious_ip} targeting {victim.username}, "
            f"followed by privilege escalation, lateral movement to {len(lateral_targets)} hosts, "
            f"and large data exfiltration to {rare_ext_ip}."
        ),
    }

    return events, ground_truth


def inject_slow_credential_abuse(
    rng: random.Random,
    entities: dict,
    start_date: datetime,
    day_offset: int = 5,
) -> tuple[list[dict], dict]:
    """
    Attack 3: Slow and hidden (low-and-slow) credential abuse.
    Tiny anomalies spread over 10+ days that are only suspicious cumulatively.
    """
    normal_users = [u for u in entities["users"] if not u.is_service_account and not u.is_admin]
    victim = rng.choice(normal_users[20:30])
    victim_host = victim.typical_hosts[0] if victim.typical_hosts else "WKS-020"
    host_obj = next((h for h in entities["hosts"] if h.hostname == victim_host), None)
    victim_ip = host_obj.ip if host_obj else "10.0.3.50"

    events = []
    all_evidence = {}

    # Spread over 12 days
    for day in range(12):
        attack_day = start_date + timedelta(days=day_offset + day)

        # Day 0-3: Occasional login failures (1-2 per day, from slightly unusual IPs)
        if day < 4:
            num_failures = rng.randint(1, 2)
            cred_ids = all_evidence.get("credential_access", [])
            for _ in range(num_failures):
                t = attack_day.replace(hour=rng.randint(1, 5), minute=rng.randint(0, 59))
                evt = _make_event(
                    timestamp=t, event_type="login_failure",
                    user=victim.username, host=victim_host,
                    src_ip=rng.choice(entities["external_ips_rare"]),
                    app="vpn_client", status="failed_password",
                    label="attack_slow_credential",
                )
                events.append(evt)
                cred_ids.append(evt["id"])
            all_evidence["credential_access"] = cred_ids

        # Day 4-6: Access 2-3 sensitive files per day (just slightly above normal)
        if 4 <= day <= 6:
            col_ids = all_evidence.get("collection", [])
            for _ in range(rng.randint(2, 3)):
                t = attack_day.replace(
                    hour=rng.randint(victim.work_start_hour, victim.work_end_hour - 1),
                    minute=rng.randint(0, 59),
                )
                evt = _make_event(
                    timestamp=t, event_type="file_access",
                    user=victim.username, host=victim_host,
                    src_ip=victim_ip,
                    file_path=rng.choice(entities["file_paths_sensitive"]),
                    app="explorer.exe",
                    bytes_transferred=rng.randint(10000, 500000),
                    label="attack_slow_credential",
                )
                events.append(evt)
                col_ids.append(evt["id"])
            all_evidence["collection"] = col_ids

        # Day 7-9: Small data transfers (slightly elevated bytes)
        if 7 <= day <= 9:
            exfil_ids = all_evidence.get("exfiltration", [])
            t = attack_day.replace(
                hour=rng.randint(victim.work_start_hour, victim.work_end_hour - 1),
                minute=rng.randint(0, 59),
            )
            evt = _make_event(
                timestamp=t, event_type="network_conn",
                user=victim.username, host=victim_host,
                src_ip=victim_ip,
                dst_ip=rng.choice(entities["external_ips_rare"]),
                bytes_transferred=rng.randint(5000000, 15000000),  # 5-15 MB each
                app="chrome",
                label="attack_slow_credential",
            )
            events.append(evt)
            exfil_ids.append(evt["id"])
            all_evidence["exfiltration"] = exfil_ids

        # Day 10-11: DNS queries to unusual domains (subtle tunneling prep)
        if day >= 10:
            exfil_ids = all_evidence.get("exfiltration", [])
            for _ in range(rng.randint(3, 6)):
                t = attack_day.replace(
                    hour=rng.randint(victim.work_start_hour, victim.work_end_hour - 1),
                    minute=rng.randint(0, 59),
                )
                # Slightly suspicious but not obviously malicious
                subdomain = ''.join(rng.choices('abcdefghijklmnop0123456789', k=rng.randint(15, 25)))
                evt = _make_event(
                    timestamp=t, event_type="dns_query",
                    user=victim.username, host=victim_host,
                    src_ip=victim_ip,
                    file_path=f"{subdomain}.data-analytics-cdn.com",
                    app="dns_client",
                    label="attack_slow_credential",
                )
                events.append(evt)
                exfil_ids.append(evt["id"])
            all_evidence["exfiltration"] = exfil_ids

    ground_truth = {
        "attack_id": "slow_credential_abuse",
        "scenario": "Low-and-slow credential abuse over 12 days",
        "attacker": victim.username,
        "hosts": [victim_host],
        "stages": list(all_evidence.keys()),
        "evidence": all_evidence,
        "first_event": events[0]["timestamp"] if events else "",
        "last_event": events[-1]["timestamp"] if events else "",
        "description": (
            f"Slow credential abuse targeting {victim.username} over 12 days: "
            f"sporadic login failures, gradual sensitive file access, "
            f"small data transfers, and DNS-based data staging."
        ),
    }

    return events, ground_truth


def inject_service_account_compromise(
    rng: random.Random,
    entities: dict,
    start_date: datetime,
    day_offset: int = 20,
) -> tuple[list[dict], dict]:
    """
    Attack 4: Compromised service account.
    Service account used from a new host, stages data, then DNS-tunnelling exfiltration.
    """
    # Use a real service account but from unusual host
    svc_user = "svc_deploy"
    normal_host = "SRV-001"

    # Attack from a workstation (unusual for a service account)
    workstations = [h for h in entities["hosts"] if h.host_type == "workstation"]
    attack_host_obj = rng.choice(workstations[:5])
    attack_host = attack_host_obj.hostname
    attack_ip = attack_host_obj.ip

    attack_day = start_date + timedelta(days=day_offset)
    events = []
    evidence_stages = {}

    # STAGE 1: Service account login from unusual workstation
    login_time = attack_day.replace(hour=14, minute=rng.randint(0, 30))
    evt = _make_event(
        timestamp=login_time, event_type="login_success",
        user=svc_user, host=attack_host, src_ip=attack_ip,
        app="windows_login", status="success",
        label="attack_svc_compromise",
    )
    events.append(evt)
    evidence_stages["initial_access"] = [evt["id"]]

    # STAGE 2: Stage data — copy many files to a staging directory
    collection_ids = []
    for i in range(rng.randint(15, 30)):
        stage_time = login_time + timedelta(minutes=rng.randint(5, 45))
        fp = rng.choice(entities["file_paths_sensitive"])
        evt = _make_event(
            timestamp=stage_time, event_type="file_copy",
            user=svc_user, host=attack_host, src_ip=attack_ip,
            file_path=f"C:\\Windows\\Temp\\staging\\{i:03d}_{fp.split(chr(92))[-1]}",
            bytes_transferred=rng.randint(100000, 5000000),
            app="robocopy",
            label="attack_svc_compromise",
        )
        events.append(evt)
        collection_ids.append(evt["id"])
    evidence_stages["collection"] = collection_ids

    # STAGE 3: DNS tunnelling-like exfiltration (many encoded DNS queries)
    exfil_ids = []
    for i in range(rng.randint(50, 100)):
        dns_time = login_time + timedelta(minutes=rng.randint(50, 120))
        # Simulate encoded data in DNS subdomain
        encoded = ''.join(rng.choices('abcdef0123456789', k=rng.randint(40, 63)))
        evt = _make_event(
            timestamp=dns_time, event_type="dns_query",
            user=svc_user, host=attack_host, src_ip=attack_ip,
            file_path=f"{encoded}.exfil-c2-domain.com",
            app="dns_client",
            label="attack_svc_compromise",
        )
        events.append(evt)
        exfil_ids.append(evt["id"])
    evidence_stages["exfiltration"] = exfil_ids

    ground_truth = {
        "attack_id": "service_account_compromise",
        "scenario": "Compromised service account with DNS tunnelling",
        "attacker": svc_user,
        "hosts": [attack_host],
        "stages": ["initial_access", "collection", "exfiltration"],
        "evidence": evidence_stages,
        "first_event": events[0]["timestamp"],
        "last_event": events[-1]["timestamp"],
        "description": (
            f"Service account {svc_user} compromised and used from unusual host {attack_host}. "
            f"Staged {len(collection_ids)} files and exfiltrated via DNS tunnelling "
            f"({len(exfil_ids)} encoded queries to C2 domain)."
        ),
    }

    return events, ground_truth
