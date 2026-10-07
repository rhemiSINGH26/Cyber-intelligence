"""
Synthetic entity generator: users, hosts, IPs, apps, file paths, devices.
Creates a realistic corporate environment with roles, departments, and asset types.
"""
import random
from dataclasses import dataclass, field


@dataclass
class SimUser:
    username: str
    full_name: str
    department: str
    role: str
    is_admin: bool = False
    is_service_account: bool = False
    typical_hosts: list[str] = field(default_factory=list)
    typical_geo: str = "US"
    work_start_hour: int = 8
    work_end_hour: int = 18


@dataclass
class SimHost:
    hostname: str
    host_type: str  # workstation, server, domain_controller, database_server
    os: str = "Windows 10"
    department: str = ""
    ip: str = ""


def generate_entities(rng: random.Random, num_users: int = 40, num_hosts: int = 50):
    """
    Generate a full corporate environment.
    Returns dict with users, hosts, internal_ips, external_ips, apps, file_paths, devices, countries.
    """
    departments = ["Engineering", "Finance", "HR", "Sales", "IT", "Legal", "Executive", "Marketing", "Operations"]
    roles = {
        "Engineering": ["developer", "senior_dev", "tech_lead", "devops"],
        "Finance": ["analyst", "accountant", "controller", "cfo_assistant"],
        "HR": ["recruiter", "hr_manager", "benefits_admin"],
        "Sales": ["sales_rep", "account_exec", "sales_manager"],
        "IT": ["sysadmin", "network_admin", "security_analyst", "helpdesk"],
        "Legal": ["paralegal", "attorney", "compliance_officer"],
        "Executive": ["ceo", "cto", "cfo", "vp"],
        "Marketing": ["content_writer", "seo_specialist", "marketing_manager"],
        "Operations": ["ops_manager", "procurement", "facilities"],
    }

    first_names = [
        "james", "mary", "john", "patricia", "robert", "jennifer", "michael", "linda",
        "david", "elizabeth", "william", "barbara", "richard", "susan", "joseph", "jessica",
        "thomas", "sarah", "charles", "karen", "daniel", "lisa", "matthew", "nancy",
        "anthony", "betty", "mark", "margaret", "steven", "sandra", "paul", "ashley",
        "andrew", "dorothy", "joshua", "kimberly", "kenneth", "emily", "kevin", "donna",
        "brian", "michelle", "george", "carol", "timothy", "amanda", "ronald", "melissa",
        "edward", "deborah",
    ]
    last_names = [
        "smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis",
        "rodriguez", "martinez", "hernandez", "lopez", "gonzalez", "wilson", "anderson",
        "thomas", "taylor", "moore", "jackson", "martin", "lee", "perez", "thompson",
        "white", "harris", "sanchez", "clark", "ramirez", "lewis", "robinson", "walker",
        "young", "allen", "king", "wright", "scott", "torres", "nguyen", "hill", "flores",
        "green", "adams", "nelson", "baker", "hall", "rivera", "campbell", "mitchell", "carter",
    ]

    # --- Users ---
    users = []
    used_usernames = set()
    for i in range(num_users):
        dept = rng.choice(departments)
        role = rng.choice(roles[dept])
        fn = rng.choice(first_names)
        ln = rng.choice(last_names)
        username = f"{fn[0]}{ln}"
        while username in used_usernames:
            username = f"{fn[0]}{ln}{rng.randint(1, 99)}"
        used_usernames.add(username)

        is_admin = role in ["sysadmin", "network_admin", "security_analyst", "devops", "cto"]
        work_start = rng.choice([7, 8, 9]) if not role.startswith("ceo") else rng.choice([6, 7, 8])
        work_end = work_start + rng.choice([8, 9, 10])
        geo = rng.choice(["US", "US", "US", "US", "UK", "DE", "CA", "IN"])

        users.append(SimUser(
            username=username,
            full_name=f"{fn.capitalize()} {ln.capitalize()}",
            department=dept,
            role=role,
            is_admin=is_admin,
            typical_geo=geo,
            work_start_hour=work_start,
            work_end_hour=min(work_end, 22),
        ))

    # Add service accounts
    service_accounts = [
        SimUser("svc_backup", "Backup Service", "IT", "service", is_service_account=True, typical_geo="US"),
        SimUser("backup_admin", "Backup Admin Service", "IT", "service", is_service_account=True, typical_geo="US"),
        SimUser("nightly_sync", "Nightly Sync Service", "IT", "service", is_service_account=True, typical_geo="US"),
        SimUser("svc_monitor", "Monitoring Service", "IT", "service", is_service_account=True, typical_geo="US"),
        SimUser("svc_deploy", "Deployment Service", "Engineering", "service", is_service_account=True, typical_geo="US"),
    ]
    users.extend(service_accounts)

    # --- Hosts ---
    hosts = []
    host_types_pool = (
        [("workstation", "Windows 10")] * 30 +
        [("workstation", "Windows 11")] * 10 +
        [("server", "Windows Server 2019")] * 5 +
        [("server", "Ubuntu 22.04")] * 3 +
        [("domain_controller", "Windows Server 2022")] * 2 +
        [("database_server", "Windows Server 2019")] * 2
    )
    rng.shuffle(host_types_pool)

    for i in range(num_hosts):
        ht = host_types_pool[i % len(host_types_pool)]
        prefix = {"workstation": "WKS", "server": "SRV", "domain_controller": "DC", "database_server": "DB"}
        hostname = f"{prefix[ht[0]]}-{i+1:03d}"
        dept = rng.choice(departments) if ht[0] == "workstation" else "IT"
        ip = f"10.{rng.randint(0, 5)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"

        hosts.append(SimHost(
            hostname=hostname,
            host_type=ht[0],
            os=ht[1],
            department=dept,
            ip=ip,
        ))

    # Assign typical hosts to users (2-3 each)
    workstations = [h for h in hosts if h.host_type == "workstation"]
    for user in users:
        if user.is_service_account:
            user.typical_hosts = [h.hostname for h in hosts if h.host_type == "server"][:3]
        else:
            assigned = rng.sample(workstations, min(rng.randint(1, 3), len(workstations)))
            user.typical_hosts = [h.hostname for h in assigned]

    # --- IPs ---
    internal_ips = [h.ip for h in hosts]
    external_ips_normal = [f"{rng.randint(40, 200)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}" for _ in range(30)]
    external_ips_rare = [f"{rng.randint(185, 195)}.{rng.randint(100, 200)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}" for _ in range(10)]
    external_ips_malicious = [f"198.51.{rng.randint(100, 200)}.{rng.randint(1, 254)}" for _ in range(5)]

    # --- Apps ---
    apps = [
        "outlook", "chrome", "firefox", "edge", "teams", "slack", "vscode",
        "excel", "word", "powerpoint", "cmd.exe", "powershell.exe", "python.exe",
        "ssh", "rdp_client", "smb", "ftp_client", "vpn_client", "sap", "jira",
        "git", "docker", "sqlplus", "pgadmin", "notepad++", "zoom",
    ]

    # --- File paths ---
    file_paths_normal = [
        "C:\\Users\\{user}\\Documents\\report.docx",
        "C:\\Users\\{user}\\Documents\\quarterly_review.xlsx",
        "C:\\Users\\{user}\\Downloads\\meeting_notes.pdf",
        "\\\\fileserver\\shared\\department\\guidelines.pdf",
        "\\\\fileserver\\shared\\templates\\expense_report.xlsx",
        "\\\\fileserver\\shared\\training\\onboarding.pptx",
        "C:\\Users\\{user}\\Desktop\\todo.txt",
        "C:\\Program Files\\App\\config.ini",
    ]
    file_paths_sensitive = [
        "\\\\fileserver\\finance\\payroll\\employee_salaries_2025.xlsx",
        "\\\\fileserver\\finance\\budgets\\q4_projections.xlsx",
        "\\\\fileserver\\hr\\personnel\\employee_records.csv",
        "\\\\fileserver\\legal\\contracts\\vendor_agreements.pdf",
        "\\\\fileserver\\engineering\\source\\proprietary_algorithm.py",
        "\\\\fileserver\\executive\\strategy\\merger_plans.docx",
        "\\\\dbserver\\backups\\customer_database.bak",
        "\\\\fileserver\\security\\audit_logs\\access_log.csv",
        "\\\\fileserver\\finance\\tax\\corporate_tax_2025.pdf",
        "\\\\fileserver\\hr\\benefits\\insurance_details.xlsx",
    ]

    # --- Devices ---
    devices = [f"USB-{rng.randint(1000, 9999)}" for _ in range(15)]

    # --- Countries ---
    normal_countries = ["US", "UK", "DE", "CA", "FR", "IN", "JP", "AU"]
    suspicious_countries = ["RU", "CN", "KP", "IR", "NG", "RO"]

    return {
        "users": users,
        "hosts": hosts,
        "internal_ips": internal_ips,
        "external_ips_normal": external_ips_normal,
        "external_ips_rare": external_ips_rare,
        "external_ips_malicious": external_ips_malicious,
        "apps": apps,
        "file_paths_normal": file_paths_normal,
        "file_paths_sensitive": file_paths_sensitive,
        "devices": devices,
        "normal_countries": normal_countries,
        "suspicious_countries": suspicious_countries,
    }
