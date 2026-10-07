"""
Centralized configuration for the CTI system.
All detection thresholds, time windows, weights, and paths live here.
Adjust these to tune detection sensitivity vs false-positive rate.
"""
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Server ---
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True

    # --- Database ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/cti.db"

    # --- Paths ---
    DATA_DIR: Path = Path("./data")
    GENERATED_DIR: Path = Path("./data/generated")
    UPLOAD_DIR: Path = Path("./data/uploads")
    WATCHED_DIR: Path = Path("./data/watched")

    # --- Groq LLM (optional) ---
    GROQ_API_KEY: Optional[str] = None
    GROQ_MODEL: str = "qwen/qwen3.8-27b"

    # --- Simulation ---
    RANDOM_SEED: int = 42
    NUM_USERS: int = 40
    NUM_HOSTS: int = 50
    NUM_DAYS: int = 30
    WORK_HOUR_START: int = 8
    WORK_HOUR_END: int = 18

    # --- Baseline ---
    BASELINE_TRAINING_DAYS: int = 7  # First N days used for baseline learning
    MIN_OBSERVATIONS_FOR_BASELINE: int = 5  # Minimum events before anomaly scoring
    PEER_GROUP_SIZE: int = 5  # Number of peers for comparison

    # --- Detection Thresholds ---
    # Brute force: N failures within T seconds from same source
    BRUTE_FORCE_THRESHOLD: int = 5
    BRUTE_FORCE_WINDOW_SECONDS: int = 600  # 10 minutes

    # Login anomaly
    LOGIN_GEO_ANOMALY_ENABLED: bool = True
    LOGIN_TIME_ANOMALY_ZSCORE: float = 2.5  # Z-score threshold for unusual hours

    # File access anomaly
    FILE_ACCESS_BURST_THRESHOLD: int = 20  # Files in a short window
    FILE_ACCESS_BURST_WINDOW_SECONDS: int = 300  # 5 minutes
    FILE_NOVELTY_RATIO_THRESHOLD: float = 0.7  # % of files never accessed before

    # Data exfiltration
    EXFIL_BYTES_ZSCORE: float = 3.0  # Z-score for outbound bytes
    EXFIL_MIN_BYTES: int = 50_000_000  # 50 MB minimum for alert
    EXFIL_RARE_IP_THRESHOLD: int = 2  # IP seen fewer than N times = rare

    # USB
    USB_AFTER_MASS_FILE_ACCESS_WINDOW: int = 1800  # 30 min

    # Privilege escalation
    PRIV_ESC_UNUSUAL_HOUR: bool = True
    PRIV_ESC_NON_ADMIN_USER: bool = True

    # Lateral movement
    LATERAL_MOVEMENT_NEW_HOST_THRESHOLD: int = 3  # N new hosts in window
    LATERAL_MOVEMENT_WINDOW_SECONDS: int = 3600  # 1 hour
    LATERAL_MOVEMENT_PROTOCOLS: list = ["rdp", "smb", "ssh", "wmi", "psexec"]

    # DNS tunneling
    DNS_QUERY_LENGTH_THRESHOLD: int = 50  # Unusually long DNS query
    DNS_QUERY_RATE_THRESHOLD: int = 100  # Queries per minute
    DNS_QUERY_RATE_WINDOW: int = 60  # seconds
    DNS_ENTROPY_THRESHOLD: float = 3.5  # Shannon entropy of subdomain

    # --- Anomaly ML ---
    ISOLATION_FOREST_CONTAMINATION: float = 0.05
    ISOLATION_FOREST_N_ESTIMATORS: int = 200
    ANOMALY_SCORE_THRESHOLD: float = -0.3  # IF score below this = anomalous
    ZSCORE_THRESHOLD: float = 2.5
    EWMA_ALPHA: float = 0.3  # Smoothing factor (lower = longer memory)

    # --- Cumulative / Slow Attack ---
    CUMULATIVE_EWMA_ALPHA: float = 0.05  # Very slow decay for long-term scoring
    CUMULATIVE_THRESHOLD: float = 15.0  # Cumulative anomaly score trigger
    CUMULATIVE_WINDOW_DAYS: int = 14  # Window for slow attack detection

    # --- Correlation ---
    SHORT_CORRELATION_WINDOW_HOURS: int = 4  # Fast attack linking
    LONG_CORRELATION_WINDOW_HOURS: int = 336  # 14 days for slow attacks
    MIN_SHARED_ENTITIES: int = 1  # Minimum shared entities to link
    MIN_STAGES_FOR_INCIDENT: int = 2  # Minimum kill-chain stages
    STAGE_ORDER_WEIGHT: float = 0.3  # Weight for correct stage ordering in scoring

    # --- Risk Scoring ---
    RISK_THRESHOLD_INCIDENT: int = 40  # Minimum risk to promote to incident
    RISK_STAGE_WEIGHTS: dict = {
        "initial_access": 15,
        "credential_access": 15,
        "execution": 20,
        "persistence": 20,
        "privilege_escalation": 25,
        "lateral_movement": 25,
        "collection": 15,
        "exfiltration": 30,
        "defense_evasion": 15,
    }
    CONFIDENCE_MIN: float = 0.3  # Minimum confidence to report
    ASSET_CRITICALITY_MULTIPLIER: dict = {
        "server": 1.5,
        "workstation": 1.0,
        "domain_controller": 2.0,
        "database_server": 1.8,
    }

    # --- Suppression ---
    MAINTENANCE_WINDOW_START: int = 2  # 2 AM
    MAINTENANCE_WINDOW_END: int = 4  # 4 AM
    BACKUP_SERVICE_ACCOUNTS: list = ["svc_backup", "backup_admin", "nightly_sync"]
    ADMIN_USERS: list = []  # Populated during baseline
    PEER_NORMAL_DEVIATION_FACTOR: float = 2.0  # Times the peer average

    # --- Streaming ---
    DEFAULT_REPLAY_SPEED: float = 60.0  # 1 real second = 60 seconds of logs
    STREAM_BATCH_SIZE: int = 50  # Logs per batch push
    DETECTION_WINDOW_SIZE: int = 500  # Sliding window for incremental detection

    # --- API ---
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500
    CORS_ORIGINS: list = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8080",
    ]

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        extra = "ignore"


# Global singleton
settings = Settings()

# Ensure directories exist
for dir_path in [settings.DATA_DIR, settings.GENERATED_DIR, settings.UPLOAD_DIR, settings.WATCHED_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)


# --- MITRE ATT&CK Mapping ---
MITRE_TACTICS = {
    "initial_access": {"id": "TA0001", "name": "Initial Access"},
    "execution": {"id": "TA0002", "name": "Execution"},
    "persistence": {"id": "TA0003", "name": "Persistence"},
    "privilege_escalation": {"id": "TA0004", "name": "Privilege Escalation"},
    "defense_evasion": {"id": "TA0005", "name": "Defense Evasion"},
    "credential_access": {"id": "TA0006", "name": "Credential Access"},
    "lateral_movement": {"id": "TA0008", "name": "Lateral Movement"},
    "collection": {"id": "TA0009", "name": "Collection"},
    "exfiltration": {"id": "TA0010", "name": "Exfiltration"},
}

MITRE_TECHNIQUES = {
    "brute_force": {"id": "T1110", "name": "Brute Force", "tactic": "credential_access"},
    "valid_accounts": {"id": "T1078", "name": "Valid Accounts", "tactic": "initial_access"},
    "external_remote_services": {"id": "T1133", "name": "External Remote Services", "tactic": "initial_access"},
    "phishing": {"id": "T1566", "name": "Phishing", "tactic": "initial_access"},
    "command_scripting": {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"},
    "scheduled_task": {"id": "T1053", "name": "Scheduled Task/Job", "tactic": "persistence"},
    "create_account": {"id": "T1136", "name": "Create Account", "tactic": "persistence"},
    "abuse_elevation": {"id": "T1548", "name": "Abuse Elevation Control", "tactic": "privilege_escalation"},
    "access_token_manipulation": {"id": "T1134", "name": "Access Token Manipulation", "tactic": "privilege_escalation"},
    "remote_services": {"id": "T1021", "name": "Remote Services", "tactic": "lateral_movement"},
    "lateral_tool_transfer": {"id": "T1570", "name": "Lateral Tool Transfer", "tactic": "lateral_movement"},
    "data_staged": {"id": "T1074", "name": "Data Staged", "tactic": "collection"},
    "data_from_local": {"id": "T1005", "name": "Data from Local System", "tactic": "collection"},
    "archive_collected": {"id": "T1560", "name": "Archive Collected Data", "tactic": "collection"},
    "exfil_over_c2": {"id": "T1041", "name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    "exfil_over_web": {"id": "T1567", "name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
    "exfil_over_alt_protocol": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "exfiltration"},
    "removable_media_exfil": {"id": "T1052", "name": "Exfiltration Over Physical Medium", "tactic": "exfiltration"},
    "dns_tunneling": {"id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "exfiltration"},
    "usb_device": {"id": "T1200", "name": "Hardware Additions", "tactic": "initial_access"},
}

# Kill-chain stage ordering (lower = earlier in attack lifecycle)
KILL_CHAIN_ORDER = {
    "initial_access": 1,
    "credential_access": 2,
    "execution": 3,
    "persistence": 4,
    "privilege_escalation": 5,
    "defense_evasion": 6,
    "lateral_movement": 7,
    "collection": 8,
    "exfiltration": 9,
}
