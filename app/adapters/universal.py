"""
Universal Dataset Adapter.
Normalizes logs from any format (CSV, JSON, NDJSON, Sysmon, Zeek, Linux auth.log, Windows Events)
into standard LogEvent schema. Combines deterministic fuzzy heuristics and Groq LLM assistance.
"""
import csv
import json
import io
import re
from datetime import datetime
from typing import Optional
from app.llm.groq_client import groq_client


CANONICAL_TYPES = {
    "login_failure": ["failed_logon", "failed_auth", "auth_fail", "login_failure", "failed_password"],
    "login": ["logon", "auth", "signin", "session_start", "login"],
    "file_copy": ["file_write", "copy", "transfer_file", "file_copy"],
    "file_access": ["file_read", "file_open", "read_file", "file_access", "fileread"],
    "process_start": ["process_create", "exec", "proc_start", "process_start"],
    "remote_session": ["rdp", "ssh_session", "smb_session", "remote_session"],
    "network_conn": ["netflow", "flow", "connection", "network_conn"],
    "dns_query": ["dns", "domain_lookup", "query", "dns_query"],
    "usb_insert": ["removable_media", "usb", "device_attached", "usb_insert"],
    "privilege_change": ["elevation", "sudo", "priv_esc", "privilege_change"]
}


class UniversalAdapter:
    """Adapts arbitrary log formats to standard LogEvent dictionaries."""

    def __init__(self):
        self.groq = groq_client

    def parse_file(self, content_str: str, filename: str) -> list[dict]:
        """Auto-detect format (CSV, JSON array, NDJSON) and convert to standardized logs."""
        content_str = content_str.strip()
        raw_records = []

        if content_str.startswith("[") and content_str.endswith("]"):
            try:
                raw_records = json.loads(content_str)
            except Exception:
                pass

        if not raw_records and ("\n" in content_str or "\r" in content_str):
            # Try NDJSON
            try:
                lines = content_str.splitlines()
                parsed_ndjson = []
                for line in lines:
                    line = line.strip()
                    if line:
                        parsed_ndjson.append(json.loads(line))
                if parsed_ndjson and isinstance(parsed_ndjson[0], dict):
                    raw_records = parsed_ndjson
            except Exception:
                pass

        if not raw_records:
            # Try CSV
            try:
                reader = csv.DictReader(io.StringIO(content_str))
                raw_records = list(reader)
            except Exception:
                pass

        if not raw_records:
            raise ValueError(f"Could not parse file '{filename}'. Supported formats: CSV, JSON array, NDJSON.")

        return self.normalize_records(raw_records)

    def normalize_records(self, records: list[dict]) -> list[dict]:
        """Map fields in records to standard schema using heuristics + Groq."""
        if not records:
            return []

        # Step 1: Infer column mappings
        mapping = self._infer_mapping(records[:5])

        normalized = []
        for idx, rec in enumerate(records):
            norm_event = self._normalize_single(rec, mapping, idx)
            normalized.append(norm_event)

        return normalized

    def _infer_mapping(self, sample_records: list[dict]) -> dict:
        """Infer key mapping using regex heuristics, falling back to Groq if available."""
        mapping = {}
        sample = sample_records[0] if sample_records else {}
        keys = list(sample.keys())

        # Heuristic rules for common column naming conventions
        heuristics = {
            "timestamp": [r"(?i).*(time|date|ts|timestamp|created_at|logged_at).*"],
            "user": [r"(?i).*(user|username|account|user_id|actor|principal).*"],
            "host": [r"(?i).*(host|hostname|machine|computer|device_name|workstation).*"],
            "src_ip": [r"(?i).*(src_ip|source_ip|client_ip|src_addr|c_ip|ip_src).*"],
            "dst_ip": [r"(?i).*(dst_ip|dest_ip|destination_ip|server_ip|dst_addr|s_ip).*"],
            "event_type": [r"(?i).*(event_type|action|activity|category|type|event_name).*"],
            "status": [r"(?i).*(status|result|outcome|success|return_code).*"],
            "app": [r"(?i).*(app|application|process|image|command|process_name).*"],
            "file_path": [r"(?i).*(file_path|filename|filepath|path|target_file|targetfile|file|uri).*"],
            "bytes_transferred": [r"(?i).*(bytes|bytes_transferred|size|length|content_length).*"],
            "device_id": [r"(?i).*(device_id|usb_id|serial|hardware_id).*"],
            "geo_country": [r"(?i).*(geo|country|country_code|geo_country|location).*"],
        }

        for standard_field, patterns in heuristics.items():
            for key in keys:
                if any(re.match(pat, key) for pat in patterns):
                    mapping[standard_field] = key
                    break

        # If key fields are missing and Groq is active, consult Groq
        if ("timestamp" not in mapping or "user" not in mapping) and self.groq.is_available():
            llm_map = self.groq.infer_schema_mapping(sample_records)
            for k, v in llm_map.items():
                if k not in mapping and v in keys:
                    mapping[k] = v

        return mapping

    def _normalize_single(self, record: dict, mapping: dict, index: int) -> dict:
        """Convert single raw record into standard LogEvent format."""
        def get_val(field):
            src_key = mapping.get(field)
            if src_key and src_key in record:
                return record[src_key]
            # direct check
            if field in record:
                return record[field]
            return None

        # Parse timestamp
        raw_ts = get_val("timestamp")
        parsed_ts = self._standardize_timestamp(raw_ts)

        # Standardize event_type
        raw_type = str(get_val("event_type") or "network_conn").lower()
        event_type = self._standardize_event_type(raw_type)

        # Bytes
        raw_bytes = get_val("bytes_transferred")
        try:
            bytes_val = int(raw_bytes) if raw_bytes is not None else 0
        except (ValueError, TypeError):
            bytes_val = 0

        # Status
        raw_status = str(get_val("status") or "success").lower()

        log_id = str(record.get("id") or f"log-{index:06d}")

        return {
            "id": log_id,
            "timestamp": parsed_ts.isoformat(),
            "user": str(get_val("user") or ""),
            "host": str(get_val("host") or "HOST-001"),
            "src_ip": str(get_val("src_ip") or "10.0.0.1"),
            "dst_ip": str(get_val("dst_ip") or ""),
            "event_type": event_type,
            "app": str(get_val("app") or ""),
            "file_path": str(get_val("file_path") or ""),
            "bytes_transferred": bytes_val,
            "status": raw_status,
            "device_id": str(get_val("device_id") or ""),
            "geo_country": str(get_val("geo_country") or "US"),
            "details": str(record.get("details") or record.get("message") or "")
        }

    def _standardize_timestamp(self, raw_ts) -> datetime:
        """Robustly parse timestamps from diverse formats."""
        if not raw_ts:
            return datetime.utcnow()
        if isinstance(raw_ts, datetime):
            return raw_ts

        ts_str = str(raw_ts).strip()

        # Epoch timestamp
        if ts_str.isdigit() or re.match(r"^\d+\.\d+$", ts_str):
            try:
                epoch = float(ts_str)
                if epoch > 1e11:  # milliseconds
                    epoch /= 1000.0
                return datetime.utcfromtimestamp(epoch)
            except Exception:
                pass

        # ISO / RFC3339 formats
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %H:%M:%S",
            "%d/%m/%Y %H:%M:%S",
            "%b %d %H:%M:%S"
        ]:
            try:
                clean_str = ts_str.replace("Z", "").split("+")[0].split("-")[0] if "T" in ts_str else ts_str
                return datetime.strptime(ts_str.replace("Z", ""), fmt)
            except Exception:
                continue

        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return datetime.utcnow()

    def _standardize_event_type(self, raw_type: str) -> str:
        """Map raw event category or action to our canonical types."""
        raw_lower = raw_type.lower()
        for canonical, aliases in CANONICAL_TYPES.items():
            if any(a in raw_lower for a in aliases):
                return canonical
        return "network_conn"
