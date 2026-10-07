"""
Fleet and Node Telemetry Manager.
Supports live multi-laptop / node telemetry, heartbeat ingestion (compatible with
https://github.com/anish232006/live-4-laptop-module.git), dynamic node registration,
per-node log tracking, and real-time simulation.
"""
import time
import uuid
import threading
from datetime import datetime
from typing import Optional, Dict, Any, List

class FleetManager:
    def __init__(self):
        self._lock = threading.Lock()
        
        # Pre-seed default laptop nodes (LAPTOP-1 to LAPTOP-4)
        now = time.time()
        self.nodes: Dict[str, Dict[str, Any]] = {
            "LAPTOP-1": {
                "id": "LAPTOP-1",
                "name": "Executive Laptop (Alice)",
                "user": "alice",
                "os": "Windows 11 Pro 23H2",
                "ip": "192.168.1.101",
                "status": "normal",
                "risk": 15,
                "events": 24,
                "signals": 0,
                "last_seen": now - 3.5,
                "created_at": now - 3600,
                "is_default": True,
            },
            "LAPTOP-2": {
                "id": "LAPTOP-2",
                "name": "SecOps Workstation (Bob)",
                "user": "bob",
                "os": "Ubuntu 22.04 LTS Linux",
                "ip": "192.168.1.102",
                "status": "warning",
                "risk": 68,
                "events": 48,
                "signals": 2,
                "last_seen": now - 1.2,
                "created_at": now - 3600,
                "is_default": True,
            },
            "LAPTOP-3": {
                "id": "LAPTOP-3",
                "name": "Finance MacBook (Charlie)",
                "user": "charlie",
                "os": "macOS Sonoma 14.4",
                "ip": "192.168.1.103",
                "status": "normal",
                "risk": 8,
                "events": 16,
                "signals": 0,
                "last_seen": now - 5.0,
                "created_at": now - 3600,
                "is_default": True,
            },
            "LAPTOP-4": {
                "id": "LAPTOP-4",
                "name": "DevOps Node (Heidi)",
                "user": "heidi",
                "os": "Windows 10 Enterprise",
                "ip": "192.168.1.104",
                "status": "compromised",
                "risk": 92,
                "events": 82,
                "signals": 4,
                "last_seen": now - 2.1,
                "created_at": now - 3600,
                "is_default": True,
            },
        }

        # Per-node log buffer
        self.node_logs: Dict[str, List[Dict[str, Any]]] = {}
        for nid in self.nodes:
            self.node_logs[nid] = []
            # Seed initial telemetry log
            self._append_log_unlocked(
                nid,
                level="INFO",
                message=f"Node {nid} initialized and registered in Fleet Telemetry stream.",
                event_type="fleet_init",
                details={"ip": self.nodes[nid]["ip"], "os": self.nodes[nid]["os"]}
            )

        # Seed interesting logs for LAPTOP-2 and LAPTOP-4
        self._append_log_unlocked(
            "LAPTOP-2",
            level="WARN",
            message="Suspicious external DNS TXT query resolved (anomaly z=2.4)",
            event_type="dns_anomaly",
            details={"domain": "query.cdn-sync.net", "process": "curl"}
        )
        self._append_log_unlocked(
            "LAPTOP-4",
            level="CRIT",
            message="PowerShell encoded command execution with bypass flags detected",
            event_type="process_execution",
            details={"command": "powershell.exe -enc SQBFAFgA...", "pid": 4182}
        )

    def _append_log_unlocked(self, node_id: str, level: str, message: str, event_type: str = "telemetry", details: Optional[Dict] = None):
        if node_id not in self.node_logs:
            self.node_logs[node_id] = []
        
        log_entry = {
            "id": f"FLOG-{uuid.uuid4().hex[:8].upper()}",
            "node_id": node_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "message": message,
            "event_type": event_type,
            "details": details or {}
        }
        self.node_logs[node_id].append(log_entry)
        if len(self.node_logs[node_id]) > 250:
            self.node_logs[node_id] = self.node_logs[node_id][-250:]
        return log_entry

    def record_heartbeat(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests heartbeat from physical/simulated laptops running fleet_agent.py.
        Supports LAPTOP-1 to LAPTOP-4, plus any custom-added computer nodes.
        """
        raw_id = str(body.get("id", "")).strip().upper()
        if not raw_id:
            raise ValueError("Missing 'id' parameter in heartbeat payload.")

        now = time.time()
        with self._lock:
            # Auto-register if not yet existing
            if raw_id not in self.nodes:
                self.nodes[raw_id] = {
                    "id": raw_id,
                    "name": body.get("name") or f"Computer {raw_id}",
                    "user": body.get("user") or "unknown",
                    "os": body.get("os") or "Unknown OS",
                    "ip": body.get("ip") or "127.0.0.1",
                    "status": body.get("status") or "normal",
                    "risk": int(body.get("risk") or 0),
                    "events": int(body.get("events") or 0),
                    "signals": int(body.get("signals") or 0),
                    "last_seen": now,
                    "created_at": now,
                    "is_default": False,
                }
                self.node_logs[raw_id] = []
                self._append_log_unlocked(
                    raw_id,
                    level="INFO",
                    message=f"New computer node '{raw_id}' auto-registered via heartbeat.",
                    event_type="node_registered",
                    details={"ip": body.get("ip"), "os": body.get("os")}
                )

            node = self.nodes[raw_id]
            node["user"] = body.get("user") or node["user"]
            node["os"] = body.get("os") or node["os"]
            node["ip"] = body.get("ip") or node["ip"]
            node["status"] = body.get("status") or node["status"]
            node["events"] = node.get("events", 0) + 1
            if "signals" in body:
                node["signals"] = int(body["signals"])
            if "risk" in body:
                node["risk"] = int(body["risk"])
            node["last_seen"] = now

            # Record heartbeat log
            log_msg = body.get("log") or f"Heartbeat received from {node['user']}@{node['ip']} ({node['os']})"
            log_level = "CRIT" if node["status"] == "compromised" else ("WARN" if node["status"] == "warning" else "INFO")
            log_entry = self._append_log_unlocked(
                raw_id,
                level=log_level,
                message=log_msg,
                event_type="heartbeat",
                details={"status": node["status"], "risk": node["risk"]}
            )

        return {
            "status": "ok",
            "node_id": raw_id,
            "registered": True,
            "log_id": log_entry["id"],
            "server_time": now
        }

    def add_node(self, node_id: str, name: str, os_name: str, ip: str, user: str) -> Dict[str, Any]:
        """Manually registers a new computer or node into the fleet."""
        clean_id = node_id.strip().upper()
        if not clean_id:
            raise ValueError("Node ID cannot be empty.")

        now = time.time()
        with self._lock:
            if clean_id in self.nodes:
                raise ValueError(f"Node '{clean_id}' already exists in the fleet.")

            self.nodes[clean_id] = {
                "id": clean_id,
                "name": name.strip() or f"Workstation {clean_id}",
                "user": user.strip() or "operator",
                "os": os_name.strip() or "Windows 11 Pro",
                "ip": ip.strip() or "192.168.1.150",
                "status": "normal",
                "risk": 5,
                "events": 1,
                "signals": 0,
                "last_seen": now,
                "created_at": now,
                "is_default": False,
            }
            self.node_logs[clean_id] = []
            log_entry = self._append_log_unlocked(
                clean_id,
                level="INFO",
                message=f"Administrator provisioned node {clean_id} ({self.nodes[clean_id]['name']}).",
                event_type="provision",
                details={"ip": ip, "user": user, "os": os_name}
            )

        return self.nodes[clean_id]

    def remove_node(self, node_id: str) -> bool:
        """Removes a computer node from the fleet."""
        clean_id = node_id.strip().upper()
        with self._lock:
            if clean_id in self.nodes:
                del self.nodes[clean_id]
                self.node_logs.pop(clean_id, None)
                return True
        return False

    def simulate_event(self, node_id: str, event_type: str = "suspicious_process") -> Dict[str, Any]:
        """Simulates security or telemetry activity on a node."""
        clean_id = node_id.strip().upper()
        now = time.time()
        with self._lock:
            if clean_id not in self.nodes:
                raise ValueError(f"Node '{clean_id}' not found.")

            node = self.nodes[clean_id]
            node["last_seen"] = now
            node["events"] = node.get("events", 0) + 1

            if event_type == "heartbeat":
                node["status"] = "normal"
                msg = f"Telemetry ping healthy from {node['user']} on {clean_id}."
                level = "INFO"
            elif event_type == "powershell_encoded":
                node["status"] = "compromised"
                node["risk"] = min(100, node["risk"] + 35)
                node["signals"] += 1
                msg = f"[CRITICAL] Obfuscated PowerShell execution detected: powershell.exe -w hidden -enc JABzAD0..."
                level = "CRIT"
            elif event_type == "usb_drive":
                node["status"] = "warning"
                node["risk"] = min(100, node["risk"] + 20)
                node["signals"] += 1
                msg = f"[ALERT] High-capacity unapproved USB storage mounted on {clean_id}: SanDisk 128GB."
                level = "WARN"
            elif event_type == "lateral_psexec":
                node["status"] = "compromised"
                node["risk"] = min(100, node["risk"] + 40)
                node["signals"] += 2
                msg = f"[CRITICAL] PsExec remote service created from DC-01 by {node['user']}."
                level = "CRIT"
            elif event_type == "failed_logins":
                node["status"] = "warning"
                node["risk"] = min(100, node["risk"] + 15)
                node["signals"] += 1
                msg = f"[WARN] Spike of 14 failed Kerberos logon attempts detected on {clean_id}."
                level = "WARN"
            else:
                msg = f"Routine background telemetry synchronized on {clean_id}."
                level = "INFO"

            log_entry = self._append_log_unlocked(
                clean_id,
                level=level,
                message=msg,
                event_type=event_type,
                details={"simulated": True, "risk": node["risk"]}
            )

        return {"node": node, "log": log_entry}

    def get_node_logs(self, node_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Returns logs for a specific node or all nodes."""
        with self._lock:
            if node_id:
                clean_id = node_id.strip().upper()
                logs = list(self.node_logs.get(clean_id, []))
            else:
                logs = []
                for nlogs in self.node_logs.values():
                    logs.extend(nlogs)
                logs.sort(key=lambda x: x["timestamp"], reverse=True)
            return logs[-limit:] if node_id else logs[:limit]

    def get_state(self) -> Dict[str, Any]:
        """Returns fleet summary and state of all computers/nodes."""
        now = time.time()
        with self._lock:
            rows = []
            online_count = 0
            elevated_risk = 0

            for nid, node in sorted(self.nodes.items()):
                last_seen = node.get("last_seen", 0)
                # Considered online if heartbeat received within last 12 seconds
                is_online = bool(last_seen and (now - last_seen) <= 12)
                if is_online:
                    online_count += 1
                    status = node.get("status") or "normal"
                else:
                    status = "offline" if last_seen else "waiting"

                risk = node.get("risk", 0)
                if risk >= 60:
                    elevated_risk += 1

                rows.append({
                    **node,
                    "online": is_online,
                    "status": status,
                    "age_seconds": round(now - last_seen, 1) if last_seen else None,
                    "logs_count": len(self.node_logs.get(nid, [])),
                })

            return {
                "timestamp": now,
                "nodes": rows,
                "stats": {
                    "total": len(rows),
                    "online": online_count,
                    "offline": len(rows) - online_count,
                    "elevated_risk": elevated_risk,
                }
            }


# Singleton instance
fleet_manager = FleetManager()
