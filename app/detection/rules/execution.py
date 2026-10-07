"""
Execution detector: suspicious process creation, Lolbins, scripted interpreters.
MITRE: T1059 Command and Scripting Interpreter
"""
from collections import defaultdict
from app.detection.rules.base import BaseDetector
from app.models.detection import Detection
from app.config import settings, MITRE_TECHNIQUES


SUSPICIOUS_APPS = {
    "powershell.exe", "powershell", "cmd.exe", "cmd", "bash", "sh",
    "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "vssadmin.exe",
    "whoami.exe", "net.exe", "net1.exe"
}


class ExecutionDetector(BaseDetector):
    """Detect suspicious process execution and command line execution."""

    def detect(self, events: list[dict], all_events: list[dict] = None) -> list[Detection]:
        detections = []
        # Group by user / host
        events_by_key = defaultdict(list)
        for e in events:
            if e.get("event_type") == "process_start":
                key = (e.get("user", ""), e.get("host", ""))
                events_by_key[key].append(e)

        for (user, host), proc_events in events_by_key.items():
            for e in proc_events:
                app_name = (e.get("app") or "").lower()
                cmd_line = (e.get("command_line") or e.get("details", "") or "").lower()
                
                is_suspicious_tool = any(s in app_name for s in SUSPICIOUS_APPS)
                is_suspicious_cmd = any(k in cmd_line for k in ["-enc", "bypass", "hidden", "invoke-expression", "iex", "base64", "downloadstring"])

                if is_suspicious_tool or is_suspicious_cmd:
                    ts = self._parse_ts(e.get("timestamp", ""))
                    if not ts:
                        continue

                    tech = MITRE_TECHNIQUES.get("command_scripting", {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "execution"})
                    det = Detection(
                        timestamp=ts,
                        stage="execution",
                        mitre_tactic=tech["tactic"],
                        mitre_technique=tech["id"],
                        technique_name=tech["name"],
                        evidence=[e["id"]],
                        reason=f"Suspicious execution observed: process '{app_name or 'interpreter'}' executed by user '{user}' on host '{host}'",
                        entities=self._get_entities([e]),
                        anomaly_score=1.8 if is_suspicious_cmd else 1.2,
                        confidence=0.75 if is_suspicious_cmd else 0.60,
                        rule_name="suspicious_process_execution"
                    )
                    detections.append(det)

        return detections
