"""
Groq LLM Client for natural language CTI analysis and universal schema adaptation.
Includes deterministic offline fallbacks when GROQ_API_KEY is not configured.
"""
import os
import json
from typing import Optional
from app.config import settings
from app.models.detection import Incident


class GroqClient:
    """Wrapper around Groq API with robust offline fallbacks."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.GROQ_API_KEY or os.environ.get("GROQ_API_KEY")
        self.model = settings.GROQ_MODEL
        self._client = None
        if self.api_key:
            try:
                from groq import Groq
                self._client = Groq(api_key=self.api_key)
            except Exception:
                self._client = None

    def is_available(self) -> bool:
        return self._client is not None

    def explain_incident(self, incident: Incident) -> str:
        """
        Produce a SOC-grade executive briefing explaining the multi-stage attack.
        Falls back to incident's precomputed explanation if Groq is unavailable.
        """
        if not self._client:
            return incident.explanation

        prompt = f"""
You are a Principal Security Incident Analyst. Write a concise, professional executive briefing (3-4 paragraphs)
for the following cyber security incident:

Title: {incident.title}
Risk Score: {incident.risk_score}/100
Severity: {incident.severity.value}
Confidence: {incident.confidence:.2f}
Timeframe: {incident.first_seen} to {incident.last_seen}
Entities Involved: {json.dumps(incident.entities)}

Kill-Chain Stages:
{json.dumps([{
    'stage': s.stage,
    'technique': s.mitre_technique,
    'technique_name': s.technique_name,
    'time': str(s.time),
    'reason': s.reason,
    'evidence_logs_count': len(s.evidence)
} for s in incident.stages], indent=2)}

Include:
1. Executive Summary: What happened and overall threat severity.
2. Step-by-Step Kill Chain Breakdown: How the attacker progressed from stage to stage.
3. Impact Assessment: Compromised identities, hosts, and data exposure risk.
"""
        try:
            chat_completion = self._client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a cyber threat intelligence analyst."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.2,
                max_tokens=600,
            )
            return chat_completion.choices[0].message.content.strip()
        except Exception:
            return incident.explanation

    def infer_schema_mapping(self, sample_rows: list[dict]) -> dict:
        """
        Use Groq to infer column-to-standard-field mappings for universal dataset ingestion.
        Returns mapping dict: {'timestamp': col_name, 'user': col_name, ...}
        """
        if not self._client or not sample_rows:
            return {}

        prompt = f"""
Given the following sample rows from an unknown security log dataset, identify which keys/columns map to our standard security schema:
Standard fields:
- "timestamp" (event time/date)
- "user" (username, account, user_id, actor)
- "host" (hostname, machine, computer_name, system)
- "src_ip" (source IP, client IP, caller_ip)
- "dst_ip" (dest IP, target IP, server_ip)
- "event_type" (action, event, type, category, method)
- "status" (outcome, result, status_code, success/failure)
- "app" (process, application, command, service)
- "file_path" (path, target_file, filename, uri)
- "bytes_transferred" (bytes, length, size, payload_size)

Sample rows:
{json.dumps(sample_rows[:3], indent=2)}

Return ONLY a JSON object mapping standard fields to dataset column names.
Example output: {{"timestamp": "EventTime", "user": "AccountName", "host": "ComputerName"}}
"""
        try:
            chat_completion = self._client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "You are a data engineering assistant. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                model=self.model,
                temperature=0.1,
                max_tokens=300,
                response_format={"type": "json_object"}
            )
            content = chat_completion.choices[0].message.content
            return json.loads(content)
        except Exception:
            return {}

    def chat(self, query: str, context: Optional[str] = None, history: Optional[list] = None) -> str:
        """
        Interactive SOC Copilot chat using Groq LLM.
        Can answer questions about detected attacks, MITRE techniques, forensic evidence, or remediation.
        """
        if not self._client:
            return (
                "ThreatLens Copilot (Offline Mode): I can analyze all detected attacks in the system.\n\n"
                f"Active Telemetry Context:\n{context[:400] if context else 'No context provided.'}\n\n"
                "Please configure a valid GROQ_API_KEY for dynamic real-time LLM reasoning."
            )

        system_prompt = (
            "You are ThreatLens SOC Copilot, an elite AI Cyber Threat Intelligence (CTI) & Incident Response assistant. "
            "You have real-time access to active telemetry, attack chain reconstructions, MITRE ATT&CK mappings, and entity graphs.\n\n"
            "Guidelines:\n"
            "1. Answer questions clearly, accurately, and authoritatively.\n"
            "2. Explain attack progression across kill-chain stages (Initial Access, Execution, Persistence, Privilege Escalation, Lateral Movement, Collection, Exfiltration).\n"
            "3. Mention specific compromised entities (users, hosts, IPs, processes) and evidence IDs when relevant.\n"
            "4. Provide actionable SOAR containment recommendations (e.g., isolating hosts via EDR, blocking malicious IPs, revoking credentials).\n"
            "5. Use clean markdown formatting with bullet points and bold highlights."
        )

        messages = [{"role": "system", "content": system_prompt}]

        if context:
            messages.append({
                "role": "system",
                "content": f"CURRENT SOC ATTACK INTELLIGENCE CONTEXT:\n{context}"
            })

        if history:
            for msg in history[-6:]:  # Keep recent turns
                role = msg.get("role", "user")
                if role in ["user", "assistant"]:
                    messages.append({"role": role, "content": msg.get("content", "")})

        messages.append({"role": "user", "content": query})

        try:
            chat_completion = self._client.chat.completions.create(
                messages=messages,
                model=self.model,
                temperature=0.3,
                max_tokens=800,
            )
            return chat_completion.choices[0].message.content.strip()
        except Exception as e:
            return f"SOC Copilot Analysis: Based on the current incident telemetry:\n\n{context[:400] if context else ''}\n\n*(Notice: Groq request encountered: {e})*"


# Global client singleton
groq_client = GroqClient()
