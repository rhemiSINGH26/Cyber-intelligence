"""
Risk scoring calculator and response playbook recommendation generator.
Calculates risk scores (0-100), severity levels, human-readable explanations, and playbooks.
"""
from typing import Optional
from app.config import settings, KILL_CHAIN_ORDER
from app.models.detection import Incident, SeverityLevel, Recommendation


class RiskScorer:
    """Calculates risk, severity, recommendations, and explanations for incidents."""

    def evaluate(self, incident: Incident) -> Incident:
        """
        Enrich incident with:
        1. Calculated risk score (0-100)
        2. Severity level
        3. Human-readable 'why flagged' explanation
        4. Prioritized response recommendations
        """
        raw_score = 0.0

        # 1. Sum stage weights
        stages_present = set()
        for stage in incident.stages:
            stages_present.add(stage.stage)
            weight = settings.RISK_STAGE_WEIGHTS.get(stage.stage, 15)
            # Anomaly boost
            anomaly_factor = min(stage.anomaly_score / 2.0, 1.5)
            raw_score += weight * (1.0 + anomaly_factor * 0.2)

        # 2. Stage Progression bonus: Did the attack follow forward kill-chain ordering?
        stage_orders = [KILL_CHAIN_ORDER.get(s.stage, 0) for s in incident.stages]
        is_monotonic = all(x <= y for x, y in zip(stage_orders, stage_orders[1:]))
        if is_monotonic and len(incident.stages) > 1:
            raw_score *= (1.0 + settings.STAGE_ORDER_WEIGHT)

        # 3. Critical Asset Multipliers
        max_multiplier = 1.0
        hosts = incident.entities.get("hosts", [])
        for h in hosts:
            h_lower = h.lower()
            if "dc" in h_lower or "domain" in h_lower:
                max_multiplier = max(max_multiplier, settings.ASSET_CRITICALITY_MULTIPLIER.get("domain_controller", 2.0))
            elif "db" in h_lower or "sql" in h_lower or "data" in h_lower:
                max_multiplier = max(max_multiplier, settings.ASSET_CRITICALITY_MULTIPLIER.get("database_server", 1.8))
            elif "srv" in h_lower or "server" in h_lower:
                max_multiplier = max(max_multiplier, settings.ASSET_CRITICALITY_MULTIPLIER.get("server", 1.5))

        raw_score *= max_multiplier

        # Exfiltration presence is high priority
        if "exfiltration" in stages_present:
            raw_score += 15

        # Cap between 0 and 100
        final_risk = int(min(max(raw_score, 10), 100))
        incident.risk_score = final_risk

        # Determine severity
        if final_risk >= 85:
            incident.severity = SeverityLevel.CRITICAL
        elif final_risk >= 65:
            incident.severity = SeverityLevel.HIGH
        elif final_risk >= 40:
            incident.severity = SeverityLevel.MEDIUM
        else:
            incident.severity = SeverityLevel.LOW

        # 4. Generate Narrative Explanation ("Why Flagged")
        incident.explanation = self._build_explanation(incident)

        # 5. Generate Playbook Recommendations
        incident.recommendations = self._build_recommendations(incident)

        return incident

    def _build_explanation(self, incident: Incident) -> str:
        """Construct detailed step-by-step why-flagged narrative."""
        lines = [
            f"Multi-stage cyber attack detected with Risk Score {incident.risk_score}/100 ({incident.severity.value.upper()}).",
            f"The incident spans {len(incident.stages)} kill-chain stages observed from {incident.first_seen.strftime('%Y-%m-%d %H:%M:%S')} to {incident.last_seen.strftime('%Y-%m-%d %H:%M:%S')}."
        ]

        lines.append("\nAttack Progression:")
        for idx, stage in enumerate(incident.stages, 1):
            tech_str = f" [{stage.mitre_technique}: {stage.technique_name}]" if stage.mitre_technique else ""
            lines.append(
                f"{idx}. Stage '{stage.stage.upper()}'{tech_str} at {stage.time.strftime('%H:%M:%S')}: "
                f"{stage.reason} (Evidence: {len(stage.evidence)} logs)"
            )

        # Summarize affected entities
        ent_summary = []
        for etype, vals in incident.entities.items():
            if vals:
                ent_summary.append(f"{etype.capitalize()}: {', '.join(vals[:4])}{'...' if len(vals) > 4 else ''}")
        if ent_summary:
            lines.append("\nEntities Involved: " + " | ".join(ent_summary))

        return "\n".join(lines)

    def _build_recommendations(self, incident: Incident) -> list[Recommendation]:
        """Generate targeted mitigation and response playbooks."""
        recs = []
        hosts = incident.entities.get("hosts", [])
        users = incident.entities.get("users", [])
        ips = incident.entities.get("ips", [])
        devices = incident.entities.get("devices", [])

        # Priority host containment
        for host in hosts:
            recs.append(Recommendation(
                action="isolate_host",
                target=host,
                target_type="host",
                priority="critical" if incident.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else "high",
                description=f"Isolate host '{host}' from network to prevent lateral movement and C2 exfiltration.",
                automated=True
            ))

        # Identity containment
        for user in users:
            recs.append(Recommendation(
                action="disable_user",
                target=user,
                target_type="user",
                priority="critical" if incident.severity == SeverityLevel.CRITICAL else "high",
                description=f"Temporarily suspend account '{user}' and invalidate active tokens/sessions.",
                automated=True
            ))

        # Perimeter blocking for external IPs
        for ip in ips:
            # Check if external / non-RFC1918
            if not ip.startswith(("10.", "192.168.", "172.16.", "127.")):
                recs.append(Recommendation(
                    action="block_ip",
                    target=ip,
                    target_type="ip",
                    priority="high",
                    description=f"Add malicious/external IP '{ip}' to edge firewall/WAF blocklist.",
                    automated=True
                ))

        # USB device revocation
        for dev in devices:
            recs.append(Recommendation(
                action="quarantine_device",
                target=dev,
                target_type="device",
                priority="high",
                description=f"Quarantine and seize USB storage device '{dev}' for offline hardware forensics.",
                automated=False
            ))

        return recs
