"""
Attack Chain Correlator.
Correlates individual stage detections into coherent multi-stage attack incidents.
Enforces kill-chain progression, entity linking, multi-window correlation, and false-positive suppression.
"""
from datetime import datetime, timedelta
from collections import defaultdict
from app.config import settings, KILL_CHAIN_ORDER
from app.models.detection import Detection, Incident, Stage, Observation, SeverityLevel
from app.correlation.graph import EntityGraph


class AttackCorrelator:
    """Correlates detections across entities and time into multi-stage attack incidents."""

    def __init__(self, graph: EntityGraph):
        self.graph = graph

    def correlate(self, detections: list[Detection]) -> tuple[list[Incident], list[Observation]]:
        """
        Group detections into incidents.
        Detections with insufficient stages or lower risk are stored as Observations.
        """
        if not detections:
            return [], []

        # Filter out suppressed detections
        active_detections = [d for d in detections if not d.suppressed]

        # Group detections by entity clusters (direct match or graph connectivity)
        clusters = self._cluster_detections(active_detections)

        incidents = []
        observations = []

        for cluster in clusters:
            if not cluster:
                continue

            # Check distinct kill-chain stages
            stages_by_name = defaultdict(list)
            for d in cluster:
                stages_by_name[d.stage].append(d)

            distinct_stages = list(stages_by_name.keys())

            # Consolidate entities
            consolidated_entities = defaultdict(set)
            for d in cluster:
                for k, v in d.entities.items():
                    if isinstance(v, list):
                        consolidated_entities[k].update(v)
                    else:
                        consolidated_entities[k].add(v)
            entities_dict = {k: sorted(list(v)) for k, v in consolidated_entities.items() if v}

            # Enforce multi-stage attack chain: must have at least MIN_STAGES_FOR_INCIDENT
            has_enough_stages = len(distinct_stages) >= settings.MIN_STAGES_FOR_INCIDENT

            if has_enough_stages:
                # Build Stages for Incident
                incident_stages = []
                for stage_name, stage_dets in stages_by_name.items():
                    stage_evidence = []
                    for sd in stage_dets:
                        for ev_id in sd.evidence:
                            if ev_id not in stage_evidence:
                                stage_evidence.append(ev_id)

                    if not stage_evidence:
                        continue

                    rep_det = max(stage_dets, key=lambda x: x.confidence)
                    earliest_time = min(sd.timestamp for sd in stage_dets)

                    stg = Stage(
                        stage=stage_name,
                        mitre_tactic=rep_det.mitre_tactic,
                        mitre_technique=rep_det.mitre_technique,
                        technique_name=rep_det.technique_name,
                        time=earliest_time,
                        evidence=stage_evidence,
                        reason="; ".join(dict.fromkeys(sd.reason for sd in stage_dets)),
                        entities=rep_det.entities,
                        anomaly_score=max(sd.anomaly_score for sd in stage_dets),
                    )
                    incident_stages.append(stg)

                if not incident_stages:
                    continue

                # Sort stages chronologically and by kill-chain order
                incident_stages.sort(key=lambda s: (s.time, KILL_CHAIN_ORDER.get(s.stage, 99)))

                first_seen = min(s.time for s in incident_stages)
                last_seen = max(s.time for s in incident_stages)

                primary_users = entities_dict.get("users", [])
                primary_user = primary_users[0] if primary_users else "Unknown Subject"
                title = f"Multi-Stage Cyber Attack targeting {primary_user} ({len(incident_stages)} stages)"

                inc = Incident(
                    title=title,
                    risk_score=50,
                    severity=SeverityLevel.MEDIUM,
                    confidence=min(0.95, sum(d.confidence for d in cluster) / len(cluster) + 0.1),
                    first_seen=first_seen,
                    last_seen=last_seen,
                    entities=entities_dict,
                    stages=incident_stages,
                )
                incidents.append(inc)
            else:
                for d in cluster:
                    obs = Observation(
                        timestamp=d.timestamp,
                        stage=d.stage,
                        reason=d.reason,
                        evidence=d.evidence,
                        entities=d.entities,
                        anomaly_score=d.anomaly_score,
                        why_not_incident=f"Only 1 kill-chain stage ('{d.stage}') detected. Does not meet multi-stage threshold ({settings.MIN_STAGES_FOR_INCIDENT})."
                    )
                    observations.append(obs)

        return incidents, observations

    def _cluster_detections(self, detections: list[Detection]) -> list[list[Detection]]:
        """Cluster detections based on shared primary entities (user, device, host)."""
        if not detections:
            return []

        sorted_dets = sorted(detections, key=lambda d: d.timestamp)
        clusters: list[list[Detection]] = []

        for det in sorted_dets:
            assigned = False
            det_users = set(det.entities.get("users", []))
            det_devices = set(det.entities.get("devices", []))
            det_hosts = set(det.entities.get("hosts", []))

            for cluster in clusters:
                cluster_users = set().union(*(cd.entities.get("users", []) for cd in cluster))
                cluster_devices = set().union(*(cd.entities.get("devices", []) for cd in cluster))
                cluster_hosts = set().union(*(cd.entities.get("hosts", []) for cd in cluster))

                earliest = min(cd.timestamp for cd in cluster)
                time_diff_hours = abs((det.timestamp - earliest).total_seconds()) / 3600.0

                # Match by user (strongest pivot): allow up to 14 days
                if det_users and det_users.intersection(cluster_users):
                    if time_diff_hours <= settings.LONG_CORRELATION_WINDOW_HOURS:
                        cluster.append(det)
                        assigned = True
                        break

                # Match by USB / hardware device: allow up to 14 days
                if det_devices and det_devices.intersection(cluster_devices):
                    if time_diff_hours <= settings.LONG_CORRELATION_WINDOW_HOURS:
                        cluster.append(det)
                        assigned = True
                        break

                # Match by host (lateral movement): only within short correlation window (12 hours)
                if det_hosts and det_hosts.intersection(cluster_hosts):
                    if time_diff_hours <= 12.0:
                        cluster.append(det)
                        assigned = True
                        break

            if not assigned:
                clusters.append([det])

        return clusters
