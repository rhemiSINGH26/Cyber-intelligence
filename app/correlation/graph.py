"""
Entity Graph builder using NetworkX.
Constructs multi-relational graphs of entities (users, hosts, IPs, apps, files, devices)
and extracts connected components and attack paths.
"""
import networkx as nx
from typing import Optional
from app.models.graph import GraphNode, GraphEdge, GraphResponse
from app.models.detection import Incident


class EntityGraph:
    """Multi-relational graph of cybersecurity entities and interactions."""

    def __init__(self):
        self.graph = nx.MultiDiGraph()

    def add_event(self, event: dict, is_suspicious: bool = False, incident_id: Optional[str] = None):
        """Add nodes and edges for a single log event."""
        user = event.get("user")
        host = event.get("host")
        src_ip = event.get("src_ip")
        dst_ip = event.get("dst_ip")
        app = event.get("app")
        file_path = event.get("file_path")
        device_id = event.get("device_id")
        ts = event.get("timestamp")
        evt_id = event.get("id", "")
        evt_type = event.get("event_type", "event")

        # Add nodes
        if user:
            self._ensure_node(f"user:{user}", user, "user", is_suspicious, incident_id)
        if host:
            self._ensure_node(f"host:{host}", host, "host", is_suspicious, incident_id)
        if src_ip:
            self._ensure_node(f"ip:{src_ip}", src_ip, "ip", is_suspicious, incident_id)
        if dst_ip:
            self._ensure_node(f"ip:{dst_ip}", dst_ip, "ip", is_suspicious, incident_id)
        if app:
            self._ensure_node(f"app:{app}", app, "app", is_suspicious, incident_id)
        if file_path:
            self._ensure_node(f"file:{file_path}", file_path, "file", is_suspicious, incident_id)
        if device_id:
            self._ensure_node(f"device:{device_id}", device_id, "device", is_suspicious, incident_id)

        # Add relationship edges
        if user and host:
            self._add_edge(f"user:{user}", f"host:{host}", evt_type, ts, is_suspicious, evt_id)
        if host and dst_ip:
            self._add_edge(f"host:{host}", f"ip:{dst_ip}", "outbound_conn", ts, is_suspicious, evt_id)
        if src_ip and host:
            self._add_edge(f"ip:{src_ip}", f"host:{host}", "inbound_conn", ts, is_suspicious, evt_id)
        if user and file_path:
            self._add_edge(f"user:{user}", f"file:{file_path}", "accessed_file", ts, is_suspicious, evt_id)
        if user and device_id:
            self._add_edge(f"user:{user}", f"device:{device_id}", "used_device", ts, is_suspicious, evt_id)
        if host and app:
            self._add_edge(f"host:{host}", f"app:{app}", "executed_app", ts, is_suspicious, evt_id)

    def _ensure_node(self, node_id: str, label: str, node_type: str, is_suspicious: bool, incident_id: Optional[str]):
        if not self.graph.has_node(node_id):
            self.graph.add_node(
                node_id,
                id=node_id,
                label=label,
                node_type=node_type,
                risk_score=10.0 if is_suspicious else 0.0,
                is_suspicious=is_suspicious,
                incident_ids=[incident_id] if incident_id else [],
            )
        else:
            n_data = self.graph.nodes[node_id]
            if is_suspicious:
                n_data["is_suspicious"] = True
                n_data["risk_score"] = max(n_data.get("risk_score", 0), 15.0)
            if incident_id and incident_id not in n_data.get("incident_ids", []):
                n_data["incident_ids"].append(incident_id)

    def _add_edge(self, src: str, dst: str, edge_type: str, ts: Optional[str], is_suspicious: bool, evt_id: str):
        self.graph.add_edge(
            src,
            dst,
            edge_type=edge_type,
            timestamp=ts,
            is_suspicious=is_suspicious,
            event_id=evt_id,
            weight=2.0 if is_suspicious else 1.0,
        )

    def find_connected_entities(self, entity_keys: list[str], max_depth: int = 2) -> set[str]:
        """Find all entities within max_depth hops of the given entities."""
        visited = set()
        frontier = set(entity_keys)

        for _ in range(max_depth):
            next_frontier = set()
            for node in frontier:
                if self.graph.has_node(node) and node not in visited:
                    visited.add(node)
                    # Add predecessors and successors
                    for neighbor in self.graph.successors(node):
                        next_frontier.add(neighbor)
                    for neighbor in self.graph.predecessors(node):
                        next_frontier.add(neighbor)
            frontier = next_frontier - visited

        return visited | frontier

    def to_graph_response(self, incident: Optional[Incident] = None, max_nodes: int = 100) -> GraphResponse:
        """Convert graph or incident attack path to GraphResponse model."""
        if not incident:
            target_nodes = set(list(self.graph.nodes())[:max_nodes])
            subgraph = self.graph.subgraph(target_nodes)
            nodes = [
                GraphNode(
                    id=n_id,
                    label=data.get("label", n_id),
                    node_type=data.get("node_type", "host"),
                    risk_score=data.get("risk_score", 0.0),
                    is_suspicious=data.get("is_suspicious", False),
                    incident_ids=data.get("incident_ids", []),
                )
                for n_id, data in subgraph.nodes(data=True)
            ]
            seen_edges = set()
            edges = []
            for u, v, data in subgraph.edges(data=True):
                key = (u, v, data.get("edge_type"))
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                edges.append(GraphEdge(
                    source=u,
                    target=v,
                    edge_type=data.get("edge_type", "connect"),
                    weight=data.get("weight", 1.0),
                    timestamp=data.get("timestamp"),
                    is_suspicious=data.get("is_suspicious", False),
                    event_ids=[data.get("event_id")] if data.get("event_id") else [],
                ))
                if len(edges) >= 50:
                    break
            return GraphResponse(
                nodes=nodes,
                edges=edges,
                attack_path=[],
                metadata={"total_nodes": len(nodes), "total_edges": len(edges)}
            )

        # Incident-specific attack chain graph
        nodes_dict: dict[str, GraphNode] = {}
        attack_edges: list[GraphEdge] = []

        users = incident.entities.get("users", [])
        hosts = incident.entities.get("hosts", [])
        ips = incident.entities.get("ips", [])
        apps = incident.entities.get("apps", [])
        files = incident.entities.get("files", [])
        devices = incident.entities.get("devices", [])

        def add_node(nid: str, label: str, ntype: str, is_susp: bool = True, score: float = 10.0):
            if nid not in nodes_dict:
                valid_type = ntype if ntype in ["user", "host", "ip", "app", "file"] else "host"
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=label,
                    node_type=valid_type,
                    risk_score=score,
                    is_suspicious=is_susp,
                    incident_ids=[incident.id],
                )

        # 1. Add primary users & hosts
        for u in users:
            add_node(f"user:{u}", u, "user", is_susp=True, score=25.0)
        for h in hosts[:5]:
            add_node(f"host:{h}", h, "host", is_susp=True, score=20.0)

        # 2. Reconstruct kill chain progression edges from stages
        stages = sorted(incident.stages or [], key=lambda s: str(s.time))
        prev_node = f"user:{users[0]}" if users else (f"host:{hosts[0]}" if hosts else None)

        edge_types_map = {
            "initial_access": "auth",
            "credential_access": "auth",
            "execution": "execute",
            "privilege_escalation": "execute",
            "lateral_movement": "connect",
            "collection": "access",
            "exfiltration": "connect",
        }

        for idx, stage in enumerate(stages):
            s_ents = stage.entities or {}
            s_users = s_ents.get("users") or users
            s_hosts = s_ents.get("hosts") or hosts
            s_ips = s_ents.get("ips") or ips
            s_apps = s_ents.get("apps") or apps
            s_files = s_ents.get("files") or files

            action = edge_types_map.get(stage.stage, "connect")
            ts = stage.time.isoformat() if hasattr(stage.time, "isoformat") else str(stage.time)

            if stage.stage == "initial_access":
                src = f"ip:{s_ips[0]}" if s_ips else (f"user:{s_users[0]}" if s_users else prev_node)
                dst = f"host:{s_hosts[0]}" if s_hosts else (prev_node or "host:Target")
                if s_ips:
                    add_node(f"ip:{s_ips[0]}", s_ips[0], "ip", is_susp=True, score=20.0)
                if s_hosts:
                    add_node(f"host:{s_hosts[0]}", s_hosts[0], "host", is_susp=True, score=20.0)
                if src and dst and src != dst:
                    attack_edges.append(GraphEdge(
                        source=src, target=dst, edge_type="auth",
                        weight=2.0, timestamp=ts, is_suspicious=True,
                        event_ids=stage.evidence[:3],
                        metadata={"stage": stage.stage, "order": idx + 1, "technique": stage.technique_name}
                    ))
                    prev_node = dst

            elif stage.stage in ["execution", "privilege_escalation"]:
                host_node = f"host:{s_hosts[0]}" if s_hosts else prev_node
                if s_apps:
                    app_node = f"app:{s_apps[0]}"
                    add_node(app_node, s_apps[0], "app", is_susp=True, score=15.0)
                    if host_node and host_node != app_node:
                        attack_edges.append(GraphEdge(
                            source=host_node, target=app_node, edge_type="execute",
                            weight=2.0, timestamp=ts, is_suspicious=True,
                            event_ids=stage.evidence[:3],
                            metadata={"stage": stage.stage, "order": idx + 1, "technique": stage.technique_name}
                        ))
                elif prev_node and host_node and prev_node != host_node:
                    attack_edges.append(GraphEdge(
                        source=prev_node, target=host_node, edge_type="execute",
                        weight=2.0, timestamp=ts, is_suspicious=True,
                        event_ids=stage.evidence[:3],
                        metadata={"stage": stage.stage, "order": idx + 1, "technique": stage.technique_name}
                    ))
                if host_node:
                    prev_node = host_node

            elif stage.stage == "lateral_movement":
                target_hosts = [h for h in s_hosts if f"host:{h}" != prev_node]
                next_host = f"host:{target_hosts[0]}" if target_hosts else (f"host:{s_hosts[0]}" if s_hosts else None)
                if next_host:
                    add_node(next_host, target_hosts[0] if target_hosts else s_hosts[0], "host", is_susp=True, score=20.0)
                src = prev_node or (f"user:{s_users[0]}" if s_users else None)
                if src and next_host and src != next_host:
                    attack_edges.append(GraphEdge(
                        source=src, target=next_host, edge_type="connect",
                        weight=2.0, timestamp=ts, is_suspicious=True,
                        event_ids=stage.evidence[:3],
                        metadata={"stage": stage.stage, "order": idx + 1, "technique": stage.technique_name}
                    ))
                    prev_node = next_host

            elif stage.stage == "collection":
                user_node = f"user:{s_users[0]}" if s_users else prev_node
                target_file = f"file:{s_files[0]}" if s_files else "file:SensitiveData"
                add_node(target_file, s_files[0] if s_files else "SensitiveData", "file", is_susp=True, score=15.0)
                if user_node and user_node != target_file:
                    attack_edges.append(GraphEdge(
                        source=user_node, target=target_file, edge_type="access",
                        weight=2.0, timestamp=ts, is_suspicious=True,
                        event_ids=stage.evidence[:3],
                        metadata={"stage": stage.stage, "order": idx + 1, "technique": stage.technique_name}
                    ))

            elif stage.stage == "exfiltration":
                host_node = prev_node or (f"host:{s_hosts[0]}" if s_hosts else None)
                dst_ip = s_ips[0] if s_ips else "188.109.152.177"
                ip_node = f"ip:{dst_ip}"
                add_node(ip_node, dst_ip, "ip", is_susp=True, score=30.0)
                if host_node and host_node != ip_node:
                    attack_edges.append(GraphEdge(
                        source=host_node, target=ip_node, edge_type="connect",
                        weight=3.0, timestamp=ts, is_suspicious=True,
                        event_ids=stage.evidence[:3],
                        metadata={"stage": stage.stage, "order": idx + 1, "technique": stage.technique_name}
                    ))

            else:
                if prev_node and s_hosts and prev_node != f"host:{s_hosts[0]}":
                    dst = f"host:{s_hosts[0]}"
                    add_node(dst, s_hosts[0], "host", is_susp=True, score=15.0)
                    attack_edges.append(GraphEdge(
                        source=prev_node, target=dst, edge_type=action,
                        weight=1.5, timestamp=ts, is_suspicious=True,
                        event_ids=stage.evidence[:3],
                        metadata={"stage": stage.stage, "order": idx + 1, "technique": stage.technique_name}
                    ))
                    prev_node = dst

        # Ensure user -> first host link exists
        if users and hosts:
            u_node = f"user:{users[0]}"
            h_node = f"host:{hosts[0]}"
            if not any(e.source == u_node and e.target == h_node for e in attack_edges):
                attack_edges.insert(0, GraphEdge(
                    source=u_node, target=h_node, edge_type="auth",
                    weight=1.0, timestamp=stages[0].time.isoformat() if stages else None,
                    is_suspicious=True,
                    metadata={"stage": "initial_user_auth", "order": 1}
                ))

        # Re-number sequence order
        for idx, e in enumerate(attack_edges):
            if not e.metadata:
                e.metadata = {}
            e.metadata["order"] = idx + 1

        final_nodes = list(nodes_dict.values())
        return GraphResponse(
            nodes=final_nodes,
            edges=attack_edges,
            attack_path=[n.id for n in final_nodes if n.is_suspicious],
            metadata={
                "total_nodes": len(final_nodes),
                "total_edges": len(attack_edges),
                "incident_id": incident.id,
            }
        )
