"""Simulated 12-node enterprise network with defensive actions."""


import random
import time
from typing import Optional

try:
    from ..models import (
        ActionResult, AlertSeverity, AlertType, NetworkAlert,
        NetworkNode, NodeStatus, NodeType, ThreatLevel,
    )
except ImportError:
    from cyber_range.models import (
        ActionResult, AlertSeverity, AlertType, NetworkAlert,
        NetworkNode, NodeStatus, NodeType, ThreatLevel,
    )


# Default 12-node topology

def create_default_network() -> list[NetworkNode]:
    """Create the default 12-node enterprise network topology."""
    return [
        NetworkNode(
            node_id="fw-01", hostname="perimeter-fw", ip_address="10.0.0.1",
            node_type=NodeType.FIREWALL, os="PfSense 2.7",
            open_ports=[443, 8443], running_services=["firewall", "vpn"],
            is_critical=True,
        ),
        NetworkNode(
            node_id="dc-01", hostname="ad-controller", ip_address="10.0.1.1",
            node_type=NodeType.DOMAIN_CONTROLLER, os="Windows Server 2022",
            open_ports=[53, 88, 389, 636, 445],
            running_services=["dns", "kerberos", "ldap", "smb"],
            is_critical=True,
        ),
        NetworkNode(
            node_id="web-01", hostname="web-frontend", ip_address="10.0.2.1",
            node_type=NodeType.WEB_SERVER, os="Ubuntu 22.04",
            open_ports=[80, 443, 22],
            running_services=["nginx", "nodejs", "ssh"],
            is_critical=True,
            vulnerabilities=["CVE-2024-1234-nginx"],
        ),
        NetworkNode(
            node_id="mail-01", hostname="mail-server", ip_address="10.0.2.2",
            node_type=NodeType.MAIL_SERVER, os="Ubuntu 22.04",
            open_ports=[25, 587, 993, 22],
            running_services=["postfix", "dovecot", "ssh"],
            is_critical=True,
        ),
        NetworkNode(
            node_id="db-01", hostname="prod-database", ip_address="10.0.3.1",
            node_type=NodeType.DATABASE, os="CentOS 9",
            open_ports=[5432, 22],
            running_services=["postgresql", "ssh"],
            is_critical=True,
        ),
        NetworkNode(
            node_id="app-01", hostname="app-backend", ip_address="10.0.3.2",
            node_type=NodeType.APP_SERVER, os="Ubuntu 22.04",
            open_ports=[8080, 8443, 22],
            running_services=["java", "tomcat", "ssh"],
            is_critical=False,
        ),
        NetworkNode(
            node_id="ws-01", hostname="analyst-pc-1", ip_address="10.0.4.1",
            node_type=NodeType.WORKSTATION, os="Windows 11",
            open_ports=[445, 3389],
            running_services=["smb", "rdp"],
            is_critical=False,
        ),
        NetworkNode(
            node_id="ws-02", hostname="dev-pc-1", ip_address="10.0.4.2",
            node_type=NodeType.WORKSTATION, os="Windows 11",
            open_ports=[445, 3389],
            running_services=["smb", "rdp"],
            is_critical=False,
        ),
        NetworkNode(
            node_id="ws-03", hostname="hr-pc-1", ip_address="10.0.4.3",
            node_type=NodeType.WORKSTATION, os="Windows 11",
            open_ports=[445, 3389],
            running_services=["smb", "rdp"],
            is_critical=False,
        ),
        NetworkNode(
            node_id="ws-04", hostname="exec-pc-1", ip_address="10.0.4.4",
            node_type=NodeType.WORKSTATION, os="macOS 14",
            open_ports=[22, 5900],
            running_services=["ssh", "vnc"],
            is_critical=False,
        ),
        NetworkNode(
            node_id="honey-01", hostname="honeypot-svr", ip_address="10.0.5.1",
            node_type=NodeType.HONEYPOT, os="Debian 12",
            open_ports=[],
            running_services=[],
            is_critical=False,
        ),
        NetworkNode(
            node_id="backup-01", hostname="backup-server", ip_address="10.0.6.1",
            node_type=NodeType.BACKUP_SERVER, os="Ubuntu 22.04",
            open_ports=[22, 873],
            running_services=["ssh", "rsync", "borg-backup"],
            is_critical=True,
        ),
    ]




class NetworkSimulator:
    """
    Simulates a 12-node enterprise network for SOC analyst training.

    Manages network topology, host statuses, SIEM alerts, and executes
    defensive actions taken by the agent.
    """

    def __init__(self, seed: Optional[int] = None) -> None:
        self._rng = random.Random(seed)
        self.nodes: dict[str, NetworkNode] = {}
        self.alerts: dict[str, NetworkAlert] = {}
        self.blocked_ips: set[str] = set()
        self.honeypot_deployed: bool = False
        self.honeypot_intel: list[str] = []
        self._alert_counter: int = 0
        self._start_time: float = 0.0
        self._step_count: int = 0
        self._budget: float = 100.0
        self._initial_budget: float = 100.0
        self._forensics_results: dict[str, dict] = {}

    def initialize(self, seed: Optional[int] = None) -> None:
        """Reset the network to clean state."""
        if seed is not None:
            self._rng = random.Random(seed)
        self.nodes = {n.node_id: n for n in create_default_network()}
        self.alerts = {}
        self.blocked_ips = set()
        self.honeypot_deployed = False
        self.honeypot_intel = []
        self._alert_counter = 0
        self._start_time = time.time()
        self._step_count = 0
        self._budget = 100.0
        self._forensics_results = {}

    def get_node(self, node_id: str) -> Optional[NetworkNode]:
        """Get a network node by ID."""
        return self.nodes.get(node_id)

    def compromise_node(self, node_id: str, step: int) -> bool:
        """Mark a node as compromised (called by attack engine)."""
        node = self.nodes.get(node_id)
        if node and node.status == NodeStatus.HEALTHY:
            node.status = NodeStatus.COMPROMISED
            node.compromised_at_step = step
            return True
        return False

    def encrypt_node(self, node_id: str) -> bool:
        """Mark a node as encrypted by ransomware."""
        node = self.nodes.get(node_id)
        if node and node.status in (NodeStatus.HEALTHY, NodeStatus.COMPROMISED):
            node.status = NodeStatus.ENCRYPTED
            return True
        return False

    # --- Agent Actions ---


    def investigate_alert(self, alert_id: str) -> ActionResult:
        """Deep-dive investigation into a specific alert."""
        alert = self.alerts.get(alert_id)
        if not alert:
            return ActionResult(
                action_type="investigate_alert", success=False,
                description=f"Alert {alert_id} not found.",
                resource_cost=0.5,
            )

        alert.investigated = True
        self._budget -= 1.0

        # Provide realistic forensic evidence instead of boolean ground-truth
        if alert.is_false_positive:
            evidence = (
                f"Forensic analysis of {alert.related_node_id} shows routine system processes. "
                f"Network traffic matches expected baseline profiles. "
                f"The alert ({alert.alert_type.value}) is likely benign."
            )
        else:
            evidence = (
                f"Analysis confirms malicious activity! "
                f"Identified unauthorized access attempts targeting {alert.related_node_id}. "
                f"Source origin traced to {alert.source_ip}. "
                f"Recommend immediate containment."
            )

        details = {
            "alert_id": alert.alert_id,
            "severity": alert.severity.value,
            "alert_type": alert.alert_type.value,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "related_node": alert.related_node_id,
            "confidence": alert.confidence,
            "raw_log": alert.raw_log,
            "forensic_evidence": evidence,
        }

        return ActionResult(
            action_type="investigate_alert", success=True,
            description=f"Investigation of alert {alert_id} complete.",
            intel_gathered=0.5 if not alert.is_false_positive else 0.1,
            resource_cost=1.0,
            details=details,
        )

    def isolate_host(self, node_id: str) -> ActionResult:
        """Quarantine a host from the network."""
        node = self.nodes.get(node_id)
        if not node:
            return ActionResult(
                action_type="isolate_host", success=False,
                description=f"Node {node_id} not found.",
                resource_cost=0.5,
            )

        if node.status == NodeStatus.ISOLATED:
            return ActionResult(
                action_type="isolate_host", success=False,
                description=f"Node {node_id} is already isolated.",
                resource_cost=0.5,
            )

        was_compromised = node.status in (NodeStatus.COMPROMISED, NodeStatus.ENCRYPTED)
        was_healthy = node.status == NodeStatus.HEALTHY
        critical_disrupted = node.is_critical and was_healthy

        node.status = NodeStatus.ISOLATED
        node.isolated_at_step = self._step_count
        self._budget -= 3.0

        return ActionResult(
            action_type="isolate_host", success=True,
            description=f"Host {node_id} ({node.hostname}) has been isolated from the network.",
            threat_neutralized=was_compromised,
            threat_severity_multiplier=2.0 if node.is_critical else 1.0,
            healthy_host_isolated=was_healthy,
            critical_services_disrupted=critical_disrupted,
            resource_cost=3.0,
            health_delta=0.05 if was_compromised else -0.10,
        )

    def block_ip(self, ip_address: str) -> ActionResult:
        """Block an IP address at the firewall."""
        if ip_address in self.blocked_ips:
            return ActionResult(
                action_type="block_ip", success=False,
                description=f"IP {ip_address} is already blocked.",
                resource_cost=0.2,
            )

        # Check if it's an internal IP (blocking internal = bad)
        is_internal = ip_address.startswith("10.0.")
        internal_node = None
        if is_internal:
            for node in self.nodes.values():
                if node.ip_address == ip_address:
                    internal_node = node
                    break

        self.blocked_ips.add(ip_address)
        self._budget -= 0.5

        # Blocking an attacker IP neutralizes related alerts
        threat_neutralized = not is_internal
        critical_disrupted = internal_node is not None and internal_node.is_critical

        return ActionResult(
            action_type="block_ip", success=True,
            description=f"IP {ip_address} blocked at firewall. {'WARNING: This is an internal IP!' if is_internal else 'External threat blocked.'}",
            threat_neutralized=threat_neutralized,
            threat_severity_multiplier=1.5,
            healthy_host_isolated=is_internal and internal_node is not None and internal_node.status == NodeStatus.HEALTHY,
            critical_services_disrupted=critical_disrupted,
            resource_cost=0.5,
            health_delta=0.03 if threat_neutralized else -0.05,
        )

    def run_forensics(self, node_id: str) -> ActionResult:
        """Run memory/disk forensics on a host."""
        node = self.nodes.get(node_id)
        if not node:
            return ActionResult(
                action_type="run_forensics", success=False,
                description=f"Node {node_id} not found.",
                resource_cost=1.0,
            )

        self._budget -= 5.0

        # Generate forensic findings based on node status
        is_compromised = node.status in (NodeStatus.COMPROMISED, NodeStatus.ENCRYPTED)
        findings = {
            "node_id": node_id,
            "hostname": node.hostname,
            "status_at_scan": node.status.value,
        }

        if is_compromised:
            findings["malware_found"] = True
            findings["suspicious_processes"] = ["svchost_fake.exe", "nc.exe"]
            findings["anomalous_connections"] = [
                {"dest": "185.220.101.42", "port": 4444, "protocol": "TCP"},
            ]
            findings["modified_files"] = ["/etc/shadow", "C:\\Windows\\System32\\config\\SAM"]
            findings["credential_theft"] = node.node_type in (
                NodeType.DOMAIN_CONTROLLER, NodeType.WORKSTATION
            )
            findings["recommendation"] = "Host is compromised. Isolate immediately and restore from backup."
        else:
            findings["malware_found"] = False
            findings["suspicious_processes"] = []
            findings["anomalous_connections"] = []
            findings["modified_files"] = []
            findings["credential_theft"] = False
            findings["recommendation"] = "No evidence of compromise found. Host appears clean."

        self._forensics_results[node_id] = findings

        return ActionResult(
            action_type="run_forensics", success=True,
            description=f"Forensic analysis of {node_id} complete.",
            intel_gathered=1.5 if is_compromised else 0.2,
            resource_cost=5.0,
            details=findings,
        )

    def deploy_patch(self, node_id: str) -> ActionResult:
        """Push a security patch to a vulnerable host."""
        node = self.nodes.get(node_id)
        if not node:
            return ActionResult(
                action_type="deploy_patch", success=False,
                description=f"Node {node_id} not found.",
                resource_cost=1.0,
            )

        if node.status in (NodeStatus.ISOLATED, NodeStatus.OFFLINE, NodeStatus.ENCRYPTED):
            return ActionResult(
                action_type="deploy_patch", success=False,
                description=f"Cannot deploy patch to {node_id} — host is {node.status.value}.",
                resource_cost=0.5,
            )

        patched_vulns = list(node.vulnerabilities)
        node.vulnerabilities = []
        self._budget -= 2.0

        return ActionResult(
            action_type="deploy_patch", success=True,
            description=f"Security patch applied to {node_id}. Patched: {patched_vulns if patched_vulns else 'no known vulnerabilities'}.",
            resource_cost=2.0,
            health_delta=0.02 if patched_vulns else 0.0,
            details={"patched_vulnerabilities": patched_vulns},
        )

    def restore_backup(self, node_id: str) -> ActionResult:
        """Restore a compromised host from backup."""
        node = self.nodes.get(node_id)
        if not node:
            return ActionResult(
                action_type="restore_backup", success=False,
                description=f"Node {node_id} not found.",
                resource_cost=1.0,
            )

        was_compromised = node.status in (NodeStatus.COMPROMISED, NodeStatus.ENCRYPTED)
        if not was_compromised and node.status != NodeStatus.ISOLATED:
            return ActionResult(
                action_type="restore_backup", success=False,
                description=f"Node {node_id} doesn't need restoration — status is {node.status.value}.",
                resource_cost=0.5,
            )

        node.status = NodeStatus.HEALTHY
        node.compromised_at_step = -1
        node.vulnerabilities = []
        self._budget -= 8.0

        return ActionResult(
            action_type="restore_backup", success=True,
            description=f"Host {node_id} restored from backup. Now healthy.",
            threat_neutralized=was_compromised,
            threat_severity_multiplier=1.5 if node.is_critical else 1.0,
            resource_cost=8.0,
            health_delta=0.08,
        )

    def dismiss_alert(self, alert_id: str) -> ActionResult:
        """Dismiss an alert as a false positive."""
        alert = self.alerts.get(alert_id)
        if not alert:
            return ActionResult(
                action_type="dismiss_alert", success=False,
                description=f"Alert {alert_id} not found.",
                resource_cost=0.0,
            )

        if alert.resolved or alert.dismissed:
            return ActionResult(
                action_type="dismiss_alert", success=False,
                description=f"Alert {alert_id} has already been handled.",
                resource_cost=0.0,
            )

        alert.dismissed = True
        correctly_dismissed = alert.is_false_positive
        ignored_real = not alert.is_false_positive

        return ActionResult(
            action_type="dismiss_alert", success=True,
            description=(
                f"Alert {alert_id} dismissed as false positive."
                + (" Correct — this was indeed a false positive." if correctly_dismissed else "")
            ),
            false_positive_correctly_dismissed=correctly_dismissed,
            real_threat_ignored=ignored_real,
            resource_cost=0.0,
        )

    def deploy_honeypot(self) -> ActionResult:
        """Deploy a honeypot to gather attacker intelligence."""
        if self.honeypot_deployed:
            return ActionResult(
                action_type="deploy_honeypot", success=False,
                description="Honeypot is already deployed.",
                resource_cost=0.5,
            )

        self.honeypot_deployed = True
        node = self.nodes.get("honey-01")
        if node:
            node.open_ports = [22, 80, 445, 3389]
            node.running_services = ["fake-ssh", "fake-http", "fake-smb", "fake-rdp"]

        self._budget -= 4.0

        return ActionResult(
            action_type="deploy_honeypot", success=True,
            description="Honeypot deployed at 10.0.5.1. It will attract and log attacker activity.",
            intel_gathered=1.0,
            resource_cost=4.0,
        )

    def escalate_incident(self, description: str) -> ActionResult:
        """Escalate to senior analyst. Safe fallback but incurs penalty."""
        self._budget -= 2.0
        return ActionResult(
            action_type="escalate_incident", success=True,
            description=f"Incident escalated: '{description}'. A senior analyst is reviewing. This buys time but uses resources.",
            resource_cost=2.0,
            health_delta=0.01,
        )

    # --- Observation helpers ---


    def add_alert(self, alert: NetworkAlert) -> None:
        """Add a new alert to the SIEM."""
        self.alerts[alert.alert_id] = alert

    def generate_alert_id(self) -> str:
        """Generate a unique alert ID."""
        self._alert_counter += 1
        return f"ALT-{self._alert_counter:04d}"

    def get_pending_alerts(self) -> list[dict]:
        """Get all unresolved alerts."""
        return [
            a.to_dict() for a in self.alerts.values()
            if not a.resolved and not a.dismissed
        ]

    def get_resolved_alert_ids(self) -> list[str]:
        """Get IDs of resolved alerts."""
        return [a.alert_id for a in self.alerts.values() if a.resolved]

    def get_visible_topology(self) -> list[dict]:
        """Get the network topology visible to the agent."""
        return [n.to_dict() for n in self.nodes.values()]

    def calculate_threat_level(self) -> str:
        """Calculate the current overall threat level."""
        compromised = sum(
            1 for n in self.nodes.values()
            if n.status in (NodeStatus.COMPROMISED, NodeStatus.ENCRYPTED)
        )
        critical_compromised = sum(
            1 for n in self.nodes.values()
            if n.is_critical and n.status in (NodeStatus.COMPROMISED, NodeStatus.ENCRYPTED)
        )
        pending = sum(
            1 for a in self.alerts.values()
            if not a.resolved and not a.dismissed and a.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH)
        )

        if critical_compromised >= 2 or compromised >= 4:
            return ThreatLevel.CRITICAL.value
        elif critical_compromised >= 1 or compromised >= 3:
            return ThreatLevel.RED.value
        elif compromised >= 2 or pending >= 3:
            return ThreatLevel.ORANGE.value
        elif compromised >= 1 or pending >= 1:
            return ThreatLevel.YELLOW.value
        return ThreatLevel.GREEN.value

    def health_score(self) -> float:
        """Calculate network health score (0.0 = catastrophic, 1.0 = perfect)."""
        total = len(self.nodes)
        if total == 0:
            return 1.0
        healthy = sum(1 for n in self.nodes.values() if n.status == NodeStatus.HEALTHY)
        isolated = sum(1 for n in self.nodes.values() if n.status == NodeStatus.ISOLATED)
        # Isolated healthy nodes penalize slightly, isolated compromised is neutral
        score = (healthy + 0.5 * isolated) / total
        return round(max(0.0, min(1.0, score)), 3)

    def compromised_count(self) -> int:
        """Count of currently compromised nodes."""
        return sum(
            1 for n in self.nodes.values()
            if n.status in (NodeStatus.COMPROMISED, NodeStatus.ENCRYPTED)
        )

    def is_catastrophic_breach(self) -> bool:
        """Check if the network is in catastrophic failure."""
        critical_down = sum(
            1 for n in self.nodes.values()
            if n.is_critical and n.status in (
                NodeStatus.COMPROMISED, NodeStatus.ENCRYPTED, NodeStatus.OFFLINE
            )
        )
        return critical_down >= 3

    def budget_remaining(self) -> float:
        """Return remaining action budget."""
        return round(max(0.0, self._budget), 1)

    def elapsed_steps(self) -> int:
        """Return steps elapsed."""
        return self._step_count

    def increment_step(self) -> None:
        """Advance the step counter."""
        self._step_count += 1

    def mark_alerts_resolved_for_node(self, node_id: str) -> int:
        """Mark all alerts related to a node as resolved."""
        count = 0
        for alert in self.alerts.values():
            if alert.related_node_id == node_id and not alert.resolved:
                alert.resolved = True
                count += 1
        return count

    def mark_alerts_resolved_for_ip(self, ip_address: str) -> int:
        """Mark all alerts from a source IP as resolved."""
        count = 0
        for alert in self.alerts.values():
            if alert.source_ip == ip_address and not alert.resolved:
                alert.resolved = True
                count += 1
        return count
