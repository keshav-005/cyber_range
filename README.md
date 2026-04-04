# 🛡️ CyberRange

**An OpenEnv environment for training AI agents as SOC (Security Operations Center) analysts.**

CyberRange drops an AI agent into a simulated 12-node enterprise network under active cyber attack. The agent must triage SIEM alerts, investigate threats, distinguish real incidents from false positives, and execute defensive actions — all under budget and time constraints. Five scenarios span four difficulty levels, from a simple brute-force attempt to a simultaneous insider + APT nightmare.

Built on the [OpenEnv](https://github.com/meta-pytorch/openenv) framework using FastMCP for tool-based interaction.

---

## Table of Contents

- [Why CyberRange?](#why-cyberrange)
- [Architecture](#architecture)
- [Network Topology](#network-topology)
- [Scenarios](#scenarios)
- [Action Space (10 MCP Tools)](#action-space-10-mcp-tools)
- [Observation Space](#observation-space)
- [Grading System](#grading-system)
- [Reward Shaping](#reward-shaping)
- [Baseline Scores](#baseline-scores)
- [Quick Start](#quick-start)
- [Building a Custom Agent](#building-a-custom-agent)
- [Project Structure](#project-structure)
- [Development](#development)
- [License](#license)

---

## Why CyberRange?

Real-world SOC analysts face a constant stream of decisions under pressure: which alerts are real? Which hosts need isolation? Is this traffic anomalous or just a scheduled backup? CyberRange captures this decision-making challenge in an environment that:

- **Simulates realistic attack patterns** — brute force, phishing, APT kill chains, ransomware lateral movement, and insider threats with multi-stage progression
- **Tests analytical judgement** — false positives are mixed in with real threats; dismissing a real alert is catastrophic, but over-reacting to every alert wastes budget and disrupts operations
- **Rewards strategic thinking** — raw "block everything" strategies are penalized for collateral damage; the optimal policy requires investigation before action
- **Is fully deterministic** — given the same seed, the same actions produce the same outcomes, making results reproducible and comparable across agents

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Agent (your code)                       │
│  MCPToolClient / LLM / RL policy / heuristic / ...          │
└────────────────────────┬─────────────────────────────────────┘
                         │  WebSocket (server mode)
                         │  or direct Python call (in-process mode)
┌────────────────────────▼─────────────────────────────────────┐
│                   FastAPI Server (app.py)                     │
│         OpenEnv HTTP API: reset() / step() / state()         │
├──────────────────────────────────────────────────────────────┤
│              CyberRangeEnvironment (MCPEnvironment)           │
│                    10 registered MCP tools                    │
├──────────────────────────────────────────────────────────────┤
│                     Simulation Engine                         │
│  ┌──────────────────┬──────────────────┬──────────────────┐  │
│  │ NetworkSimulator │  AttackEngine    │ RewardCalculator │  │
│  │  12-node topo    │  5 scenarios     │  multi-objective │  │
│  │  SIEM alerts     │  kill chains     │  reward signals  │  │
│  │  host statuses   │  graders         │  cumulative      │  │
│  └──────────────────┴──────────────────┴──────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### Component Breakdown

| Component | File | Responsibility |
|-----------|------|----------------|
| **FastAPI server** | `server/app.py` | HTTP/WebSocket entry point. Creates the OpenEnv-compatible `create_app()` |
| **Environment** | `server/cyber_environment.py` | Core `MCPEnvironment` subclass. Registers 10 MCP tools, implements `reset()` / `step()` / `state()` |
| **Network simulator** | `server/network_simulator.py` | Maintains the 12-node topology, host statuses, SIEM alerts, and executes defensive actions |
| **Attack engine** | `server/attack_engine.py` | Defines 5 scenarios with multi-phase attack chains, drives attacker progression, and runs deterministic grading |
| **Reward calculator** | `server/reward_calculator.py` | Computes per-step reward from `ActionResult` using a multi-objective function |
| **Data models** | `models.py` | Enums (`NodeStatus`, `AlertSeverity`, `AlertType`, `ThreatLevel`, `Difficulty`) and dataclasses (`NetworkNode`, `NetworkAlert`, `AttackPhase`, `ScenarioConfig`, `ActionResult`, `EpisodeMetrics`) |
| **Client** | `client.py` | `CyberRangeEnv` — a thin `MCPToolClient` wrapper for connecting to the server |

---

## Network Topology

CyberRange simulates a segmented enterprise network with 12 hosts across 6 network segments:

```
                        ┌─────────────────────┐
                        │     INTERNET         │
                        └──────────┬──────────┘
                                   │
                   ┌───────────────▼───────────────┐
                   │           DMZ                  │
                   │  fw-01 (PfSense 2.7) ★        │
                   │  web-01 (Ubuntu 22.04) ★       │
                   └───────────────┬───────────────┘
                                   │
          ┌────────────────────────┼────────────────────────┐
          │                        │                        │
┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌──────────▼──────────┐
│    CORPORATE       │  │     DATA           │  │    WORKSTATIONS      │
│ dc-01 (Win2022) ★  │  │ db-01 (CentOS) ★   │  │ ws-01 (Win 11)       │
│ mail-01 (Ubuntu) ★ │  │ backup-01 (Ubuntu)★ │  │ ws-02 (Win 11)       │
│ app-01 (Ubuntu)    │  └────────────────────┘  │ ws-03 (Win 11)       │
└────────────────────┘                          │ ws-04 (macOS 14)     │
                                                └──────────────────────┘
          ┌────────────────────────┐  ┌────────────────────────┐
          │      MANAGEMENT        │  │      DECEPTION          │
          │  ids-01 (Debian 12)    │  │  honeypot-01 (Debian)   │
          └────────────────────────┘  └────────────────────────┘

★ = critical infrastructure (isolating when healthy incurs heavy penalty)
```

| Node ID | Hostname | Type | OS | Critical | Open Ports |
|---------|----------|------|----|----------|------------|
| `fw-01` | perimeter-fw | Firewall | PfSense 2.7 | ✅ | 443, 8443 |
| `dc-01` | ad-controller | Domain Controller | Windows Server 2022 | ✅ | 53, 88, 389, 636, 445 |
| `web-01` | web-frontend | Web Server | Ubuntu 22.04 | ✅ | 80, 443, 22 |
| `mail-01` | mail-server | Mail Server | Ubuntu 22.04 | ✅ | 25, 587, 993, 22 |
| `db-01` | prod-database | Database | CentOS 9 | ✅ | 5432, 22 |
| `app-01` | app-backend | App Server | Ubuntu 22.04 | ❌ | 8080, 8443, 22 |
| `ws-01` | analyst-pc-1 | Workstation | Windows 11 | ❌ | 445, 3389 |
| `ws-02` | dev-pc-1 | Workstation | Windows 11 | ❌ | 445, 3389 |
| `ws-03` | hr-pc-1 | Workstation | Windows 11 | ❌ | 445, 3389 |
| `ws-04` | exec-pc-1 | Workstation | macOS 14 | ❌ | 22, 5900 |
| `honey-01` | honeypot-svr | Honeypot | Debian 12 | ❌ | (none) |
| `backup-01` | backup-server | Backup Server | Ubuntu 22.04 | ✅ | 22, 873 |

### Host Statuses

| Status | Meaning |
|--------|---------|
| `healthy` | Normal operation |
| `compromised` | Attacker has gained access |
| `isolated` | Quarantined (cannot communicate) |
| `offline` | Powered down |
| `encrypted` | Ransomware has encrypted the host |

---

## Scenarios

### 1. Script Kiddie Brute Force — `script_kiddie`

| | |
|---|---|
| **Difficulty** | 🟢 Easy |
| **Max Steps** | 15 |
| **Threats** | 1 |
| **False Positives** | 1 |

A script kiddie is running an SSH brute force attack against your web server (`web-01`) from external IP `185.220.101.42`. One alert is real, one is a false positive from a scheduled backup job. Block the attacker and dismiss the false positive.

**Kill Chain:** `SSH Brute Force → web-01 compromised (8 steps)`

---

### 2. Phishing Campaign Triage — `phishing_campaign`

| | |
|---|---|
| **Difficulty** | 🟡 Medium |
| **Max Steps** | 25 |
| **Threats** | 3 |
| **False Positives** | 2 |

A targeted phishing campaign hits the organization. Three workstations (`ws-01`, `ws-02`) clicked phishing links and are infected with malware. Two false positives from legitimate email activity add noise. The malware may attempt lateral movement to `app-01` if `ws-01` isn't contained in time.

**Kill Chain:** `ws-01 infection → ws-02 infection → (if unchecked) lateral spread to app-01`

---

### 3. APT Kill Chain — `apt_lateral_movement`

| | |
|---|---|
| **Difficulty** | 🔴 Hard |
| **Max Steps** | 35 |
| **Threats** | 5 |
| **False Positives** | 3 |

An Advanced Persistent Threat group has exploited a vulnerability on `web-01` and is executing a full multi-stage attack. The agent must trace and interrupt the kill chain before data is exfiltrated from the production database.

**Kill Chain:**
```
Initial Access (web-01) → Credential Harvesting (web-01) → Lateral Movement (dc-01)
→ Privilege Escalation (dc-01) → Data Exfiltration (db-01, 5 MB/step)
```

---

### 4. Ransomware Outbreak — `ransomware_outbreak`

| | |
|---|---|
| **Difficulty** | 🔴 Hard |
| **Max Steps** | 20 |
| **Threats** | 4 |
| **False Positives** | 1 |

A ransomware payload has detonated on `ws-01` and is spreading via SMB, encrypting hosts every few steps. The agent faces a strategic dilemma: isolate aggressively (causing business disruption) or attempt targeted containment (risking further spread). If `backup-01` gets encrypted, recovery becomes impossible.

**Kill Chain:**
```
ws-01 encrypted → ws-02 encrypted → app-01 encrypted → backup-01 encrypted (game over)
```

---

### 5. Insider + External APT — `insider_threat_apt`

| | |
|---|---|
| **Difficulty** | 💀 Nightmare |
| **Max Steps** | 45 |
| **Threats** | 7 |
| **False Positives** | 4 |

Two simultaneous threats. A malicious insider on the executive workstation (`ws-04`) is exfiltrating sensitive HR/financial data to personal cloud storage. Meanwhile, an external APT group has compromised the mail server (`mail-01`) and is moving laterally toward the domain controller. Four false positives add noise. Both threats must be contained while managing limited resources.

**Kill Chains (parallel):**
```
INSIDER:  Data Staging (ws-04) → Data Exfiltration (ws-04, 3 MB/step)

APT:      Mail Compromise (mail-01) → Credential Harvest (mail-01) → Lateral Movement (dc-01)
          → Privilege Escalation (dc-01) → Mass Exfiltration (db-01, 10 MB/step)
```

---

## Action Space (10 MCP Tools)

Every tool call advances the simulation by one step — the attacker also progresses, new alerts may fire, and the agent receives a reward signal.

### Reconnaissance

| Tool | Cost | Description |
|------|------|-------------|
| `observe_network()` | 0 | Get a real-time snapshot of the entire network: node statuses, pending alerts, threat level, health score, budget remaining, and episode progress. **Always call this first.** |

### Investigation

| Tool | Cost | Description |
|------|------|-------------|
| `investigate_alert(alert_id)` | 2 | Deep-dive into a specific alert. Returns forensic evidence, confidence levels, and recommended actions. Reveals whether the alert is a false positive or a real threat. |
| `run_forensics(node_id)` | 5 | Memory and disk forensic analysis on a host. Detects malware, suspicious processes, anomalous connections, and credential theft. Expensive but provides critical intelligence. |

### Containment

| Tool | Cost | Description |
|------|------|-------------|
| `isolate_host(node_id)` | 3 | Quarantine a host from the network. Prevents lateral movement from/to the host. ⚠️ Isolating a healthy critical host incurs severe penalties. |
| `block_ip(ip_address)` | 2 | Block an IP at the perimeter firewall. Effective against external attackers. ⚠️ Blocking internal IPs disrupts business operations. |

### Remediation

| Tool | Cost | Description |
|------|------|-------------|
| `deploy_patch(node_id)` | 3 | Push a security patch to remediate known CVEs. Cannot patch isolated, offline, or encrypted hosts. |
| `restore_backup(node_id)` | 8 | Restore a compromised/encrypted host from its last known-good backup. Expensive but fully remediates the threat and returns the host to healthy status. |

### Triage

| Tool | Cost | Description |
|------|------|-------------|
| `dismiss_alert(alert_id)` | 0 | Mark an alert as a false positive and close it. Correctly dismissing FPs earns +3 reward. ⚠️ Dismissing a real threat incurs -15 penalty. |

### Deception

| Tool | Cost | Description |
|------|------|-------------|
| `deploy_honeypot()` | 4 | Deploy a network honeypot at `honey-01` to attract and log attacker activity. Provides ongoing intel about attacker behavior. Can only be deployed once per episode. |

### Management

| Tool | Cost | Description |
|------|------|-------------|
| `escalate_incident(description)` | 1 | Escalate to a senior analyst. Safe fallback when uncertain, but costs budget and time. |

---

## Observation Space

### Initial Observation (from `reset()`)

```json
{
  "scenario": {
    "id": "script_kiddie",
    "name": "Script Kiddie Brute Force",
    "description": "A script kiddie is running an SSH brute force...",
    "difficulty": "easy",
    "max_steps": 15
  },
  "network_topology": [
    {
      "node_id": "fw-01",
      "hostname": "perimeter-fw",
      "ip_address": "10.0.0.1",
      "node_type": "firewall",
      "os": "PfSense 2.7",
      "status": "healthy",
      "open_ports": [443, 8443],
      "running_services": ["firewall", "vpn"],
      "is_critical": true
    }
  ],
  "pending_alerts": [
    {
      "alert_id": "ALT-0001",
      "severity": "high",
      "source_ip": "185.220.101.42",
      "alert_type": "brute_force",
      "description": "[HIGH] SSH Brute Force: Automated SSH login attempts...",
      "confidence": 0.92,
      "raw_log": "sshd[12345]: Failed password for root from 185.220.101.42..."
    }
  ],
  "threat_level": "yellow",
  "health_score": 1.0,
  "budget_remaining": 100.0,
  "available_actions": ["observe_network", "investigate_alert", "..."]
}
```

### Step Observation (from tool calls)

Each tool returns a result dict specific to the action, plus a `network_summary`:

```json
{
  "action": "investigate_alert",
  "result": "Investigation of alert ALT-0001 complete.",
  "success": true,
  "details": {
    "alert_id": "ALT-0001",
    "severity": "high",
    "source_ip": "185.220.101.42",
    "forensic_evidence": "Analysis confirms malicious activity! Identified unauthorized access attempts targeting web-01. Source origin traced to 185.220.101.42. Recommend immediate containment."
  },
  "reward": 0.5,
  "network_summary": {
    "threat_level": "yellow",
    "health_score": 1.0,
    "budget_remaining": 99.0,
    "step": 2,
    "max_steps": 15,
    "pending_alerts_count": 2,
    "compromised_hosts": 0,
    "episode_done": false,
    "cumulative_reward": 0.5
  }
}
```

### Key Observation Fields

| Field | Type | Description |
|-------|------|-------------|
| `network_topology` | `list[dict]` | All 12 nodes with IDs, hostnames, IPs, statuses, ports, services |
| `pending_alerts` | `list[dict]` | Unresolved alerts with severity, type, confidence, raw logs |
| `resolved_alerts` | `list[str]` | IDs of handled alerts |
| `active_incidents` | `list[str]` | Currently active attack phase descriptions |
| `threat_level` | `str` | Overall assessment: `green` / `yellow` / `orange` / `red` / `critical` |
| `health_score` | `float` | Network health from 0.0 (catastrophic) to 1.0 (perfect) |
| `budget_remaining` | `float` | Remaining action budget (starts at 100.0) |
| `step` / `max_steps` | `int` | Current step and episode length |
| `cumulative_reward` | `float` | Total reward accumulated so far |
| `honeypot_intel` | `list[str]` | Intelligence gathered by the honeypot (if deployed) |

---

## Grading System

Each scenario has a **deterministic grader** (seed=42) that produces a final score from **0.0** to **1.0** composed of five weighted components:

| # | Component | Weight | What It Measures |
|---|-----------|--------|------------------|
| 1 | **Threat Neutralization** | 35% | Ratio of threats successfully contained vs. total threats. Penalizes attacker-completed objectives. |
| 2 | **False Positive Handling** | 20% | Ratio of FPs correctly dismissed vs. total FPs. Penalizes acting on false positives. |
| 3 | **Data Protection** | 20% | Penalizes data exfiltration. Score = 1.0 if no data stolen; degrades proportional to MB exfiltrated. |
| 4 | **Collateral Damage** | 15% | Penalizes isolating healthy hosts (-0.25 each), disrupting critical services (-0.4 each), and ignoring real threats (-0.3 each). |
| 5 | **Efficiency** | 10% | Rewards speed. ≤50% steps = 1.0, ≤75% = 0.7, ≤100% = 0.4. |

**Formula:**

```
final_score = Σ(component_score × weight)

where:
  threat_neutralization = max(0, neutralized/total - 0.5 × completed_uncontained/phases)
  false_positive_handling = max(0, fp_dismissed/fp_total - 0.3 × fp_mistaken/fp_total)
  data_protection = 1.0 - min(1.0, exfiltrated_mb / max_possible_mb)
  collateral_damage = max(0, 1.0 - 0.25×healthy_isolated - 0.4×critical_disrupted - 0.3×threats_ignored)
  efficiency = {1.0 if steps ≤ 50%, 0.7 if ≤ 75%, 0.4 if ≤ 100%, 0.1 otherwise}
```

### Episode Termination

An episode ends when any of these conditions is met:
- **Step limit reached** — agent used all available steps
- **Full containment** — all attack phases are contained or completed
- **Catastrophic breach** — 3+ critical hosts compromised/encrypted/offline
- **Budget exhausted** — action budget reaches 0

---

## Reward Shaping

CyberRange provides **step-level reward signals** (not just end-of-episode), enabling reinforcement learning:

### Positive Rewards

| Signal | Reward | Condition |
|--------|--------|-----------|
| Threat neutralized | `+10 × severity_multiplier` | Isolating a compromised host or blocking attacker IP |
| False positive dismissed | `+3.0` | Correctly dismissing a false positive alert |
| Exfiltration prevented | `+5.0 × MB` | Containing an active exfiltration |
| Intelligence gathered | `+2.0 × intel_value` | Honeypot deployment, forensics on compromised host |
| Health improvement | `+2.0 × health_delta` | Actions that improve network health |
| Attack chain resolved | `+25.0` | Resolving an entire multi-stage attack chain |

### Negative Rewards (Penalties)

| Signal | Penalty | Condition |
|--------|---------|-----------|
| Healthy host isolated | `-8.0` | Isolating a host that wasn't compromised |
| Real threat ignored | `-15.0` | Dismissing an alert that was a real threat |
| Critical service disrupted | `-20.0` | Isolating a healthy critical infrastructure host |
| Resource cost | `-0.5 × cost` | Every action has a budget cost |
| Failed action | `-0.5` | Attempting an invalid or no-op action |

---

## Baseline Scores

Measured with `seed=42` for full reproducibility:

| Scenario | Difficulty | Random Agent | Heuristic Agent |
|----------|------------|-------------|-----------------|
| Script Kiddie | 🟢 Easy | 0.322 | 0.800 |
| Phishing Campaign | 🟡 Medium | 0.307 | 0.650 |
| APT Kill Chain | 🔴 Hard | 0.203 | 0.627 |
| Ransomware Outbreak | 🔴 Hard | 0.412 | 0.590 |
| Insider + APT | 💀 Nightmare | 0.202 | 0.569 |

**Reproduce with:**
```bash
python inference.py              # Heuristic agent (no API key needed)
python random_baseline.py        # Random agent
```

---

## Quick Start

### Prerequisites

- Python ≥ 3.10
- `openenv-core[core] >= 0.2.2`

### Option 1: Install & Run Locally

```bash
# Clone the repo
git clone <repository-url>
cd cyber_range

# Install with dev + inference dependencies
pip install -e ".[dev,inference]"

# Run the heuristic baseline (no API key needed)
python inference.py

# Run with an LLM
export HF_TOKEN="your_huggingface_token"
export MODEL_NAME="meta-llama/Llama-3.3-70B-Instruct"
python inference.py
```

### Option 2: Run the Server (WebSocket mode)

```bash
# Start the FastAPI server
uvicorn cyber_range.server.app:app --host 0.0.0.0 --port 8000

# The server exposes:
#   - WebSocket endpoint for agent connections
#   - /health endpoint for monitoring
#   - /docs for interactive API docs (Swagger UI)
```

### Option 3: Docker

```bash
# Build and run
docker build -t cyber-range -f cyber_range/server/Dockerfile .
docker run -p 8000:8000 cyber-range

# Or with docker-compose
docker compose up
```

### Verify Installation

```bash
python validate.py    # Runs 30+ structural, import, and grader checks
```

---

## Building a Custom Agent

### In-Process (Recommended for Development)

```python
from cyber_range.server.cyber_environment import CyberRangeEnvironment
from openenv.core.env_server.mcp_types import CallToolAction

# Create environment — no server needed
env = CyberRangeEnvironment()

# Reset with a specific scenario and seed
obs = env.reset(task_id="phishing_campaign", seed=42)

# The agent loop
while not obs.done:
    # 1. Read the observation
    alerts = obs.metadata.get("pending_alerts", [])
    threat_level = obs.metadata.get("threat_level", "green")

    # 2. Decide on an action (your agent logic here)
    action = CallToolAction(
        tool_name="investigate_alert",
        arguments={"alert_id": alerts[0]["alert_id"]}
    )

    # 3. Execute
    obs = env.step(action)
    print(f"Reward: {obs.reward}, Done: {obs.done}")

# 4. Get final grade
grader = getattr(env.state, "grader_result", {})
print(f"Final Score: {grader.get('final_score', 0.0)}")
```

### Via WebSocket Client

```python
from cyber_range import CyberRangeEnv

env = CyberRangeEnv(scenario="apt_lateral_movement")
tools = env.get_tools()   # List all 10 available tools
obs = env.reset()

while not obs.done:
    tool_name, args = my_agent.decide(obs)
    obs = env.step(tool_name=tool_name, arguments=args)

print(f"Score: {env.state.grader_result['final_score']}")
```

### Agent Template

A ready-to-use template is provided at [`examples/custom_agent_template.py`](examples/custom_agent_template.py).

### Environment Variables for LLM-Based Agents

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HF_TOKEN` | For LLM mode | — | Hugging Face API token |
| `API_BASE_URL` | No | `https://router.huggingface.co/v1` | LLM API endpoint |
| `MODEL_NAME` | No | `meta-llama/Llama-3.3-70B-Instruct` | Model identifier |

---

## Project Structure

```
cyber_range/
├── __init__.py                    # Package exports: CyberRangeEnv, CallToolAction, ListToolsAction
├── models.py                      # Enums, dataclasses (NetworkNode, NetworkAlert, ActionResult, ...)
├── client.py                      # CyberRangeEnv — MCPToolClient wrapper for WebSocket mode
├── openenv.yaml                   # OpenEnv manifest (spec_version, tasks, tools, grading, network)
├── pyproject.toml                 # Build config, dependencies, tool settings
├── LICENSE                        # BSD-3-Clause
├── CONTRIBUTING.md                # Contributor guidelines
├── README.md                      # This file
├── server/
│   ├── __init__.py
│   ├── app.py                     # FastAPI entry point (create_app with CyberRangeEnvironment)
│   ├── cyber_environment.py       # MCPEnvironment subclass — 10 MCP tools, reset/step/state
│   ├── network_simulator.py       # 12-node network topology, host management, defensive actions
│   ├── attack_engine.py           # 5 scenario definitions, attack progression, deterministic grading
│   ├── reward_calculator.py       # Multi-objective step-level reward function
│   ├── Dockerfile                 # Multi-stage Docker build using openenv-base
│   └── requirements.txt           # Server-specific dependencies
├── examples/
│   └── custom_agent_template.py   # Starter template for building your own agent
└── outputs/
    └── evals/                     # Episode logs (JSON) — auto-generated after each episode

tests/                             # pytest suite (165 tests)
├── conftest.py                    # Shared fixtures (environment, network, attack engine)
├── test_attack_engine.py          # Attack progression, scenario loading, grading
├── test_environment.py            # MCP tool execution, reset/step/state contract
├── test_inference.py              # Inference script parsing, heuristic agent logic
├── test_network_simulator.py      # Network topology, defensive actions, host statuses
├── test_reward_calculator.py      # Reward signals for all action types
└── test_scenarios.py              # Scenario-specific end-to-end tests

inference.py                       # Baseline LLM + heuristic agent (OpenEnv spec-compliant)
random_baseline.py                 # Random agent for lower-bound scoring
validate.py                        # Pre-submission validation (30+ checks)
docker-compose.yml                 # Docker composition for server mode
```

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run full test suite (165 tests)
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=cyber_range

# Lint and format
ruff check . && ruff format .

# Pre-submission validation
python validate.py
```

### Resource Requirements

| Mode | CPU | Memory | GPU |
|------|-----|--------|-----|
| In-process (inference) | 1 vCPU | 512 MB | ❌ |
| Server (Docker) | 1 vCPU | 512 MB | ❌ |
| With LLM inference | 2 vCPU | 8 GB | ❌ |

---

## License

[BSD-3-Clause](LICENSE)
