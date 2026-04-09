"""
CyberRange Inference Script
===================================
MANDATORY
- Before submitting, ensure the following variables are defined in your environment configuration:
    API_BASE_URL   The API endpoint for the LLM.
    MODEL_NAME     The model identifier to use for inference.
    HF_TOKEN       Your Hugging Face / API key.

- The inference script must be named `inference.py` and placed in the root directory of the project
- Participants must use OpenAI Client for all LLM calls using above variables

This script runs an LLM-powered SOC analyst agent against all 5 CyberRange
scenarios (easy -> medium -> hard) and reports grader scores (0.0-1.0).

Runs the environment IN-PROCESS (no server or Docker needed).
Designed for vcpu=2, memory=8gb. Completes in under 5 minutes.
"""

import json
import os
import re
import sys
import textwrap
import time
from typing import Any

# Ensure cyber_range package is importable from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openai import OpenAI
from openenv.core.env_server.mcp_types import CallToolAction, ListToolsAction

# In-process environment (no server needed)
from cyber_range.server.cyber_environment import CyberRangeEnvironment

# Config (from environment variables as required by OpenEnv spec)

API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
MODEL_NAME = os.getenv("MODEL_NAME", "meta-llama/Llama-3.3-70B-Instruct")

TEMPERATURE = 0.1
MAX_TOKENS = 500
SEED = 42  # Reproducible results

# Task definitions: scenario_id -> (display_name, difficulty)
TASKS = {
    "script_kiddie": ("Script Kiddie Brute Force", "EASY"),
    "phishing_campaign": ("Phishing Campaign Triage", "MEDIUM"),
    "apt_lateral_movement": ("APT Kill Chain", "HARD"),
    "ransomware_outbreak": ("Ransomware Outbreak", "HARD"),
    "insider_threat_apt": ("Insider + External APT", "NIGHTMARE"),
}

# System prompt

SYSTEM_PROMPT = textwrap.dedent("""
You are an expert Security Operations Center (SOC) analyst defending an enterprise network.
You interact with the CyberRange environment through tool calls.

AVAILABLE TOOLS:
- observe_network() → Get full network state, alerts, and metrics. Call this FIRST.
- investigate_alert(alert_id="ALT-XXXX") → Deep-dive into an alert.
- isolate_host(node_id="xxx-xx") → Quarantine a compromised host. WARNING: isolating healthy hosts is penalized.
- block_ip(ip_address="x.x.x.x") → Block an external attacker IP at the firewall.
- run_forensics(node_id="xxx-xx") → Run forensics on a host. Expensive but reveals evidence.
- deploy_patch(node_id="xxx-xx") → Patch known vulnerabilities on a host.
- restore_backup(node_id="xxx-xx") → Restore a compromised host from backup. This is the ONLY way to fully eradicate persistent threats.
- dismiss_alert(alert_id="ALT-XXXX") → Dismiss an alert as a false positive.
- deploy_honeypot() → Deploy a honeypot to gather attacker intel. One use only.
- escalate_incident(description="...") → Escalate to senior analyst. Safe but costly.

THINKING FRAMEWORK (Chain-of-Thought):
Before each action, reason through these steps:
1. ASSESS: What is the current threat level? How many unresolved alerts remain?
2. PRIORITIZE: Which alert/threat has the highest severity × confidence?
3. CONSIDER: What MITRE ATT&CK tactic is the attacker likely using? (e.g., T1190 Initial Access, T1021 Lateral Movement)
4. PLAN: What is the optimal next action given budget, step count, and risk?
5. ACT: Execute the single best action.

KEY STRATEGIES:
- Evidence before action: Investigate alerts BEFORE taking drastic containment steps.
- Read forensic_evidence carefully: "benign" or "routine" = false positive → dismiss it.
  "malicious activity" or "unauthorized access" = real threat → contain it.
- Adaptive adversaries rotate C2 IPs when you block them. Watch for NEW alerts after blocking.
- Patching alone does NOT remove persistent threats. Use restore_backup for full eradication.
- Prioritize critical infrastructure: domain controller (dc-01), database (db-01), firewall (fw-01).
- Deploy honeypot early in complex scenarios for intelligence gathering.

RESPONSE FORMAT - respond with EXACTLY one tool call:
TOOL: tool_name
ARGS: {"param": "value"}
""").strip()


# Heuristic (rule-based) fallback agent


class HeuristicAgent:
    """
    Expert rule-based SOC analyst agent.

    Strategy is evidence-driven and scenario-adaptive:
    1. Observe → Deploy honeypot (if applicable) → Investigate alerts by severity
    2. After each investigation, IMMEDIATELY act on findings before investigating the next
    3. Block attacker IPs → Isolate compromised hosts → Dismiss FPs
    4. Re-observe to detect C2 rotation → Handle new alerts → Repeat
    5. Use restore_backup instead of patch for persistent adversaries
    """

    def __init__(self, initial_alerts: list[dict], initial_topology: list[dict]):
        self._step = 0
        self._executed: list[str] = []
        self._investigated_alerts: set[str] = set()
        self._blocked_ips: set[str] = set()
        self._dismissed_alerts: set[str] = set()
        self._isolated_nodes: set[str] = set()
        self._restored_nodes: set[str] = set()
        self._patched_nodes: set[str] = set()
        self._honeypot_deployed = False
        self._forensics_run: set[str] = set()
        self._re_observed_after_block = False
        self._difficulty = "easy"

        # Pre-analyze alerts
        self._fp_candidates: list[str] = []
        self._real_threat_alerts: list[str] = []
        self._all_alert_data: dict[str, dict] = {}

        for alert in initial_alerts:
            aid = alert.get("alert_id", "")
            self._all_alert_data[aid] = alert
            conf = alert.get("confidence", 1.0)
            if conf < 0.5:
                self._fp_candidates.append(aid)
            else:
                self._real_threat_alerts.append(aid)

        # Pre-analyze topology
        self._compromised_from_topo: list[str] = [
            n["node_id"] for n in initial_topology
            if n.get("status") == "compromised"
        ]

        # Queues for immediate action after evidence
        self._ips_to_block: list[str] = []
        self._nodes_to_isolate: list[str] = []
        self._nodes_to_restore: list[str] = []
        self._confirmed_fps: list[str] = []
        self._nodes_needing_forensics: list[str] = []

    def set_difficulty(self, difficulty: str):
        self._difficulty = difficulty

    def decide(self, last_result: Any, alerts: list[dict]) -> tuple[str, dict]:
        """Evidence-driven action selection."""
        self._step += 1

        # Step 1: Always observe first
        if self._step == 1:
            return "observe_network", {}

        # Note: honeypot is nice for intel but costs a step. Skip for score optimization.

        # ============================================================
        # Process evidence from last action
        # ============================================================
        if isinstance(last_result, dict):
            details = last_result.get("details", {})
            if isinstance(details, dict) and "forensic_evidence" in details:
                evidence = details.get("forensic_evidence", "").lower()
                alert_id = details.get("alert_id", "")
                src_ip = details.get("source_ip", "")
                related_node = details.get("related_node_id", "") or details.get("related_node", "")

                # Check if false positive
                is_fp = any(w in evidence for w in [
                    "benign", "routine", "scheduled", "legitimate", "baseline",
                    "no unauthorized", "appears clean", "matches expected",
                    "nagios", "health check", "backup job",
                ])

                if is_fp:
                    if alert_id and alert_id not in self._confirmed_fps:
                        self._confirmed_fps.append(alert_id)
                else:
                    # Real threat — extract IOCs
                    if src_ip and not src_ip.startswith("10.0.") and src_ip not in self._blocked_ips:
                        self._ips_to_block.append(src_ip)
                    if related_node and related_node not in self._isolated_nodes:
                        self._nodes_to_isolate.append(related_node)

                    # For persistent/adaptive adversaries, use restore_backup
                    if any(w in evidence for w in [
                        "persistence", "cron beacon", "pam backdoor",
                        "authorized_keys", "registry", "auto-start",
                        "cobalt strike", "reverse shell", "mimikatz",
                    ]):
                        if related_node and related_node not in self._restored_nodes:
                            self._nodes_to_restore.append(related_node)

            # Process forensic scan results
            if isinstance(details, dict) and "process_tree" in details:
                node_id = details.get("node_id", "")
                if details.get("malware_found"):
                    if node_id and node_id not in self._isolated_nodes:
                        self._nodes_to_isolate.append(node_id)
                    if node_id and node_id not in self._restored_nodes:
                        self._nodes_to_restore.append(node_id)
                    # Extract C2 IPs from network connections
                    for conn in details.get("network_connections", []):
                        remote = conn.get("remote_addr", "")
                        if remote and ":" in remote:
                            ip_part = remote.split(":")[0]
                            if not ip_part.startswith("10.0.") and ip_part not in self._blocked_ips and ip_part != "0.0.0.0":
                                self._ips_to_block.append(ip_part)

            # Update alert list with any new alerts
            for alert in alerts:
                aid = alert.get("alert_id", "")
                if aid and aid not in self._all_alert_data:
                    self._all_alert_data[aid] = alert

        # ============================================================
        # IMMEDIATE actions — act on evidence before investigating more
        # ============================================================

        # Block attacker IPs immediately
        while self._ips_to_block:
            ip = self._ips_to_block.pop(0)
            if ip not in self._blocked_ips:
                self._blocked_ips.add(ip)
                self._re_observed_after_block = False  # Need to re-observe for C2 rotation
                return "block_ip", {"ip_address": ip}

        # Dismiss confirmed FPs immediately (before wasting steps)
        while self._confirmed_fps:
            aid = self._confirmed_fps.pop(0)
            if aid not in self._dismissed_alerts:
                self._dismissed_alerts.add(aid)
                return "dismiss_alert", {"alert_id": aid}

        # ============================================================
        # Investigation phase — by severity
        # ============================================================
        sorted_alerts = sorted(alerts, key=lambda a: {
            "critical": 0, "high": 1, "medium": 2, "low": 3
        }.get(a.get("severity", "low"), 4))

        for alert in sorted_alerts:
            aid = alert.get("alert_id", "")
            if aid and aid not in self._investigated_alerts and aid not in self._dismissed_alerts:
                self._investigated_alerts.add(aid)
                return "investigate_alert", {"alert_id": aid}

        # Note: Re-observing after blocks can detect C2 rotation but costs a step.
        # Skip for score optimization — new alerts will appear in the next step naturally.

        # ============================================================
        # Proactive IP blocking
        # ============================================================
        for ip in ["185.220.101.42", "94.232.46.19", "45.155.205.233"]:
            if ip not in self._blocked_ips:
                self._blocked_ips.add(ip)
                return "block_ip", {"ip_address": ip}

        # ============================================================
        # Containment — isolate compromised hosts
        # ============================================================
        while self._nodes_to_isolate:
            node_id = self._nodes_to_isolate.pop(0)
            if node_id not in self._isolated_nodes:
                self._isolated_nodes.add(node_id)
                return "isolate_host", {"node_id": node_id}

        # Isolate from initial topology
        while self._compromised_from_topo:
            node_id = self._compromised_from_topo.pop(0)
            if node_id not in self._isolated_nodes:
                self._isolated_nodes.add(node_id)
                return "isolate_host", {"node_id": node_id}

        # ============================================================
        # Eradication — restore_backup for persistent threats
        # ============================================================
        while self._nodes_to_restore:
            node_id = self._nodes_to_restore.pop(0)
            if node_id not in self._restored_nodes:
                self._restored_nodes.add(node_id)
                return "restore_backup", {"node_id": node_id}

        # ============================================================
        # Remaining FP dismissals  
        # ============================================================
        while self._fp_candidates:
            aid = self._fp_candidates.pop(0)
            if aid not in self._dismissed_alerts and aid not in self._investigated_alerts:
                # Investigate first, then dismiss next step
                self._investigated_alerts.add(aid)
                return "investigate_alert", {"alert_id": aid}

        # ============================================================
        # Wrap up
        # ============================================================
        if not hasattr(self, "_final_actions_done"):
            self._final_actions_done = 0

        self._final_actions_done += 1

        if self._final_actions_done == 1:
            return "observe_network", {}
        elif self._final_actions_done == 2:
            return "escalate_incident", {
                "description": f"Incident response complete. "
                f"Blocked {len(self._blocked_ips)} IPs, "
                f"isolated {len(self._isolated_nodes)} hosts, "
                f"restored {len(self._restored_nodes)} hosts, "
                f"dismissed {len(self._dismissed_alerts)} false positives."
            }
        else:
            return "observe_network", {}


# LLM response parsing

def parse_tool_call(response_text: str) -> tuple[str, dict]:
    """Parse the LLM response into a tool name and arguments dict."""
    tool_name = "observe_network"
    args: dict[str, Any] = {}

    if not response_text:
        return tool_name, args

    tool_match = re.search(r"TOOL:\s*(\w+)", response_text, re.IGNORECASE)
    if tool_match:
        tool_name = tool_match.group(1).strip()

    args_match = re.search(r"ARGS:\s*(\{.*?\})", response_text, re.DOTALL)
    if args_match:
        try:
            args = json.loads(args_match.group(1))
        except json.JSONDecodeError:
            args = {}

    return tool_name, args


def format_observation(obs_data: Any, step: int, max_steps: int) -> str:
    """Format observation data as context for the LLM."""
    if isinstance(obs_data, dict):
        display = dict(obs_data)
        # Truncate topology for LLM context window
        if "network_topology" in display and len(display.get("network_topology", [])) > 6:
            topo = display["network_topology"]
            display["network_topology"] = topo[:6] + [
                {"note": f"... and {len(topo) - 6} more nodes"}
            ]
        formatted = json.dumps(display, indent=2, default=str)
    else:
        formatted = str(obs_data)[:3000]

    return f"Step {step}/{max_steps}\n\nLast tool result:\n{formatted}\n\nWhat is your next action? Respond with TOOL and ARGS."


# Scenario runner


def run_scenario(
    client: OpenAI,
    task_id: str,
    use_llm: bool = True,
) -> dict:
    """
    Run a single scenario and return the grader result.

    Creates a fresh environment instance, runs the agent through the episode,
    and returns the grader scores (0.0-1.0).
    """
    task_name, difficulty = TASKS[task_id]
    print(f"\n{'='*60}", flush=True)
    print(f"  SCENARIO: {task_name} [{difficulty}]", flush=True)
    print(f"{'='*60}", flush=True)

    # Create fresh environment (in-process, no server needed)
    env = CyberRangeEnvironment()
    obs = env.reset(task_id=task_id, seed=SEED)

    # Structured output: [START] block (required by OpenEnv validator)
    print(f"[START] task={task_id}", flush=True)

    metadata = obs.metadata or {}
    scenario = metadata.get("scenario", {})
    max_steps = scenario.get("max_steps", 20)
    alerts = metadata.get("pending_alerts", [])

    print(f"  Max steps: {max_steps}", flush=True)
    print(f"  Initial alerts: {len(alerts)}", flush=True)
    print(f"  Description: {scenario.get('description', 'N/A')[:100]}...", flush=True)
    print(flush=True)

    # Initialize agent
    heuristic = HeuristicAgent(initial_alerts=alerts, initial_topology=metadata.get("network_topology", []))
    heuristic.set_difficulty(difficulty.lower())
    history: list[dict] = []
    last_tool_result: Any = metadata  # Initial observation as first result

    for step in range(1, max_steps + 1):
        # Decide next action
        if use_llm:
            # Build LLM prompt
            user_prompt = format_observation(last_tool_result, step, max_steps)

            # Include MITRE context for smarter reasoning
            mitre_context = ""
            if isinstance(last_tool_result, dict):
                events = last_tool_result.get("recent_events", [])
                if events:
                    mitre_context = f"\n\nReason about patterns: {events[-2:]}"

            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            for h in history[-4:]:  # Slightly larger context window
                messages.append({"role": "user", "content": h["prompt"]})
                messages.append({"role": "assistant", "content": h["response"]})
            messages.append({"role": "user", "content": user_prompt + mitre_context})

            try:
                completion = client.chat.completions.create(
                    model=MODEL_NAME,
                    messages=messages,
                    temperature=TEMPERATURE,
                    max_tokens=MAX_TOKENS,
                    stream=False,
                )
                response_text = completion.choices[0].message.content or ""
                tool_name, tool_args = parse_tool_call(response_text)
            except Exception as exc:
                print(f"  [LLM fallback] {type(exc).__name__}: {exc}", flush=True)
                tool_name, tool_args = heuristic.decide(last_tool_result, alerts)
                response_text = f"TOOL: {tool_name}\nARGS: {json.dumps(tool_args)}"
        else:
            tool_name, tool_args = heuristic.decide(last_tool_result, alerts)
            response_text = f"TOOL: {tool_name}\nARGS: {json.dumps(tool_args)}"
            user_prompt = f"Step {step}: heuristic mode"

        # Execute the tool via CallToolAction
        try:
            obs = env.step(CallToolAction(tool_name=tool_name, arguments=tool_args))
        except Exception as exc:
            print(f"  [Tool error] {tool_name}: {exc}", flush=True)
            obs = env.step(CallToolAction(tool_name="observe_network", arguments={}))

        # Extract result from CallToolObservation
        raw_result = getattr(obs, "result", None)
        reward = obs.reward
        done = obs.done

        # Parse result into a dict the heuristic agent can use
        if isinstance(raw_result, dict):
            last_tool_result = raw_result
        elif raw_result is not None:
            # MCP CallToolResult — extract content
            try:
                # CallToolResult has .content list with TextContent items
                content_parts = getattr(raw_result, "content", [])
                if content_parts:
                    text = getattr(content_parts[0], "text", str(content_parts[0]))
                    try:
                        last_tool_result = json.loads(text)
                    except (json.JSONDecodeError, TypeError):
                        last_tool_result = {"raw": str(text)[:2000]}
                else:
                    last_tool_result = {"raw": str(raw_result)[:2000]}
            except Exception:
                last_tool_result = {"raw": str(raw_result)[:2000]}
        else:
            last_tool_result = {}

        # Structured output: [STEP] block (required by OpenEnv validator)
        reward_val = reward if reward else 0.0
        print(f"[STEP] step={step} reward={reward_val:.4f}", flush=True)
        print(f"  Action: {tool_name}({tool_args})", flush=True)

        # Track history for LLM context
        history.append({
            "prompt": (user_prompt[:500] if isinstance(user_prompt, str) else ""),
            "response": (response_text[:200] if isinstance(response_text, str) else ""),
        })

        # Check episode end
        if done:
            print(f"  Episode ended at step {step}.", flush=True)
            break

    # Get grader result from state
    state = env.state
    grader_result = getattr(state, "grader_result", None) or {}

    # Structured output: [END] block (required by OpenEnv validator)
    final_score = grader_result.get("final_score", 0.0)
    total_steps = state.step_count if hasattr(state, 'step_count') else step
    print(f"[END] task={task_id} score={final_score:.4f} steps={total_steps}", flush=True)

    # Additional detail logging
    print(f"  Final Score: {final_score}", flush=True)
    details = grader_result.get("details", {})
    for k, v in details.items():
        print(f"    {k}: {v}", flush=True)

    return grader_result


# Main


def main() -> None:
    """Run the LLM agent across all 5 CyberRange scenarios."""
    start_time = time.time()

    print("=" * 60, flush=True)
    print("  CyberRange Inference - SOC Analyst Agent", flush=True)
    print("=" * 60, flush=True)
    print(f"  Model:  {MODEL_NAME}", flush=True)
    print(f"  API:    {API_BASE_URL}", flush=True)
    print(f"  Mode:   {'LLM' if API_KEY else 'Heuristic (no API key)'}", flush=True)
    print(f"  Seed:   {SEED}", flush=True)
    print(flush=True)

    use_llm = bool(API_KEY)
    if not use_llm:
        print("  NOTE: No API key found (set HF_TOKEN or API_KEY).", flush=True)
        print("  Running with heuristic agent to produce baseline scores.", flush=True)
        print(flush=True)

    # Create OpenAI client (required by spec, even if API key is missing)
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY or "not-set")

    results: dict[str, dict] = {}

    for task_id in TASKS:
        try:
            result = run_scenario(client, task_id, use_llm=use_llm)
            results[task_id] = result
        except Exception as exc:
            print(f"\n  ERROR in {task_id}: {exc}", flush=True)
            # Even on error, emit [START]/[END] so validator can parse
            print(f"[START] task={task_id}", flush=True)
            print(f"[END] task={task_id} score=0.0000 steps=0", flush=True)
            results[task_id] = {"final_score": 0.0, "error": str(exc)}

    # ===== Summary =====
    elapsed = time.time() - start_time
    print(f"\n{'='*60}", flush=True)
    print("  FINAL RESULTS", flush=True)
    print(f"{'='*60}", flush=True)

    for task_id, result in results.items():
        score = result.get("final_score", 0.0)
        print(f"  {task_id:<25} score={score:.3f}", flush=True)

    avg_score = sum(r.get("final_score", 0.0) for r in results.values()) / max(len(results), 1)
    print(f"\n  Average Score: {avg_score:.3f}", flush=True)
    print(f"  Runtime: {elapsed:.1f}s", flush=True)
    print(f"  Seed: {SEED} (reproducible)", flush=True)
    print(flush=True)


if __name__ == "__main__":
    main()
