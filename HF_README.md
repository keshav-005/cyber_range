---
title: CyberRange Environment Server
emoji: 🛡️
colorFrom: red
colorTo: blue
sdk: docker
app_port: 7860
tags:
  - openenv
  - reinforcement-learning
  - cybersecurity
  - soc-analyst
pinned: false
---

# 🛡️ CyberRange — OpenEnv Environment

An OpenEnv-compatible RL environment for training AI agents as SOC (Security Operations Center) analysts.

## Quick Start

Install the client:
```bash
pip install git+https://huggingface.co/spaces/keshav-005/cyber_range
```

Use the environment:
```python
from cyber_range import CyberRangeEnv, CallToolAction

env = CyberRangeEnv(base_url="https://keshav-005-cyber-range.hf.space")
obs = env.reset(task_id="script_kiddie")
obs = env.step(CallToolAction(tool_name="observe_network", arguments={}))
```

## Features
- 5 scenarios (Easy → Nightmare)
- 10 MCP defensive tools
- Deterministic multi-objective grading
- Step-level reward signals for RL training

## Endpoints
- `/web` — Interactive web interface
- `/docs` — API documentation
- `/health` — Health check
