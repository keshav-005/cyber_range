"""Deploy CyberRange to HuggingFace Spaces using upload_folder (fast)."""
import os
import sys
import tempfile
import shutil

os.environ["PYTHONUTF8"] = "1"

from huggingface_hub import HfApi, create_repo

REPO_ID = "keshav-005/cyber_range"
TOKEN = "hf_yJZnynEqOMXJwClxKfyourkBnNWYduEAiO"

api = HfApi(token=TOKEN)
project_root = os.path.dirname(os.path.abspath(__file__))

# Step 1: Create the Space
print("Creating HuggingFace Space...")
try:
    url = create_repo(
        repo_id=REPO_ID,
        repo_type="space",
        space_sdk="docker",
        token=TOKEN,
        exist_ok=True,
    )
    print(f"  Space ready: {url}")
except Exception as e:
    print(f"  Note: {e}")

# Step 2: Build a staging directory with everything we need
staging = os.path.join(project_root, "_hf_staging")
if os.path.exists(staging):
    shutil.rmtree(staging)
os.makedirs(staging)

# Copy project files (excluding junk)
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "_hf_staging", ".agents"}
SKIP_FILES = {"deploy_to_hf.py", "validation_results.log", "HF_README.md"}

for root, dirs, files in os.walk(project_root):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for fname in files:
        if fname in SKIP_FILES or fname.endswith((".pyc", ".pyo")):
            continue
        src = os.path.join(root, fname)
        rel = os.path.relpath(src, project_root)
        dst = os.path.join(staging, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy2(src, dst)

# Step 3: Create the HF-specific Dockerfile at staging root
dockerfile_content = """\
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \\
    curl git \\
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app/

ENV PYTHONPATH="/app:$PYTHONPATH"
ENV ENABLE_WEB_INTERFACE=true

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \\
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:7860/health')" || exit 1

CMD ["uvicorn", "cyber_range.server.app:app", "--host", "0.0.0.0", "--port", "7860"]
"""
with open(os.path.join(staging, "Dockerfile"), "w") as f:
    f.write(dockerfile_content)

# Step 4: Create the HF Space README (with YAML frontmatter)
# This replaces the project README for the Space display
readme_content = """\
---
title: CyberRange Environment Server
emoji: "\U0001f6e1\ufe0f"
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

# CyberRange - OpenEnv Environment

An OpenEnv-compatible RL environment for training AI agents as SOC analysts.

## Quick Start

```bash
pip install git+https://huggingface.co/spaces/keshav-005/cyber_range
```

```python
from cyber_range import CyberRangeEnv, CallToolAction

env = CyberRangeEnv(base_url="https://keshav-005-cyber-range.hf.space")
obs = env.reset(task_id="script_kiddie")
obs = env.step(CallToolAction(tool_name="observe_network", arguments={}))
```

## Features
- 5 scenarios (Easy to Nightmare)
- 10 MCP defensive tools
- Deterministic multi-objective grading
- Step-level reward signals for RL training

## Endpoints
- `/web` - Interactive web interface
- `/docs` - API documentation (Swagger)
- `/health` - Health check
"""

# Save original README as PROJECT_README.md
orig_readme = os.path.join(staging, "README.md")
if os.path.exists(orig_readme):
    shutil.copy2(orig_readme, os.path.join(staging, "PROJECT_README.md"))

with open(os.path.join(staging, "README.md"), "w", encoding="utf-8") as f:
    f.write(readme_content)

# Count files
file_count = sum(1 for r, d, fs in os.walk(staging) for _ in fs)
print(f"\nUploading {file_count} files to Space...")

# Step 5: Upload entire folder at once (FAST)
api.upload_folder(
    folder_path=staging,
    repo_id=REPO_ID,
    repo_type="space",
    token=TOKEN,
)

# Cleanup
shutil.rmtree(staging)

print(f"\n{'='*60}")
print(f"  DEPLOYMENT COMPLETE!")
print(f"  Space: https://huggingface.co/spaces/{REPO_ID}")
print(f"  Web:   https://keshav-005-cyber-range.hf.space/web")
print(f"  Docs:  https://keshav-005-cyber-range.hf.space/docs")
print(f"{'='*60}")
