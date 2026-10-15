# RepoMedic 🩺

> **AI-Assisted Repository Maintenance Workbench for Dependency Resilience**  
> *Built for Hacktoberfest Hack Day Mumbai × ISTE KJSSE (Track 2: Maintenance Agent Skill)*  
> Target Repository: [LinkWatch](https://github.com/rishrek/LinkWatch)

---

## Overview

**RepoMedic** is an evidence-backed repository maintenance engine designed to diagnose and resolve real-world dependency rot, silent incompatibilities, abandoned libraries, and manifest drift.

Unlike chatbots that hallucinate changes, RepoMedic enforces a **three-tier architecture**:
1. **Deterministic Repository Intelligence:** Python AST parsing, cross-manifest reconciliation, and cryptographic evidence hashing.
2. **AI Reasoning Layer (Hermes Agent / Ollama):** Evidence-grounded maintenance recommendations powered by open-weight models (e.g., `qwen2.5-coder:3b` or `qwen2.5-coder:1.5b`) with zero-hallucination fallback.
3. **Sandbox Verification:** Safe execution of checks and test suites in disposable staging sandboxes, preserving target repositories completely untouched.

---

## Architecture

```
                              ┌──────────────────────────────────────────────┐
                              │            Target Repository (LinkWatch)     │
                              └──────────────────────┬───────────────────────┘
                                                     │
                                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. DETERMINISTIC REPO INTELLIGENCE ENGINE                                                              │
│  ├── scanner.py & inventory.py   : Root validation, manifest parsing (TOML/txt), boundary-safe walk    │
│  ├── ghost.py                    : AST import detection, distribution-to-module mapping, ghost detector │
│  ├── compat.py                   : Local metadata version constraints (importlib.metadata)            │
│  ├── impact.py & blast.py        : AST graph building (dependency -> files -> affected test suites)    │
│  ├── tripwire.py                 : Rule-based migration comparison (breaking APIs, deprecations)       │
│  └── ledger.py                   : SHA-256 evidence hashing, staleness check, audit trail             │
└────────────────────────────────────────────────────┬───────────────────────────────────────────────────┘
                                                     │ Verified Evidence Ledger
                                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 2. AI REASONING LAYER                                                                                  │
│  ├── hermes_adapter.py           : Hermes / Ollama OpenAI API client (Qwen2.5-Coder / Hermes-3)         │
│  └── skills/dependency-resilience/SKILL.md : Agent Skills Open Standard definition                     │
└────────────────────────────────────────────────────┬───────────────────────────────────────────────────┘
                                                     │ AI Recommendations
                                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. SANDBOX VERIFICATION & REPORTING                                                                    │
│  ├── verifier.py                 : Isolated scratch copy execution of pytest test suite                │
│  ├── capsule.py                  : Portable Dependency Exit Capsule (.json & .md)                      │
│  └── cli.py                      : Rich terminal workbench (status, scan, analyze, impact, capsule)   │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Track 2: Maintenance Agent Skill Standard

RepoMedic provides a native skill compliant with the **Agent Skills Open Standard (`SKILL.md`)**:
- Location: `repomedic/skills/dependency-resilience/SKILL.md`
- Features: Progressive disclosure, strict evidence-ledger schema, and deterministic rule triggers.

---

## Quickstart

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/rishrek/RepoMedic.git
cd RickRoll1

# Install in editable mode
python -m pip install -e .
```

### 2. Runtime Status Check

Verify local Python interpreter, Ollama availability, and Hermes runtime:
```bash
python -m repomedic.cli status
```

### 3. Scan Target Repository (LinkWatch)

Inspect declared manifests and AST imports:
```bash
python -m repomedic.cli scan target_repo/linkwatch
```

### 4. Run Resilience Rules Engine

Detect ghost dependencies, manifest conflicts, migration tripwires, and private API imports:
```bash
python -m repomedic.cli analyze target_repo/linkwatch
```

### 5. Generate Change Blast-Radius Map

Graph dependency usages against affected source modules and test files:
```bash
python -m repomedic.cli impact target_repo/linkwatch
```

### 6. Export Proof-Carrying Dependency Exit Capsule

Produce reproducible, content-addressed JSON and Markdown audit reports:
```bash
python -m repomedic.cli capsule target_repo/linkwatch -o reports
```

### 7. Run Test Suite

```bash
python -m pytest tests -v
```

---

## Local AI Model Configuration (Ollama)

RepoMedic supports local inference via Ollama without cloud lock-in:

1. **Hardware Recommendation:**
   - **Tested Target:** NVIDIA GeForce RTX 3050 Laptop GPU (4.0 GB VRAM), 16GB RAM.
   - **Recommended Model:** `qwen2.5-coder:3b` or `qwen2.5-coder:1.5b` (Apache-2.0 License).
2. **Download Model:**
   ```bash
   ollama pull qwen2.5-coder:3b
   ```
3. **Configure Environment:**
   ```bash
   # In PowerShell
   $env:REPOMEDIC_LOCAL_MODEL_URL = "http://127.0.0.1:11434"
   $env:REPOMEDIC_LOCAL_MODEL = "qwen2.5-coder:3b"
   ```

If the Ollama daemon is offline or unconfigured, RepoMedic automatically switches to its **deterministic fallback engine**, ensuring zero hallucinations and uninterrupted CI/CD execution.

---

## License

MIT License. See [LICENSE](file:///D:/SVU%20Hackathon/RickRoll1/LICENSE) for details.
