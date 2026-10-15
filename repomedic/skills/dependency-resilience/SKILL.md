---
name: dependency-resilience
description: Inspects Python repository manifests and source AST imports to detect ghost dependencies, evaluate migration tripwires, calculate blast radius, and generate proof-carrying Dependency Exit Capsules.
---

# Dependency Resilience Skill

This skill equips Hermes Agent and AI coding assistants to conduct rigorous repository dependency audits, detect unmaintained or ghost packages, map change blast radiuses, safely verify proposed migrations, and produce evidence-backed Dependency Exit Capsules.

## Operating Principles

1. **Non-destructive Baseline**: Never modify repository source files or manifests automatically without explicit approval.
2. **Evidence-based Findings**: Every finding must reference concrete files, line numbers, or AST import statements.
3. **Rigorous Status Vocabulary**:
   - `observed`: Concrete factual evidence directly extracted from manifests or source code.
   - `inferred`: Logical deduction made from static AST import cross-referencing.
   - `recommended`: AI or rule-based proposal for package migration, replacement, or removal.
   - `verified`: Tested in an isolated sandbox with exit code 0.
   - `failed`: Tested in an isolated sandbox with non-zero exit code.
   - `blocked`: Prerequisite or test runner unavailable in current environment.
   - `not_run`: Planned check that has not yet been executed.
4. **Sandboxed Verification**: Run checks in an isolated temporary worktree or copy to prevent unintended side effects on the working tree.

## Step-by-Step Execution Workflow

### Step 1: Inventory Repository and Manifests
- Locate dependency manifests: `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, `setup.cfg`.
- Extract declared packages, pinned versions, and exact line numbers.
- Record target Python versions (`requires-python = ">=3.10"`).

### Step 2: Extract AST Import Evidence
- Traverse all Python source files (`.py`) and test suites (`tests/`).
- Parse Abstract Syntax Trees (AST) using Python's `ast` module.
- Track top-level module names, imported symbols, line numbers, and conditional `try/except` wrappers.

### Step 3: Run Deterministic Resilience Rules
- **Dependency Ghost Detector**:
  - Compare declared packages against observed AST imports.
  - Flag packages declared in manifests with 0 observed imports (e.g., `six`, `idna`).
  - Analyze potential justifications (CLI tool, dynamic import, plugin).
- **Migration Tripwire**:
  - Flag unmaintained or deprecated packages:
    - `toml` -> Migrate to Python standard library `tomllib` (Python 3.11+).
    - `appdirs` -> Migrate to active community replacement `platformdirs`.
    - `nose` -> Remove obsolete test runner; standardize on `pytest`.
    - `pkg_resources` -> Migrate to stdlib `importlib.resources`.
    - `pydantic` -> Detect V1 `@validator` / `class Config` incompatibilities under Pydantic V2.
- **Manifest Divergence**:
  - Compare version constraints across files (e.g. `pyproject.toml` `pydantic>=2` vs `requirements.txt` `pydantic==1.10.13`).

### Step 4: Map Change Blast-Radius
- For any proposed package change, identify:
  1. Direct source modules importing the package.
  2. Candidate test suites importing the package or importing affected internal modules.
  3. Risk level (`low`, `medium`, `high`, `critical`).

### Step 5: Safe Sandbox Verification
- Execute baseline test suite in an isolated copy of the repository.
- Capture command arguments, duration, exit code, stdout, and stderr.
- Identify **Verification Debt** (recommendations that cannot be fully verified due to missing dependencies or test runners).

### Step 6: Generate Dependency Exit Capsule
- Compute SHA-256 fingerprint of manifests and source files.
- Export structured JSON data (`capsule.json`) and human-readable Markdown report (`capsule.md`).
- Document all limitations, blockers, and reproduction instructions honestly.
