# DocRep 🩺
*(Formerly RepoMedic)*

> **Evidence-Backed Repository Maintenance Workbench for Dependency Resilience**  
> *Target Repository Case Study: [LinkWatch](https://github.com/rishrek/LinkWatch)*

---

## 1. Problem & Solution

### The Problem
Real-world software repositories suffer from silent dependency rot, unmaintained libraries, manifest drift (e.g. contradictory version pins across `pyproject.toml` and `requirements.txt`), abandoned packages, and breaking API changes during runtime upgrades. Standard chatbot solutions often hallucinate dependency updates or suggest blind migrations without checking the codebase or verifying whether tests pass.

### The DocRep Solution
**DocRep** is a deterministic, evidence-backed repository maintenance workbench. It replaces guesswork with proof:
1. **Deterministic Repository Intelligence:** Scans Python AST imports, matches against declared manifests, computes SHA-256 evidence hashes, and maps change blast radii.
2. **Local AI Reasoning Layer (Hermes Agent / Ollama):** Employs local open-weight models (`qwen2.5-coder:1.5b`) via an OpenAI-compatible endpoint with strict schema validation, retry-once resilience, and recommendation challenges.
3. **Sandbox Verification:** Executes real tests in disposable staging copies, never modifying the source repository.
4. **Proof-Carrying Dependency Exit Capsule:** Generates content-addressed `capsule.json` and human-readable `capsule.md` separating observed facts, AI suggestions, and verified test results.

---

## 2. Architecture

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
│  ├── hermes_adapter.py           : Local OpenAI-compatible client (Qwen2.5-Coder / Ollama / Hermes)    │
│  └── Recommendation Challenges   : Assumptions, counterarguments, disproving evidence per finding     │
└────────────────────────────────────────────────────┬───────────────────────────────────────────────────┘
                                                     │ AI Recommendations & Challenges
                                                     ▼
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│ 3. SANDBOX VERIFICATION & REPORTING                                                                    │
│  ├── verifier.py                 : Isolated staging copy execution of allow-listed checks & pytest     │
│  ├── capsule.py                  : Portable Dependency Exit Capsule (capsule.json & capsule.md)        │
│  ├── cli.py                      : Rich terminal commands (scan, analyze, verify, capsule, run, gui)  │
│  └── gui.py & static/index.html  : Zero-dependency offline Web GUI on 127.0.0.1                       │
└────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Installation & Requirements

- **Supported Python:** Python 3.10, 3.11, 3.12, 3.13, 3.14 (Verified on Python 3.14 on Windows 11).
- **Core Dependencies:** `click`, `rich`, `pydantic>=2`, `jinja2`.

```bash
# Clone the repository
git clone https://github.com/kaivalya-joil/RickRoll1.git
cd RickRoll1

# Install in editable mode
python -m pip install -e .
```

---

## 4. Local AI Model Setup (Ollama & Hermes)

DocRep is 100% offline-ready and uses local open-weight models without cloud lock-in.

### Exact Model Specifications
- **Model Identifier:** `qwen2.5-coder:1.5b`
- **Format:** GGUF (`Q4_K_M` quantization)
- **Digest:** `d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668`
- **Model Source:** Alibaba Cloud / Ollama Library
- **License:** Apache 2.0

### How DocRep Reaches the Model
DocRep communicates with the local Ollama daemon via its OpenAI-compatible HTTP REST endpoint:
- **Default Endpoint:** `http://127.0.0.1:11434/v1/chat/completions`
- **Model Discovery:** `http://127.0.0.1:11434/api/tags`
- **Fallback Policy:** If Ollama is offline or uninstalled, DocRep automatically falls back to deterministic rule-based expert recommendations without ever fabricating model output.

### Setup Instructions
1. Install [Ollama](https://ollama.com).
2. Pull the verified model:
   ```bash
   ollama pull qwen2.5-coder:1.5b
   ```
3. (Optional) Custom endpoint configuration:
   ```bash
   # In PowerShell
   $env:REPOMEDIC_LOCAL_MODEL_URL = "http://127.0.0.1:11434"
   $env:REPOMEDIC_LOCAL_MODEL = "qwen2.5-coder:1.5b"
   ```

---

## 5. Command Line Interface (CLI)

Both `python -m repomedic.cli` and `python -m docrep` are supported.

| Command | Purpose | Example |
|---|---|---|
| `status` | Inspect local Python, Ollama, and Hermes runtime availability | `python -m repomedic.cli status` |
| `scan` | Inspect declared dependency manifests and AST source imports | `python -m repomedic.cli scan --repo target_repo/linkwatch` |
| `analyze` | Run deterministic rules engine (ghosts, tripwires, conflicts) | `python -m repomedic.cli analyze --repo target_repo/linkwatch` |
| `verify` | Execute safe sandbox checks (syntax, manifests, tests) | `python -m repomedic.cli verify --repo target_repo/linkwatch` |
| `capsule` | Generate `capsule.json` and `capsule.md` reports | `python -m repomedic.cli capsule --repo target_repo/linkwatch -o reports` |
| `run` | Execute the complete end-to-end pipeline in one step | `python -m repomedic.cli run --repo target_repo/linkwatch` |
| `gui` | Launch the offline browser workbench on `127.0.0.1` | `python -m repomedic.cli gui` |

### CLI Flags
- `--deep`: Runs local AI model reasoning over all discovered findings (default is fast mode: top 5).
- `--no-ai`: Disables all AI calls, running pure deterministic scanner rules and sandbox verification. Clearly labeled as "no AI analysis".
- `--repo PATH` or positional argument: Path to target repository (validates path existence).

---

## 6. Easy Offline Web GUI

DocRep includes a zero-dependency web interface powered exclusively by Python's standard library (`http.server`):
- **No npm, no webpack, no external CDN calls.**
- **Binds strictly to `127.0.0.1`** (picks a free port dynamically).
- **Light & Dark mode** with automatic OS preference detection and manual toggle.
- **Responsive design** on laptop, tablet, and mobile viewports.
- **Real-time background polling** for progress and status.

### Launch Options
- **CLI:** `python -m repomedic.cli gui`
- **Windows Double-Click:** Double-click `start.bat`
- **macOS / Linux:** Run `./start.sh`

### Interface Tabs
1. **Home:** Repository path box, LinkWatch selector, Run Full Analysis button, Fast/Deep toggle, AI on/off switch, live status badges.
2. **Findings:** Sortable and filterable table by severity/category. Click any row to expand the concrete evidence box with exact file paths and line numbers.
3. **AI Suggestions:** AI recommendations with badges (`[OBSERVED]`, `[AI SUGGESTION]`, `[VERIFIED]`, `[CACHED]`), plus Recommendation Challenges detailing assumptions, counterarguments, and disproving evidence.
4. **Change Blast-Radius:** Interactive map showing which source modules directly import each dependency and which test suites are impacted.
5. **Verification:** Real sandbox execution results with PASS, FAILED, and BLOCKED status badges, exit codes, durations, and stderr logs.
6. **Debt & Limits:** Verification Debt ledger highlighting unverified recommendations and maintainer next actions.
7. **Capsule Export:** Formatted Markdown preview, download buttons for `capsule.md` and `capsule.json`, and one-click path copier.

---

## 7. How to Analyze LinkWatch

LinkWatch (`target_repo/linkwatch`) is a URL monitoring CLI with real dependency issues:

```bash
# Execute full analysis on LinkWatch
python -m repomedic.cli run --repo target_repo/linkwatch -o reports
```

### Discovered Findings in LinkWatch
1. **Manifest Conflict (`MANIFEST-DIV-001`):** `pyproject.toml` declares `pydantic>=2` while `requirements.txt` pins `pydantic==1.10.13`.
2. **Ghost Dependencies (`GHOST-001..003`):** `six`, `idna`, and `nose` are declared in manifests but have 0 observed AST imports across all source files.
3. **Migration Tripwires (`TRIPWIRE-001..005`):**
   - `toml==0.10.2`: Unmaintained since 2020; targets Python >= 3.10 where standard library `tomllib` is available.
   - `appdirs==1.4.4`: Abandoned since 2017; community standard replacement is `platformdirs`.
   - `nose==1.3.7`: Obsolete test runner specified in `requirements-dev.txt`; fails under Python 3.12+.
   - `pkg_resources`: Imported in `linkwatch/resources.py`; deprecated by setuptools, replaceable with `importlib.resources.files()`.
   - `pydantic` V1 patterns: Deprecated `@validator` and `class Config` used in `linkwatch/config.py`.
4. **Private API Import (`PRIVATE-API-001`):** `linkwatch/encoding.py` imports private `_parse_content_type_header` from `requests.utils`.

---

## 8. Reading the Dependency Exit Capsule

The generated `capsule.md` and `capsule.json` are organized into three distinct sections:
- **SECTION 1: OBSERVED EVIDENCE (Deterministic Facts):** Manifest inventory, file SHA-256 hashes, declared dependency records, observed AST imports, and change blast-radius mappings.
- **SECTION 2: AI SUGGESTIONS & REASONING (Non-Deterministic):** Model metadata, AI recommendations, Recommendation Challenges (assumptions, counterarguments, disproving criteria), and proposed phased migration plans.
- **SECTION 3: VERIFIED RESULTS & AUDIT DEBT:** Real sandbox execution results, exact commands and exit codes, Verification Debt items with required maintainer actions, known limitations, and composite audit hash.

---

## 9. Test Suite Verification

Run the full pytest suite:

```bash
python -m pytest -q
```

**Results:** `95 passed, 1 skipped in 11.01s` (100% of runnable tests passing).
- Tests cover: Schema validation, JSON roundtrip agreement, missing evidence references, failed/inconclusive checks preservation, malformed model JSON handling, partial scanner outputs, model metadata preservation, section separation, and GUI HTTP server endpoints.

---

## 10. Limitations & Failure Cases

- **Dynamic Imports:** DocRep uses static AST analysis; packages imported dynamically via `importlib.import_module()` or `__import__()` must be verified via runtime tests.
- **Target Test Execution:** If `pytest` is not installed in the target sandbox environment, test suite execution will be recorded as `BLOCKED` and flagged under Verification Debt.
- **Model Offline:** If Ollama is not running, DocRep gracefully switches to deterministic fallback rules without fabricating synthetic AI runs.

---

## 11. Security, Privacy & Integrity

- **Read-Only Guarantee:** DocRep never mutates the target repository. All checks run in disposable staging sandboxes (`IsolatedSandbox`).
- **100% Offline & Private:** No external API keys or telemetry. All model inferences stay on `127.0.0.1`.
- **Command Allow-List:** Verification checks are strictly constrained to pre-approved verification procedures. Arbitrary shell execution is rejected.

---

## 12. Credits & License

- **DocRep (RepoMedic):** Developed under the MIT License. See [LICENSE](file:///D:/SVU%20Hackathon/RickRoll1/LICENSE).
- **Target Repository:** [LinkWatch](https://github.com/rishrek/LinkWatch) by @rishrek.
- **Model:** Qwen2.5-Coder by Alibaba Cloud (Apache 2.0).
- **Agent Skill Specification:** Built to comply with the Agent Skills Open Standard (`SKILL.md`).
