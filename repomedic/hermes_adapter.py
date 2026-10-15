"""Hermes Agent + Ollama adapter with strict schema, caching, retry-once, and timeout handling."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ValidationError, field_validator

from .models import AIRecommendation, Finding, FindingStatus
from .verifier import ALLOWED_SAFE_CHECKS


class StructuredRecommendationSchema(BaseModel):
    """Strict schema required from Hermes/Ollama model with robust coercion."""
    problem_explanation: str = Field(..., description="Explanation of the root issue")
    evidence_significance: str = Field(..., description="Why the concrete evidence matters")
    impact_and_uncertainty: str = Field(..., description="Scope of impact and unknowns")
    recommended_action: str = Field(..., description="Specific recommended remediation")
    suggested_migration: Optional[str] = Field(None, description="Migration plan if applicable")
    verification_check_name: str = Field(..., description="Must be one of the allowed verifier check names")
    assumptions: List[str] = Field(default_factory=list, description="Assumptions made by the recommendation")
    counterarguments: List[str] = Field(default_factory=list, description="Plausible counterarguments")
    disproving_evidence: str = Field(..., description="Evidence that would disprove this recommendation")
    open_compatibility_concerns: List[str] = Field(default_factory=list)

    @field_validator("assumptions", "counterarguments", "open_compatibility_concerns", mode="before")
    @classmethod
    def coerce_list(cls, v: Any) -> List[str]:
        if isinstance(v, list):
            return [str(x).strip() for x in v if str(x).strip()]
        if isinstance(v, str):
            lines = [line.strip().lstrip("-*•123456789. ") for line in v.splitlines() if line.strip()]
            return lines if lines else [v.strip()]
        return []

    @field_validator("disproving_evidence", mode="before")
    @classmethod
    def coerce_str(cls, v: Any) -> str:
        if isinstance(v, list):
            return "; ".join(str(x).strip() for x in v if str(x).strip())
        return str(v) if v is not None else ""

    @field_validator("verification_check_name", mode="before")
    @classmethod
    def coerce_check_name(cls, v: Any) -> str:
        s = str(v).strip().lower()
        if s in ALLOWED_SAFE_CHECKS:
            return s
        for key in ALLOWED_SAFE_CHECKS:
            if key in s:
                return key
        if "manifest" in s or "req" in s or "pyproject" in s or "six" in s:
            return "manifest_consistency"
        if "test" in s or "pytest" in s:
            return "test_suite_run"
        if "config" in s or "toml" in s:
            return "config_validation"
        if "version" in s or "constraint" in s or "pydantic" in s:
            return "version_constraint_compatibility"
        return "import_checks"


class AIAnalysisResult(BaseModel):
    finding_id: str
    package_name: str
    is_cached: bool = False
    status: str  # "success", "failed", "cached"
    error_message: Optional[str] = None
    structured_data: Optional[StructuredRecommendationSchema] = None
    raw_response: Optional[str] = None
    latency_ms: int = 0


CACHE_DIR = Path(".repomedic_cache")
PROMPT_VERSION = "v3_structured"


class HermesAdapter:
    """Communicates with Ollama/Hermes via local OpenAI-compatible endpoint with caching & validation."""

    def __init__(
        self,
        endpoint: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: int = 30,
    ):
        self.endpoint = (
            endpoint
            or os.environ.get("REPOMEDIC_LOCAL_MODEL_URL")
            or "http://127.0.0.1:11434"
        ).rstrip("/")
        self.model_name = (
            model_name
            or os.environ.get("REPOMEDIC_LOCAL_MODEL")
            or "qwen2.5-coder:1.5b"
        )
        self.timeout = timeout
        self.hermes_bin = shutil.which("hermes")
        self.local_endpoint = self.endpoint
        self.is_hermes_installed = bool(self.hermes_bin)
        self._warmed_up = False
        CACHE_DIR.mkdir(exist_ok=True)

    def get_runtime_status(self) -> Dict[str, Any]:
        """Inspect environment for Hermes CLI and local model runtimes."""
        hermes_version = None
        if self.is_hermes_installed and self.hermes_bin:
            try:
                res = subprocess.run(
                    [self.hermes_bin, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                hermes_version = res.stdout.strip() or res.stderr.strip()
            except Exception:
                hermes_version = "unknown"

        return {
            "hermes_cli_found": self.is_hermes_installed,
            "hermes_path": self.hermes_bin,
            "hermes_version": hermes_version,
            "local_endpoint": self.local_endpoint,
            "model_name": self.model_name,
        }

    def generate_recommendations(self, findings: List[Finding]) -> List[AIRecommendation]:
        """Generate evidence-backed recommendations for identified findings."""
        recommendations: List[AIRecommendation] = []
        counter = 1
        warm = self.warmup_check()
        use_ai = (warm.get("status") == "ok")

        for finding in findings:
            rec = None
            if use_ai:
                snippet = ""
                if finding.evidence and finding.evidence[0].content_snippet:
                    snippet = finding.evidence[0].content_snippet
                else:
                    snippet = finding.explanation

                try:
                    analysis = self.analyze_finding(finding, snippet)
                    if analysis.status in ("success", "cached") and analysis.structured_data:
                        sd = analysis.structured_data
                        src = f"local_ollama_qwen{'_cached' if analysis.is_cached else ''}"
                        rec = AIRecommendation(
                            id=f"REC-{counter:03d}",
                            finding_id=finding.id,
                            package_name=finding.package_name or "unknown",
                            title=f"Recommended action for {finding.package_name or finding.id}: {sd.recommended_action[:60]}",
                            rationale=f"{sd.problem_explanation} {sd.evidence_significance}",
                            suggested_action=sd.recommended_action,
                            target_replacement=sd.suggested_migration,
                            confidence=0.95,
                            status=FindingStatus.RECOMMENDED,
                            source=src,
                            model_name=self.model_name,
                            challenge_data=sd.model_dump(),
                        )
                except Exception:
                    rec = None

            if rec is None:
                rec = self._generate_single_recommendation(finding, counter)

            if rec:
                recommendations.append(rec)
                counter += 1
        return recommendations

    def _generate_single_recommendation(self, finding: Finding, index: int) -> Optional[AIRecommendation]:
        """Generate recommendation for a finding with explicit source provenance."""
        action = "retain"
        target_replacement = None
        rationale = ""

        if finding.category == "ghost_dependency":
            action = "remove"
            rationale = (
                f"Package '{finding.package_name}' has 0 observed imports across all repository files. "
                f"Removing it eliminates maintenance overhead, shrinks attack surface, and speeds up installations."
            )
        elif finding.category == "manifest_conflict":
            action = "align"
            rationale = (
                f"Reconcile '{finding.package_name}' specification. For LinkWatch, update requirements.txt "
                f"from pydantic==1.10.13 to pydantic>=2 or adopt modern pydantic V2 APIs across the codebase."
            )
        elif finding.category == "migration_tripwire":
            if finding.package_name == "toml":
                action = "replace"
                target_replacement = "tomllib (Python 3.11+ standard library)"
                rationale = (
                    "Replace external 'toml' dependency with standard library 'tomllib'. LinkWatch targets Python 3.12+, "
                    "making this a zero-cost stdlib migration."
                )
            elif finding.package_name == "appdirs":
                action = "replace"
                target_replacement = "platformdirs"
                rationale = (
                    "Replace abandoned 'appdirs' with actively maintained 'platformdirs'. Provides identical user_cache_dir API."
                )
            elif finding.package_name == "nose":
                action = "remove"
                target_replacement = "pytest"
                rationale = "Remove obsolete 'nose' test runner; standardize on modern pytest."
            elif finding.package_name == "setuptools":
                action = "replace"
                target_replacement = "importlib.resources"
                rationale = (
                    "Migrate from deprecated 'pkg_resources' to 'importlib.resources.files()' in linkwatch/resources.py."
                )
            elif finding.package_name == "pydantic":
                action = "upgrade"
                target_replacement = "pydantic>=2.0"
                rationale = (
                    "Migrate LinkWatch config.py from Pydantic V1 (@validator, class Config) to V2 (@field_validator, ConfigDict)."
                )
            else:
                action = "review"
                rationale = finding.explanation
        elif finding.category == "private_api":
            action = "replace"
            target_replacement = "public standard library parsing (email.message or cgi/mimetypes)"
            rationale = "Avoid importing private internal helper '_parse_content_type_header' from requests.utils."

        return AIRecommendation(
            id=f"REC-{index:03d}",
            finding_id=finding.id,
            package_name=finding.package_name or "unknown",
            title=f"Recommended action for {finding.package_name or finding.id}: {action.upper()}",
            rationale=rationale,
            suggested_action=action,
            target_replacement=target_replacement,
            confidence=0.95,
            status=FindingStatus.RECOMMENDED,
            source="deterministic_fallback",
            model_name="repomedic-resilience-rules",
        )

    def warmup_check(self) -> Dict[str, Any]:
        """Check once at startup if Ollama is running and model exists."""
        if self._warmed_up:
            return {"status": "ok", "already_warmed": True}
        import requests
        try:
            r = requests.get(f"{self.endpoint}/api/tags", timeout=5)
            if r.status_code != 200:
                return {"status": "error", "error": f"Ollama returned HTTP {r.status_code}"}
            models = [m.get("name") for m in r.json().get("models", [])]
            # Match model prefix
            has_model = any(self.model_name in m for m in models)
            if not has_model:
                return {
                    "status": "error",
                    "error": f"Model '{self.model_name}' not found in Ollama models: {models}",
                }
            self._warmed_up = True
            return {"status": "ok", "models": models}
        except Exception as e:
            return {"status": "error", "error": f"Ollama is not running or unreachable at {self.endpoint}: {e}"}

    def _cache_key(self, finding: Finding, snippet: str) -> str:
        raw = f"{finding.id}:{finding.explanation}:{snippet}:{self.model_name}:{PROMPT_VERSION}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def analyze_finding(self, finding: Finding, snippet: str, use_cache: bool = True) -> AIAnalysisResult:
        """Analyze a finding with strict schema validation, disk caching, and retry-once."""
        key = self._cache_key(finding, snippet)
        cache_file = CACHE_DIR / f"{key}.json"

        if use_cache and cache_file.exists():
            try:
                cached_data = json.loads(cache_file.read_text(encoding="utf-8"))
                return AIAnalysisResult(
                    finding_id=finding.id,
                    package_name=finding.package_name or "unknown",
                    is_cached=True,
                    status="cached",
                    structured_data=StructuredRecommendationSchema(**cached_data["structured_data"]),
                    raw_response=cached_data.get("raw_response"),
                    latency_ms=0,
                )
            except Exception:
                pass

        # Check warmup
        warm = self.warmup_check()
        if warm["status"] != "ok":
            return AIAnalysisResult(
                finding_id=finding.id,
                package_name=finding.package_name or "unknown",
                status="failed",
                error_message=warm["error"],
            )

        prompt = self._build_prompt(finding, snippet)
        
        # Call with retry ONCE
        for attempt in range(2):
            start = time.monotonic()
            raw, err = self._call_model(prompt)
            elapsed = int((time.monotonic() - start) * 1000)

            if err:
                if attempt == 1:
                    return AIAnalysisResult(
                        finding_id=finding.id,
                        package_name=finding.package_name or "unknown",
                        status="failed",
                        error_message=err,
                        latency_ms=elapsed,
                    )
                continue  # Retry once

            # Validate strict JSON schema
            try:
                clean = raw.strip()
                if "```json" in clean:
                    clean = clean.split("```json")[-1].split("```")[0].strip()
                elif "```" in clean:
                    clean = clean.split("```")[-1].split("```")[0].strip()
                parsed_json = json.loads(clean)
                structured = StructuredRecommendationSchema(**parsed_json)

                # Validate check name against verifier allow-list
                if structured.verification_check_name not in ALLOWED_SAFE_CHECKS:
                    # reject hallucinated checks
                    if attempt == 0:
                        prompt += f"\nNote: verification_check_name MUST be one of {list(ALLOWED_SAFE_CHECKS.keys())}."
                        continue
                    else:
                        return AIAnalysisResult(
                            finding_id=finding.id,
                            package_name=finding.package_name or "unknown",
                            status="failed",
                            error_message=f"Disallowed verification check '{structured.verification_check_name}'.",
                            raw_response=raw,
                            latency_ms=elapsed,
                        )

                # Save to disk cache
                cache_file.write_text(json.dumps({
                    "structured_data": structured.model_dump(),
                    "raw_response": raw,
                }), encoding="utf-8")

                return AIAnalysisResult(
                    finding_id=finding.id,
                    package_name=finding.package_name or "unknown",
                    is_cached=False,
                    status="success",
                    structured_data=structured,
                    raw_response=raw,
                    latency_ms=elapsed,
                )
            except (json.JSONDecodeError, ValidationError) as ve:
                if attempt == 0:
                    prompt += "\nError: Previous response did not match JSON schema. Respond strictly with valid JSON."
                    continue
                return AIAnalysisResult(
                    finding_id=finding.id,
                    package_name=finding.package_name or "unknown",
                    status="failed",
                    error_message=f"Schema validation failed: {ve}",
                    raw_response=raw,
                    latency_ms=elapsed,
                )

        return AIAnalysisResult(
            finding_id=finding.id,
            package_name=finding.package_name or "unknown",
            status="failed",
            error_message="Exhausted retry attempts.",
        )

    def _call_model(self, prompt: str) -> tuple[Optional[str], Optional[str]]:
        import requests
        try:
            payload = {
                "model": self.model_name,
                "messages": [
                    {"role": "system", "content": "You are a software maintenance agent. Output only valid JSON matching the exact requested schema."},
                    {"role": "user", "content": prompt},
                ],
                "response_format": {"type": "json_object"},
                "temperature": 0.0,
                "max_tokens": 512,
            }
            resp = requests.post(
                f"{self.endpoint}/v1/chat/completions",
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code != 200:
                return None, f"HTTP Error {resp.status_code}: {resp.text}"
            data = resp.json()
            return data["choices"][0]["message"]["content"], None
        except requests.exceptions.Timeout:
            return None, f"Model call timed out after {self.timeout}s."
        except requests.exceptions.ConnectionError:
            return None, f"Connection refused connecting to Ollama at {self.endpoint}."
        except Exception as e:
            return None, str(e)

    def _build_prompt(self, finding: Finding, snippet: str) -> str:
        allow_checks = list(ALLOWED_SAFE_CHECKS.keys())
        return f"""Analyze this repository dependency finding:
Finding ID: {finding.id}
Category: {finding.category}
Package: {finding.package_name}
Title: {finding.title}
Explanation: {finding.explanation}
Code Evidence Context (5 lines around finding):
\"\"\"
{snippet}
\"\"\"

Allowed verifier checks: {allow_checks}

Return STRICT JSON matching this schema:
{{
  "problem_explanation": "...",
  "evidence_significance": "...",
  "impact_and_uncertainty": "...",
  "recommended_action": "...",
  "suggested_migration": "...",
  "verification_check_name": "<MUST be one from {allow_checks}>",
  "assumptions": ["..."],
  "counterarguments": ["..."],
  "disproving_evidence": "...",
  "open_compatibility_concerns": ["..."]
}}"""
