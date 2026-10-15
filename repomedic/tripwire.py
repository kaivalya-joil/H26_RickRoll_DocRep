"""Migration Tripwire — rule-based comparison between an original dependency
and a proposed replacement, grounded only in evidence collected from the
repository's actual code.

Classification vocabulary:
  confirmed_from_local_evidence  — evidence directly observed in scanned code
  potential_breaking_change       — plausible based on known public API facts
  compatibility_unknown           — cannot determine without running code
  not_checked                     — this aspect was not evaluated

This module NEVER:
  - Rewrites source code.
  - Claims an API is removed/deprecated without supporting evidence.
  - Queries the network.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .models import (
    DependencyDeclaration,
    EvidenceReference,
    Finding,
    FindingSeverity,
    FindingStatus,
    SourceImport,
)


class TripwireClassification(str, Enum):
    CONFIRMED_LOCAL   = "confirmed_from_local_evidence"
    POTENTIAL_BREAK   = "potential_breaking_change"
    COMPAT_UNKNOWN    = "compatibility_unknown"
    NOT_CHECKED       = "not_checked"


@dataclass
class TripwireObservation:
    """One specific migration concern with its evidence and classification."""
    observation_id: str
    title: str
    classification: TripwireClassification
    package_from: str
    package_to: Optional[str]
    evidence: List[EvidenceReference]
    explanation: str
    api_calls_at_risk: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Known migration rules
# Each rule is a dict with:
#   from_pkg, to_pkg, module_name, api_calls, classification, title, explanation
# ---------------------------------------------------------------------------

_MIGRATION_RULES: List[Dict] = [
    # toml → tomllib (Python 3.11+ stdlib)
    {
        "from_pkg":      "toml",
        "to_pkg":        "tomllib",
        "module_name":   "toml",
        "api_calls":     ["toml.load", "toml.loads", "toml.dumps", "toml.dump"],
        "classification": TripwireClassification.POTENTIAL_BREAK,
        "title":         "toml.dumps() / toml.dump() have no stdlib equivalent",
        "explanation": (
            "tomllib (Python 3.11+ stdlib) is read-only; it has no write/serialise API. "
            "If the codebase calls toml.dumps() or toml.dump(), a separate package "
            "(tomli-w) is required for the write path. "
            "tomllib also requires binary read mode (open(..., 'rb')) instead of text mode."
        ),
        "confirmed_apis": ["toml.loads", "toml.load"],   # safe to migrate
        "breaking_apis":  ["toml.dumps", "toml.dump"],   # write API missing in tomllib
    },
    # appdirs → platformdirs
    {
        "from_pkg":      "appdirs",
        "to_pkg":        "platformdirs",
        "module_name":   "appdirs",
        "api_calls":     [
            "user_data_dir", "user_cache_dir", "user_log_dir",
            "site_data_dir", "user_config_dir",
        ],
        "classification": TripwireClassification.CONFIRMED_LOCAL,
        "title":         "appdirs → platformdirs: largely compatible API",
        "explanation": (
            "platformdirs provides the same directory-finding functions as appdirs "
            "with the same call signatures. The migration is largely a drop-in rename "
            "from 'import appdirs' to 'from platformdirs import ...' or "
            "'import platformdirs'. No API removal was observed in local evidence."
        ),
        "confirmed_apis": [
            "user_data_dir", "user_cache_dir", "user_log_dir",
            "site_data_dir", "user_config_dir",
        ],
        "breaking_apis":  [],
    },
    # nose → pytest
    {
        "from_pkg":      "nose",
        "to_pkg":        "pytest",
        "module_name":   "nose",
        "api_calls":     ["nose.tools", "nose.loader", "@nottest", "with_setup"],
        "classification": TripwireClassification.POTENTIAL_BREAK,
        "title":         "nose → pytest: nose-specific decorators require rewriting",
        "explanation": (
            "pytest is broadly compatible with nose-style tests written using plain "
            "assert statements. However, nose-specific decorators (@nottest, @with_setup), "
            "nose.tools utilities, and nose.loader customisations have no direct pytest "
            "equivalents and must be rewritten."
        ),
        "confirmed_apis": [],
        "breaking_apis":  ["nose.tools", "@nottest", "with_setup", "nose.loader"],
    },
    # pkg_resources → importlib.resources
    {
        "from_pkg":      "setuptools",
        "to_pkg":        "importlib.resources",
        "module_name":   "pkg_resources",
        "api_calls":     [
            "resource_filename", "resource_string", "resource_stream",
            "get_distribution", "require",
        ],
        "classification": TripwireClassification.POTENTIAL_BREAK,
        "title":         "pkg_resources → importlib.resources: partial API coverage",
        "explanation": (
            "importlib.resources (Python 3.9+) replaces pkg_resources for resource access. "
            "importlib.resources.files() covers resource_filename/resource_string/resource_stream. "
            "However, get_distribution() and require() have no stdlib equivalent "
            "(use importlib.metadata instead). "
            "Also note: importlib.resources does not support editable installs before "
            "Python 3.12 without the importlib_resources backport."
        ),
        "confirmed_apis": ["resource_filename", "resource_string", "resource_stream"],
        "breaking_apis":  ["get_distribution", "require"],
    },
    # pydantic v1 → v2
    {
        "from_pkg":      "pydantic",
        "to_pkg":        "pydantic>=2",
        "module_name":   "pydantic",
        "api_calls":     [
            "validator", "root_validator", "class Config", "schema()",
            ".dict()", ".json()", "parse_obj", "parse_raw",
        ],
        "classification": TripwireClassification.POTENTIAL_BREAK,
        "title":         "Pydantic V1 API patterns require migration to V2",
        "explanation": (
            "Pydantic V2 introduced breaking API changes. V1 patterns observed in "
            "scanned code that require migration: @validator → @field_validator, "
            "@root_validator → @model_validator, class Config → model_config = ConfigDict(), "
            ".dict() → .model_dump(), .json() → .model_dump_json(), "
            "parse_obj() → model_validate(), parse_raw() → model_validate_json()."
        ),
        "confirmed_apis": [],
        "breaking_apis":  [
            "validator", "root_validator", "Config", "schema",
            ".dict", ".json", "parse_obj", "parse_raw",
        ],
    },
]

# Build lookup by (from_pkg, to_pkg) and by from_pkg alone
_RULES_BY_FROM: Dict[str, List[Dict]] = {}
for _r in _MIGRATION_RULES:
    _RULES_BY_FROM.setdefault(_r["from_pkg"].lower(), []).append(_r)


class MigrationTripwire:
    """Rule-based preliminary comparison between original and replacement packages.

    Parameters
    ----------
    declarations:
        All manifest dependency declarations.
    imports:
        All AST imports from source and test files.
    source_texts:
        Optional mapping of relative_path → raw source text for deeper API analysis.
    """

    def __init__(
        self,
        declarations: List[DependencyDeclaration],
        imports: List[SourceImport],
        source_texts: Optional[Dict[str, str]] = None,
    ) -> None:
        self._declarations = declarations
        self._imports = imports
        self._source_texts = source_texts or {}
        self._module_imports: Dict[str, List[SourceImport]] = {}
        for imp in imports:
            self._module_imports.setdefault(imp.module.lower(), []).append(imp)

    def analyze_migration(
        self,
        from_pkg: str,
        to_pkg: Optional[str] = None,
    ) -> List[TripwireObservation]:
        """Analyse migration from *from_pkg* to *to_pkg*.

        If *to_pkg* is None, all known rules for *from_pkg* are applied.
        """
        rules = _RULES_BY_FROM.get(from_pkg.lower(), [])
        if not rules:
            return [self._unknown_migration(from_pkg, to_pkg)]

        results: List[TripwireObservation] = []
        obs_counter = 1
        for rule in rules:
            if to_pkg and rule["to_pkg"].lower() != to_pkg.lower():
                # Only apply rules matching the specified replacement
                if not rule["to_pkg"].lower().startswith(to_pkg.lower()):
                    continue
            obs = self._apply_rule(rule, obs_counter)
            results.extend(obs)
            obs_counter += len(obs)

        return results if results else [self._unknown_migration(from_pkg, to_pkg)]

    def analyze_all_known(self) -> List[TripwireObservation]:
        """Run all applicable migration rules for every declared dependency."""
        declared_names = {d.name.lower() for d in self._declarations}
        all_obs: List[TripwireObservation] = []
        obs_counter = 1
        for pkg_name in sorted(declared_names):
            if pkg_name in _RULES_BY_FROM:
                for rule in _RULES_BY_FROM[pkg_name]:
                    obs = self._apply_rule(rule, obs_counter)
                    all_obs.extend(obs)
                    obs_counter += len(obs)
        return all_obs

    # ── rule application ──────────────────────────────────────────────────────

    def _apply_rule(self, rule: Dict, start_id: int) -> List[TripwireObservation]:
        from_pkg    = rule["from_pkg"]
        to_pkg      = rule["to_pkg"]
        module_name = rule["module_name"]
        breaking    = rule.get("breaking_apis", [])
        confirmed   = rule.get("confirmed_apis", [])

        # Is the package even declared?
        declared = [d for d in self._declarations if d.name.lower() == from_pkg.lower()]
        if not declared:
            return []

        # AST imports for this module
        module_imps = self._module_imports.get(module_name.lower(), [])

        manifest_evidence = [
            EvidenceReference(
                file_path=d.manifest_path,
                line_start=d.line_number,
                line_end=d.line_number,
                content_snippet=d.raw_declaration[:120],
                source_type="manifest",
            )
            for d in declared
        ]
        import_evidence = [
            EvidenceReference(
                file_path=imp.file_path,
                line_start=imp.line_number,
                line_end=imp.line_number,
                content_snippet=(
                    f"from {imp.module} import {', '.join(imp.imported_names[:4])}"
                    if imp.imported_names else f"import {imp.module}"
                )[:120],
                source_type="test_ast" if imp.is_test_file else "source_ast",
            )
            for imp in module_imps[:10]
        ]
        all_evidence = manifest_evidence + import_evidence

        # Deep API search in source texts
        at_risk_calls: List[str] = []
        safe_calls: List[str] = []
        text_evidence: List[EvidenceReference] = []

        for rel_path, text in self._source_texts.items():
            for api in breaking:
                pattern = re.compile(re.escape(api))
                for m in pattern.finditer(text):
                    lineno = text[:m.start()].count("\n") + 1
                    snippet = text.splitlines()[lineno - 1].strip()[:120]
                    if api not in at_risk_calls:
                        at_risk_calls.append(api)
                    text_evidence.append(EvidenceReference(
                        file_path=rel_path,
                        line_start=lineno,
                        line_end=lineno,
                        content_snippet=snippet,
                        source_type="source_ast",
                    ))
            for api in confirmed:
                if re.search(re.escape(api), text):
                    if api not in safe_calls:
                        safe_calls.append(api)

        # Also check imported names from AST
        imported_names_found = set()
        for imp in module_imps:
            for name in imp.imported_names:
                imported_names_found.add(name)

        for api in breaking:
            if any(api.split(".")[-1] in n for n in imported_names_found):
                if api not in at_risk_calls:
                    at_risk_calls.append(api)

        # Determine final classification
        if at_risk_calls and text_evidence:
            classification = TripwireClassification.CONFIRMED_LOCAL
        elif at_risk_calls or module_imps:
            classification = rule["classification"]
        elif declared:
            classification = TripwireClassification.POTENTIAL_BREAK
        else:
            classification = TripwireClassification.NOT_CHECKED

        explanation = rule["explanation"]
        if at_risk_calls:
            explanation += (
                f"\n\nAPI calls at risk found in this repository: {', '.join(at_risk_calls)}."
            )
        if safe_calls:
            explanation += (
                f"\n\nMigration-safe API calls confirmed in this repository: {', '.join(safe_calls)}."
            )

        limitations = [
            "Static analysis cannot resolve runtime-constructed API call strings.",
            "Subclasses and mixins may expose affected methods indirectly.",
        ]
        if not self._source_texts:
            limitations.append(
                "Source text was not provided; deep API pattern search was skipped. "
                "Only AST import names were analysed."
            )

        return [TripwireObservation(
            observation_id=f"TW-{start_id:03d}",
            title=f"{from_pkg} → {to_pkg}: {rule['title']}",
            classification=classification,
            package_from=from_pkg,
            package_to=to_pkg,
            evidence=all_evidence + text_evidence[:10],
            explanation=explanation,
            api_calls_at_risk=at_risk_calls,
            limitations=limitations,
        )]

    def _unknown_migration(self, from_pkg: str, to_pkg: Optional[str]) -> TripwireObservation:
        return TripwireObservation(
            observation_id="TW-000",
            title=f"Migration '{from_pkg}' → '{to_pkg or '?'}': no rule available",
            classification=TripwireClassification.COMPAT_UNKNOWN,
            package_from=from_pkg,
            package_to=to_pkg,
            evidence=[],
            explanation=(
                f"No migration rule is defined for '{from_pkg}' → '{to_pkg}'. "
                f"Compatibility cannot be assessed without inspecting the API surfaces "
                f"of both packages. A replacement name alone is not proof of compatibility."
            ),
            limitations=[
                "This tool only covers a predefined set of known migrations.",
                "Add a migration rule to repomedic/tripwire.py to analyse this pair.",
            ],
        )

    def to_findings(self, observations: List[TripwireObservation]) -> List[Finding]:
        """Convert tripwire observations to Finding objects."""
        findings: List[Finding] = []
        for i, obs in enumerate(observations, start=1):
            sev = {
                TripwireClassification.CONFIRMED_LOCAL: FindingSeverity.HIGH,
                TripwireClassification.POTENTIAL_BREAK: FindingSeverity.MEDIUM,
                TripwireClassification.COMPAT_UNKNOWN:  FindingSeverity.LOW,
                TripwireClassification.NOT_CHECKED:     FindingSeverity.INFO,
            }[obs.classification]

            status = {
                TripwireClassification.CONFIRMED_LOCAL: FindingStatus.OBSERVED,
                TripwireClassification.POTENTIAL_BREAK: FindingStatus.INFERRED,
                TripwireClassification.COMPAT_UNKNOWN:  FindingStatus.INFERRED,
                TripwireClassification.NOT_CHECKED:     FindingStatus.NOT_RUN,
            }[obs.classification]

            limitations_text = (
                "\nLimitations: " + " | ".join(obs.limitations) if obs.limitations else ""
            )
            findings.append(Finding(
                id=f"TRIPWIRE-{i:03d}",
                category="migration_tripwire",
                title=obs.title,
                explanation=obs.explanation + limitations_text,
                severity=sev,
                status=status,
                package_name=obs.package_from,
                evidence=obs.evidence,
                remediation_hint=(
                    f"Before replacing '{obs.package_from}' with '{obs.package_to}', "
                    f"address at-risk APIs: {', '.join(obs.api_calls_at_risk) or 'none confirmed yet'}. "
                    "Run the full test suite with the replacement installed."
                ) if obs.package_to else None,
            ))
        return findings
