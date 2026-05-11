"""Evaluator — discovers, instantiates, and runs all audit rules.

Auto-discovers rule modules under ``ssh_auditor.rules`` (auth, crypto,
access, hardening), instantiates each rule class, and runs ``check()``
against parsed sshd_config directives.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ssh_auditor.parser import parse_sshd_config_to_dicts
from ssh_auditor.rules.base import Finding, Severity

# Mapping of rule module name → list of rule classes.
_RULE_MODULES = ("auth", "crypto", "access", "hardening")


def _discover_rules() -> list[Any]:
    """Discover and instantiate all rule classes from known modules.

    Returns:
        A flat list of instantiated rule objects.
    """
    rules: list[Any] = []
    for module_name in _RULE_MODULES:
        try:
            mod = importlib.import_module(f"ssh_auditor.rules.{module_name}")
        except ImportError as exc:
            print(f"Warning: could not import rule module '{module_name}': {exc}")
            continue

        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            # Only pick classes that are direct subclasses of Rule (not
            # the base class itself) and have a non-empty rule_id.
            if (
                isinstance(obj, type)
                and issubclass(obj, object)  # safety net
                and hasattr(obj, "rule_id")
                and obj.rule_id
            ):
                # Check it's a Rule subclass by checking for check method.
                if hasattr(obj, "check") and callable(getattr(obj, "check")):
                    rules.append(obj())

    return rules


class Evaluator:
    """Runs all audit rules against a parsed sshd_config.

    Attributes:
        findings: List of ``Finding`` objects collected from all rules.
        config_path: Path to the scanned configuration file.
    """

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.config_path: str = ""

    # -- public API ----------------------------------------------------------

    def get_findings(self, config_path: str | Path) -> list[Finding]:
        """Parse *config_path* and run all rules against it.

        Args:
            config_path: Path to the sshd_config file.

        Returns:
            List of ``Finding`` objects (may be empty if compliant).
        """
        self.config_path = str(config_path)
        directives = parse_sshd_config_to_dicts(config_path)

        rules = _discover_rules()
        self.findings = []
        for rule in rules:
            findings = rule.check(directives)
            self.findings.extend(findings)

        return self.findings

    def get_summary(self) -> dict[str, Any]:
        """Return a summary of the last evaluation.

        Returns:
            Dict with keys ``config_file``, ``scan_date``, ``total_findings``,
            and ``severity_counts`` (dict mapping severity string → count).
        """
        return {
            "config_file": self.config_path,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self.findings),
            "severity_counts": self.count_by_severity(),
        }

    def count_by_severity(self) -> dict[str, int]:
        """Count findings grouped by severity.

        Returns:
            Dict mapping severity name (e.g. ``"critical"``) to count.
        """
        counts = Counter(f.severity.value for f in self.findings)
        # Ensure all severity levels appear even if zero.
        for sev in Severity:
            counts.setdefault(sev.value, 0)
        return dict(counts)
