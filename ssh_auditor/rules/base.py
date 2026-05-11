"""Base class for SSH audit rules."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Severity levels for audit findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    """A single audit finding."""

    rule_id: str
    directive: str
    severity: Severity
    description: str
    remediation: str
    cis_reference: str = ""

    @property
    def label(self) -> str:
        return f"[{self.severity.value.upper()}] {self.rule_id}: {self.description}"


class Rule:
    """Base class for SSH configuration audit rules.

    Subclasses implement ``check()`` which receives the parsed
    sshd_config directives and returns a list of ``Finding`` objects.

    Subclasses should define class attributes:
        rule_id (str), severity (Severity), description (str),
        remediation (str), cis_reference (str).
    """

    rule_id: str = ""
    severity: Severity = Severity.MEDIUM
    description: str = ""
    remediation: str = ""
    cis_reference: str = ""

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        """Override in subclass to implement the actual check.

        Args:
            directives: List of parsed sshd_config directive dicts,
                each with keys like ``directive``, ``value``, ``file``,
                ``line_number``.

        Returns:
            List of Finding objects (empty if config is compliant).
        """
        raise NotImplementedError
