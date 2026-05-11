"""JSON report generator for SSH audit findings."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ssh_auditor.rules.base import Finding


def _finding_to_dict(finding: Finding) -> dict[str, str]:
    """Convert a ``Finding`` to a plain dict for JSON serialisation."""
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "directive": finding.directive,
        "description": finding.description,
        "remediation": finding.remediation,
        "cis_reference": finding.cis_reference,
    }


def generate_json_report(
    findings: list[Finding],
    config_path: str,
) -> dict[str, Any]:
    """Generate a JSON-serialisable report dict from findings.

    Args:
        findings: List of ``Finding`` objects.
        config_path: Path to the scanned configuration file.

    Returns:
        A dict suitable for ``json.dump`` or ``json.dumps``.
    """
    severity_counts: dict[str, int] = {}
    for sev in ("critical", "high", "medium", "low"):
        severity_counts[sev] = sum(1 for f in findings if f.severity.value == sev)

    return {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "config_file": config_path,
        "total_findings": len(findings),
        "summary_by_severity": severity_counts,
        "detailed_findings": [_finding_to_dict(f) for f in findings],
    }


def write_json_report(
    findings: list[Finding],
    config_path: str,
    output: str | Path | None = None,
) -> str:
    """Generate a JSON report and write it to *output*.

    Args:
        findings: List of ``Finding`` objects.
        config_path: Path to the scanned configuration file.
        output: File path to write the report. If ``None``, returns the JSON
            string without writing to disk.

    Returns:
        The JSON report as a string.
    """
    report = generate_json_report(findings, config_path)
    json_str = json.dumps(report, indent=2)

    if output is not None:
        Path(output).write_text(json_str, encoding="utf-8")

    return json_str
