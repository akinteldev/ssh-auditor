"""General hardening audit rules.

Checks for X11 forwarding, banners, MOTD, client alive intervals,
log levels, SSH protocol version, and strict modes.
"""

from __future__ import annotations

from typing import Any

from ssh_auditor.rules.base import Finding, Rule, Severity


class X11ForwardingRule(Rule):
    """X11Forwarding should be 'no'."""

    rule_id = "HARD-001"
    severity = Severity.MEDIUM
    description = "X11Forwarding is not set to 'no'"
    remediation = "Set 'X11Forwarding no' in sshd_config"
    cis_reference = "CIS 5.2.4"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "x11forwarding":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="X11Forwarding",
                            severity=self.severity,
                            description=f"X11Forwarding is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="X11Forwarding",
                    severity=self.severity,
                    description="X11Forwarding is not configured (defaults to 'no')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class BannerRule(Rule):
    """Banner should be configured (directive present and non-empty)."""

    rule_id = "HARD-002"
    severity = Severity.LOW
    description = "No Banner is configured"
    remediation = "Set 'Banner /etc/ssh/banner' in sshd_config"
    cis_reference = "CIS 5.2.11"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "banner":
                found = True
                value = d["value"].strip().lower()
                if value and value != "none":
                    return []  # Banner is configured properly.
                else:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="Banner",
                            severity=self.severity,
                            description="Banner is set to 'none' or empty",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="Banner",
                    severity=self.severity,
                    description="No Banner is configured",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class PrintMotdRule(Rule):
    """PrintMotd should be 'no'."""

    rule_id = "HARD-003"
    severity = Severity.LOW
    description = "PrintMotd is not set to 'no'"
    remediation = "Set 'PrintMotd no' in sshd_config"
    cis_reference = "CIS 5.2.12"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "printmotd":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="PrintMotd",
                            severity=self.severity,
                            description=f"PrintMotd is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="PrintMotd",
                    severity=self.severity,
                    description="PrintMotd is not configured (defaults to 'yes')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class ClientAliveIntervalRule(Rule):
    """ClientAliveInterval should be > 0 (prevent idle session abuse)."""

    rule_id = "HARD-004"
    severity = Severity.MEDIUM
    description = "ClientAliveInterval is not set (idle sessions not timed out)"
    remediation = "Set 'ClientAliveInterval 300' and 'ClientAliveCountMax 2' in sshd_config"
    cis_reference = "CIS 5.2.3"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "clientaliveinterval":
                found = True
                try:
                    value = int(d["value"])
                except ValueError:
                    continue
                if value <= 0:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="ClientAliveInterval",
                            severity=self.severity,
                            description=f"ClientAliveInterval is set to {value} (should be > 0)",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="ClientAliveInterval",
                    severity=self.severity,
                    description="ClientAliveInterval is not configured (idle sessions never timeout)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class LogLevelRule(Rule):
    """LogLevel should be VERBOSE or INFO (not QUIET)."""

    rule_id = "HARD-005"
    severity = Severity.LOW
    description = "LogLevel is not set to VERBOSE or INFO"
    remediation = "Set 'LogLevel VERBOSE' in sshd_config for adequate audit logging"
    cis_reference = "CIS 5.2.20"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "loglevel":
                found = True
                value = d["value"].upper()
                if value not in ("VERBOSE", "INFO"):
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="LogLevel",
                            severity=self.severity,
                            description=f"LogLevel is set to '{d['value']}' (should be VERBOSE or INFO)",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="LogLevel",
                    severity=self.severity,
                    description="LogLevel is not configured (defaults to INFO)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class ProtocolRule(Rule):
    """Protocol must be 2 only (flag if '1' or '2,1')."""

    rule_id = "HARD-006"
    severity = Severity.MEDIUM
    description = "SSH Protocol version 1 is enabled or not explicitly set to 2"
    remediation = "Set 'Protocol 2' in sshd_config (SSHv1 is deprecated and insecure)"
    cis_reference = "CIS 5.2.1"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "protocol":
                found = True
                value = d["value"].strip()
                # Accept only a single '2'.
                if value != "2":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="Protocol",
                            severity=self.severity,
                            description=f"Protocol is set to '{value}' (should be '2' only)",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="Protocol",
                    severity=self.severity,
                    description="Protocol is not configured (defaults may include SSHv1)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class StrictModesRule(Rule):
    """StrictModes should be 'yes'."""

    rule_id = "HARD-007"
    severity = Severity.LOW
    description = "StrictModes is not set to 'yes'"
    remediation = "Set 'StrictModes yes' in sshd_config"
    cis_reference = "CIS 5.2.2"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "strictmodes":
                found = True
                if d["value"].lower() != "yes":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="StrictModes",
                            severity=self.severity,
                            description=f"StrictModes is set to '{d['value']}' (should be 'yes')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="StrictModes",
                    severity=self.severity,
                    description="StrictModes is not configured (defaults to 'yes')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


# Export all rule classes.
RULES = [
    X11ForwardingRule,
    BannerRule,
    PrintMotdRule,
    ClientAliveIntervalRule,
    LogLevelRule,
    ProtocolRule,
    StrictModesRule,
]
