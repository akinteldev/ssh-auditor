"""Authentication-related audit rules.

Checks for common authentication misconfigurations in sshd_config:
root login, empty passwords, password auth, challenge-response auth,
max authentication tries, login grace time, and PAM usage.
"""

from __future__ import annotations

import math
from typing import Any

from ssh_auditor.rules.base import Finding, Rule, Severity


class PermitRootLoginRule(Rule):
    """PermitRootLogin must be 'no'.

    CIS 5.2.7: Ensure permissions on /etc/ssh/sshd_config are configured
    """

    rule_id = "AUTH-001"
    severity = Severity.CRITICAL
    description = "PermitRootLogin is not set to 'no'"
    remediation = "Set 'PermitRootLogin no' in sshd_config"
    cis_reference = "CIS 5.2.7"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "permitrootlogin":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="PermitRootLogin",
                            severity=self.severity,
                            description=f"PermitRootLogin is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="PermitRootLogin",
                    severity=self.severity,
                    description="PermitRootLogin is not configured (defaults to 'prohibit-password')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class PermitEmptyPasswordsRule(Rule):
    """PermitEmptyPasswords must be 'no'."""

    rule_id = "AUTH-002"
    severity = Severity.CRITICAL
    description = "PermitEmptyPasswords is not set to 'no'"
    remediation = "Set 'PermitEmptyPasswords no' in sshd_config"
    cis_reference = "CIS 5.2.8"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "permitemptypasswords":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="PermitEmptyPasswords",
                            severity=self.severity,
                            description=f"PermitEmptyPasswords is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="PermitEmptyPasswords",
                    severity=self.severity,
                    description="PermitEmptyPasswords is not configured (defaults to 'no' but should be explicit)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class PasswordAuthenticationRule(Rule):
    """PasswordAuthentication should be 'no' (key-only auth preferred)."""

    rule_id = "AUTH-003"
    severity = Severity.HIGH
    description = "PasswordAuthentication is not set to 'no'"
    remediation = "Set 'PasswordAuthentication no' and use key-based authentication"
    cis_reference = "CIS 5.2.10"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "passwordauthentication":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="PasswordAuthentication",
                            severity=self.severity,
                            description=f"PasswordAuthentication is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="PasswordAuthentication",
                    severity=self.severity,
                    description="PasswordAuthentication is not configured (defaults to 'yes')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class ChallengeResponseAuthenticationRule(Rule):
    """ChallengeResponseAuthentication should be 'no'."""

    rule_id = "AUTH-004"
    severity = Severity.HIGH
    description = "ChallengeResponseAuthentication is not set to 'no'"
    remediation = "Set 'ChallengeResponseAuthentication no' in sshd_config"
    cis_reference = "CIS 5.2.9"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "challengeresponseauthentication":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="ChallengeResponseAuthentication",
                            severity=self.severity,
                            description=f"ChallengeResponseAuthentication is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="ChallengeResponseAuthentication",
                    severity=self.severity,
                    description="ChallengeResponseAuthentication is not configured (defaults to 'yes')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class MaxAuthTriesRule(Rule):
    """MaxAuthTries should be <= 6."""

    rule_id = "AUTH-005"
    severity = Severity.MEDIUM
    description = "MaxAuthTries is set too high"
    remediation = "Set 'MaxAuthTries 6' or lower in sshd_config"
    cis_reference = "CIS 5.2.6"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "maxauthtries":
                found = True
                try:
                    value = int(d["value"])
                except ValueError:
                    continue
                if value > 6:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="MaxAuthTries",
                            severity=self.severity,
                            description=f"MaxAuthTries is set to {value} (should be <= 6)",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="MaxAuthTries",
                    severity=self.severity,
                    description="MaxAuthTries is not configured (defaults to 6)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class LoginGraceTimeRule(Rule):
    """LoginGraceTime should be <= 120 seconds."""

    rule_id = "AUTH-006"
    severity = Severity.MEDIUM
    description = "LoginGraceTime is set too high or not configured"
    remediation = "Set 'LoginGraceTime 120' or lower in sshd_config"
    cis_reference = "CIS 5.2.5"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "logingracetime":
                found = True
                value = d["value"]
                seconds: int | None = None

                # Handle time suffixes (e.g. "2m", "1h")
                if value.lower().endswith("m"):
                    try:
                        seconds = int(value[:-1]) * 60
                    except ValueError:
                        continue
                elif value.lower().endswith("h"):
                    try:
                        seconds = int(value[:-1]) * 3600
                    except ValueError:
                        continue
                else:
                    try:
                        seconds = int(value)
                    except ValueError:
                        continue

                if seconds is not None and seconds > 120:
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="LoginGraceTime",
                            severity=self.severity,
                            description=f"LoginGraceTime is set to {seconds}s (should be <= 120s)",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="LoginGraceTime",
                    severity=self.severity,
                    description="LoginGraceTime is not configured (defaults to 120s)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class UsePAMRule(Rule):
    """UsePAM should be 'yes'."""

    rule_id = "AUTH-007"
    severity = Severity.LOW
    description = "UsePAM is not set to 'yes'"
    remediation = "Set 'UsePAM yes' in sshd_config"
    cis_reference = "CIS 5.2.13"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "usepam":
                found = True
                if d["value"].lower() != "yes":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="UsePAM",
                            severity=self.severity,
                            description=f"UsePAM is set to '{d['value']}' (should be 'yes')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="UsePAM",
                    severity=self.severity,
                    description="UsePAM is not configured (defaults to 'yes' on most systems)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


# Export all rule classes.
RULES = [
    PermitRootLoginRule,
    PermitEmptyPasswordsRule,
    PasswordAuthenticationRule,
    ChallengeResponseAuthenticationRule,
    MaxAuthTriesRule,
    LoginGraceTimeRule,
    UsePAMRule,
]
