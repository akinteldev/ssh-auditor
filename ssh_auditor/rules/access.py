"""Access control audit rules.

Checks for gateway ports, TCP forwarding, tunnel permissions, and
user/group allow lists in sshd_config.
"""

from __future__ import annotations

from typing import Any

from ssh_auditor.rules.base import Finding, Rule, Severity


class AllowUsersOrGroupsRule(Rule):
    """AllowUsers or AllowGroups should be set (not left open to all)."""

    rule_id = "ACCESS-001"
    severity = Severity.CRITICAL
    description = "No AllowUsers or AllowGroups directive configured"
    remediation = (
        "Add 'AllowUsers' or 'AllowGroups' to restrict SSH access "
        "to specific users or groups"
    )
    cis_reference = "CIS 5.2.16"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        has_allow = False
        for d in directives:
            dl = d["directive"].lower()
            if dl in ("allowusers", "allowgroups"):
                has_allow = True
                break
        if not has_allow:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="AllowUsers/AllowGroups",
                    severity=self.severity,
                    description="No AllowUsers or AllowGroups directive configured (all users can SSH)",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class GatewayPortsRule(Rule):
    """GatewayPorts must be 'no'."""

    rule_id = "ACCESS-002"
    severity = Severity.HIGH
    description = "GatewayPorts is not set to 'no'"
    remediation = "Set 'GatewayPorts no' in sshd_config"
    cis_reference = "CIS 5.2.18"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "gatewayports":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="GatewayPorts",
                            severity=self.severity,
                            description=f"GatewayPorts is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="GatewayPorts",
                    severity=self.severity,
                    description="GatewayPorts is not configured (defaults to 'no')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class AllowTcpForwardingRule(Rule):
    """AllowTcpForwarding should be 'no' (unless explicitly needed)."""

    rule_id = "ACCESS-003"
    severity = Severity.MEDIUM
    description = "AllowTcpForwarding is not set to 'no'"
    remediation = "Set 'AllowTcpForwarding no' in sshd_config unless TCP forwarding is required"
    cis_reference = "CIS 5.2.17"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "allowtcpforwarding":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="AllowTcpForwarding",
                            severity=self.severity,
                            description=f"AllowTcpForwarding is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="AllowTcpForwarding",
                    severity=self.severity,
                    description="AllowTcpForwarding is not configured (defaults to 'yes')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


class PermitTunnelRule(Rule):
    """PermitTunnel should be 'no'."""

    rule_id = "ACCESS-004"
    severity = Severity.MEDIUM
    description = "PermitTunnel is not set to 'no'"
    remediation = "Set 'PermitTunnel no' in sshd_config unless tunneling is required"
    cis_reference = "CIS 5.2.19"

    def check(self, directives: list[dict[str, Any]]) -> list[Finding]:
        found = False
        for d in directives:
            if d["directive"].lower() == "permittunnel":
                found = True
                if d["value"].lower() != "no":
                    return [
                        Finding(
                            rule_id=self.rule_id,
                            directive="PermitTunnel",
                            severity=self.severity,
                            description=f"PermitTunnel is set to '{d['value']}' (should be 'no')",
                            remediation=self.remediation,
                            cis_reference=self.cis_reference,
                        )
                    ]
        if not found:
            return [
                Finding(
                    rule_id=self.rule_id,
                    directive="PermitTunnel",
                    severity=self.severity,
                    description="PermitTunnel is not configured (defaults to 'no')",
                    remediation=self.remediation,
                    cis_reference=self.cis_reference,
                )
            ]
        return []


# Export all rule classes.
RULES = [
    AllowUsersOrGroupsRule,
    GatewayPortsRule,
    AllowTcpForwardingRule,
    PermitTunnelRule,
]
