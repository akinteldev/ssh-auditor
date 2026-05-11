"""Tests for ssh_auditor.rules.access and hardening."""

from __future__ import annotations

import pytest

from ssh_auditor.rules.access import (
    AllowTcpForwardingRule,
    AllowUsersOrGroupsRule,
    GatewayPortsRule,
    PermitTunnelRule,
)
from ssh_auditor.rules.base import Severity
from ssh_auditor.rules.hardening import (
    BannerRule,
    ClientAliveIntervalRule,
    LogLevelRule,
    PrintMotdRule,
    ProtocolRule,
    StrictModesRule,
    X11ForwardingRule,
)


def _directives(pairs: list[tuple[str, str]]) -> list[dict]:
    return [{"directive": k, "value": v} for k, v in pairs]


# ---- Access rules ---------------------------------------------------------

class TestAllowUsersOrGroupsRule:
    def test_violation(self) -> None:
        rule = AllowUsersOrGroupsRule()
        findings = rule.check([])
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_compliant_allowusers(self) -> None:
        rule = AllowUsersOrGroupsRule()
        findings = rule.check(_directives([("AllowUsers", "admin")]))
        assert len(findings) == 0

    def test_compliant_allowgroups(self) -> None:
        rule = AllowUsersOrGroupsRule()
        findings = rule.check(_directives([("AllowGroups", "sshusers")]))
        assert len(findings) == 0


class TestGatewayPortsRule:
    def test_violation(self) -> None:
        rule = GatewayPortsRule()
        findings = rule.check(_directives([("GatewayPorts", "yes")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = GatewayPortsRule()
        findings = rule.check(_directives([("GatewayPorts", "no")]))
        assert len(findings) == 0


class TestAllowTcpForwardingRule:
    def test_violation(self) -> None:
        rule = AllowTcpForwardingRule()
        findings = rule.check(_directives([("AllowTcpForwarding", "yes")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = AllowTcpForwardingRule()
        findings = rule.check(_directives([("AllowTcpForwarding", "no")]))
        assert len(findings) == 0


class TestPermitTunnelRule:
    def test_violation(self) -> None:
        rule = PermitTunnelRule()
        findings = rule.check(_directives([("PermitTunnel", "yes")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = PermitTunnelRule()
        findings = rule.check(_directives([("PermitTunnel", "no")]))
        assert len(findings) == 0


# ---- Hardening rules ------------------------------------------------------

class TestX11ForwardingRule:
    def test_violation(self) -> None:
        rule = X11ForwardingRule()
        findings = rule.check(_directives([("X11Forwarding", "yes")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = X11ForwardingRule()
        findings = rule.check(_directives([("X11Forwarding", "no")]))
        assert len(findings) == 0


class TestBannerRule:
    def test_violation_missing(self) -> None:
        rule = BannerRule()
        findings = rule.check([])
        assert len(findings) == 1

    def test_violation_none(self) -> None:
        rule = BannerRule()
        findings = rule.check(_directives([("Banner", "none")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = BannerRule()
        findings = rule.check(_directives([("Banner", "/etc/ssh/banner")]))
        assert len(findings) == 0


class TestPrintMotdRule:
    def test_violation(self) -> None:
        rule = PrintMotdRule()
        findings = rule.check(_directives([("PrintMotd", "yes")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = PrintMotdRule()
        findings = rule.check(_directives([("PrintMotd", "no")]))
        assert len(findings) == 0


class TestClientAliveIntervalRule:
    def test_violation_zero(self) -> None:
        rule = ClientAliveIntervalRule()
        findings = rule.check(_directives([("ClientAliveInterval", "0")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = ClientAliveIntervalRule()
        findings = rule.check(_directives([("ClientAliveInterval", "300")]))
        assert len(findings) == 0


class TestLogLevelRule:
    def test_violation_quiet(self) -> None:
        rule = LogLevelRule()
        findings = rule.check(_directives([("LogLevel", "QUIET")]))
        assert len(findings) == 1

    def test_compliant_verbose(self) -> None:
        rule = LogLevelRule()
        findings = rule.check(_directives([("LogLevel", "VERBOSE")]))
        assert len(findings) == 0

    def test_compliant_info(self) -> None:
        rule = LogLevelRule()
        findings = rule.check(_directives([("LogLevel", "INFO")]))
        assert len(findings) == 0


class TestProtocolRule:
    def test_violation_2_1(self) -> None:
        rule = ProtocolRule()
        findings = rule.check(_directives([("Protocol", "2,1")]))
        assert len(findings) == 1

    def test_violation_1(self) -> None:
        rule = ProtocolRule()
        findings = rule.check(_directives([("Protocol", "1")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = ProtocolRule()
        findings = rule.check(_directives([("Protocol", "2")]))
        assert len(findings) == 0


class TestStrictModesRule:
    def test_violation(self) -> None:
        rule = StrictModesRule()
        findings = rule.check(_directives([("StrictModes", "no")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = StrictModesRule()
        findings = rule.check(_directives([("StrictModes", "yes")]))
        assert len(findings) == 0
