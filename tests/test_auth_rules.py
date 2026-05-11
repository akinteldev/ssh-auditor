"""Tests for ssh_auditor.rules.auth."""

from __future__ import annotations

import pytest

from ssh_auditor.rules.auth import (
    ChallengeResponseAuthenticationRule,
    LoginGraceTimeRule,
    MaxAuthTriesRule,
    PasswordAuthenticationRule,
    PermitEmptyPasswordsRule,
    PermitRootLoginRule,
    UsePAMRule,
)
from ssh_auditor.rules.base import Severity


def _directives(pairs: list[tuple[str, str]]) -> list[dict]:
    """Helper to create directive dicts."""
    return [{"directive": k, "value": v} for k, v in pairs]


class TestPermitRootLoginRule:
    def test_violation_yes(self) -> None:
        rule = PermitRootLoginRule()
        findings = rule.check(_directives([("PermitRootLogin", "yes")]))
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_violation_prohibit_password(self) -> None:
        rule = PermitRootLoginRule()
        findings = rule.check(_directives([("PermitRootLogin", "prohibit-password")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = PermitRootLoginRule()
        findings = rule.check(_directives([("PermitRootLogin", "no")]))
        assert len(findings) == 0

    def test_missing(self) -> None:
        rule = PermitRootLoginRule()
        findings = rule.check([])
        assert len(findings) == 1


class TestPermitEmptyPasswordsRule:
    def test_violation(self) -> None:
        rule = PermitEmptyPasswordsRule()
        findings = rule.check(_directives([("PermitEmptyPasswords", "yes")]))
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_compliant(self) -> None:
        rule = PermitEmptyPasswordsRule()
        findings = rule.check(_directives([("PermitEmptyPasswords", "no")]))
        assert len(findings) == 0


class TestPasswordAuthenticationRule:
    def test_violation(self) -> None:
        rule = PasswordAuthenticationRule()
        findings = rule.check(_directives([("PasswordAuthentication", "yes")]))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_compliant(self) -> None:
        rule = PasswordAuthenticationRule()
        findings = rule.check(_directives([("PasswordAuthentication", "no")]))
        assert len(findings) == 0


class TestChallengeResponseAuthenticationRule:
    def test_violation(self) -> None:
        rule = ChallengeResponseAuthenticationRule()
        findings = rule.check(_directives([("ChallengeResponseAuthentication", "yes")]))
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_compliant(self) -> None:
        rule = ChallengeResponseAuthenticationRule()
        findings = rule.check(_directives([("ChallengeResponseAuthentication", "no")]))
        assert len(findings) == 0


class TestMaxAuthTriesRule:
    def test_violation(self) -> None:
        rule = MaxAuthTriesRule()
        findings = rule.check(_directives([("MaxAuthTries", "10")]))
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_compliant(self) -> None:
        rule = MaxAuthTriesRule()
        findings = rule.check(_directives([("MaxAuthTries", "3")]))
        assert len(findings) == 0

    def test_boundary(self) -> None:
        rule = MaxAuthTriesRule()
        findings = rule.check(_directives([("MaxAuthTries", "6")]))
        assert len(findings) == 0


class TestLoginGraceTimeRule:
    def test_violation(self) -> None:
        rule = LoginGraceTimeRule()
        findings = rule.check(_directives([("LoginGraceTime", "300")]))
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = LoginGraceTimeRule()
        findings = rule.check(_directives([("LoginGraceTime", "60")]))
        assert len(findings) == 0

    def test_boundary(self) -> None:
        rule = LoginGraceTimeRule()
        findings = rule.check(_directives([("LoginGraceTime", "120")]))
        assert len(findings) == 0


class TestUsePAMRule:
    def test_violation(self) -> None:
        rule = UsePAMRule()
        findings = rule.check(_directives([("UsePAM", "no")]))
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_compliant(self) -> None:
        rule = UsePAMRule()
        findings = rule.check(_directives([("UsePAM", "yes")]))
        assert len(findings) == 0
