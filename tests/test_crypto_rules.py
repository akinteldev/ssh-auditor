"""Tests for ssh_auditor.rules.crypto."""

from __future__ import annotations

import pytest

from ssh_auditor.rules.crypto import (
    CBCModeCipherRule,
    DSAHostKeyRule,
    PreferEd25519Rule,
    ThreeDesCipherRule,
    WeakKexAlgorithmsRule,
)
from ssh_auditor.rules.base import Severity


def _directives(pairs: list[tuple[str, str]]) -> list[dict]:
    return [{"directive": k, "value": v} for k, v in pairs]


class TestThreeDesCipherRule:
    def test_violation(self) -> None:
        rule = ThreeDesCipherRule()
        findings = rule.check(
            _directives([("Ciphers", "aes256-ctr,3des-cbc,aes128-ctr")])
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_compliant(self) -> None:
        rule = ThreeDesCipherRule()
        findings = rule.check(
            _directives([("Ciphers", "aes256-gcm,chacha20-poly1305")])
        )
        assert len(findings) == 0


class TestCBCModeCipherRule:
    def test_violation(self) -> None:
        rule = CBCModeCipherRule()
        findings = rule.check(
            _directives([("Ciphers", "aes128-cbc,aes256-ctr")])
        )
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_compliant(self) -> None:
        rule = CBCModeCipherRule()
        findings = rule.check(
            _directives([("Ciphers", "aes256-gcm,chacha20-poly1305")])
        )
        assert len(findings) == 0


class TestWeakKexAlgorithmsRule:
    def test_group1(self) -> None:
        rule = WeakKexAlgorithmsRule()
        findings = rule.check(
            _directives([("KexAlgorithms", "diffie-hellman-group1-sha1")])
        )
        assert len(findings) == 1

    def test_group14_sha1(self) -> None:
        rule = WeakKexAlgorithmsRule()
        findings = rule.check(
            _directives([("KexAlgorithms", "diffie-hellman-group14-sha1")])
        )
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = WeakKexAlgorithmsRule()
        findings = rule.check(
            _directives([("KexAlgorithms", "curve25519-sha256")])
        )
        assert len(findings) == 0


class TestDSAHostKeyRule:
    def test_violation(self) -> None:
        rule = DSAHostKeyRule()
        findings = rule.check(
            _directives([("HostKeyAlgorithms", "ssh-rsa,ssh-dss")])
        )
        assert len(findings) == 1

    def test_compliant(self) -> None:
        rule = DSAHostKeyRule()
        findings = rule.check(
            _directives([("HostKeyAlgorithms", "ssh-ed25519,rsa-sha2-512")])
        )
        assert len(findings) == 0


class TestPreferEd25519Rule:
    def test_violation(self) -> None:
        rule = PreferEd25519Rule()
        findings = rule.check(
            _directives([("HostKeyAlgorithms", "ecdsa-sha2-nistp256")])
        )
        assert len(findings) == 1

    def test_compliant_ed25519(self) -> None:
        rule = PreferEd25519Rule()
        findings = rule.check(
            _directives([("HostKeyAlgorithms", "ssh-ed25519,rsa-sha2-512")])
        )
        assert len(findings) == 0

    def test_compliant_rsa(self) -> None:
        rule = PreferEd25519Rule()
        findings = rule.check(
            _directives([("HostKeyAlgorithms", "rsa-sha2-512,ssh-ed25519")])
        )
        assert len(findings) == 0
